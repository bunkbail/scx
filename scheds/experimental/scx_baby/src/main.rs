// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
mod tiers;
use stats::Census;
use stats::Ranks;
use stats::WaitB;
use stats::WaitCls;
use stats::WaitGateMiss;
use stats::{WaitLCRI, WaitType};
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::debug;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::CoreType;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use stats::Metrics;
use tiers::CoreClasses;

const SCHEDULER_NAME: &str = "scx_baby";

/// Highest possible NUMA node id plus one, from sysfs. The topology's
/// node map only holds nodes with online CPUs, while the BPF side
/// creates a DSQ for every possible node id.
fn possible_node_ids() -> Result<usize> {
    let text = std::fs::read_to_string("/sys/devices/system/node/possible")
        .context("reading /sys/devices/system/node/possible")?;
    let mut max: Option<usize> = None;
    for part in text.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let end = part.rsplit('-').next().unwrap().trim();
        let end: usize = end
            .parse()
            .with_context(|| format!("parsing NUMA node range {part:?}"))?;
        max = Some(max.map_or(end, |m| m.max(end)));
    }
    max.map(|m| m + 1).context("empty possible NUMA node list")
}

/// The original prio_factor[40] table, in nanoseconds at the original
/// 1.18ms deadline. Userspace rescales it to the configured deadline
/// so the base offset and the nice shift keep their proportions.
const PRIO_FACTOR_BASE: [i64; 40] = [
    /* -20 */ -1080000, -980000, -880000, -780000, -680000, /* -15 */ -580000, -480000,
    -380000, -280000, -180000, /* -10 */ -80000, -79000, -78000, -77000, -76000,
    /*  -5 */ -75000, -74000, -73000, -72000, -71000, /*   0 */ 0, 1080000, 1090000,
    1100000, 1110000, /*   5 */ 1120000, 1130000, 1140000, 1150000, 1160000,
    /*  10 */ 1170000, 1180000, 1190000, 1200000, 1210000, /*  15 */ 1220000, 1230000,
    1240000, 1250000, 1260000,
];

const DEADLINE_NS_DEFAULT: i64 = 1_180_000;

/// Rescale the nice table to the configured deadline. The result is an
/// absolute offset from now, so the BPF side never multiplies: the
/// floor keeps a boosted task's deadline in the future even at the
/// smallest accepted `-d`.
fn scaled_prio_offsets(deadline_ns: u64) -> [i64; consts_BABY_PRIO_OFFSET_NR as usize] {
    let base = deadline_ns as i64;
    let floor = (base >> 5).max(10_000);
    let mut table = [0i64; consts_BABY_PRIO_OFFSET_NR as usize];

    for (slot, factor) in table.iter_mut().zip(PRIO_FACTOR_BASE) {
        *slot = (base + factor * base / DEADLINE_NS_DEFAULT).max(floor);
    }
    table
}

/// Classify the cores from the topology and the sysfs capacity and
/// frequency ladders. Pure over its inputs, so the tier counts can be
/// written as rodata before load.
fn classify_cores(topo: &Topology) -> (CoreClasses, tiers::TierSource) {
    // The kernel's own per-CPU capacity, exported by hybrid and ARM
    // parts.
    let capacity = |id: usize| {
        std::fs::read_to_string(format!("/sys/devices/system/cpu/cpu{id}/cpu_capacity"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    };
    // The core types as scx_utils derived them from its capacity
    // ladder; the input of the fallback branch.
    let is_big_core_type = |id: usize| {
        topo.all_cpus
            .get(&id)
            .map(|cpu| matches!(cpu.core_type, CoreType::Big { .. }))
    };
    // The hardware maximum frequency: the corroboration input that
    // keeps a claimed core-type split from being a ranking artifact
    // (see tiers::classify).
    let max_freq = |id: usize| {
        std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{id}/cpufreq/cpuinfo_max_freq"
        ))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|freq| *freq > 0)
    };

    let ids: Vec<usize> = topo.all_cpus.keys().copied().collect();
    tiers::classify(&ids, &capacity, &is_big_core_type, &max_freq)
}

#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_baby",
    version,
    disable_version_flag = true,
    about = "An earliest-deadline-first sched_ext scheduler with warm seats and hybrid-tier compaction.",
    long_about = r#"
Every runnable task owns a deadline, an absolute timestamp by which it
would like to run, and each CPU serves the earliest deadline it can
reach: waking tasks go straight onto idle cores, and once the machine
is oversubscribed they park in the warm seat on the CPU they last ran
on, behind the task holding it.

Four classes - latency-critical, interactive, foreground and heavy,
classified from burst history and wake frequency - set the slice
lengths and decide who may preempt whom. A latency-critical waiter cuts
a saturated CPU's holding slice short at the tick, and on hybrid
platforms light work compacts onto the little cores while heavy tasks
hold the big ones.

Tasks that voluntarily sleep before consuming their deadline are
treated as interactive: their effective nice level is boosted by one
step (down to -20), which pulls their future deadlines earlier.

CPU hogs are accounted by a burst tracker over a 200ms window. The
wake-path preemption will not displace a task inside the narrow band
where its current window is about to complete the previous one; a
proven hog is always reschedulable by an earlier deadline.

The deadline scheme, the burst throttle and the sleep-before-deadline
boost descend from Hamad Al Marri's Baby CPU Scheduler, deadline
variant (baby-dl); the queue topology, warm seats, classes and
placement are original to this scheduler.
"#
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Deadline offset in microseconds: every task is assigned
    /// deadline = now + deadline offset (default 1180us, the original
    /// DEADLINE_NS). This is also the base time slice of each task. The
    /// scheduler is a deadline machine, so a value near zero collapses
    /// every slice to nothing; accepted range is 100 to 100000. Above
    /// 10000 the tick is the only preemption source for a full slice,
    /// and the scheduler warns.
    #[clap(
        short = 'd',
        long,
        default_value = "1180",
        value_parser = clap::value_parser!(u64).range(100..=100_000)
    )]
    deadline_us: u64,

    /// CPU frequency performance level (0 = min, 1024 = max). Accepted
    /// range is -2 to 1024.
    ///
    /// By default (-1, auto) the scheduler scales the performance level
    /// of each CPU in function of its utilization. -2 leaves the
    /// platform's cpufreq setup entirely alone.
    #[clap(
        short = 'p',
        long,
        allow_hyphen_values = true,
        default_value = "-1",
        value_parser = clap::value_parser!(i64).range(-2..=1024)
    )]
    perf_lvl: i64,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable BPF debugging via /sys/kernel/tracing/trace_pipe.
    #[clap(short = 'D', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        // Initialize CPU topology.
        let topo = Topology::new().context("failed to read CPU topology")?;

        // The BPF side iterates every possible node id, including
        // memory-only nodes the topology does not list, so the bound is
        // the kernel's possible-node range, not the online node count.
        let nr_node_ids = possible_node_ids().context("failed to read possible NUMA nodes")?;
        ensure!(
            nr_node_ids <= consts_BABY_MAX_NODES as usize,
            "too many NUMA node ids ({}) for the {} node DSQs the id layout holds",
            nr_node_ids,
            consts_BABY_MAX_NODES
        );
        ensure!(
            *NR_CPU_IDS <= consts_BABY_MAX_CPUS as usize,
            "scx_baby supports at most {} CPU IDs, this host has {}",
            consts_BABY_MAX_CPUS,
            *NR_CPU_IDS
        );

        // The tier split is pure over its sysfs inputs, so classify it
        // before load: the counts are rodata the verifier reads, and
        // only the cpumasks need the loaded program.
        let (classes, tier_source) = classify_cores(&topo);
        info!(
            "core classes ({tier_source:?}): big={:?} little={:?} lp={:?}",
            classes.big, classes.little, classes.lp
        );

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if topo.smt_enabled {
                "SMT on"
            } else {
                "SMT off"
            }
        );

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, baby_ops, open_opts)?;

        skel.struct_ops.baby_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.debug = opts.debug;
        rodata.deadline_ns = opts.deadline_us * 1000;
        rodata.prio_offset_ns = scaled_prio_offsets(rodata.deadline_ns);

        // The wait/census instrument and the distance histograms run
        // only when the scheduler was started with --stats: the flag
        // is fixed at load. The wait stamps stay unconditional; the
        // starve-rescue timer reads them.
        rodata.stats_enabled = opts.stats.is_some();

        // Topology counts are rodata: the verifier folds every bound
        // check and prunes the hybrid arms when a tier is empty.
        rodata.nr_cpu_ids = *NR_CPU_IDS as u64;
        rodata.nr_node_ids = nr_node_ids as u64;
        rodata.nr_big_cpus = classes.big.len() as u64;
        rodata.nr_little_cpus = classes.little.len() as u64;

        // Publish the cache-topology distance tables. The BPF side
        // compares ids for equality, and 0 means "unfilled" there, so
        // every id is stored offset by one: an id of 0 becomes 1, and
        // an entry the userspace never filled can never compare equal
        // to a filled one. Entries are indexed by CPU id, so an
        // offline CPU leaves its entry unfilled instead of shifting
        // the table under the following CPUs.
        for cpu in topo.all_cpus.values() {
            rodata.topo_node[cpu.id] = cpu.node_id as u32 + 1;
            rodata.topo_llc[cpu.id] = cpu.llc_id as u32 + 1;
            rodata.topo_l2[cpu.id] = cpu.l2_id as u32 + 1;
            rodata.topo_core[cpu.id] = cpu.core_id as u32 + 1;
        }
        info!(
            "distance ladder: smt={} l2s={} llcs={} nodes={}",
            topo.smt_enabled,
            topo.all_cpus
                .values()
                .map(|c| c.l2_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            topo.all_cpus
                .values()
                .map(|c| c.llc_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            topo.nodes.len(),
        );

        // Set the CPU frequency performance level (-1 = automatic).
        info!(
            "cpuperf level: {}",
            match opts.perf_lvl {
                n if n < 0 => "auto".into(),
                0 => "min".into(),
                1024 => "max".into(),
                n => n.to_string(),
            }
        );
        rodata.cpuperf_lvl = opts.perf_lvl;

        // Set scheduler flags.
        //
        // SCX_OPS_ENQ_LAST stops the kernel from automatically keeping
        // prev and refilling it with the 20ms SCX_SLICE_DFL when
        // ops.dispatch() leaves the local DSQ empty. The task instead
        // re-enters ops.enqueue() with SCX_ENQ_LAST and keeps its
        // deadline.
        skel.struct_ops.baby_ops_mut().flags = *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.baby_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, baby_ops, uei)?;

        // Publish the tier masks; the counts went in as rodata above.
        Self::publish_core_classes(&mut skel, &classes)?;

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, baby_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn publish_core_classes(skel: &mut BpfSkel<'_>, classes: &CoreClasses) -> Result<()> {
        for id in &classes.big {
            Self::enable_core_class(skel, *id, core_tier_CORE_TIER_BIG)?;
        }
        for id in &classes.little {
            Self::enable_core_class(skel, *id, core_tier_CORE_TIER_LITTLE)?;
        }
        for id in &classes.lp {
            Self::enable_core_class(skel, *id, core_tier_CORE_TIER_LP)?;
        }
        Ok(())
    }

    fn enable_core_class(skel: &mut BpfSkel<'_>, cpu: usize, tier: u32) -> Result<()> {
        let prog = &mut skel.progs.enable_core_class;
        let mut args = core_arg {
            cpu_id: cpu as i32,
            tier: tier as i32,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog
            .test_run(input)
            .context("enable_core_class test_run failed")?;
        if out.return_value != 0 {
            return Err(anyhow::anyhow!(
                "enable_core_class failed for CPU {}: {}",
                cpu,
                out.return_value
            ));
        }

        Ok(())
    }

    fn get_metrics(&mut self) -> Metrics {
        let metrics = self.read_metrics();

        /*
         * Reset the BPF maxima after the read, so the next snapshot
         * reports its own interval maximum rather than the all-time
         * high-water mark. A BPF update racing the reset can lose one
         * sample; the report is diagnostic and the counts are not.
         */
        let bss_data = self.skel.maps.bss_data.as_mut().unwrap();
        bss_data.nr_wait_max.fill(0);
        bss_data.nr_wait_cls_max.fill(0);
        bss_data.nr_wait_type_max.fill(0);
        bss_data.nr_wait_lcri_max.fill(0);
        bss_data.nr_wait_wg_max.fill(0);

        metrics
    }

    fn read_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_running: bss_data.nr_running,
            stats_enabled: self.skel.maps.rodata_data.as_ref().unwrap().stats_enabled as u64,
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_preemptions: bss_data.nr_preemptions,
            nr_boosts: bss_data.nr_boosts,
            nr_sticky: bss_data.nr_sticky,
            nr_coldspreads: bss_data.nr_coldspreads,
            nr_class: bss_data.nr_class.to_vec(),
            nr_lane: bss_data.nr_lane.to_vec(),
            nr_tick_preempts: bss_data.nr_tick_preempts,
            nr_tick_preempts_warm: bss_data.nr_tick_preempts_warm,
            nr_tick_cut_refused: bss_data.nr_tick_cut_refused,
            nr_lease_requeues: bss_data.nr_lease_requeues,
            nr_home_takebacks: bss_data.nr_home_takebacks,
            nr_depth1_pulls: bss_data.nr_depth1_pulls,
            nr_depth1_pulls_seat: bss_data.nr_depth1_pulls_seat,
            nr_bulk_backstop: bss_data.nr_bulk_backstop,
            nr_wake_preempts: bss_data.nr_wake_preempts,
            nr_land: Ranks::of(&bss_data.nr_land),
            nr_wake_land: Ranks::of(&bss_data.nr_wake_land),
            nr_seat_self: bss_data.nr_seat_self,
            nr_seat_move: Ranks::of(&bss_data.nr_seat_move),
            nr_pull_land: Ranks::of(&bss_data.nr_pull_land),
            // The per-type arrival array is the single source: a seat
            // arrival is type * 2, a shared arrival type * 2 + 1.
            nr_arr_seat: bss_data.nr_arr_type[0] + bss_data.nr_arr_type[2],
            nr_arr_shared: bss_data.nr_arr_type[1] + bss_data.nr_arr_type[3],
            wait_n: WaitB::of(&bss_data.nr_wait_n),
            wait_ns: WaitB::of(&bss_data.nr_wait_ns),
            wait_max: WaitB::of(&bss_data.nr_wait_max),
            wait_slow: WaitB::of(&bss_data.nr_wait_slow),
            wait_cls: WaitCls::of(
                &bss_data.nr_wait_cls_n,
                &bss_data.nr_wait_cls_ns,
                &bss_data.nr_wait_cls_max,
                &bss_data.nr_wait_cls_slow,
            ),
            wait_type: WaitType::of(
                &bss_data.nr_wait_type_n,
                &bss_data.nr_wait_type_ns,
                &bss_data.nr_wait_type_max,
                &bss_data.nr_wait_type_slow,
            ),
            wait_lcri: WaitLCRI::of(
                &bss_data.nr_wait_lcri_n,
                &bss_data.nr_wait_lcri_ns,
                &bss_data.nr_wait_lcri_max,
                &bss_data.nr_wait_lcri_slow,
            ),
            wait_wg: WaitGateMiss::of(
                &bss_data.nr_wait_wg_n,
                &bss_data.nr_wait_wg_ns,
                &bss_data.nr_wait_wg_max,
                &bss_data.nr_wait_wg_slow,
            ),
            nr_arr_wake_seat: bss_data.nr_arr_type[2],
            nr_arr_wake_shared: bss_data.nr_arr_type[3],
            nr_arr_rot_seat: bss_data.nr_arr_type[0],
            nr_arr_rot_shared: bss_data.nr_arr_type[1],
            census: Census::of(&bss_data.nr_census_seat, &bss_data.nr_census_shared),
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    scx_utils::init_libbpf_logging(None);
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    if opts.deadline_us > 10_000 {
        warn!(
            "-d {}us is above 10ms: the tick is the only preemption source for a full slice",
            opts.deadline_us
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut monitor = None;
    if let Some(intv) = opts.monitor.or(opts.stats) {
        ensure!(
            intv.is_finite() && intv > 0.0,
            "--stats/--monitor interval must be a positive number of seconds"
        );
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
        monitor = Some(jh);
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    /*
     * Stop the monitor with the scheduler. Without this the thread
     * outlives run(), across every hotplug restart, and keeps asking a
     * skeleton that is about to be dropped for metrics.
     */
    shutdown.store(true, Ordering::Relaxed);
    if let Some(jh) = monitor {
        let _ = jh.join();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_us_outside_the_range_is_rejected() {
        assert!(Opts::try_parse_from(["scx_baby", "-d", "50"]).is_err());
        assert!(Opts::try_parse_from(["scx_baby", "-d", "0"]).is_err());
        assert!(Opts::try_parse_from(["scx_baby", "-d", "100001"]).is_err());

        let ok = Opts::try_parse_from(["scx_baby", "-d", "500"]).unwrap();
        assert_eq!(ok.deadline_us, 500);
    }

    /// Test-only mirror of the wake-rate blend and peak gate in
    /// class.bpf.c. The BPF side cannot be unit tested from userspace, so
    /// this pins the arithmetic the class bar depends on: the 50/50
    /// warmup, the round-up that lets a 5-sample rate reach 5, and the
    /// four-sample warmup that keeps one startup spike from arming the
    /// peak.
    fn wake_rate_blend(avg: u64, raw: u64, samples: u32) -> u64 {
        if samples < 4 {
            (avg + raw + 1) >> 1
        } else {
            (3 * avg + raw + 3) >> 2
        }
    }

    fn class_peak_after(seq: &[u64]) -> u32 {
        let mut avg = 0u64;
        let mut samples = 0u32;
        let mut peak = 0u32;

        for &raw in seq {
            avg = wake_rate_blend(avg, raw, samples);
            if samples < 4 {
                samples += 1;
            }
            peak -= peak >> 6;
            if samples >= 4 {
                let cand = avg as u32;

                if cand > peak {
                    peak = cand;
                }
            }
        }
        peak
    }

    #[test]
    fn rounded_blend_reaches_the_wake_bar() {
        // 100Hz reaches 10; a 50Hz sample of 5 reaches the class bar
        // of 5. A truncating 3:1 blend has a fixed point at 9 for the
        // 100Hz input, so the round-up matters.
        assert_eq!(wake_rate_blend(9, 10, 4), 10);
        assert!(class_peak_after(&[10; 8]) >= 10);
        assert!(class_peak_after(&[5; 8]) >= 5);
    }

    #[test]
    fn sixty_hz_clears_the_wake_bar() {
        // 60Hz is six wakes per 100ms: above the class bar of 5. The
        // foreground test adds the runtime floor on top of the bar,
        // which this mirror does not model.
        let peak = class_peak_after(&[6; 16]);
        assert!(peak >= 5);
    }

    #[test]
    fn one_startup_spike_is_smoothed_out() {
        // One very short interval followed by three slow wakes blends
        // down to 7 by the time the peak can arm; it does not latch
        // the spike.
        assert_eq!(class_peak_after(&[100, 0, 0, 0]), 7);
    }

    #[test]
    fn fast_wakers_keep_the_class() {
        assert!(class_peak_after(&[12; 8]) >= 5);
        // After a slowdown the hold stays above the bar even though
        // the current average is no longer there.
        let peak = class_peak_after(&[12, 12, 12, 12, 6, 6, 6, 6]);
        assert!(peak >= 5);
    }

    #[test]
    fn woke_task_keeps_interactive_through_a_zero_window() {
        // Mirror of is_interactive: runtime in either window, or four
        // wake samples, keeps a task interactive; a fresh hog is
        // rejected by the burst bound.
        fn interactive(prev: u64, curr: u64, samples: u32) -> bool {
            (prev > 0 || curr > 0 || samples >= 4) && prev < 50_000_000 && curr < 50_000_000
        }
        assert!(interactive(0, 10_000_000, 4));
        assert!(interactive(0, 10_000_000, 0));
        assert!(!interactive(0, 60_000_000, 0));
        assert!(!interactive(60_000_000, 10_000_000, 4));
    }

    #[test]
    fn prio_offsets_keep_nice_zero_at_the_base() {
        for deadline_ns in [100_000u64, 500_000, 1_180_000, 10_000_000] {
            let table = scaled_prio_offsets(deadline_ns);
            assert_eq!(table[20], deadline_ns as i64);
        }
    }

    #[test]
    fn negative_nice_offsets_stay_in_the_future() {
        let table = scaled_prio_offsets(100_000);
        // Nice -20 at the smallest accepted -d: the floor, not a
        // deadline in the past.
        assert_eq!(table[0], 10_000);
        // Nice -1 is pulled earlier than the base but stays positive.
        assert!(table[19] > 0 && table[19] < 100_000);
    }

    #[test]
    fn prio_offsets_scale_with_the_deadline() {
        let small = scaled_prio_offsets(1_180_000);
        let large = scaled_prio_offsets(2_360_000);
        assert!(large[0] > small[0]);
        assert_eq!(small[20], 1_180_000);
        assert_eq!(large[20], 2_360_000);
    }

    #[test]
    fn perf_lvl_outside_the_range_is_rejected() {
        assert!(Opts::try_parse_from(["scx_baby", "-p", "-3"]).is_err());
        assert!(Opts::try_parse_from(["scx_baby", "-p", "1025"]).is_err());

        let ok = Opts::try_parse_from(["scx_baby", "-p", "-2"]).unwrap();
        assert_eq!(ok.perf_lvl, -2);
        let ok = Opts::try_parse_from(["scx_baby", "-p", "1024"]).unwrap();
        assert_eq!(ok.perf_lvl, 1024);
    }

    // Load only, never attach: the synthetic shapes drive no live
    // scheduler. The topology counts are rodata, so the BPF loops and
    // bounds checks are verified against the synthetic width too, and
    // both hybrid-gate arms are exercised by publishing a tier split
    // for every shape.
    #[test]
    #[ignore = "requires BPF load capabilities and a sched_ext kernel"]
    fn verifier_load_synthetic_topologies() -> anyhow::Result<()> {
        libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, |_, message| {
            eprint!("{message}");
        })));

        let mut failures = Vec::new();
        for nr_cpus in [1usize, 14, 128] {
            let mut object = MaybeUninit::uninit();
            let builder = BpfSkelBuilder::default();
            let mut skel = scx_ops_open!(builder, &mut object, baby_ops, None)?;
            let ro = skel.maps.rodata_data.as_mut().unwrap();
            ro.deadline_ns = 1180 * 1000;
            ro.prio_offset_ns = scaled_prio_offsets(ro.deadline_ns);
            ro.nr_cpu_ids = nr_cpus as u64;
            ro.nr_node_ids = 2;
            ro.nr_big_cpus = (nr_cpus / 2) as u64;
            ro.nr_little_cpus = (nr_cpus - nr_cpus / 2) as u64;
            for cpu in 0..nr_cpus.min(ro.topo_node.len()) {
                // Two node-ish halves, eight LLCs, per-pair L2 groups
                // and SMT pairs - a denser distance ladder than any
                // real host of this size.
                ro.topo_node[cpu] = if cpu < nr_cpus / 2 { 1 } else { 2 };
                ro.topo_llc[cpu] = (cpu % 8) as u32 + 1;
                ro.topo_l2[cpu] = (cpu / 2) as u32 + 1;
                ro.topo_core[cpu] = (cpu / 2) as u32 + 1;
            }
            match scx_ops_load!(skel, baby_ops, uei) {
                Ok(loaded) => drop(loaded),
                Err(error) => failures.push(format!("{nr_cpus} CPUs: {error:#}")),
            }
        }
        anyhow::ensure!(failures.is_empty(), "{}", failures.join("\n"));
        Ok(())
    }
}
