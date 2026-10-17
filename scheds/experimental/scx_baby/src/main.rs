// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2026 bunkbail <nabildanial.93@gmail.com>
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

const SCHEDULER_NAME: &str = "scx_baby";

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

Four measured classes - latency-critical, interactive, foreground and
heavy, classified from burst history and wake frequency - set the
slice lengths and decide who may preempt whom. A latency-critical
waiter cuts a saturated CPU's holding slice short at the tick, and on
hybrid platforms light work compacts onto the little cores while
heavy tasks hold the big ones.

Tasks that voluntarily sleep before consuming their deadline are
treated as interactive: their effective nice level is boosted by one
step (down to -20), which pulls their future deadlines earlier.

CPU hogs are throttled by a burst tracker that accounts the runtime a
task accumulates over a 200ms window: a task whose bursts keep growing
behind the previous window cannot preempt other tasks even when its
deadline is earlier.

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
    /// DEADLINE_NS). This is also the time slice of each task. The
    /// scheduler is a deadline machine, so a value near zero collapses
    /// every slice to nothing; accepted range is 100 to 100000.
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

        // The wait/census instrument and the distance histograms run
        // only when the scheduler was started with --stats: the flag
        // is fixed at load. The wait stamps stay unconditional; the
        // starve-rescue timer reads them.
        rodata.stats_enabled = opts.stats.is_some();

        // Publish the cache-topology distance tables. The BPF side
        // compares ids for equality, and 0 means "unfilled" there, so
        // every id is stored offset by one: an id of 0 becomes 1, and
        // an entry the userspace never filled can never compare equal
        // to a filled one. Entries are indexed by CPU id, so an
        // offline CPU leaves its entry unfilled instead of shifting
        // the table under the following CPUs.
        if *NR_CPU_IDS > rodata.topo_node.len() {
            anyhow::bail!(
                "scx_baby supports at most {} CPUs, this host has {} CPU IDs",
                rodata.topo_node.len(),
                *NR_CPU_IDS
            );
        }
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
        skel.maps.bss_data.as_mut().unwrap().cpuperf_lvl = opts.perf_lvl;

        // Set scheduler flags.
        //
        // SCX_OPS_ENQ_LAST keeps a task that expires its time slice while
        // staying runnable in the deadline order: the task competes for
        // the CPU again by its deadline, like the original scheduler does
        // across its deadline renewals.
        skel.struct_ops.baby_ops_mut().flags = *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.baby_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, baby_ops, uei)?;

        // Classify the cores and publish the big/little CPU sets.
        Self::init_core_classes(&mut skel, &topo)?;

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, baby_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    // Interactive tasks steer to the big cores, the rest to the little
    // ones. The decision is pure (tiers.rs); this function gathers the
    // sysfs inputs and applies the result. On a platform without a
    // usable tier split every CPU lands in one tier and the hybrid
    // gates are statically false.
    fn init_core_classes(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<()> {
        // The kernel's own per-CPU capacity, exported by hybrid and
        // ARM parts.
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
        // keeps a claimed core-type split from being a ranking
        // artifact (see tiers::classify).
        let max_freq = |id: usize| {
            std::fs::read_to_string(format!(
                "/sys/devices/system/cpu/cpu{id}/cpufreq/cpuinfo_max_freq"
            ))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|freq| *freq > 0)
        };

        let ids: Vec<usize> = topo.all_cpus.keys().copied().collect();
        let (classes, source) = tiers::classify(&ids, &capacity, &is_big_core_type, &max_freq);
        info!(
            "core classes ({source:?}): big={:?} little={:?} lp={:?}",
            classes.big, classes.little, classes.lp
        );

        for id in &ids {
            if !classes.big.contains(id) && classes.lp.contains(id) {
                continue;
            }
            Self::enable_core_class(skel, *id, classes.big.contains(id))?;
        }

        Ok(())
    }

    fn enable_core_class(skel: &mut BpfSkel<'_>, cpu: usize, big: bool) -> Result<()> {
        let prog = &mut skel.progs.enable_core_class;
        let mut args = core_arg {
            cpu_id: cpu as i32,
            big: big as i32,
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
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(anyhow::anyhow!(
                "enable_core_class failed for CPU {}: {}",
                cpu,
                out.return_value
            ));
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_running: bss_data.nr_running,
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_shared_dispatches: bss_data.nr_shared_dispatches,
            nr_preemptions: bss_data.nr_preemptions,
            nr_boosts: bss_data.nr_boosts,
            nr_sticky: bss_data.nr_sticky,
            nr_warmseats: bss_data.nr_warmseats,
            nr_coldspreads: bss_data.nr_coldspreads,
            nr_tick_preempts: bss_data.nr_tick_preempts,
            nr_tick_preempts_warm: bss_data.nr_tick_preempts_warm,
            nr_depth1_pulls: bss_data.nr_depth1_pulls,
            nr_depth1_pulls_seat: bss_data.nr_depth1_pulls_seat,
            nr_wake_preempts: bss_data.nr_wake_preempts,
            nr_land: Ranks::of(&bss_data.nr_land),
            nr_wake_land: Ranks::of(&bss_data.nr_wake_land),
            nr_seat_self: bss_data.nr_seat_self,
            nr_seat_move: Ranks::of(&bss_data.nr_seat_move),
            nr_pull_land: Ranks::of(&bss_data.nr_pull_land),
            nr_arr_seat: bss_data.nr_arr_seat,
            nr_arr_shared: bss_data.nr_arr_shared,
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

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
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
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
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
    // scheduler. The BPF loops stay bounded by the host's CPU count -
    // what varies here is the rodata the distance tables feed, so this
    // pins the loader against tier-table and distance regressions
    // across shapes, not against loop width; a 128-CPU runner is
    // needed for the latter. The hybrid-gate arms need no synthetic
    // tier counts to verify: the BSS counters are unknown scalars to
    // the verifier, so every load proves both sides of every gate.
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
