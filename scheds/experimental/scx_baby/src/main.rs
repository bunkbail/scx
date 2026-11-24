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
    /// deadline = now + deadline offset. This is also the base time
    /// slice of each task. The default is 1180us (the original
    /// DEADLINE_NS), except under `gaming`, which uses 800us; an
    /// explicit -d always wins. The scheduler is a deadline machine, so
    /// a value near zero collapses every slice to nothing; accepted
    /// range is 100 to 100000. Above 10000 the tick is the only
    /// preemption source for a full slice, and the scheduler warns.
    #[clap(
        short = 'd',
        long,
        value_parser = clap::value_parser!(u64).range(100..=100_000)
    )]
    deadline_us: Option<u64>,

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

    /// Scheduling profile. `default` keeps the throughput-first
    /// placement on the 1180us slice. `gaming` runs the plain
    /// virtual-time queue on an 800us slice with the SMT-pair game pin
    /// armed, trading throughput under saturation for lower frame
    /// latency.
    #[clap(
        long,
        default_value = "default",
        value_parser = clap::builder::PossibleValuesParser::new([
            "default", "gaming"
        ])
    )]
    profile: String,

    /// Shorthand for `--profile gaming`: the plain virtual-time queue
    /// on the 800us slice, with the SMT-pair game pin armed.
    /// `--no-game-pin` turns the pin off under either spelling.
    #[clap(long, action = clap::ArgAction::SetTrue, conflicts_with = "profile")]
    game: bool,

    /// Minimal EDF baseline: bypass the warm seats and the two-lane
    /// bulk/fast-lane split. One shared deadline queue per node plus
    /// direct dispatch to an idle CPU. For scheduler comparisons, not
    /// for production.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    plain: bool,

    /// Plain EDF on the base slice. Implies --plain.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    plain_1x: bool,

    /// Bounded wake preemption on plain mode. Implies --plain-1x.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    plain_wake: bool,

    /// Virtual-time ordering on plain mode: one per-node queue keyed by
    /// weighted runtime instead of an absolute deadline, with a
    /// wake-frequency bounded credit. Implies --plain-1x.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    plain_vtime: bool,

    /// Credit window for --plain-vtime, in microseconds: a waking task
    /// may sort ahead by at most this much virtual time per unit of
    /// wake frequency. 20 ms is cosmos's slice_lag.
    #[clap(long, default_value = "20000")]
    vtime_lag_us: u64,

    /// Explicit opt-in for the native SMT-pair pin on the
    /// --plain-vtime queue: the two busiest threads of one process each
    /// keep a physical core to themselves, so a game's render and
    /// submission threads do not wait behind helpers on their cores.
    /// --game and --profile gaming already arm it; --no-game-pin
    /// clears it again.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    game_pin: bool,

    /// Disable the SMT-pair game pin even under --game or --profile
    /// gaming. The pin is an overlay on the plain virtual-time queue,
    /// so this has no effect on a run that never reaches that queue.
    #[clap(long, action = clap::ArgAction::SetTrue, conflicts_with = "game_pin")]
    no_game_pin: bool,

    /// Grace window of the game pin, in microseconds: how long a pinned
    /// thread's core stays reserved after it leaves the CPU or is
    /// enqueued. It has to span the gap between two frames, not one
    /// frame, or a thread that sleeps through a whole frame hands the
    /// core away and pays a migration on every wake. Default 20000us;
    /// inert unless the pin resolves on.
    #[clap(
        long,
        default_value = "20000",
        value_parser = clap::value_parser!(u64).range(0..=1_000_000)
    )]
    pin_grace_us: u64,

    /// Pin slots: 1 keeps one core for the busiest thread of the game,
    /// 2 (the default) also holds a second core for another thread of
    /// the same process once the first has proven its duty. Inert
    /// unless the pin resolves on.
    #[clap(
        long,
        default_value = "2",
        value_parser = clap::value_parser!(u32).range(1..=2)
    )]
    pin_max: u32,

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

/// The base slice and the plain-family rodata the options resolve to.
///
/// `gaming` selects `--plain-vtime` on an 800us slice and arms the game
/// pin. Every other profile keeps the throughput dispatch and the
/// 1180us slice untouched, with the pin off.
struct Mode {
    gaming: bool,
    deadline_us: u64,
    plain: bool,
    plain_1x: bool,
    plain_wake: bool,
    plain_vtime: bool,
    game_pin: bool,
    pin_grace_ns: u64,
    pin_max: u32,
    seat_guard: bool,
}

/// The `-d` defaults: the original DEADLINE_NS, and the gaming slice.
const DEADLINE_US_DEFAULT: u64 = 1180;
const DEADLINE_US_GAMING: u64 = 800;

impl Mode {
    fn from_opts(opts: &Opts) -> Self {
        let gaming = opts.game || opts.profile == "gaming";
        let deadline_us = opts.deadline_us.unwrap_or(if gaming {
            DEADLINE_US_GAMING
        } else {
            DEADLINE_US_DEFAULT
        });

        /*
         * Each plain variant implies --plain, and --plain-wake and
         * --plain-vtime both imply --plain-1x. The game pin is an
         * overlay on the plain virtual-time queue only: without it
         * every pin branch stays dead in the BPF program.
         *
         * Gaming arms the pin, --no-game-pin clears it, and an explicit
         * --game-pin still arms it on --plain-vtime. The gate is
         * plain_vtime rather than plain, so --plain, --plain-1x and
         * --plain-wake, which never select the virtual-time queue,
         * stay pin-free. That is the queue the warning names and the
         * README describes.
         */
        let plain_vtime = opts.plain_vtime || gaming;
        let plain_1x = opts.plain_1x || opts.plain_wake || plain_vtime;
        let plain = opts.plain || plain_1x;
        let game_pin = !opts.no_game_pin && (gaming || opts.game_pin) && plain_vtime;

        /*
         * The seat guard belongs to the default profile alone. Every
         * plain variant runs the minimal EDF baseline, whose whole
         * point is the placement without the guard, and --game has to
         * stay verifier-DCE-isolated from the default's preemption and
         * steal rules, so both resolve to false there.
         */
        let seat_guard = !plain && !gaming;

        Self {
            gaming,
            deadline_us,
            plain,
            plain_1x,
            plain_wake: opts.plain_wake,
            plain_vtime,
            game_pin,
            /*
             * The pin's knobs are rodata the BPF side reads only when
             * game_pin holds. Publish the resolved values: with the pin
             * off both read zero, so a default run's rodata is inert
             * field by field rather than only through the verifier
             * pruning the pin branches.
             */
            pin_grace_ns: if game_pin {
                opts.pin_grace_us * 1000
            } else {
                0
            },
            pin_max: if game_pin { opts.pin_max } else { 0 },
            seat_guard,
        }
    }
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
        // Distinct LLCs, from the same cache dump that fills topo_llc.
        // The BPF side drops its node ring on a machine with one LLC,
        // where that ring can only re-read the LLC ring's CPUs.
        let nr_llc_ids = topo
            .all_cpus
            .values()
            .map(|c| c.llc_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
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
        let mode = Mode::from_opts(opts);
        rodata.debug = opts.debug;
        rodata.deadline_ns = mode.deadline_us * 1000;
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
        rodata.nr_llc_ids = nr_llc_ids as u64;
        rodata.nr_big_cpus = classes.big.len() as u64;
        rodata.nr_little_cpus = classes.little.len() as u64;

        // Publish the cache-topology distance tables. The BPF side
        // compares ids for equality, and 0 means "unfilled" there, so
        // every id is stored offset by one: an id of 0 becomes 1, and
        // an entry the userspace never filled can never compare equal
        // to a filled one. Entries are indexed by CPU id, so an
        // offline CPU leaves its entry unfilled instead of shifting
        // the table under the following CPUs.
        let mut by_core: std::collections::HashMap<usize, Vec<usize>> =
            std::collections::HashMap::new();
        for cpu in topo.all_cpus.values() {
            by_core.entry(cpu.core_id).or_default().push(cpu.id);
        }
        for cpu in topo.all_cpus.values() {
            rodata.topo_node[cpu.id] = cpu.node_id as u32 + 1;
            rodata.topo_llc[cpu.id] = cpu.llc_id as u32 + 1;
            rodata.topo_l2[cpu.id] = cpu.l2_id as u32 + 1;
            rodata.topo_core[cpu.id] = cpu.core_id as u32 + 1;
            let sib = by_core
                .get(&cpu.core_id)
                .and_then(|v| v.iter().copied().find(|&c| c != cpu.id));
            rodata.topo_sibling[cpu.id] = sib.map(|c| c as u32 + 1).unwrap_or(0);
        }
        info!(
            "distance ladder: smt={} l2s={} llcs={} nodes={}",
            topo.smt_enabled,
            topo.all_cpus
                .values()
                .map(|c| c.l2_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            nr_llc_ids,
            topo.nodes.len(),
        );

        // Set the CPU frequency performance level (-1 = automatic).
        info!(
            "cpuperf level: {}",
            match opts.perf_lvl {
                -2 => "off".into(),
                -1 => "auto".into(),
                n if n < 0 => n.to_string(),
                0 => "min".into(),
                1024 => "max".into(),
                n => n.to_string(),
            }
        );
        rodata.cpuperf_lvl = opts.perf_lvl;

        // Scheduling profile: the default keeps the throughput
        // placement; the gaming profile runs the plain virtual-time
        // queue on the 800us slice.
        info!(
            "profile: {}",
            if mode.gaming { "gaming" } else { "default" }
        );
        rodata.gaming = mode.gaming;
        rodata.plain = mode.plain;
        rodata.plain_1x = mode.plain_1x;
        rodata.plain_wake = mode.plain_wake;
        rodata.plain_vtime = mode.plain_vtime;
        /*
         * The seat guard is the default profile's alone; every plain
         * variant and --game publish false, so their BPF branches are
         * pruned by the verifier and their rodata stays inert.
         */
        rodata.seat_guard = mode.seat_guard;
        /*
         * Gaming arms the pin; --no-game-pin or a run that never
         * selects the plain virtual-time queue clears it. The BPF
         * branches below it are verifier-pruned when it is off.
         */
        rodata.game_pin = mode.game_pin;
        rodata.pin_grace_ns = mode.pin_grace_ns;
        rodata.pin_max = mode.pin_max;
        /* 1 s bounds the BPF-side product (lag * freq cap * weight). */
        let vtime_lag_ns = opts.vtime_lag_us.min(1_000_000) * 1000;
        rodata.vtime_lag_ns = vtime_lag_ns;
        if mode.plain {
            info!("plain EDF baseline: warm seats and the lane split are off");
        }
        if mode.plain_vtime {
            info!(
                "plain virtual time: node queues keyed by weighted runtime, \
                 credit window {}us",
                vtime_lag_ns / 1000
            );
        }
        if mode.game_pin {
            info!(
                "game pin: {} slot(s), grace {}us",
                mode.pin_max,
                mode.pin_grace_ns / 1000
            );
        }

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
            nr_preempt_refused_lat: bss_data.nr_preempt_refused_lat,
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

    let mode = Mode::from_opts(&opts);
    if mode.deadline_us > 10_000 {
        warn!(
            "-d {}us is above 10ms: the tick is the only preemption source for a full slice",
            mode.deadline_us
        );
    }
    if opts.game_pin && !mode.plain_vtime {
        warn!(
            "--game-pin needs the plain virtual-time queue (--game or \
             --plain-vtime), ignoring it"
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
        assert_eq!(ok.deadline_us, Some(500));
    }

    /// `gaming` is the flag that changes the dispatch: it selects
    /// --plain-vtime on an 800us slice, an explicit -d still wins, and
    /// the default profile resolves to exactly what it did before.
    #[test]
    fn game_selects_plain_vtime_on_the_800us_slice() {
        let game = Mode::from_opts(&Opts::try_parse_from(["scx_baby", "--game"]).unwrap());
        assert!(game.gaming);
        assert!(game.plain && game.plain_1x && game.plain_vtime);
        assert!(!game.plain_wake);
        assert_eq!(game.deadline_us, 800);

        let alias =
            Mode::from_opts(&Opts::try_parse_from(["scx_baby", "--profile", "gaming"]).unwrap());
        assert!(alias.gaming && alias.plain_vtime);
        assert_eq!(alias.deadline_us, 800);

        let explicit =
            Mode::from_opts(&Opts::try_parse_from(["scx_baby", "--game", "-d", "1000"]).unwrap());
        assert!(explicit.plain_vtime);
        assert_eq!(explicit.deadline_us, 1000);

        let default = Mode::from_opts(&Opts::try_parse_from(["scx_baby"]).unwrap());
        assert!(!default.gaming);
        assert!(!default.plain && !default.plain_1x);
        assert!(!default.plain_wake && !default.plain_vtime);
        assert_eq!(default.deadline_us, 1180);

        let bench = Mode::from_opts(
            &Opts::try_parse_from(["scx_baby", "--plain-vtime", "-d", "800"]).unwrap(),
        );
        assert!(!bench.gaming);
        assert!(bench.plain_vtime);
        assert_eq!(bench.deadline_us, 800);
    }

    /// The pin knobs bind their ranges at parse time: at most two slots
    /// (the SMT pair) and a grace window the BPF side sees in
    /// nanoseconds.
    #[test]
    fn pin_knobs_reject_out_of_range_values() {
        assert!(Opts::try_parse_from(["scx_baby", "--pin-max", "0"]).is_err());
        assert!(Opts::try_parse_from(["scx_baby", "--pin-max", "3"]).is_err());
        assert!(Opts::try_parse_from(["scx_baby", "--pin-grace-us", "1000001"]).is_err());

        let one = Opts::try_parse_from(["scx_baby", "--pin-max", "1"]).unwrap();
        assert_eq!(one.pin_max, 1);
        let two = Opts::try_parse_from(["scx_baby", "--pin-max", "2"]).unwrap();
        assert_eq!(two.pin_max, 2);
        assert_eq!(two.pin_grace_us, 20000);
    }

    /*
     * The pin resolves from the profile and the queue: --game and
     * --profile gaming arm it, --no-game-pin clears it, an explicit
     * --game-pin still arms it on --plain-vtime, and a run outside the
     * plain virtual-time queue stays off whatever the flags say. The
     * last two cases pin that boundary: --plain-wake alone never
     * selects the virtual-time queue, and --game --plain-wake does,
     * which makes it a pin-on shape the verifier gate has to load. The
     * knobs are rodata the BPF side reads only when the pin is on, so
     * they publish zero whenever it is off: a default run's rodata is
     * inert field by field, not only through the verifier pruning the
     * branches.
     */
    #[test]
    fn game_pin_resolves_from_the_profile_and_the_plain_queue() {
        // argv, then (gaming, plain, plain_1x, plain_vtime, game_pin,
        // deadline_us, pin_grace_ns, pin_max).
        let cases: &[(&[&str], (bool, bool, bool, bool, bool, u64, u64, u32))] = &[
            (&[], (false, false, false, false, false, 1180, 0, 0)),
            (
                &["--game"],
                (true, true, true, true, true, 800, 20_000_000, 2),
            ),
            (
                &["--profile", "gaming"],
                (true, true, true, true, true, 800, 20_000_000, 2),
            ),
            (
                &["--game", "--no-game-pin"],
                (true, true, true, true, false, 800, 0, 0),
            ),
            (
                &["--profile", "gaming", "--no-game-pin"],
                (true, true, true, true, false, 800, 0, 0),
            ),
            (
                &["--plain-vtime"],
                (false, true, true, true, false, 1180, 0, 0),
            ),
            (
                &["--plain-vtime", "--game-pin"],
                (false, true, true, true, true, 1180, 20_000_000, 2),
            ),
            (
                &["--game-pin"],
                (false, false, false, false, false, 1180, 0, 0),
            ),
            (
                &["--plain-wake", "--game-pin"],
                (false, true, true, false, false, 1180, 0, 0),
            ),
            (
                &["--game", "--plain-wake"],
                (true, true, true, true, true, 800, 20_000_000, 2),
            ),
        ];

        for (args, want) in cases {
            let mut argv = vec!["scx_baby"];
            argv.extend_from_slice(args);
            let mode = Mode::from_opts(&Opts::try_parse_from(&argv).unwrap());
            let got = (
                mode.gaming,
                mode.plain,
                mode.plain_1x,
                mode.plain_vtime,
                mode.game_pin,
                mode.deadline_us,
                mode.pin_grace_ns,
                mode.pin_max,
            );

            assert_eq!(got, *want, "{args:?}");
        }

        assert!(Opts::try_parse_from(["scx_baby", "--game-pin", "--no-game-pin"]).is_err());
    }

    /// The seat guard is the default profile's flag alone: every plain
    /// variant runs the minimal EDF baseline and --game has to stay
    /// verifier-DCE-isolated from the default's preemption, deep-rung
    /// and seat-steal rules, so both publish false.
    #[test]
    fn seat_guard_resolves_to_the_default_profile_only() {
        let cases: &[(&[&str], bool)] = &[
            (&[], true),
            (&["--game"], false),
            (&["--profile", "gaming"], false),
            (&["--game", "--no-game-pin"], false),
            (&["--game", "-d", "1000"], false),
            (&["--plain"], false),
            (&["--plain-1x"], false),
            (&["--plain-wake"], false),
            (&["--plain-vtime"], false),
            (&["--plain-vtime", "--game-pin"], false),
            (&["--game", "--plain-wake"], false),
        ];

        for (args, want) in cases {
            let mut argv = vec!["scx_baby"];
            argv.extend_from_slice(args);
            let mode = Mode::from_opts(&Opts::try_parse_from(&argv).unwrap());

            assert_eq!(mode.seat_guard, *want, "{args:?}");
        }
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
    fn the_two_bars_stay_distinct() {
        // The bug this pins: LAT_CRI_WAKE_FREQ and FOREGROUND_WAKE_FREQ
        // were both 5, so is_foreground() collapsed into "latency
        // critical with real work" and every 60Hz-class poller earned
        // the fourfold slice. The bars live in the BPF header, which
        // userspace cannot read; baby.bpf.h carries static assertions
        // for the relationship, and this test pins the consequence: a
        // 60Hz cadence (six wakes per 100ms) clears the latency bar and
        // stays below the foreground bar, a 100Hz cadence clears both.
        let sixty = class_peak_after(&[6; 16]);
        assert!(sixty >= 5, "60Hz must clear the latency bar, got {sixty}");
        assert!(
            sixty < 10,
            "60Hz must not reach the foreground bar, got {sixty}"
        );

        let hundred = class_peak_after(&[10; 16]);
        assert!(
            hundred >= 10,
            "100Hz must reach the foreground bar, got {hundred}"
        );
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
    // for every shape. The plain flags, the game pin and the profile
    // are rodata as well, so every combination `Mode::from_opts` can
    // produce is loaded with its production rodata: a branch the
    // verifier prunes when a flag is off is still checked when it is
    // on, and a reachable combination left out of the matrix is a
    // load-time regression waiting for the kernel that trips it.
    fn load_synthetic(
        nr_cpus: usize,
        plain: bool,
        plain_1x: bool,
        plain_wake: bool,
        plain_vtime: bool,
        game_pin: bool,
        gaming: bool,
    ) -> anyhow::Result<()> {
        let mut object = MaybeUninit::uninit();
        let builder = BpfSkelBuilder::default();
        let mut skel = scx_ops_open!(builder, &mut object, baby_ops, None)?;
        let ro = skel.maps.rodata_data.as_mut().unwrap();
        /* Gaming is the only profile that selects the 800us slice. */
        ro.deadline_ns = if gaming { 800 } else { 1180 } * 1000;
        ro.prio_offset_ns = scaled_prio_offsets(ro.deadline_ns);
        ro.gaming = gaming;
        ro.nr_cpu_ids = nr_cpus as u64;
        ro.nr_node_ids = 2;
        /*
         * The synthetic table below publishes LLC ids cpu % 8, so a
         * one-CPU load reports a single LLC and takes the arm where
         * the node ring is pruned.
         */
        ro.nr_llc_ids = nr_cpus.min(8) as u64;
        ro.nr_big_cpus = (nr_cpus / 2) as u64;
        ro.nr_little_cpus = (nr_cpus - nr_cpus / 2) as u64;
        ro.plain = plain;
        ro.plain_1x = plain_1x;
        ro.plain_wake = plain_wake;
        ro.plain_vtime = plain_vtime;
        ro.game_pin = game_pin;
        /* The seat guard resolves from the profile, like from_opts(). */
        ro.seat_guard = !plain && !gaming;
        /* The knobs publish zero whenever the pin resolves off. */
        ro.pin_grace_ns = if game_pin { 20_000_000 } else { 0 };
        ro.pin_max = if game_pin { 2 } else { 0 };
        ro.vtime_lag_ns = 20_000_000;
        for cpu in 0..nr_cpus.min(ro.topo_node.len()) {
            // Two node-ish halves, eight LLCs, per-pair L2 groups
            // and SMT pairs - a denser distance ladder than any
            // real host of this size.
            ro.topo_node[cpu] = if cpu < nr_cpus / 2 { 1 } else { 2 };
            ro.topo_llc[cpu] = (cpu % 8) as u32 + 1;
            ro.topo_l2[cpu] = (cpu / 2) as u32 + 1;
            ro.topo_core[cpu] = (cpu / 2) as u32 + 1;
        }
        let loaded = scx_ops_load!(skel, baby_ops, uei)?;
        drop(loaded);
        Ok(())
    }

    #[test]
    #[ignore = "requires BPF load capabilities and a sched_ext kernel"]
    fn verifier_load_synthetic_topologies() -> anyhow::Result<()> {
        libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, |_, message| {
            eprint!("{message}");
        })));

        let mut failures = Vec::new();
        /*
         * Every tuple Mode::from_opts can produce, named by the argv
         * that produces it. Twelve shapes x three widths: a reachable
         * combination that is missing here is a load the verifier
         * never sees.
         */
        for (plain, plain_1x, plain_wake, plain_vtime, game_pin, gaming) in [
            /* default */
            (false, false, false, false, false, false),
            /* --plain */
            (true, false, false, false, false, false),
            /* --plain-1x */
            (true, true, false, false, false, false),
            /* --plain-wake */
            (true, true, true, false, false, false),
            /* --plain-vtime */
            (true, true, false, true, false, false),
            /* --plain-wake --plain-vtime */
            (true, true, true, true, false, false),
            /* --plain-vtime --game-pin */
            (true, true, false, true, true, false),
            /* --plain-wake --plain-vtime --game-pin */
            (true, true, true, true, true, false),
            /* --game --no-game-pin */
            (true, true, false, true, false, true),
            /* --game */
            (true, true, false, true, true, true),
            /* --game --no-game-pin --plain-wake */
            (true, true, true, true, false, true),
            /* --game --plain-wake */
            (true, true, true, true, true, true),
        ] {
            for nr_cpus in [1usize, 14, 128] {
                if let Err(error) = load_synthetic(
                    nr_cpus,
                    plain,
                    plain_1x,
                    plain_wake,
                    plain_vtime,
                    game_pin,
                    gaming,
                ) {
                    failures.push(format!(
                        "{nr_cpus} CPUs plain={plain} 1x={plain_1x} \
                         wake={plain_wake} vtime={plain_vtime} pin={game_pin} \
                         gaming={gaming}: {error:#}"
                    ));
                }
            }
        }
        anyhow::ensure!(failures.is_empty(), "{}", failures.join("\n"));
        Ok(())
    }
}
