// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2021, Hamad Al Marri <hamad.s.almarri@gmail.com>
// (original baby-dl scheduler)
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use stats::Census;
use stats::Ranks;
use stats::WaitB;
use stats::WaitCls;
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
    about = "A sched_ext port of the Baby CPU Scheduler (deadline variant).",
    long_about = r#"
scx_baby is a port of the Baby Scheduler deadline variant (baby-dl) by
Hamad Al Marri to sched_ext.

Every runnable task owns a deadline, an absolute timestamp by which it
would like to run. The CPU always runs the task with the earliest
deadline: tasks are inserted into a global deadline-ordered queue and
dispatched earliest-deadline-first.

Tasks that voluntarily sleep before consuming their deadline are treated
as interactive: their effective nice level is boosted by one step (down
to -20), which pulls their future deadlines earlier.

CPU hogs are throttled by a burst tracker that accounts the runtime a
task accumulates over a 200ms window: a task whose bursts keep growing
behind the previous window cannot preempt other tasks even when its
deadline is earlier.
"#
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Deadline offset in microseconds: every task is assigned
    /// deadline = now + deadline offset (default 1180us, the original
    /// DEADLINE_NS). This is also the time slice of each task.
    #[clap(short = 'd', long, default_value = "1180")]
    deadline_us: u64,

    /// CPU frequency performance level (0 = min, 1024 = max).
    ///
    /// By default (-1, auto) the scheduler scales the performance level
    /// of each CPU in function of its utilization. -2 leaves the
    /// platform's cpufreq setup entirely alone.
    #[clap(short = 'p', long, allow_hyphen_values = true, default_value = "-1")]
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

        // Publish the cache-topology distance tables. The BPF side
        // compares ids for equality, and 0 means "unfilled" there, so
        // every id is stored offset by one: an id of 0 becomes 1, and
        // an entry the userspace never filled can never compare equal
        // to a filled one.
        for (idx, cpu) in topo.all_cpus.values().enumerate() {
            if idx >= rodata.topo_node.len() {
                break;
            }
            rodata.topo_node[idx] = cpu.node_id as u32 + 1;
            rodata.topo_llc[idx] = cpu.llc_id as u32 + 1;
            rodata.topo_l2[idx] = cpu.l2_id as u32 + 1;
            rodata.topo_core[idx] = cpu.core_id as u32 + 1;
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
    // ones. On platforms without a core type split every CPU lands in
    // the little set and the preference is a no-op.
    fn init_core_classes(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<()> {
        // The big cores are the highest-capacity class, read from the
        // kernel's capacity ranking when available and falling back to
        // the topology core types otherwise. A machine without a
        // capacity split has no big cores and the preference is a
        // no-op.
        let capacity = |id: usize| {
            std::fs::read_to_string(format!("/sys/devices/system/cpu/cpu{id}/cpu_capacity"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
        };
        let ids: Vec<usize> = topo.all_cpus.keys().copied().collect();
        let capacities: Vec<Option<u32>> = ids.iter().map(|id| capacity(*id)).collect();
        let caps: Vec<u32> = capacities.iter().flatten().copied().collect();
        let max_cap = caps.iter().max().copied();
        let min_cap = caps.iter().min().copied();
        let capacity_split =
            matches!((min_cap, max_cap), (Some(lo), Some(hi)) if lo * 100 < hi * 85);

        let mut big: Vec<usize> = Vec::new();
        if capacity_split {
            for (idx, id) in ids.iter().enumerate() {
                if capacities[idx] != max_cap {
                    continue;
                }
                big.push(*id);
            }
        } else {
            for cpu in topo.all_cpus.values() {
                if matches!(cpu.core_type, CoreType::Big { .. }) {
                    big.push(cpu.id);
                }
            }
        }

        let rest: Vec<usize> = ids.iter().copied().filter(|c| !big.contains(c)).collect();

        // Cores far below the little tier - the L3-less low-power
        // islands on hybrid laptop parts - stay out of the little set:
        // that set is the tier the queue work waits in, and a worker
        // pulled onto an LP core runs at a fraction of the little
        // cores' speed with no last-level cache, which stretches every
        // batch of a batch-parallel workload to its slowest worker.
        // They are not lost to scheduling: the kernel's placement and
        // the direct-dispatch scan still run work there when nothing
        // else fits. Only the tier assignment skips them.
        let little_cap = rest.iter().filter_map(|c| capacity(*c)).max();
        let mut little = Vec::new();
        let mut lp = Vec::new();
        for c in rest {
            match (capacity(c), little_cap) {
                (Some(cap), Some(max)) if cap * 2 < max => lp.push(c),
                _ => little.push(c),
            }
        }
        info!("core classes: big={big:?} little={little:?} lp={lp:?}");

        for id in &ids {
            if !big.contains(id) && lp.contains(id) {
                continue;
            }
            Self::enable_core_class(skel, *id, big.contains(id))?;
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
    let mut sched = Scheduler::init(&opts, &mut open_object)?;
    sched.run(shutdown.clone())?;

    Ok(())
}
