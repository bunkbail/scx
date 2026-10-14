use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

/// One placement-distance histogram: landings bucketed by the distance
/// rank between the task's previous CPU and where it actually went
/// (self, SMT sibling, same L2, same LLC, same node, beyond).
#[stat_doc]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Ranks {
    #[stat(desc = "Landed on the previous CPU itself")]
    pub r_self: u64,
    #[stat(desc = "Landed on the previous CPU's SMT sibling")]
    pub r_sib: u64,
    #[stat(desc = "Landed on an L2-sharing CPU")]
    pub r_l2: u64,
    #[stat(desc = "Landed on an LLC-sharing CPU")]
    pub r_llc: u64,
    #[stat(desc = "Landed on the same NUMA node")]
    pub r_node: u64,
    #[stat(desc = "Landed beyond the node")]
    pub r_far: u64,
}

impl Ranks {
    /// Read the histogram out of a BPF-side array indexed by rank.
    pub fn of(a: &[u64; 8]) -> Self {
        Ranks {
            r_self: a[0],
            r_sib: a[1],
            r_l2: a[2],
            r_llc: a[3],
            r_node: a[4],
            r_far: a[5] + a[6] + a[7],
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        Ranks {
            r_self: self.r_self.saturating_sub(rhs.r_self),
            r_sib: self.r_sib.saturating_sub(rhs.r_sib),
            r_l2: self.r_l2.saturating_sub(rhs.r_l2),
            r_llc: self.r_llc.saturating_sub(rhs.r_llc),
            r_node: self.r_node.saturating_sub(rhs.r_node),
            r_far: self.r_far.saturating_sub(rhs.r_far),
        }
    }

    fn total(&self) -> u64 {
        self.r_self + self.r_sib + self.r_l2 + self.r_llc + self.r_node + self.r_far
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        let t = self.total();
        if t == 0 {
            write!(w, "none")?;
            return Ok(());
        }
        write!(
            w,
            "self {:.1}% sib {:.1}% l2 {:.1}% llc {:.1}% node {:.1}% far {:.1}%",
            self.r_self as f64 * 100.0 / t as f64,
            self.r_sib as f64 * 100.0 / t as f64,
            self.r_l2 as f64 * 100.0 / t as f64,
            self.r_llc as f64 * 100.0 / t as f64,
            self.r_node as f64 * 100.0 / t as f64,
            self.r_far as f64 * 100.0 / t as f64,
        )?;
        Ok(())
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of running tasks")]
    pub nr_running: u64,
    #[stat(desc = "Number of direct dispatches to an idle CPU")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of tasks enqueued to the global deadline queue")]
    pub nr_shared_dispatches: u64,
    #[stat(desc = "Number of preemption kicks sent to a CPU")]
    pub nr_preemptions: u64,
    #[stat(desc = "Number of interactive priority boosts granted")]
    pub nr_boosts: u64,
    #[stat(desc = "Number of slice-end continuations of the deadline winner")]
    pub nr_sticky: u64,
    #[stat(desc = "Number of tasks parked on their previous CPU's warm seat")]
    pub nr_warmseats: u64,
    #[stat(desc = "Number of enqueues the oversubscription gate sent to the shared queue")]
    pub nr_coldspreads: u64,
    #[stat(desc = "Landings by distance at the point of truth (dispatch)")]
    pub nr_land: Ranks,
    #[stat(desc = "ops.select_cpu() idle picks by distance")]
    pub nr_wake_land: Ranks,
    #[stat(desc = "Warm seats held on the previous CPU")]
    pub nr_seat_self: u64,
    #[stat(desc = "Warm seats rebalanced to another CPU, by distance")]
    pub nr_seat_move: Ranks,
    #[stat(desc = "Shared-queue pulls by distance")]
    pub nr_pull_land: Ranks,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] tasks -> r: {:>2} | dispatch -> d: {:<5} s: {:<5} | preempt: {:<5} | boost: {:<5} | sticky: {:<5} | warm: {:<5} | cold: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.nr_direct_dispatches,
            self.nr_shared_dispatches,
            self.nr_preemptions,
            self.nr_boosts,
            self.nr_sticky,
            self.nr_warmseats,
            self.nr_coldspreads,
        )?;
        write!(w, "  land: ")?;
        self.nr_land.format(w)?;
        write!(w, " | wake: ")?;
        self.nr_wake_land.format(w)?;
        writeln!(w)?;
        write!(w, "  seatmove: ")?;
        self.nr_seat_move.format(w)?;
        write!(w, " | pull: ")?;
        self.nr_pull_land.format(w)?;
        writeln!(w)?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_running: self.nr_running,
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_shared_dispatches: self.nr_shared_dispatches - rhs.nr_shared_dispatches,
            nr_preemptions: self.nr_preemptions - rhs.nr_preemptions,
            nr_boosts: self.nr_boosts - rhs.nr_boosts,
            nr_sticky: self.nr_sticky - rhs.nr_sticky,
            nr_warmseats: self.nr_warmseats - rhs.nr_warmseats,
            nr_coldspreads: self.nr_coldspreads - rhs.nr_coldspreads,
            nr_land: self.nr_land.sub(&rhs.nr_land),
            nr_wake_land: self.nr_wake_land.sub(&rhs.nr_wake_land),
            nr_seat_self: self.nr_seat_self.saturating_sub(rhs.nr_seat_self),
            nr_seat_move: self.nr_seat_move.sub(&rhs.nr_seat_move),
            nr_pull_land: self.nr_pull_land.sub(&rhs.nr_pull_land),
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
