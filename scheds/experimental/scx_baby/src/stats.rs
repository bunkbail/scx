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

/// Wait-at-depth buckets: the BPF side clamps queue depth into
/// buckets 0, 1, 2 and 3+; a bucket value is the number (or total ns,
/// or max ns) of waits served at that depth.
#[stat_doc]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct WaitB {
    #[stat(desc = "waits at depth 0 (nothing queued ahead)")]
    pub b0: u64,
    #[stat(desc = "waits at depth 1")]
    pub b1: u64,
    #[stat(desc = "waits at depth 2")]
    pub b2: u64,
    #[stat(desc = "waits at depth 3 or deeper")]
    pub b3: u64,
}

impl WaitB {
    pub fn of(a: &[u64; 4]) -> Self {
        WaitB {
            b0: a[0],
            b1: a[1],
            b2: a[2],
            b3: a[3],
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        WaitB {
            b0: self.b0.saturating_sub(rhs.b0),
            b1: self.b1.saturating_sub(rhs.b1),
            b2: self.b2.saturating_sub(rhs.b2),
            b3: self.b3.saturating_sub(rhs.b3),
        }
    }
}

/// The wait-at-depth charge split by class (16 entries, class-major:
/// class * 4 + depth). Class 0 is neither interactive nor foreground,
/// 1 is interactive-only, 2 is foreground-only, 3 is both. `other`
/// sums classes 0 and 1; `urgent` sums classes 2 and 3 - the
/// foreground side, the classes a deadline-ordering change would
/// prioritize.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct WaitCls {
    #[stat(desc = "foreground (cls 2+3) waits at depth 0")]
    pub fg_b0: u64,
    #[stat(desc = "foreground waits at depth 1")]
    pub fg_b1: u64,
    #[stat(desc = "foreground waits at depth 2")]
    pub fg_b2: u64,
    #[stat(desc = "foreground waits at depth 3 or deeper")]
    pub fg_b3: u64,
    #[stat(desc = "foreground wait totals (ns) at depth 0")]
    pub fg_ns_b0: u64,
    #[stat(desc = "foreground wait totals (ns) at depth 1")]
    pub fg_ns_b1: u64,
    #[stat(desc = "foreground wait totals (ns) at depth 2")]
    pub fg_ns_b2: u64,
    #[stat(desc = "foreground wait totals (ns) at depth 3 or deeper")]
    pub fg_ns_b3: u64,
    #[stat(desc = "foreground wait maxima (ns) at depth 0")]
    pub fg_max_b0: u64,
    #[stat(desc = "foreground wait maxima (ns) at depth 1")]
    pub fg_max_b1: u64,
    #[stat(desc = "foreground wait maxima (ns) at depth 2")]
    pub fg_max_b2: u64,
    #[stat(desc = "foreground wait maxima (ns) at depth 3 or deeper")]
    pub fg_max_b3: u64,
    #[stat(desc = "foreground waits over 5ms, by depth bucket")]
    pub fg_slow: Vec<u64>,
    #[stat(desc = "other (cls 0+1) waits at depth 0")]
    pub other_b0: u64,
    #[stat(desc = "other waits at depth 1")]
    pub other_b1: u64,
    #[stat(desc = "other waits at depth 2")]
    pub other_b2: u64,
    #[stat(desc = "other waits at depth 3 or deeper")]
    pub other_b3: u64,
    #[stat(desc = "other wait totals (ns) at depth 0")]
    pub other_ns_b0: u64,
    #[stat(desc = "other wait totals (ns) at depth 1")]
    pub other_ns_b1: u64,
    #[stat(desc = "other wait totals (ns) at depth 2")]
    pub other_ns_b2: u64,
    #[stat(desc = "other wait totals (ns) at depth 3 or deeper")]
    pub other_ns_b3: u64,
    #[stat(desc = "other wait maxima (ns) at depth 0")]
    pub other_max_b0: u64,
    #[stat(desc = "other wait maxima (ns) at depth 1")]
    pub other_max_b1: u64,
    #[stat(desc = "other wait maxima (ns) at depth 2")]
    pub other_max_b2: u64,
    #[stat(desc = "other wait maxima (ns) at depth 3 or deeper")]
    pub other_max_b3: u64,
    #[stat(desc = "other waits over 5ms, by depth bucket")]
    pub other_slow: Vec<u64>,
}

impl WaitCls {
    pub fn of(a_n: &[u64; 16], a_ns: &[u64; 16], a_max: &[u64; 16], a_slow: &[u64; 16]) -> Self {
        let mut fg_slow = Vec::with_capacity(4);
        let mut other_slow = Vec::with_capacity(4);
        for b in 0..4 {
            fg_slow.push(a_slow[2 * 4 + b] + a_slow[3 * 4 + b]);
            other_slow.push(a_slow[0 * 4 + b] + a_slow[1 * 4 + b]);
        }
        WaitCls {
            fg_b0: a_n[2 * 4] + a_n[3 * 4],
            fg_b1: a_n[2 * 4 + 1] + a_n[3 * 4 + 1],
            fg_b2: a_n[2 * 4 + 2] + a_n[3 * 4 + 2],
            fg_b3: a_n[2 * 4 + 3] + a_n[3 * 4 + 3],
            fg_ns_b0: a_ns[2 * 4] + a_ns[3 * 4],
            fg_ns_b1: a_ns[2 * 4 + 1] + a_ns[3 * 4 + 1],
            fg_ns_b2: a_ns[2 * 4 + 2] + a_ns[3 * 4 + 2],
            fg_ns_b3: a_ns[2 * 4 + 3] + a_ns[3 * 4 + 3],
            fg_max_b0: a_max[2 * 4].max(a_max[3 * 4]),
            fg_max_b1: a_max[2 * 4 + 1].max(a_max[3 * 4 + 1]),
            fg_max_b2: a_max[2 * 4 + 2].max(a_max[3 * 4 + 2]),
            fg_max_b3: a_max[2 * 4 + 3].max(a_max[3 * 4 + 3]),
            fg_slow,
            other_b0: a_n[0] + a_n[4],
            other_b1: a_n[1] + a_n[5],
            other_b2: a_n[2] + a_n[6],
            other_b3: a_n[3] + a_n[7],
            other_ns_b0: a_ns[0] + a_ns[4],
            other_ns_b1: a_ns[1] + a_ns[5],
            other_ns_b2: a_ns[2] + a_ns[6],
            other_ns_b3: a_ns[3] + a_ns[7],
            other_max_b0: a_max[0].max(a_max[4]),
            other_max_b1: a_max[1].max(a_max[5]),
            other_max_b2: a_max[2].max(a_max[6]),
            other_max_b3: a_max[3].max(a_max[7]),
            other_slow,
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        let vsub = |a: &Vec<u64>, b: &Vec<u64>| -> Vec<u64> {
            a.iter()
                .zip(b.iter())
                .map(|(x, y)| x.saturating_sub(*y))
                .collect()
        };
        WaitCls {
            fg_b0: self.fg_b0.saturating_sub(rhs.fg_b0),
            fg_b1: self.fg_b1.saturating_sub(rhs.fg_b1),
            fg_b2: self.fg_b2.saturating_sub(rhs.fg_b2),
            fg_b3: self.fg_b3.saturating_sub(rhs.fg_b3),
            fg_ns_b0: self.fg_ns_b0.saturating_sub(rhs.fg_ns_b0),
            fg_ns_b1: self.fg_ns_b1.saturating_sub(rhs.fg_ns_b1),
            fg_ns_b2: self.fg_ns_b2.saturating_sub(rhs.fg_ns_b2),
            fg_ns_b3: self.fg_ns_b3.saturating_sub(rhs.fg_ns_b3),
            fg_max_b0: self.fg_max_b0.max(rhs.fg_max_b0),
            fg_max_b1: self.fg_max_b1.max(rhs.fg_max_b1),
            fg_max_b2: self.fg_max_b2.max(rhs.fg_max_b2),
            fg_max_b3: self.fg_max_b3.max(rhs.fg_max_b3),
            fg_slow: vsub(&self.fg_slow, &rhs.fg_slow),
            other_b0: self.other_b0.saturating_sub(rhs.other_b0),
            other_b1: self.other_b1.saturating_sub(rhs.other_b1),
            other_b2: self.other_b2.saturating_sub(rhs.other_b2),
            other_b3: self.other_b3.saturating_sub(rhs.other_b3),
            other_ns_b0: self.other_ns_b0.saturating_sub(rhs.other_ns_b0),
            other_ns_b1: self.other_ns_b1.saturating_sub(rhs.other_ns_b1),
            other_ns_b2: self.other_ns_b2.saturating_sub(rhs.other_ns_b2),
            other_ns_b3: self.other_ns_b3.saturating_sub(rhs.other_ns_b3),
            other_max_b0: self.other_max_b0.max(rhs.other_max_b0),
            other_max_b1: self.other_max_b1.max(rhs.other_max_b1),
            other_max_b2: self.other_max_b2.max(rhs.other_max_b2),
            other_max_b3: self.other_max_b3.max(rhs.other_max_b3),
            other_slow: vsub(&self.other_slow, &rhs.other_slow),
        }
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
    #[stat(desc = "Waiting arrivals parked in a warm seat")]
    pub nr_arr_seat: u64,
    #[stat(desc = "Waiting arrivals parked in the shared queue")]
    pub nr_arr_shared: u64,
    #[stat(desc = "Wait counts by depth bucket")]
    pub wait_n: WaitB,
    #[stat(desc = "Wait totals (ns) by depth bucket")]
    pub wait_ns: WaitB,
    #[stat(desc = "Wait maxima (ns) by depth bucket")]
    pub wait_max: WaitB,
    #[stat(desc = "Waits over 5ms by depth bucket")]
    pub wait_slow: WaitB,
    #[stat(desc = "The same waits split by class (foreground vs other)")]
    pub wait_cls: WaitCls,
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
        let mean = |ns: u64, n: u64| -> String {
            if n > 0 {
                format!("{:.0}", ns as f64 / n as f64 / 1000.0)
            } else {
                "-".into()
            }
        };
        let (wn, wns, wmax, wsl) = (&self.wait_n, &self.wait_ns, &self.wait_max, &self.wait_slow);
        writeln!(
            w,
            "  wait n[{} {} {} {}] mean[{} {} {} {}] max[{} {} {} {}] slow5ms[{} {} {} {}] arr(seat {} shared {})",
            wn.b0,
            wn.b1,
            wn.b2,
            wn.b3,
            mean(wns.b0, wn.b0),
            mean(wns.b1, wn.b1),
            mean(wns.b2, wn.b2),
            mean(wns.b3, wn.b3),
            wmax.b0,
            wmax.b1,
            wmax.b2,
            wmax.b3,
            wsl.b0,
            wsl.b1,
            wsl.b2,
            wsl.b3,
            self.nr_arr_seat,
            self.nr_arr_shared,
        )?;
        let wc = &self.wait_cls;
        let fmean = |ns: u64, n: u64| -> String {
            if n > 0 {
                format!("{:.0}", ns as f64 / n as f64 / 1000.0)
            } else {
                "-".into()
            }
        };
        writeln!(
            w,
            "  waitfg n[{} {} {} {}] mean[{} {} {} {}] max[{} {} {} {}] slow5ms[{} {} {} {}]",
            wc.fg_b0,
            wc.fg_b1,
            wc.fg_b2,
            wc.fg_b3,
            fmean(wc.fg_ns_b0, wc.fg_b0),
            fmean(wc.fg_ns_b1, wc.fg_b1),
            fmean(wc.fg_ns_b2, wc.fg_b2),
            fmean(wc.fg_ns_b3, wc.fg_b3),
            wc.fg_max_b0,
            wc.fg_max_b1,
            wc.fg_max_b2,
            wc.fg_max_b3,
            wc.fg_slow[0],
            wc.fg_slow[1],
            wc.fg_slow[2],
            wc.fg_slow[3],
        )?;
        writeln!(
            w,
            "  waitot n[{} {} {} {}] mean[{} {} {} {}] max[{} {} {} {}] slow5ms[{} {} {} {}]",
            wc.other_b0,
            wc.other_b1,
            wc.other_b2,
            wc.other_b3,
            fmean(wc.other_ns_b0, wc.other_b0),
            fmean(wc.other_ns_b1, wc.other_b1),
            fmean(wc.other_ns_b2, wc.other_b2),
            fmean(wc.other_ns_b3, wc.other_b3),
            wc.other_max_b0,
            wc.other_max_b1,
            wc.other_max_b2,
            wc.other_max_b3,
            wc.other_slow[0],
            wc.other_slow[1],
            wc.other_slow[2],
            wc.other_slow[3],
        )?;
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
            nr_arr_seat: self.nr_arr_seat.saturating_sub(rhs.nr_arr_seat),
            nr_arr_shared: self.nr_arr_shared.saturating_sub(rhs.nr_arr_shared),
            wait_n: self.wait_n.sub(&rhs.wait_n),
            wait_ns: self.wait_ns.sub(&rhs.wait_ns),
            wait_max: WaitB {
                b0: self.wait_max.b0.max(rhs.wait_max.b0),
                b1: self.wait_max.b1.max(rhs.wait_max.b1),
                b2: self.wait_max.b2.max(rhs.wait_max.b2),
                b3: self.wait_max.b3.max(rhs.wait_max.b3),
            },
            wait_slow: self.wait_slow.sub(&rhs.wait_slow),
            wait_cls: self.wait_cls.sub(&rhs.wait_cls),
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
