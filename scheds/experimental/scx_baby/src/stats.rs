// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::consts_BABY_CENSUS_NR;
use crate::consts_BABY_DIST_NR;
use crate::consts_BABY_WCLS_NR;
use crate::consts_BABY_WDEPTH_NR;
use crate::consts_BABY_WG_NR;
use crate::consts_BABY_WTYPE_NR;
use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

/// Instrument widths, taken from the BPF-side enum so the Rust side
/// cannot drift from the arrays it reads.
const DIST: usize = consts_BABY_DIST_NR as usize;
const WDEPTH: usize = consts_BABY_WDEPTH_NR as usize;
const WCLS: usize = consts_BABY_WCLS_NR as usize;
const WTYPE: usize = consts_BABY_WTYPE_NR as usize;
const WG: usize = consts_BABY_WG_NR as usize;
const CENSUS: usize = consts_BABY_CENSUS_NR as usize;

/// Element-wise subtraction for the fixed-width census vectors.
fn vec_sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x.saturating_sub(*y))
        .collect()
}

/// The mean wait in microseconds, or a dash when nothing was counted.
fn mean_us(ns: u64, n: u64) -> String {
    if n > 0 {
        format!("{:.0}", ns as f64 / n as f64 / 1000.0)
    } else {
        "-".into()
    }
}

/// The interval maximum in nanoseconds, or a dash when nothing was
/// counted. The BPF maxima are reset after every snapshot, so a value is
/// this interval's maximum.
fn max_ns(max: u64, n: u64) -> String {
    if n > 0 { max.to_string() } else { "-".into() }
}

/// One wait-at-depth row. Every row shares the same four buckets and the
/// same mean/max layout; only the tag and the optional arrival tail
/// differ.
fn fmt_wait_row<W: Write>(
    w: &mut W,
    tag: &str,
    n: [u64; WDEPTH],
    ns: [u64; WDEPTH],
    max: [u64; WDEPTH],
    slow: &[u64],
    arr: Option<(u64, u64)>,
) -> Result<()> {
    write!(
        w,
        "  {} n[{} {} {} {}] mean_us[{} {} {} {}] max_ns[{} {} {} {}] slow5ms[{} {} {} {}]",
        tag,
        n[0],
        n[1],
        n[2],
        n[3],
        mean_us(ns[0], n[0]),
        mean_us(ns[1], n[1]),
        mean_us(ns[2], n[2]),
        mean_us(ns[3], n[3]),
        max_ns(max[0], n[0]),
        max_ns(max[1], n[1]),
        max_ns(max[2], n[2]),
        max_ns(max[3], n[3]),
        slow[0],
        slow[1],
        slow[2],
        slow[3],
    )?;
    if let Some((seat, shared)) = arr {
        write!(w, " arr(seat {} shared {})", seat, shared)?;
    }
    writeln!(w)?;
    Ok(())
}

/// Build a `sub()` from four field lists: saturating scalars, `vec_sub`
/// vectors, copied scalars and cloned vectors. The struct literal makes
/// the compiler enforce that every field appears exactly once.
macro_rules! sub_fields {
    (
        scalar: $($scalar:ident),* ;
        vec: $($vec:ident),* ;
        copy: $($copy:ident),* ;
        clone: $($clone:ident),* ;
    ) => {
        fn sub(&self, rhs: &Self) -> Self {
            Self {
                $( $scalar: self.$scalar.saturating_sub(rhs.$scalar), )*
                $( $vec: vec_sub(&self.$vec, &rhs.$vec), )*
                $( $copy: self.$copy, )*
                $( $clone: self.$clone.clone(), )*
            }
        }
    };
}

/// The named wait fields assume exactly four depth buckets.
const _: () = assert!(WDEPTH == 4);

/// One depth row of a flat depth-major array.
fn row(a: &[u64], r: usize) -> [u64; WDEPTH] {
    std::array::from_fn(|b| a[r * WDEPTH + b])
}

/// The sum of two depth rows.
fn sum2(a: &[u64], r0: usize, r1: usize) -> [u64; WDEPTH] {
    std::array::from_fn(|b| a[r0 * WDEPTH + b] + a[r1 * WDEPTH + b])
}

/// The elementwise maximum of two depth rows.
fn max2(a: &[u64], r0: usize, r1: usize) -> [u64; WDEPTH] {
    std::array::from_fn(|b| a[r0 * WDEPTH + b].max(a[r1 * WDEPTH + b]))
}

/// One vector-width wait row: the wlcri rows and the wake-gate depth
/// rows. The mean uses integer division, unlike the fixed-width rows.
fn fmt_vec_wait<W: Write>(
    w: &mut W,
    tag: &str,
    n: &[u64],
    ns: &[u64],
    max: &[u64],
    slow: &[u64],
) -> Result<()> {
    let mean: Vec<String> = ns
        .iter()
        .zip(n)
        .map(|(ns, n)| {
            if *n > 0 {
                (ns / n / 1000).to_string()
            } else {
                "-".to_string()
            }
        })
        .collect();
    let maxs: Vec<String> = max
        .iter()
        .zip(n)
        .map(|(m, n)| {
            if *n > 0 {
                m.to_string()
            } else {
                "-".to_string()
            }
        })
        .collect();
    writeln!(
        w,
        "  {} n[{:?}] mean_us[{:?}] max_ns[{:?}] slow5ms[{:?}]",
        tag, n, mean, maxs, slow
    )?;
    Ok(())
}

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
    pub fn of(a: &[u64; DIST]) -> Self {
        Ranks {
            r_self: a[0],
            r_sib: a[1],
            r_l2: a[2],
            r_llc: a[3],
            r_node: a[4],
            r_far: a[5] + a[6] + a[7],
        }
    }

    sub_fields! {
        scalar: r_self, r_sib, r_l2, r_llc, r_node, r_far;
        vec: ;
        copy: ;
        clone: ;
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
    pub fn of(a: &[u64; WDEPTH]) -> Self {
        WaitB {
            b0: a[0],
            b1: a[1],
            b2: a[2],
            b3: a[3],
        }
    }

    sub_fields! {
        scalar: b0, b1, b2, b3;
        vec: ;
        copy: ;
        clone: ;
    }
}

/// The wait-at-depth charge split by class (16 entries, class-major:
/// class * 4 + depth). Class 0 is neither interactive nor foreground,
/// 1 is interactive-only, 2 is foreground-only, 3 is both. `other`
/// sums classes 0 and 1; `fg` sums classes 2 and 3.
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
    pub fn of(
        a_n: &[u64; WDEPTH * WCLS],
        a_ns: &[u64; WDEPTH * WCLS],
        a_max: &[u64; WDEPTH * WCLS],
        a_slow: &[u64; WDEPTH * WCLS],
    ) -> Self {
        let [fg_b0, fg_b1, fg_b2, fg_b3] = sum2(a_n, 2, 3);
        let [fg_ns_b0, fg_ns_b1, fg_ns_b2, fg_ns_b3] = sum2(a_ns, 2, 3);
        let [fg_max_b0, fg_max_b1, fg_max_b2, fg_max_b3] = max2(a_max, 2, 3);
        let fg_slow = sum2(a_slow, 2, 3).to_vec();
        let [other_b0, other_b1, other_b2, other_b3] = sum2(a_n, 0, 1);
        let [other_ns_b0, other_ns_b1, other_ns_b2, other_ns_b3] = sum2(a_ns, 0, 1);
        let [other_max_b0, other_max_b1, other_max_b2, other_max_b3] = max2(a_max, 0, 1);
        let other_slow = sum2(a_slow, 0, 1).to_vec();
        WaitCls {
            fg_b0,
            fg_b1,
            fg_b2,
            fg_b3,
            fg_ns_b0,
            fg_ns_b1,
            fg_ns_b2,
            fg_ns_b3,
            fg_max_b0,
            fg_max_b1,
            fg_max_b2,
            fg_max_b3,
            fg_slow,
            other_b0,
            other_b1,
            other_b2,
            other_b3,
            other_ns_b0,
            other_ns_b1,
            other_ns_b2,
            other_ns_b3,
            other_max_b0,
            other_max_b1,
            other_max_b2,
            other_max_b3,
            other_slow,
        }
    }

    sub_fields! {
        scalar: fg_b0, fg_b1, fg_b2, fg_b3,
                fg_ns_b0, fg_ns_b1, fg_ns_b2, fg_ns_b3,
                other_b0, other_b1, other_b2, other_b3,
                other_ns_b0, other_ns_b1, other_ns_b2, other_ns_b3;
        vec: fg_slow, other_slow;
        copy: fg_max_b0, fg_max_b1, fg_max_b2, fg_max_b3,
              other_max_b0, other_max_b1, other_max_b2, other_max_b3;
        clone: ;
    }
}

/// The wait-at-depth charge split by arrival type (8 entries, type-major:
/// type * 4 + depth). `wk` is a wake handoff: the arrival became runnable
/// with SCX_ENQ_WAKEUP. `rot` is the rotation: slice-expiry and
/// preemption requeues, which re-enter without a runnable transition.
/// Under a request-response load the wake side is the request path and
/// the rotation side the compute workers.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct WaitType {
    #[stat(desc = "wake handoffs at depth 0")]
    pub wk_b0: u64,
    #[stat(desc = "wake handoffs at depth 1")]
    pub wk_b1: u64,
    #[stat(desc = "wake handoffs at depth 2")]
    pub wk_b2: u64,
    #[stat(desc = "wake handoffs at depth 3 or deeper")]
    pub wk_b3: u64,
    #[stat(desc = "wake handoff wait totals (ns) at depth 0")]
    pub wk_ns_b0: u64,
    #[stat(desc = "wake handoff wait totals (ns) at depth 1")]
    pub wk_ns_b1: u64,
    #[stat(desc = "wake handoff wait totals (ns) at depth 2")]
    pub wk_ns_b2: u64,
    #[stat(desc = "wake handoff wait totals (ns) at depth 3 or deeper")]
    pub wk_ns_b3: u64,
    #[stat(desc = "wake handoff wait maxima (ns) at depth 0")]
    pub wk_max_b0: u64,
    #[stat(desc = "wake handoff wait maxima (ns) at depth 1")]
    pub wk_max_b1: u64,
    #[stat(desc = "wake handoff wait maxima (ns) at depth 2")]
    pub wk_max_b2: u64,
    #[stat(desc = "wake handoff wait maxima (ns) at depth 3 or deeper")]
    pub wk_max_b3: u64,
    #[stat(desc = "wake handoffs over 5ms, by depth bucket")]
    pub wk_slow: Vec<u64>,
    #[stat(desc = "rotation requeues at depth 0")]
    pub rot_b0: u64,
    #[stat(desc = "rotation requeues at depth 1")]
    pub rot_b1: u64,
    #[stat(desc = "rotation requeues at depth 2")]
    pub rot_b2: u64,
    #[stat(desc = "rotation requeues at depth 3 or deeper")]
    pub rot_b3: u64,
    #[stat(desc = "rotation wait totals (ns) at depth 0")]
    pub rot_ns_b0: u64,
    #[stat(desc = "rotation wait totals (ns) at depth 1")]
    pub rot_ns_b1: u64,
    #[stat(desc = "rotation wait totals (ns) at depth 2")]
    pub rot_ns_b2: u64,
    #[stat(desc = "rotation wait totals (ns) at depth 3 or deeper")]
    pub rot_ns_b3: u64,
    #[stat(desc = "rotation wait maxima (ns) at depth 0")]
    pub rot_max_b0: u64,
    #[stat(desc = "rotation wait maxima (ns) at depth 1")]
    pub rot_max_b1: u64,
    #[stat(desc = "rotation wait maxima (ns) at depth 2")]
    pub rot_max_b2: u64,
    #[stat(desc = "rotation wait maxima (ns) at depth 3 or deeper")]
    pub rot_max_b3: u64,
    #[stat(desc = "rotation requeues over 5ms, by depth bucket")]
    pub rot_slow: Vec<u64>,
}

impl WaitType {
    pub fn of(
        a_n: &[u64; WDEPTH * WTYPE],
        a_ns: &[u64; WDEPTH * WTYPE],
        a_max: &[u64; WDEPTH * WTYPE],
        a_slow: &[u64; WDEPTH * WTYPE],
    ) -> Self {
        let [wk_b0, wk_b1, wk_b2, wk_b3] = row(a_n, 1);
        let [wk_ns_b0, wk_ns_b1, wk_ns_b2, wk_ns_b3] = row(a_ns, 1);
        let [wk_max_b0, wk_max_b1, wk_max_b2, wk_max_b3] = row(a_max, 1);
        let wk_slow = row(a_slow, 1).to_vec();
        let [rot_b0, rot_b1, rot_b2, rot_b3] = row(a_n, 0);
        let [rot_ns_b0, rot_ns_b1, rot_ns_b2, rot_ns_b3] = row(a_ns, 0);
        let [rot_max_b0, rot_max_b1, rot_max_b2, rot_max_b3] = row(a_max, 0);
        let rot_slow = row(a_slow, 0).to_vec();
        WaitType {
            wk_b0,
            wk_b1,
            wk_b2,
            wk_b3,
            wk_ns_b0,
            wk_ns_b1,
            wk_ns_b2,
            wk_ns_b3,
            wk_max_b0,
            wk_max_b1,
            wk_max_b2,
            wk_max_b3,
            wk_slow,
            rot_b0,
            rot_b1,
            rot_b2,
            rot_b3,
            rot_ns_b0,
            rot_ns_b1,
            rot_ns_b2,
            rot_ns_b3,
            rot_max_b0,
            rot_max_b1,
            rot_max_b2,
            rot_max_b3,
            rot_slow,
        }
    }

    sub_fields! {
        scalar: wk_b0, wk_b1, wk_b2, wk_b3,
                wk_ns_b0, wk_ns_b1, wk_ns_b2, wk_ns_b3,
                rot_b0, rot_b1, rot_b2, rot_b3,
                rot_ns_b0, rot_ns_b1, rot_ns_b2, rot_ns_b3;
        vec: wk_slow, rot_slow;
        copy: wk_max_b0, wk_max_b1, wk_max_b2, wk_max_b3,
              rot_max_b0, rot_max_b1, rot_max_b2, rot_max_b3;
        clone: ;
    }
}

/// The wait-at-depth charge split by wake-rate latency-criticality
/// (8 entries, lcri-major: lcri * 4 + depth). `lat` is a task the
/// is_lat_cri() predicate (wake samples + peak frequency) holds at
/// charge time; `other` is everything else. It shows whether the wakees
/// the tick gate serves actually wait, at what depth, and for how long.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct WaitLCRI {
    #[stat(desc = "latency-critical waits, by depth bucket")]
    pub lat_n: Vec<u64>,
    #[stat(desc = "latency-critical wait totals (ns), by depth bucket")]
    pub lat_ns: Vec<u64>,
    #[stat(desc = "latency-critical wait maxima (ns), by depth bucket")]
    pub lat_max: Vec<u64>,
    #[stat(desc = "latency-critical waits over 5ms, by depth bucket")]
    pub lat_slow: Vec<u64>,
    #[stat(desc = "non-latency-critical waits, by depth bucket")]
    pub other_n: Vec<u64>,
    #[stat(desc = "non-latency-critical wait totals (ns), by depth bucket")]
    pub other_ns: Vec<u64>,
    #[stat(desc = "non-latency-critical wait maxima (ns), by depth bucket")]
    pub other_max: Vec<u64>,
    #[stat(desc = "non-latency-critical waits over 5ms, by depth bucket")]
    pub other_slow: Vec<u64>,
}

impl WaitLCRI {
    pub fn of(
        a_n: &[u64; WDEPTH * 2],
        a_ns: &[u64; WDEPTH * 2],
        a_max: &[u64; WDEPTH * 2],
        a_slow: &[u64; WDEPTH * 2],
    ) -> Self {
        let (other_n, lat_n) = a_n.split_at(WDEPTH);
        let (other_ns, lat_ns) = a_ns.split_at(WDEPTH);
        let (other_max, lat_max) = a_max.split_at(WDEPTH);
        let (other_slow, lat_slow) = a_slow.split_at(WDEPTH);
        WaitLCRI {
            lat_n: lat_n.to_vec(),
            lat_ns: lat_ns.to_vec(),
            lat_max: lat_max.to_vec(),
            lat_slow: lat_slow.to_vec(),
            other_n: other_n.to_vec(),
            other_ns: other_ns.to_vec(),
            other_max: other_max.to_vec(),
            other_slow: other_slow.to_vec(),
        }
    }

    sub_fields! {
        scalar: ;
        vec: lat_n, lat_ns, lat_slow, other_n, other_ns, other_slow;
        copy: ;
        clone: lat_max, other_max;
    }
}

/// The latency-critical wait split by the wake-gate miss reason: the
/// condition in ops.select_cpu() that gated the depth-0 wake preempt
/// for the task's most recent wake. Depth-major rows of 10 reasons
/// each (depth * 10 + reason in the BPF array); a rotation requeue
/// files reason 0. The per-depth reason sums equal the wlcri lat
/// counts and ns. Reasons: 0 non-wake, 1 no gate contact, 2 wakee not
/// lat-cri, 3 affinity, 4 seat busy, 5 local busy, 6 victim degenerate,
/// 7 victim lat-cri, 8 prio loss, 9 under the 200us residency floor.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct WaitGateMiss {
    #[stat(desc = "Lat waits by depth x wake-gate miss reason (depth-major 4x10)")]
    pub n: Vec<u64>,
    #[stat(desc = "Lat wait totals (ns) by depth x wake-gate miss reason")]
    pub ns: Vec<u64>,
    #[stat(desc = "Lat wait maxima (ns) by depth x wake-gate miss reason")]
    pub max: Vec<u64>,
    #[stat(desc = "Lat waits over 5ms by depth x wake-gate miss reason")]
    pub slow: Vec<u64>,
}

impl WaitGateMiss {
    pub fn of(
        a_n: &[u64; WDEPTH * WG],
        a_ns: &[u64; WDEPTH * WG],
        a_max: &[u64; WDEPTH * WG],
        a_slow: &[u64; WDEPTH * WG],
    ) -> Self {
        WaitGateMiss {
            n: a_n.to_vec(),
            ns: a_ns.to_vec(),
            max: a_max.to_vec(),
            slow: a_slow.to_vec(),
        }
    }

    sub_fields! {
        scalar: ;
        vec: n, ns, slow;
        copy: ;
        clone: max;
    }

    /// Per-depth row views into the flat depth-major arrays.
    fn row(&self, depth: usize) -> (&[u64], &[u64], &[u64], &[u64]) {
        let lo = depth * WG;
        let hi = lo + WG;
        (
            &self.n[lo..hi],
            &self.ns[lo..hi],
            &self.max[lo..hi],
            &self.slow[lo..hi],
        )
    }
}

/// Where the queues stood when a lane came to pick work, sampled in
/// ops.dispatch(): the seat depth is what its warm queue holds at the
/// pick, the shared backlog the rotation it turns against. Eight
/// buckets, the last one 7 or deeper.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Census {
    #[stat(desc = "warm-seat depth buckets at dispatch, 0..=6 then 7+")]
    pub seat: Vec<u64>,
    #[stat(desc = "shared-queue backlog buckets at dispatch, 0..=6 then 7+")]
    pub shared: Vec<u64>,
}

impl Census {
    pub fn of(seat: &[u64; CENSUS], shared: &[u64; CENSUS]) -> Self {
        Census {
            seat: seat.to_vec(),
            shared: shared.to_vec(),
        }
    }

    sub_fields! {
        scalar: ;
        vec: seat, shared;
        copy: ;
        clone: ;
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        let pct = |v: &Vec<u64>, i: usize| -> String {
            let t: u64 = v.iter().sum();
            if t > 0 {
                format!("{:.1}%", v[i] as f64 * 100.0 / t as f64)
            } else {
                "-".into()
            }
        };
        write!(w, "seat[")?;
        for i in 0..CENSUS {
            if i > 0 {
                write!(w, " ")?;
            }
            write!(w, "{}", pct(&self.seat, i))?;
        }
        write!(w, "] shared[")?;
        for i in 0..CENSUS {
            if i > 0 {
                write!(w, " ")?;
            }
            write!(w, "{}", pct(&self.shared, i))?;
        }
        writeln!(w, "]")?;
        Ok(())
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of running tasks")]
    pub nr_running: u64,
    #[stat(desc = "1 when the scheduler was started with --stats")]
    pub stats_enabled: u64,
    #[stat(desc = "Number of direct dispatches to an idle CPU")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Wake-path preemptions admitted by ops.enqueue()")]
    pub nr_preemptions: u64,
    #[stat(desc = "Number of interactive priority boosts granted")]
    pub nr_boosts: u64,
    #[stat(desc = "Number of slice-end continuations of the deadline winner")]
    pub nr_sticky: u64,
    #[stat(desc = "Number of enqueues the oversubscription gate sent to the shared queue")]
    pub nr_coldspreads: u64,
    #[stat(desc = "Runs by class: 0 bulk normal, 1 bulk heavy, 2 fast base, 3 fast fourfold")]
    pub nr_class: Vec<u64>,
    #[stat(desc = "Runs by lane: 0 bulk, 1 fast")]
    pub nr_lane: Vec<u64>,
    #[stat(desc = "Victims cut short at ops.tick for a shared-queue waiter")]
    pub nr_tick_preempts: u64,
    #[stat(desc = "Victims cut short at ops.tick for a warm-seat waiter")]
    pub nr_tick_preempts_warm: u64,
    #[stat(desc = "Tick cuts whose fast-lane waiter the next dispatch refused")]
    pub nr_tick_cut_refused: u64,
    #[stat(desc = "Latency-critical tasks requeued from an RT lease")]
    pub nr_lease_requeues: u64,
    #[stat(desc = "Dispatches that served an RT-lease task back on its home CPU")]
    pub nr_home_takebacks: u64,
    #[stat(desc = "Fast-lane node-queue pulls while bulk work waited")]
    pub nr_depth1_pulls: u64,
    #[stat(desc = "Fast-lane warm-seat pulls while bulk work waited")]
    pub nr_depth1_pulls_seat: u64,
    #[stat(desc = "Dispatches where the bulk backstop withheld the fast lane")]
    pub nr_bulk_backstop: u64,
    #[stat(desc = "Lat-cri wakees preempting a running non-lat-cri victim at wake")]
    pub nr_wake_preempts: u64,
    #[stat(desc = "Direct dispatches to an idle CPU, by distance")]
    pub nr_land: Ranks,
    #[stat(desc = "ops.select_cpu() idle picks by distance")]
    pub nr_wake_land: Ranks,
    #[stat(desc = "Warm seats held on the previous CPU")]
    pub nr_seat_self: u64,
    #[stat(desc = "Warm seats rebalanced to another CPU, by distance")]
    pub nr_seat_move: Ranks,
    #[stat(desc = "Bulk shared-queue pulls, by distance")]
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
    #[stat(desc = "The same waits split by arrival type (wake handoff vs rotation)")]
    pub wait_type: WaitType,
    #[stat(desc = "The same waits split by wake-rate latency-criticality")]
    pub wait_lcri: WaitLCRI,
    #[stat(desc = "Lat waits split by wake-gate miss reason (depth-major 4x10)")]
    pub wait_wg: WaitGateMiss,
    #[stat(desc = "Wake arrivals parked in a warm seat")]
    pub nr_arr_wake_seat: u64,
    #[stat(desc = "Wake arrivals parked in the shared queue")]
    pub nr_arr_wake_shared: u64,
    #[stat(desc = "Rotation arrivals parked in a warm seat")]
    pub nr_arr_rot_seat: u64,
    #[stat(desc = "Rotation arrivals parked in the shared queue")]
    pub nr_arr_rot_shared: u64,
    #[stat(desc = "Queue depths seen at dispatch, by bucket")]
    pub census: Census,
}

/// Build `Metrics::delta` from four field lists: saturating counters,
/// copied snapshot values, `vec_sub` vectors and sub-structs with their
/// own `sub()`. The copy list keeps the maxima rule explicit: a maximum
/// is the interval's own value and is never subtracted.
macro_rules! metrics_delta {
    (
        sub: $($sub:ident),* ;
        copy: $($copy:ident),* ;
        vec: $($vec:ident),* ;
        nested: $($nested:ident),* $(,)?
    ) => {
        fn delta(&self, rhs: &Self) -> Self {
            Self {
                $( $sub: self.$sub.saturating_sub(rhs.$sub), )*
                $( $copy: self.$copy, )*
                $( $vec: vec_sub(&self.$vec, &rhs.$vec), )*
                $( $nested: self.$nested.sub(&rhs.$nested), )*
            }
        }
    };
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        if self.stats_enabled == 0 {
            writeln!(
                w,
                "  stats instrument off: this scheduler instance was started without --stats"
            )?;
        }
        writeln!(
            w,
            "[{}] tasks -> r: {:>2} | dispatch -> d: {:<5} s: {:<5} | preempt: {:<5} tick: {:<4}+{:<4} tkref: {:<4} | d1pull: {:<4}+{:<4} | bkstop: {:<4} | wkpre: {:<5} | lease: {:<4}/{:<4} | boost: {:<4} | sticky: {:<5} | warm: {:<5} | cold: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.nr_direct_dispatches,
            self.nr_arr_shared,
            self.nr_preemptions,
            self.nr_tick_preempts,
            self.nr_tick_preempts_warm,
            self.nr_tick_cut_refused,
            self.nr_depth1_pulls,
            self.nr_depth1_pulls_seat,
            self.nr_bulk_backstop,
            self.nr_wake_preempts,
            self.nr_lease_requeues,
            self.nr_home_takebacks,
            self.nr_boosts,
            self.nr_sticky,
            self.nr_arr_seat,
            self.nr_coldspreads,
        )?;
        writeln!(
            w,
            "  class[{:?}] lane[bulk {} fast {}]",
            self.nr_class,
            self.nr_lane.first().copied().unwrap_or(0),
            self.nr_lane.get(1).copied().unwrap_or(0),
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
        let (wn, wns, wmax, wsl) = (&self.wait_n, &self.wait_ns, &self.wait_max, &self.wait_slow);
        fmt_wait_row(
            w,
            "wait",
            [wn.b0, wn.b1, wn.b2, wn.b3],
            [wns.b0, wns.b1, wns.b2, wns.b3],
            [wmax.b0, wmax.b1, wmax.b2, wmax.b3],
            &[wsl.b0, wsl.b1, wsl.b2, wsl.b3],
            Some((self.nr_arr_seat, self.nr_arr_shared)),
        )?;
        let wc = &self.wait_cls;
        fmt_wait_row(
            w,
            "waitfg",
            [wc.fg_b0, wc.fg_b1, wc.fg_b2, wc.fg_b3],
            [wc.fg_ns_b0, wc.fg_ns_b1, wc.fg_ns_b2, wc.fg_ns_b3],
            [wc.fg_max_b0, wc.fg_max_b1, wc.fg_max_b2, wc.fg_max_b3],
            &wc.fg_slow,
            None,
        )?;
        fmt_wait_row(
            w,
            "waitot",
            [wc.other_b0, wc.other_b1, wc.other_b2, wc.other_b3],
            [
                wc.other_ns_b0,
                wc.other_ns_b1,
                wc.other_ns_b2,
                wc.other_ns_b3,
            ],
            [
                wc.other_max_b0,
                wc.other_max_b1,
                wc.other_max_b2,
                wc.other_max_b3,
            ],
            &wc.other_slow,
            None,
        )?;
        let wt = &self.wait_type;
        fmt_wait_row(
            w,
            "waitwk",
            [wt.wk_b0, wt.wk_b1, wt.wk_b2, wt.wk_b3],
            [wt.wk_ns_b0, wt.wk_ns_b1, wt.wk_ns_b2, wt.wk_ns_b3],
            [wt.wk_max_b0, wt.wk_max_b1, wt.wk_max_b2, wt.wk_max_b3],
            &wt.wk_slow,
            Some((self.nr_arr_wake_seat, self.nr_arr_wake_shared)),
        )?;
        fmt_wait_row(
            w,
            "waitrot",
            [wt.rot_b0, wt.rot_b1, wt.rot_b2, wt.rot_b3],
            [wt.rot_ns_b0, wt.rot_ns_b1, wt.rot_ns_b2, wt.rot_ns_b3],
            [wt.rot_max_b0, wt.rot_max_b1, wt.rot_max_b2, wt.rot_max_b3],
            &wt.rot_slow,
            Some((self.nr_arr_rot_seat, self.nr_arr_rot_shared)),
        )?;
        let wl = &self.wait_lcri;
        fmt_vec_wait(
            w,
            "wlcri lat",
            &wl.lat_n,
            &wl.lat_ns,
            &wl.lat_max,
            &wl.lat_slow,
        )?;
        fmt_vec_wait(
            w,
            "wlcri other",
            &wl.other_n,
            &wl.other_ns,
            &wl.other_max,
            &wl.other_slow,
        )?;
        let wg = &self.wait_wg;
        for (depth, tag) in [
            (0usize, "wg d0"),
            (1usize, "wg d1"),
            (2usize, "wg d2"),
            (3usize, "wg d3"),
        ] {
            let (n, ns, max, slow) = wg.row(depth);
            fmt_vec_wait(w, tag, n, ns, max, slow)?;
        }
        write!(w, "  census: ")?;
        self.census.format(w)?;
        Ok(())
    }

    metrics_delta! {
        sub: nr_direct_dispatches, nr_preemptions, nr_boosts, nr_sticky,
             nr_coldspreads, nr_tick_preempts, nr_tick_preempts_warm,
             nr_tick_cut_refused, nr_lease_requeues, nr_home_takebacks,
             nr_depth1_pulls, nr_depth1_pulls_seat, nr_bulk_backstop,
             nr_wake_preempts, nr_seat_self, nr_arr_seat, nr_arr_shared,
             nr_arr_wake_seat, nr_arr_wake_shared, nr_arr_rot_seat,
             nr_arr_rot_shared;
        copy: nr_running, stats_enabled, wait_max;
        vec: nr_class, nr_lane;
        nested: nr_land, nr_wake_land, nr_seat_move, nr_pull_land, wait_n,
                wait_ns, wait_slow, wait_cls, wait_type, wait_lcri,
                wait_wg, census,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_max_is_the_current_snapshot() {
        // The BPF maxima are reset after every snapshot, so the delta
        // must report the current value, not the larger of the two.
        let cur = Metrics {
            wait_n: WaitB {
                b0: 1,
                ..Default::default()
            },
            wait_max: WaitB {
                b0: 42,
                ..Default::default()
            },
            ..Default::default()
        };
        let prev = Metrics {
            wait_max: WaitB {
                b0: 999,
                ..Default::default()
            },
            ..Default::default()
        };
        let delta = cur.delta(&prev);
        assert_eq!(delta.wait_n.b0, 1);
        assert_eq!(delta.wait_max.b0, 42);
    }

    /// A snapshot with every wait row populated, so a formatting change
    /// that drops or moves a value shows up in the golden text.
    fn sample_metrics() -> Metrics {
        Metrics {
            nr_running: 7,
            stats_enabled: 1,
            nr_direct_dispatches: 11,
            nr_preemptions: 17,
            nr_boosts: 59,
            nr_sticky: 61,
            nr_coldspreads: 71,
            nr_class: vec![1, 2, 3, 4],
            nr_lane: vec![5, 6],
            nr_tick_preempts: 19,
            nr_tick_preempts_warm: 23,
            nr_tick_cut_refused: 29,
            nr_lease_requeues: 47,
            nr_home_takebacks: 53,
            nr_depth1_pulls: 31,
            nr_depth1_pulls_seat: 37,
            nr_bulk_backstop: 41,
            nr_wake_preempts: 43,
            nr_land: Ranks {
                r_self: 1,
                r_sib: 2,
                r_l2: 3,
                r_llc: 4,
                r_node: 5,
                r_far: 6,
            },
            nr_wake_land: Ranks {
                r_self: 2,
                r_sib: 3,
                r_l2: 4,
                r_llc: 5,
                r_node: 6,
                r_far: 7,
            },
            nr_seat_self: 67,
            nr_seat_move: Ranks {
                r_self: 3,
                r_sib: 4,
                r_l2: 5,
                r_llc: 6,
                r_node: 7,
                r_far: 8,
            },
            nr_pull_land: Ranks {
                r_self: 4,
                r_sib: 5,
                r_l2: 6,
                r_llc: 7,
                r_node: 8,
                r_far: 9,
            },
            nr_arr_seat: 73,
            nr_arr_shared: 79,
            wait_n: WaitB {
                b0: 3,
                b1: 2,
                b2: 1,
                b3: 4,
            },
            wait_ns: WaitB {
                b0: 3_000,
                b1: 6_000,
                b2: 9_000,
                b3: 12_000,
            },
            wait_max: WaitB {
                b0: 111,
                b1: 222,
                b2: 333,
                b3: 444,
            },
            wait_slow: WaitB {
                b0: 1,
                b1: 2,
                b2: 3,
                b3: 4,
            },
            wait_cls: WaitCls {
                fg_b0: 1,
                fg_b1: 2,
                fg_b2: 3,
                fg_b3: 4,
                fg_ns_b0: 1_000,
                fg_ns_b1: 2_000,
                fg_ns_b2: 3_000,
                fg_ns_b3: 4_000,
                fg_max_b0: 10,
                fg_max_b1: 20,
                fg_max_b2: 30,
                fg_max_b3: 40,
                fg_slow: vec![1, 2, 3, 4],
                other_b0: 4,
                other_b1: 3,
                other_b2: 2,
                other_b3: 1,
                other_ns_b0: 8_000,
                other_ns_b1: 6_000,
                other_ns_b2: 4_000,
                other_ns_b3: 2_000,
                other_max_b0: 80,
                other_max_b1: 60,
                other_max_b2: 40,
                other_max_b3: 20,
                other_slow: vec![4, 3, 2, 1],
            },
            wait_type: WaitType {
                wk_b0: 2,
                wk_b1: 3,
                wk_b2: 4,
                wk_b3: 5,
                wk_ns_b0: 2_000,
                wk_ns_b1: 3_000,
                wk_ns_b2: 4_000,
                wk_ns_b3: 5_000,
                wk_max_b0: 20,
                wk_max_b1: 30,
                wk_max_b2: 40,
                wk_max_b3: 50,
                wk_slow: vec![1, 2, 3, 4],
                rot_b0: 5,
                rot_b1: 4,
                rot_b2: 3,
                rot_b3: 2,
                rot_ns_b0: 5_000,
                rot_ns_b1: 4_000,
                rot_ns_b2: 3_000,
                rot_ns_b3: 2_000,
                rot_max_b0: 50,
                rot_max_b1: 40,
                rot_max_b2: 30,
                rot_max_b3: 20,
                rot_slow: vec![4, 3, 2, 1],
            },
            wait_lcri: WaitLCRI {
                lat_n: vec![1, 2, 3, 4],
                lat_ns: vec![1_000, 2_000, 3_000, 4_000],
                lat_max: vec![10, 20, 30, 40],
                lat_slow: vec![1, 2, 3, 4],
                other_n: vec![4, 3, 2, 1],
                other_ns: vec![4_000, 3_000, 2_000, 1_000],
                other_max: vec![40, 30, 20, 10],
                other_slow: vec![4, 3, 2, 1],
            },
            wait_wg: WaitGateMiss {
                n: (1..=40).collect(),
                ns: (1..=40).map(|i| i * 1_000).collect(),
                max: (1..=40).map(|i| i * 10).collect(),
                slow: (0..40).map(|i| i % 5).collect(),
            },
            nr_arr_wake_seat: 83,
            nr_arr_wake_shared: 89,
            nr_arr_rot_seat: 97,
            nr_arr_rot_shared: 101,
            census: Census {
                seat: vec![1, 2, 3, 4, 5, 6, 7, 10],
                shared: vec![10, 7, 6, 5, 4, 3, 2, 1],
            },
        }
    }

    /// The recorded output of `sample_metrics()`. The trailing spaces on
    /// the summary line are part of the format and are spelled out.
    const GOLDEN: &str = concat!(
        "[scx_baby] tasks -> r:  7 | dispatch -> d: 11    s: 79    | preempt: 17    tick: 19  +23   tkref: 29   | d1pull: 31  +37   | bkstop: 41   | wkpre: 43    | lease: 47  /53   | boost: 59   | sticky: 61    | warm: 73    | cold: 71\x20\x20\x20\n",
        "  class[[1, 2, 3, 4]] lane[bulk 5 fast 6]\n",
        "  land: self 4.8% sib 9.5% l2 14.3% llc 19.0% node 23.8% far 28.6% | wake: self 7.4% sib 11.1% l2 14.8% llc 18.5% node 22.2% far 25.9%\n",
        "  seatmove: self 9.1% sib 12.1% l2 15.2% llc 18.2% node 21.2% far 24.2% | pull: self 10.3% sib 12.8% l2 15.4% llc 17.9% node 20.5% far 23.1%\n",
        "  wait n[3 2 1 4] mean_us[1 3 9 3] max_ns[111 222 333 444] slow5ms[1 2 3 4] arr(seat 73 shared 79)\n",
        "  waitfg n[1 2 3 4] mean_us[1 1 1 1] max_ns[10 20 30 40] slow5ms[1 2 3 4]\n",
        "  waitot n[4 3 2 1] mean_us[2 2 2 2] max_ns[80 60 40 20] slow5ms[4 3 2 1]\n",
        "  waitwk n[2 3 4 5] mean_us[1 1 1 1] max_ns[20 30 40 50] slow5ms[1 2 3 4] arr(seat 83 shared 89)\n",
        "  waitrot n[5 4 3 2] mean_us[1 1 1 1] max_ns[50 40 30 20] slow5ms[4 3 2 1] arr(seat 97 shared 101)\n",
        "  wlcri lat n[[1, 2, 3, 4]] mean_us[[\"1\", \"1\", \"1\", \"1\"]] max_ns[[\"10\", \"20\", \"30\", \"40\"]] slow5ms[[1, 2, 3, 4]]\n",
        "  wlcri other n[[4, 3, 2, 1]] mean_us[[\"1\", \"1\", \"1\", \"1\"]] max_ns[[\"40\", \"30\", \"20\", \"10\"]] slow5ms[[4, 3, 2, 1]]\n",
        "  wg d0 n[[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]] mean_us[[\"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\"]] max_ns[[\"10\", \"20\", \"30\", \"40\", \"50\", \"60\", \"70\", \"80\", \"90\", \"100\"]] slow5ms[[0, 1, 2, 3, 4, 0, 1, 2, 3, 4]]\n",
        "  wg d1 n[[11, 12, 13, 14, 15, 16, 17, 18, 19, 20]] mean_us[[\"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\"]] max_ns[[\"110\", \"120\", \"130\", \"140\", \"150\", \"160\", \"170\", \"180\", \"190\", \"200\"]] slow5ms[[0, 1, 2, 3, 4, 0, 1, 2, 3, 4]]\n",
        "  wg d2 n[[21, 22, 23, 24, 25, 26, 27, 28, 29, 30]] mean_us[[\"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\"]] max_ns[[\"210\", \"220\", \"230\", \"240\", \"250\", \"260\", \"270\", \"280\", \"290\", \"300\"]] slow5ms[[0, 1, 2, 3, 4, 0, 1, 2, 3, 4]]\n",
        "  wg d3 n[[31, 32, 33, 34, 35, 36, 37, 38, 39, 40]] mean_us[[\"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\", \"1\"]] max_ns[[\"310\", \"320\", \"330\", \"340\", \"350\", \"360\", \"370\", \"380\", \"390\", \"400\"]] slow5ms[[0, 1, 2, 3, 4, 0, 1, 2, 3, 4]]\n",
        "  census: seat[2.6% 5.3% 7.9% 10.5% 13.2% 15.8% 18.4% 26.3%] shared[26.3% 18.4% 15.8% 13.2% 10.5% 7.9% 5.3% 2.6%]\n",
    );

    fn format_text(metrics: &Metrics) -> String {
        let mut out = Vec::new();
        metrics.format(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn format_matches_the_recorded_output() {
        assert_eq!(format_text(&sample_metrics()), GOLDEN);
    }

    #[test]
    fn zero_waits_print_a_dash() {
        let mut metrics = sample_metrics();
        metrics.wait_n = WaitB::default();
        metrics.wait_ns = WaitB {
            b0: 1_000,
            ..Default::default()
        };
        metrics.wait_max = WaitB {
            b0: 500,
            ..Default::default()
        };
        let text = format_text(&metrics);
        let line = text
            .lines()
            .find(|line| line.starts_with("  wait n["))
            .unwrap();
        assert!(line.contains("mean_us[- - - -]"), "{line}");
        assert!(line.contains("max_ns[- - - -]"), "{line}");
    }

    #[test]
    fn wait_mean_rounds_to_the_nearest_microsecond() {
        let mut metrics = sample_metrics();
        metrics.wait_n = WaitB {
            b0: 2,
            ..Default::default()
        };
        metrics.wait_ns = WaitB {
            b0: 1_999,
            ..Default::default()
        };
        let text = format_text(&metrics);
        let line = text
            .lines()
            .find(|line| line.starts_with("  wait n["))
            .unwrap();
        // 1999ns over two waits is 0.9995us, which rounds to 1.
        assert!(line.contains("mean_us[1 "), "{line}");
    }

    #[test]
    fn delta_subtracts_counts_and_keeps_maxima() {
        let cur = sample_metrics();
        let mut prev = sample_metrics();
        prev.wait_cls.fg_b0 = cur.wait_cls.fg_b0 + 5;
        prev.wait_cls.other_ns_b3 = cur.wait_cls.other_ns_b3 + 7;
        prev.wait_cls.fg_max_b0 = u64::MAX;
        prev.wait_type.wk_b0 = cur.wait_type.wk_b0 + 5;
        prev.wait_type.rot_max_b0 = u64::MAX;
        prev.wait_lcri.lat_n[0] = 0;
        prev.wait_lcri.lat_max[0] = u64::MAX;
        prev.wait_wg.n[5] = u64::MAX;
        prev.wait_wg.max[0] = u64::MAX;
        prev.wait_max.b0 = u64::MAX;
        prev.nr_running = cur.nr_running + 3;
        prev.stats_enabled = cur.stats_enabled + 1;
        prev.census.seat[0] = cur.census.seat[0] + 5;
        prev.census.shared[7] = 0;

        let delta = cur.delta(&prev);

        assert_eq!(delta.wait_cls.fg_b0, 0);
        assert_eq!(delta.wait_cls.other_ns_b3, 0);
        assert_eq!(delta.wait_cls.fg_max_b0, cur.wait_cls.fg_max_b0);
        assert_eq!(delta.wait_type.wk_b0, 0);
        assert_eq!(delta.wait_type.rot_max_b0, cur.wait_type.rot_max_b0);
        assert_eq!(delta.wait_lcri.lat_n[0], cur.wait_lcri.lat_n[0]);
        assert_eq!(delta.wait_lcri.lat_max[0], cur.wait_lcri.lat_max[0]);
        assert_eq!(delta.wait_wg.n[5], 0);
        assert_eq!(delta.wait_wg.max[0], cur.wait_wg.max[0]);
        assert_eq!(delta.wait_max.b0, cur.wait_max.b0);
        assert_eq!(delta.nr_running, cur.nr_running);
        assert_eq!(delta.stats_enabled, cur.stats_enabled);
        assert_eq!(delta.census.seat[0], 0);
        assert_eq!(delta.census.shared[7], cur.census.shared[7]);
    }

    #[test]
    fn wait_constructors_map_rows_exactly() {
        // Every cell is distinct and the maxima are not the row sums, so
        // a swapped class/type row or a sum used as a maximum fails.
        let n: [u64; WDEPTH * WCLS] = std::array::from_fn(|i| i as u64 + 1);
        let ns: [u64; WDEPTH * WCLS] = std::array::from_fn(|i| (i as u64 + 1) * 100);
        let max: [u64; WDEPTH * WCLS] = std::array::from_fn(|i| {
            // Alternate which row wins per depth, so dropping either row
            // of max2 or substituting another row fails.
            let (r, d) = (i / WDEPTH, i % WDEPTH);
            if (r + d) % 2 == 0 {
                50_000 + i as u64 * 1000
            } else {
                i as u64 * 1000 + 7
            }
        });
        let slow: [u64; WDEPTH * WCLS] = std::array::from_fn(|i| (i as u64 + 1) * 10);

        let cls = WaitCls::of(&n, &ns, &max, &slow);
        assert_eq!(
            [cls.fg_b0, cls.fg_b1, cls.fg_b2, cls.fg_b3],
            [22, 24, 26, 28]
        );
        assert_eq!(
            [cls.fg_ns_b0, cls.fg_ns_b1, cls.fg_ns_b2, cls.fg_ns_b3],
            [2200, 2400, 2600, 2800]
        );
        assert_eq!(
            [cls.fg_max_b0, cls.fg_max_b1, cls.fg_max_b2, cls.fg_max_b3],
            [58000, 63000, 60000, 65000]
        );
        assert_eq!(cls.fg_slow, vec![220, 240, 260, 280]);
        assert_eq!(
            [cls.other_b0, cls.other_b1, cls.other_b2, cls.other_b3],
            [6, 8, 10, 12]
        );
        assert_eq!(
            [
                cls.other_max_b0,
                cls.other_max_b1,
                cls.other_max_b2,
                cls.other_max_b3
            ],
            [50000, 55000, 52000, 57000]
        );
        assert_eq!(
            [
                cls.other_ns_b0,
                cls.other_ns_b1,
                cls.other_ns_b2,
                cls.other_ns_b3
            ],
            [600, 800, 1000, 1200]
        );
        assert_eq!(cls.other_slow, vec![60, 80, 100, 120]);

        let n: [u64; WDEPTH * WTYPE] = std::array::from_fn(|i| i as u64 + 1);
        let ns: [u64; WDEPTH * WTYPE] = std::array::from_fn(|i| (i as u64 + 1) * 100);
        let max: [u64; WDEPTH * WTYPE] = std::array::from_fn(|i| (i as u64 + 1) * 1000 + 7);
        let slow: [u64; WDEPTH * WTYPE] = std::array::from_fn(|i| (i as u64 + 1) * 10);

        let ty = WaitType::of(&n, &ns, &max, &slow);
        assert_eq!([ty.wk_b0, ty.wk_b1, ty.wk_b2, ty.wk_b3], [5, 6, 7, 8]);
        assert_eq!(
            [ty.wk_ns_b0, ty.wk_ns_b1, ty.wk_ns_b2, ty.wk_ns_b3],
            [500, 600, 700, 800]
        );
        assert_eq!(
            [ty.wk_max_b0, ty.wk_max_b1, ty.wk_max_b2, ty.wk_max_b3],
            [5007, 6007, 7007, 8007]
        );
        assert_eq!(ty.wk_slow, vec![50, 60, 70, 80]);
        assert_eq!([ty.rot_b0, ty.rot_b1, ty.rot_b2, ty.rot_b3], [1, 2, 3, 4]);
        assert_eq!(
            [ty.rot_max_b0, ty.rot_max_b1, ty.rot_max_b2, ty.rot_max_b3],
            [1007, 2007, 3007, 4007]
        );
        assert_eq!(
            [ty.rot_ns_b0, ty.rot_ns_b1, ty.rot_ns_b2, ty.rot_ns_b3],
            [100, 200, 300, 400]
        );
        assert_eq!(ty.rot_slow, vec![10, 20, 30, 40]);
    }
}
