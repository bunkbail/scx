# ADR 0011: the laptop light regression and the phase-2 placement debt

Date: 2026-10-17 (small hours). Status: adopted; the fix is the named
next round. Round: laptop gates, ZCode-driven (user handed the laptop
over). old = /usr/bin/scx_baby (Oct 11, b105975b6-era), tip =
scx_baby-oc2p7 (dfe271355). Fresh boot throughout.

## Context

The laptop gates (lGB/light) had never been measured for the
E13/modularization/oc2 lineage; the 5600X suite verified every build
on that box only. A warm-boot first pass produced two machine-state
artifacts - baby GB SC 902 and light 1267 - that a fresh reboot
cleared; the A/B against the still-installed Oct-11 build then
exposed a real regression underneath.

## The gates (fresh boot, interleaved, alternated arm order)

GB 2 pairs: baby SC 1724/1743 vs lavd 1394/1614 - baby wins SC in
both rounds, median +15%; MC lavd +2.7%, inside the historical swap
range. The e13c anchor (Oct 15: SC 1744/1702, MC 13416/13912) holds,
so the warm-boot SC 902 was machine state, not the build - the
cpuperf-latch suspicion against the modularization is cleared. The
Oct-11 metronome band (SC 1304-1316) and the "lavd wins SC ~15%"
story are obsolete: the SC flip to baby predates oc2p7 and belongs to
the phase-2/E13 window; its size vs the incumbent build is unmeasured
(the old build has no GB score on this kernel).

Light 3 pairs vs lavd: baby 1573/1688/1576 (median 1576) vs lavd
1405/1438/1287 (median 1405) - +12%, zero overlap. Passes against
lavd, but the bar that matters is the incumbent build.

## The regression (light vs the incumbent)

Same fresh boot, 3 interleaved pairs: oc2p7 1571/1707/1775 (median
1707) vs old 2009/2016/2016 (median 2016, its historical band
reproduced exactly) = -15%, every round loses. The laptop light gate
FAILS for oc2p7.

## The probe (target/light_spread.sh)

Per-cpu busy/freq plus a worker-psr histogram through a light round.
Old build: workers packed on E4-E9 at 88-93% busy with E boost
~4300MHz and P cores idle - the compaction shape, an L2-coherent E
stack racing to idle. oc2p7: workers scattered over all 12 P+E cores
at 3-51% busy, P cores carrying 30-50% at 1.7-2.2GHz. cpuperf is
alive (E cores still boost to 4.0-4.3GHz), so the loss is placement:
a worker on a sub-2GHz P pays about 2x the per-cycle cost of one on
a boosted E. e13c additionally spills onto the LP cores (53/43% busy
at 0.7-1.4GHz).

## The bisect (musl build + probe per commit, single rounds)

2021 (old) -> 1747 at 7d53fae4f (global queue; -274 across
f96925578+7d53) -> 1651 at b92e0152c (warm seats, -96) -> 1510 at
a19f63056 (-141 across f6f7c90fb..a19f) -> 1513 at f40d1a46b (tie) ->
1279 at 3bf82aa27 (E13 slice rung, -233) -> 1596 at dfe271355 (oc2
era, +317 recovery).

No single culprit; three additive legs:

1. The phase-2 global-queue redesign is the largest leg (-274 by
   7d53fae4f). The per-CPU homing that produced the light stacking
   went away with the queue topology.
2. E13's arrival-slice upward rung costs -233 (3bf82aa27). A slice
   rung gated on backlog should be inert at light depth; that its
   gate fires on the laptop's light profile needs inspection.
3. The warm-seat/distance era adds -96 to -141. The oc2 machinery
   (tick preempt, depth-1 pull, depth-0 wake preempt) then RECOVERS
   +317 - the same changes the 5600X scored as neutral partially
   repair the placement the earlier rounds broke.

## Consequences

1. oc2p7 stays the 5600X baseline. The laptop keeps /usr/bin/scx_baby
   (Oct 11) as the daily build until the fix lands: oc2p7 trades -15%
   light for a GB SC win whose size against the incumbent is
   unmeasured.
2. The named next round: restore hybrid light compaction. Readout =
   light_spread.sh: the stacking shape back (E-stack busy
   concentration, P cores idle, no LP spill) with light >= 1900 on
   the laptop while the 5600X gate suite and GB SC hold. Candidates:
   scope the warm-seat/sum-gate placement to oversubscribed states on
   hybrid, re-tighten little-tier stacking in the global-queue world,
   and inspect why E13's rung fires at light depth on the laptop.
3. The 5600X gate suite is structurally blind to hybrid placement
   losses: cpuperf has no consumer there, and the light ties were
   real. The laptop suite (lGB + light A/B against the incumbent)
   joins the mandatory gate set for every future baseline claim.
4. Machine-state law for this laptop: back-to-back heavy suites
   depress the next rig (both MC scores halved after a 25-minute
   suite), and SC can halve on a stale boot. Fresh boot, cooldowns
   between rigs, and paired same-session reads are the protocol.
5. Bisect infrastructure: worktree ~/bisect-e13c (left at
   f40d1a46b); incremental musl builds take ~22s using the crate
   README's command - the memory recipe omits the ac_cv_search_* env
   vars and fails without them. Binaries kept as
   target/scx_baby-e13c-bisect and target/scx_baby-bisect.
