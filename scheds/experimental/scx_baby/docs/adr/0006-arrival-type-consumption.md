# ADR 0006: consumption-side architecture - the arrival-type split and
# the wall quantum

Date: 2026-10-15. Status: accepted. Round: E13, the consumption-side
grill (six user rounds; every arm's decision tree pre-registered before
it ran).

## Context

E12 (adr/0005) falsified the wake-rate ordering axis and named the
consumption side - seat topology and dispatch arbitration - as the
next lever for the 2x gap to lavd (190-193 rps / 35-47 ms p99.9 vs
248 / 21). The round opened with an instrument instead of a mechanism:
every stamped wait now carries an arrival-type bit (f40d1a46b), set by
ops.runnable() from SCX_ENQ_WAKEUP and cleared by ops.stopping(), plus
a dispatch census of seat depth and shared backlog.

## Findings (the typed baseline, oc2way-20261015-181501)

- The wait charges are rotation-dominated: waits/s match the
  slice-boundary rate to ~2 percent; wake handoffs are ~8 percent of
  charges. The oc2way 2x load is 24 never-sleeping stress-ng spinners
  (the overcommit itself) plus 4 schbench probe threads (the
  scoreboard); probe rps is throughput - cycle time = threads/rps, so
  190 rps is a 21 ms probe cycle against lavd's 248 = 16.1 ms, the
  ~4.9 ms/cycle gap this program chased (request p99.9 includes the
  probe's 10 ms sleep).
- The blend premise behind adr/0003 is overturned: "depth-0 wakes
  average 2.2 ms" was the requeue signature. A true wake pays
  1526 us at d0 and 1941 us at d1, lands one-deep 73 percent of the
  time, and sorts ahead of the fresh requeue inside its seat.
- The wall is full (r 11.88 of 12, 47 of 48 windows): idle-lane
  rescue is dead as a 2x lever.

## Arms and verdicts (all pre-registered, all archived on branches)

- e13a wake-share exemption: wakes skip the seat, join the shared
  queue. 2x +10 percent rps, wake waits collapse (475/533 us, slow
  tail 0.0) - and sat -15 percent: at the wall the shared queue IS
  the workload's own overflow, and feeding deadline-early wakes to
  its front starves the wall's rotation. VETO at sat.
- e13b full-global consumption: dispatch consumes the earliest
  deadline across all seats plus shared. Cross-pulls ran at 45
  percent of consumption and the rotation exploded to ~5 ms at every
  depth (rot slow 61 percent), -11 percent rps. A requeued task
  carries a FRESH deadline and ranks last machine-wide; the
  lane-private seat was protecting the rotation. VETO. The round's
  deep lesson: consumption scope splits by arrival type - wakes
  global, rotation lane-private.
- e13ac (a+c combined): +15.7 percent rps at 2x, vetoed at sat by the
  wake-share half (-13.7 percent).
- e13a2 depth-capped exemption (wakes share only while shared backlog
  < 2): failed both regimes (2x +5-6 percent, sat -10 percent) - the
  wall's shared-depth dips let the exemption through.
- e13c f=4 arrival slice (the upward rung E11 never ran): +5.6
  percent rps at 2x with a BETTER tail, and every other leg a tie.
  The pre-registered tie-or-negative prediction was falsified: the
  wake wait does not scale with the quantum it waits behind, and the
  rotation's d0 wait held at ~2.2 ms under a 4.72 ms slice.
- e13d/e13d2 tiered slices (machine-sum tier, then local-depth tier):
  the sum tier missed its 4x recovery on an assumed threshold; the
  local-depth tier loaded and diluted 2x to +3.9 percent. Both
  archived. Detour cost: three E2BIG loads (enqueue, census-top
  dispatch, arbitration-inline), one undeclared kfunc, one stale-
  binary phantom behind a tail-masked build failure.

## The 4x resolution

The 4x leg that drove the tier detour was itself noise-limited: at 4
interleaved rounds (oc2way-20261015-200448), e13c read the tightest
4x series of the day (92.25-94.83) while the control ran 93.85/94.45/
96.50 plus one 113.60 outlier round whose scheduler state matches its
own stable rounds. Three of four paired rounds tie. The 4x regression
does not survive four rounds; the earlier -11/-13 percent was one
lucky control window.

## Decision

Adopt e13c (branch merged; scx-baby at 3bf82aa27): the gated arrival
slice at both gated sites takes 4 * deadline_ns where the deep-backlog
condition held 2 * deadline_ns, on top of the arrival-type instrument.
The typed baseline's neutrality and the full gate sheet (trio, sat,
med, light, 1x ties; 4x tie at four rounds) are the adoption record.
2x moves 190-193 to ~201 rps against lavd's 248.

## Consequences

1. The remaining 2x gap (~201 vs 248) is unattributed. The wake-share
   exemption is the recorded next lever (+10 percent alone, +15.7
   percent combined) pending a wall-safe bound: the two bounds tried
   (none, shared-depth cap) both broke the wall.
2. The verifier headroom map stands: enqueue takes no new statements;
   the census block at the top of dispatch takes none; the
   arbitration block takes no inline loop-subprogram calls; e13b's
   branch-guarded subprogram form fits. Build output must never run
   through a tail pipe without pipefail - a masked clang failure
   leaves a stale binary that looks like a verifier verdict.
3. The instruments are the round's keepers: arrival-type wait arrays,
   per-type routing, and the dispatch census all read in the stats
   lines (waitwk/waitrot/census) from the bss layout.
