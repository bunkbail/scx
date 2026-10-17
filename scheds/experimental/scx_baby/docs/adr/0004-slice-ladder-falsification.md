# ADR 0004: the slice ladder cannot close the 2x handoff

Date: 2026-10-15. Status: accepted. Round: E11, the lavd-study grill
(all seven questions approved; the two binding caveats - f=1 as a
falsification check only, no micro-tuning on regression, and the
classification paper note - were both honored).

## Context

The wait-at-depth instrument (a3f9d6486) read the 2x d0 warm wait as
one full remaining slice doubled by the deep-backlog slice
(2f98f4096), and the falsified E10 matrix left slice policy as the
next lever for the 2x gap to lavd (191 rps / 43 ms p99.9 vs 248 / 21).
The lavd study then corrected the premise: lavd's slice at 2x is
~5 ms (10 ms targeted latency x 12 active / ~16 queued EWMA, clamped),
LONGER than baby's doubled 2.36 ms, and lavd's latency is carried by
lat_cri deadline compression, not slice length.

## Decision

E11 ran the first-pass ladder arm anyway, as a falsification check:
the arrival slice under the oversubscription gate flipped from
2 * deadline_ns (f=2, control) to deadline_ns (f=1) on both gated
sites (the warm seat, today balance.bpf.c; the shared enqueue path,
today main.bpf.c). 2x oc2way,
2 interleaved rounds each, A=f=1, B=f=2.

## Result (oc2way-20261015-144522)

- rps: f=1 195.18/194.53, f=2 191.65/192.22. Tie inside run noise.
- p99.9: f=1 37.2/39.5 ms, f=2 36.5/45.4 ms. Tie.
- d0 wait mean: f=1 ~2.03-2.09 ms, f=2 ~2.20-2.27 ms. Essentially
  unmoved, NOT halved.
- MECHANISM (instrument readout): the seat population grew - seat
  arrivals 26010/21976 under f=1 vs 21679/22924 under f=2, shared
  arrivals collapsed to 0 in A_r2 - while per-arrival exposure stayed
  at the same residual. The seat-depth histogram (target_nr buckets)
  shifted: seat-count growth doubled the d0 population rather than
  halving the d0 wait. Shortening the arrival slice did not shorten
  the wake handoff; it changed which queue the rotation boundary
  forms in.

## Consequences

1. The verdict pre-registered in the grill stands: slice length
   cannot close the 2x gap. No micro-tuning of slice fractions; the
   ladder stops at the first rung.
2. "You cannot out-slice an ordering problem" now has a measured
   anchor on our own rig. The 2x gap is order-shaped: urgent wakers
   queue behind the backlog in arrival order (deadline = now +
   deadline_ns + prio), and no slice constant changes that.
3. The path forward is the classification/ordering design (executed
   as E12 and falsified in adr/0005): compress the deadline
   offset for urgent classes (computed at runnable/stopping, carried
   in task_ctx, inert below the oversubscription gate) so urgent
   wakers sort ahead in the shared queue - lavd's lat_cri direction,
   adapted to baby's absolute-deadline queue. Its five design
   questions (1x exposure, E2BIG budget, graded-vs-buckets, greedy
   counterweight, seat interaction) are the next grill's agenda.
4. The gate sheet for E11 (trio, ab5600 sat/med/light, 1x/4x
   invariance reads) ran to completion for the record; with rps/p99.9
   tied, no arm is adopted - the tree stays at a3f9d6486 and f=1 is
   archived as ~/scx_baby-e11. Full sheet: 1x f=1 246.47 rps /
   27.8 ms vs f=2 245.70 / 26.4 (the recorded 1x win reproduces; the
   gate fails as designed, seat+shared arrivals ~7.6k); 4x f=1 99.28
   / 52.2 ms vs f=2 93.90 / 60.9 (invariance prediction confirmed
   directionally, d2/d3+ slow counts dominating both arms); trio
   settled rounds tie (stress 19.14-19.32, argon 9.56-9.57, xz
   59.94-60.47; A_r1's 26.86 s stress was a first-attach warm-up
   artifact, its rerun landed at 19.14); ab5600 sat 1359-1362 vs
   1359-1367, med 1541/1534 vs 1546/1543, light 1014 vs 1013-1015 -
   every profile a tie, the sat-wall veto untouched.
