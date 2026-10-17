# ADR 0005: the wake-rate ordering axis cannot close the 2x handoff

Date: 2026-10-15. Status: accepted. Round: E12, the classification
grill (Round 1 all-approve with the precompute constraint; Round 2
all-approve with the slope fix; E12a null-intervention diagnosis;
E12b re-span executed with the user's pre-registered decision tree).

## Context

E11 (adr/0004) measured that slice length cannot close the 2x gap and
pointed at the ordering key; the wait-class instrument had measured the
deep wait at 6.7% foreground-qualifying with a 5 ms tail that is 99%
other-class, so a foreground-bit-keyed design could move a rounding
error and the signal had to be wake-rate shape. The classification design compressed the
deadline offset of fast-waking tasks so they sort ahead of the shared
backlog: u_scaled in 1/64ths, offset = deadline_ns * u_scaled >> 6,
computed in ops.runnable (tctx->deadline_offset, the E2BIG-safe
precompute), written at the two approved sites (ops.stopping's
sleep-early renewal and init_task). E12a's span (rate 0-48 mapped
1:1) was a null intervention: schbench at 2x wakes ~4.8-9.5 per
100 ms, so the offset moved only 1180 -> 1005-1092 us, ~100 us against
2.4-3.6 ms rotation slices - the probe was miscalibrated, not the
mechanism falsified.

## Decision

E12b re-spanned the probe per the user's formula: the wake rate is
amplified 5x and capped at 48 (URGENCY_AMP 5), so the foreground bar
itself (rate >= 10) reads full compression - offset 295 us, an ~885 us
lead over a flat deadline. Decision tree pre-registered before the
run: (1) d0/d1 wait drops + rps/p99.9 improves = mechanism lands;
(2) d0/d1 wait drops + rps flat = stop rule (b), consumption-side;
(3) d0/d1 wait does not move = stop rule (a), wake-rate axis
abandoned.

## Result (oc2way-20261015-174141, 2x, 2 interleaved rounds each)

Branch 3 fired.

- rps: E12b 191.22/191.80 vs control 190.40/188.28. Tie (the band
  E11/E11w established: +-1%).
- p99.9: E12b 38.0/39.2 ms vs control 42.0/47.3 ms. Inside the tie
  band (E11w neutral verdicts ranged 40.4-45.1).
- The instrument: urgent-class d0 mean 2016/2107 us vs control
  ~2000-2230 - unchanged at every depth, for both classes, despite
  the ~885 us lead. Wait distributions are statistically identical
  arm-to-arm (A_r1 2262/3643 vs B_r1 2249/3652).
- Mechanism signature check: sticky counts 30-42 (E12b) vs 32-46
  (control), preempt 968-1013 vs 981-1045 - the compressed deadlines
  did not measurably break sticky continuations either. Attach clean,
  no warm-up artifact in the settled lines.

## Consequences

1. Stop rule (a) fires as pre-registered: the wake-rate ordering
   axis is abandoned. An ~885 us deadline lead - three quarters of a
   flat offset, applied to every foreground-bar waker - does not
   change when a waking task runs relative to the backlog. The wait
   is not paid in queue position; it is paid in seat depth and
   rotation, which the deadline key does not reach.
2. With E11 (slice length) and E12 (deadline compression) both
   falsified on measurements, the ordering thesis of the
   classification round ("you cannot out-slice an ordering problem")
   is refined: the problem is not the ORDER either - the
   deep wait is seat-depth-bound (E11's mechanism finding) and
   rotation-bound (the 4x readout). The next lever, if any, is
   consumption-side: seat topology and dispatch arbitration, the
   side stop rule (b) named. That is a new grill, not a
   continuation of this one.
3. No arm is adopted; the tree stays at a19f63056. Archived on the
   box: ~/scx_baby-e12a (flat span), ~/scx_baby-e12b (re-span).
4. The wait-class instrument (a19f63056) and the E11/E12 falsification
   records are the round's keepers: they converted three standing
   leads into measured negatives and pinned the wait's structure at
   2x (seat-depth-bound, not order-bound, not slice-bound).
