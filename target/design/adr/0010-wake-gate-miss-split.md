# ADR 0010: the wake-gate miss split and the depth-0 attribution

Date: 2026-10-16 (late evening). Status: adopted; the lever decision it
feeds is pending (argon round 7). Round: argon arbiter round 6, executed
same day. Commit d1d0cfe31. Deploy oc2p7.

## Context

ADR 0009 left the depth-0 lat residual (~810us mean at 2x) attributed
to the wake preempt's gate-missed pairs by inference alone: "seat
non-empty is the largest class by the census". No per-reason counter
existed, and the next lever was to be chosen only after a split
attributed the residual. Argon round 6 arbitrated the split design and
the agenda sequencing (morning game2 re-verify is time-gated to
tomorrow; the split is not).

## The design (commit d1d0cfe31)

A u8 wake-gate miss reason rides task_ctx. ops.select_cpu() resets it
to NO_GATE at entry (so it always describes the most recent wake),
stores a code at each miss exit, and charge_wait() consumes it in
ops.running(), filing latency-critical charges into reason-major
arrays nested by depth (entry depth * 10 + reason). Ten codes: 0
non-wake (rotation requeue, its arrival_is_wake bit clear), 1 no gate
contact, 2 wakee not lat-cri at gate time, 3 affinity, 4 seat busy,
5 local busy, 6 victim degenerate, 7 victim lat-cri, 8 prio loss,
9 under the 200us residency floor. The seat and local legs of the old
combined queue check and the three victim conditions split into
sequential exits with the same truth table - the gate's behavior is
unchanged, one store per exit.

ops.enqueue is byte-untouched (E2BIG ceiling), and needs no clear
point: a wake the enqueue-side gate serves never parks, so it never
charges a wait; every wake charge had a same-cycle select_cpu contact
(the core routes every wakeup through it), and rotation requeues file
reason 0. The reason classes partition the wlcri lat bucket exactly -
per depth, the reason sums equal the wlcri lat counts and ns - and the
readout checks that identity per 5s interval.

## The measured attribution (4 paired same-state rounds, 2x, evening)

Perf neutrality of the instrument: paired medians 229.6 (oc2p7) vs
230.9 (oc2p6), -0.6 percent, inside the 218-231 band; p99.9 at or
below the control in 3/4 paired rounds; the partition identity held
20/20 intervals in every arm. A fresh lavd anchor in the same session
reads 248.6/249.5/248.8 (p99.9 21.3-21.7us) - the 248 holds; the gap
is ~18 rps tonight.

Of the ~900us depth-0 lat mean (fast-state rounds), by ns share:

- rotation requeues (reason 0): 57-66 percent, mean 1030-1070us,
  ~1500-1850 charges per round. Lat-cri tasks whose runtime stretched
  past the slice under 2x load, requeued to an empty seat, waiting
  about one rotation quantum. NOT wake arrivals.
- seat busy (reason 4): 26-35 percent, mean ~685us, ~1050-1400 per
  round. The wakee's seat was busy at the gate; it parked at depth 0
  anyway - the shallowest-seat move relocated it to another CPU's
  empty seat, or the seat drained between gate and enqueue. The
  tick-quantization shape: the CPU it landed on was never evaluated
  by the wake gate.
- local busy (reason 5): 1-3 percent, n 10-21, mean 4-5.4ms - the
  second-of-a-burst wakee behind an in-flight preempted wakee. Tiny
  count, long tail. In the slow-state round it grows to 27 percent.
- residency (reason 9): 4-6 percent, n 133-222, mean 760-840us - the
  200us floor working as designed, tick-served at quantization cost.
- victim lat-cri (7): ~0-3 percent. prio (8), degenerate (6),
  not-lat (2), no-gate (1): ~0.

## What the split falsifies

ADR 0009's framing of the residual is wrong in its weighting: the
depth-0 lat bucket is majority rotation, not gate-missed wakes. The
"seat non-empty is the largest class" claim was about miss events
(the depth-1 population, the pull's territory), not about the depth-0
ns burden. The wake-gate-attributable share of the bucket is
~35-45 percent, dominated by the seat-relocation class at ~30 percent
(~240-316us of the mean; eliminating it predicts ~+1.4-1.8 percent,
~+3-4 rps). No single wake-side class clears argon's 35 percent
dominance threshold robustly: seat sits at the threshold in its best
round and under it pooled, and the rotation class that does dominate
is outside the gate's scope (slice-side levers are falsified, E11).

## Consequences

1. Argon round 7 (same night) applied the dominance rule to the
   measured split and the STOP condition FIRES: the schbench-2x
   wake-gate frontier closes at ~231 rps vs lavd ~249. The rotation
   class (57-66 percent) is the pre-registered STOP clause's shape -
   outside the gate's scope, its slice-side levers falsified. The
   seat class fails both gates: under the 35 percent threshold pooled
   (~30 percent), and its full-elimination ceiling (+3-4 rps)
   collapses to ~1-2 rps realistic capture, inside the box's variance
   band (the paired medians differ by 1.3 rps with an inert
   instrument). Splitting the seat class into its two sub-mechanisms
   (relocation vs prev-seat drain) is rejected - neither sub-class
   could reach the threshold or resolve in rps. The d0 wake-gate
   frontier is exhausted; no lever round is opened.
2. The oc2p7 instrument is retained as baseline (d1d0cfe31): neutral
   throughput and tail, exact partition identity, zero enqueue
   growth. The ~18 rps gap to lavd stands partitioned and documented:
   worker slice-expiry rotation (the primary leg, ~515-593us of the
   depth-0 mean) plus sub-threshold tick-quantized wake wait.
3. The rotation share (~515-593us of the depth-0 mean) is the
   worker-side leg measured directly for the first time; it matches
   the calibration model's ~11 rps remainder. Its levers are
   falsified territory (E11 ladder, E12 ordering).
4. The morning game2 oc2 re-verify (both round-5 and this round's
   gates read the evening band) runs tomorrow on oc2p6 and oc2p7 with
   stock and lavd anchors under oc2audit.sh; after it, the session
   frontier moves to the laptop/battery port.
