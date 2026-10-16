# ADR 0008: the depth-1 out-of-turn pull at consumption

Date: 2026-10-16. Status: adopted. Round: argon arbiter round 4 (the
consumption-side schbench-2x wall), executed same day. Commit 3f9ec1282.

## Context

The schbench-2x wall (baby 218-223 rps vs lavd 248, p99.9 32-38us vs
21.6) was characterized in round 3 as consumption-side after the
graded lat-cri deadline compression (lcomp) came back neutral with a
structural insight: at saturation the node queue's head is an OVERDUE
batch requeue - its deadline is already past - and no bounded offset
compression can promote a wakee past it. Correlation from the lcomp
matrix: the one round that reached lavd parity (246.9 rps) was the one
round whose wlcri histogram flipped to depth-0-dominant.

Round 4's pre-flight (zero code, same session):

- The oc2way counter read on the tip: the tick gate's warm-head path
  fires 1158-2205 cuts per 5s window at 2x while the node-head path
  fires 0-36 - the gate is live but blind to exactly the waiters the
  wall pays for.
- Fresh lavd re-anchor on today's ambient: 248.4/247.3 rps, p99.9
  21.98/22.30us (oc2way) - the 2026-10-11 anchor reproduces to 0.5%,
  so 248 is a real target, not drift.
- Stock re-read in the same window: 144 rps at 2x (the 2026-10-11
  anchor was 166).

## The decomposition (argon round 4, corrected by the logs)

Argon's verdict: execute the bounded depth-1 out-of-turn pull at
ops.dispatch (option A). Its wait decomposition: depth-1 lat wait
1720us = 887us (overdue head H consuming the first node dispatch) +
833us (the waiter's own second-rotation wait as the new head); both
legs measured. Offset compression was doomed because it re-orders
only against FUTURE deadlines; the inversion must be resolved at
consumption time.

Two corrections the round's logs made to argon's model:

1. SCOPE: the depth-1 lat waiters are wake arrivals parked in WARM
   SEATS, not node-queue waits. waitwk arr(seat 2094 shared 2) at 2x;
   the node queue holds requeues. Argon's node-only pull would never
   fire - and in the gate run it fired 0 times (nr_depth1_pulls).
   The seat variant (nr_depth1_pulls_seat) carries all the service:
   351-653 pulls per 5s window.
2. SEQUENCE: the pull must run BEFORE the head's move_to_local in the
   same dispatch - if the head move succeeds first, the waiter waits
   one more rotation and the mechanism is dead.

## Mechanism (commit 3f9ec1282)

At dispatch, when the queue the CPU would pull from holds two or more
tasks: walk the first two entries (straight-line, two iterator steps,
no loop); if the head is NOT lat-cri and the entry behind it IS, move
the waiter to this CPU's local queue with scx_bpf_dsq_move() and let
the caller's normal path take the head next. Serves the waiter at the
head's own expiry cadence - no extra context switch, no tick
machinery touched.

Starvation bound - one bypass per head: a successful pull records the
skipped head's pid in a per-queue stamp (node_skip_pid global,
seat_skip_pid per CPU); the next dispatch that finds the same head
consumes it and clears the record. Under a lat-cri flood the head
still goes through every other batch dispatch - the e13a/e13b veto
shape avoided. The record is cleared whenever no bypass was decided
(depth<2 guard, lat-cri head, non-lat-cri waiter, failed move), so a
head's next incarnation starts with a clean bound.

Verifier cliffs crossed (probe-verified on the 7.2.9 kernel):

- The pull must be same-frame with its RCU scope: a noinline callee's
  bpf_rcu_read_unlock() demotes the caller's already-peeked task
  pointers to untrusted ("R1 must be a rcu pointer" at the
  scx_bpf_task_cpu of a peeked head), while an always-inlined
  lock/unlock pair leaves them intact - the scx_flow flow_drain_own()
  shape.
- bpf_iter_scx_dsq_destroy() must run on the failed-new path too:
  the verifier holds the iterator reference until the destroy
  regardless of new()'s outcome ("BPF_EXIT in main prog would lead
  to reference leak"); the compat __COMPAT_scx_bpf_dsq_peek() is the
  proven shape.
- scx_bpf_dsq_nr_queued() stays outside the RCU section
  (node_backlog note).
- cpus_ptr is read through a bpf_task_from_pid() re-acquire (the
  tickless note: raw iterated pointers do not verify for member
  access); the pid read on the raw pointer does verify.

## Gates (oc2p4 vs oc2p3, interleaved, 2026-10-16 evening)

- oc2way 2x: 4/4 rounds positive, A medians 225.0 vs B 217.6 (+3.4%).
  Readout signature as predicted: wlcri lat d1 mean 1183-1368us vs
  B 1466-1993us (-600us), slow5ms 29-72 vs 86-147 (halved);
  d1pull seat 351-653/window, node 0.
- game2: clean/bg50/mem hold (baby best in bg50/mem). The oc2 cell
  read 450-466 tonight for EVERY baby build including the 548-band
  original (stock 486, lavd 532 held) - an environmental evening
  shift, not a regression; same-window ordering oc2p4 > oc2p3 > oc2p.
  The oc2 cell needs a re-verify in a morning window before this ADR
  claims the gaming cell holds.
- ab5600: sat 1347.0 vs 1356.1 (-0.7%), med 1534.3 vs 1532.0 (+0.3%),
  light 1007.2 vs 1008.6 (-0.1%), all inside the +-1.5% band.

## Consequences

1. The schbench-2x residual narrows from ~30 to ~23 rps (225 vs 248).
   The depth-1 leg of the lat wait is served; what remains is the
   depth-0 leg (~830us mean, one pull cadence) and the worker-side
   rotation, which the deadline-order machinery already prices.
2. The d1pull counters are part of the instrument suite; a build
   whose seat pull fires 0 at 2x has a dead pull and should be
   debugged before any verdict.
3. The one-skip bound is untested against a genuine lat-cri flood
   (no such workload in the gates); if one appears in the field, the
   bound's floor (>=50% batch dispatch share) is the invariant to
   check.
4. Open question for the wall: whether the remaining ~23 rps is the
   depth-0 cadence itself (lavd's 21.6us p99.9 suggests it serves
   wakes much deeper than one pull cadence) or the worker/throughput
   side; the wlcri arrays answer with one more bench session.
