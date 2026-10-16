# ADR 0009: the depth-0 wake-path preempt, pair-gated

Date: 2026-10-16. Status: adopted. Round: argon arbiter round 5,
executed same day. Commit 1fd10b08c.

## Context

ADR 0008's depth-1 pull removed the behind-a-head leg of the lat-cri
wait at 2x (+3.4 percent). The depth-0 leg remained at a mean of
~810us across every round of both round-4 arms, and the calibration
model (validated: +600us removed predicted +3.3, measured +3.4)
attributed it to the tick gate's quantization: the cut happens at the
first 1000Hz tick past the 200us residency window, mean ~700us of
wait on a wake that could in principle be served at wake time with an
IPI (~10-20us, lavd's shape - its 2x p99.9 is 21.6us).

## The two premises falsified on the way (the round's real work)

The brief's candidate moved the enqueue-side wakeup-preempt gate's
conditions to ops.select_cpu with the deadline beat dropped, on the
argument that running victims hold overdue deadlines so no fresh
wakee can ever beat one. The A/B counters falsified that premise:
the OLD enqueue-side gate already fires ~1228 times per 5s window at
2x (oc2p5's new gate fired 1256) - the beat passes most of the time.
The running victim is not an overdue requeue; it renews its deadline
forward at the renewal points while it runs.

The first build (oc2p5, everything else identical) was a dead tie
with oc2p4 (223.25/227.38/219.53 vs 223.38/231.40/218.65). The
remaining difference between the old gate and the new one was
can_resched - the anti-hog burst check. The tick gate cuts victims
without it; the second build dropped it from the new gate only
(oc2p6) and moved 4/4 rounds positive, medians 230.9 vs 227.1
(+1.9 percent). The anti-hog check was blocking exactly the victims
that also bind the tick gate's service - stress workers deep into
their burst window - and the pair gate (lat-cri wakee vs non-lat-cri
victim) plus the 200us residency floor bound the churn in their
place.

## Mechanism (commit 1fd10b08c)

At ops.select_cpu's idle-failure path (pick_idle_cpu found nothing,
the wake needs a CPU now): fire the preempt iff

- the wakee is lat-cri (is_lat_cri, the same graded wake-rate
  predicate everywhere else);
- the wakee can run on prev_cpu (cpumask test - mandatory here, the
  kernel scx_ops_errors a LOCAL_ON insert outside cpus_ptr);
- the wakee's seat AND the target's local DSQ are both empty (the
  local check prevents an IPI-in-flight double preempt);
- the victim (cpu_curr) is non-NULL, not this wakee, not PF_IDLE,
  has a task_ctx, is NOT lat-cri, and static_prio >= wakee's;
- the victim has held the CPU >= BABY_TICK_PREEMPT_PROTECT_NS
  (200us, the tick gate's own floor, read from cpu_running_at).

Then insert SCX_DSQ_LOCAL_ON | prev_cpu + SCX_ENQ_PREEMPT with the
wakee's task_slice, bump nr_wake_preempts, return prev_cpu (tasks
inserted in select_cpu never reach ops.enqueue - the idle path
already relies on that).

Kernel semantics verified from v6.12 ext.c: SCX_ENQ_PREEMPT lands at
the local DSQ HEAD (do_enqueue_task list_add on the PREEMPT/HEAD
flags), zeroes rq->curr's slice and rescheds; the displaced victim
with slice remaining is kept by put_prev_task_scx via
dispatch_enqueue(SCX_ENQ_HEAD) WITHOUT calling ops.enqueue - so the
4x deep-backlog rung (an ops.enqueue decision) is never in play and
no tick_preempted-style mark is needed. The victim resumes after the
wakee's slice with its remainder intact.

What was deliberately NOT added: is_pcpu_task exclusion (prio and
the pair gate protect the classes that matter; excluding pinned
batch victims diverges from the tick gate), a raised wake-rate bar
(schbench passes FOREGROUND_WAKE_FREQ=10; raising it fractures the
lat_cri definition), a 1-skip stamp (self-bounding: the local DSQ
empties before the next wake fires the gate, and the victim's fresh
200us residency on resume throttles repeats).

## The partition

One waiter, three mechanisms, no overlap, by queue state:

1. seat + local empty at wake -> this gate (IPI-fast, ~10-20us);
2. lat-cri seat head -> the tick gate's warm cut (residency ok, the
   gate now rarely sees these - the wake preempt ate the work: its
   cut counts dropped to 0 in rounds where the wake preempt ran
   hottest);
3. non-lat-cri head with lat-cri behind -> the depth-1 pull (ADR
   0008).

## Gates (oc2p6 vs oc2p4, 2026-10-16 evening)

- oc2way 2x: 4/4 paired rounds positive, medians 230.9 vs 227.1
  (+1.9). wlcri lat d1 mean 859-1203us vs 1180-1369us - the pull's
  victims now get cut sooner and re-queue shallower, so the depth-1
  mean fell AGAIN without the pull being touched. wkpre fires
  1102-2536 per 5s window.
- game2: clean/bg50/mem hold (baby best bg50 r2, mem both rounds).
  The oc2 evening band reproduced (462.8/462.9) and stock fell into
  it too in r2 (457.4) - the band is environmental; the morning
  re-verify stays open before any oc2 claim.
- ab5600: sat -0.4, med -0.5, light -0.1 percent, inside +-1.5.

## Consequences

1. 2x rps now ~231 vs lavd 248 - the residual ~17 rps is no longer
   wake-wait shaped: d0 mean STILL ~810us (the preempt serves the
   pair it gates, but the d0 waits that remain are the ones where
   some condition missed - seat non-empty is the largest class by
   the census). The wlcri d0 bucket needs one more split (by gate
   condition missed) before the next lever is chosen - do not
   guess.
2. The falsified premises are recorded: deadline-beat drop alone =
   no effect (beat passes at wake time); can_resched = the real
   binder of BOTH gates' service at the wall. Any future gate that
   re-adds can_resched to a wall-time preempt path will re-tie.
3. The box's two-state cycling (cold=0/shared=0 nr_running-12
   stretches vs mixed stretches) is real and read in both arms'
   logs; the wlcri histograms follow the state, not the build -
   paired same-state reads are the only valid comparison, and
   medians of paired rounds are the verdict unit.
4. Morning re-verify owed for the game2 oc2 cell (both round-4 and
   round-5 gates read the evening band).
