/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Copyright (C) 2021, Hamad Al Marri <hamad.s.almarri@gmail.com>
 * (original baby-dl scheduler, baby-dl-5.14.patch)
 *
 * Every task owns a deadline, an absolute timestamp by which it would like
 * to run. The CPU always runs the task with the earliest deadline: tasks
 * are inserted into a global deadline-ordered queue and dispatched
 * earliest-deadline-first.
 *
 * Tasks that voluntarily sleep before consuming their deadline are treated
 * as interactive: their effective nice level is boosted by one step (down
 * to -20), which pulls their future deadlines earlier. CPU hogs are
 * throttled by a burst tracker that accounts the runtime a task accumulates
 * over a 200ms window: a task whose bursts keep growing behind the previous
 * window cannot preempt other tasks even when its deadline is earlier.
 */
#include "baby.bpf.h"

char _license[] SEC("license") = "GPL";

/*
 * Default deadline offset (1.18ms, the original DEADLINE_NS).
 */
const volatile u64 deadline_ns = 1180000ULL;

 /* Report additional debugging information */
const volatile bool debug;

/*
 * Big and little CPU sets, published by userspace at startup from the
 * platform's core types. The deadline order is placement-blind - an
 * idle CPU pulls the earliest-deadline task from wherever it waits -
 * so the sets steer nothing on a single-tier machine; they stay for
 * the per-tier queues a hybrid platform needs.
 */
private(BABY) struct bpf_cpumask __kptr *big_cpumask;
private(BABY) struct bpf_cpumask __kptr *little_cpumask;

/*
 * Saturation deferred preemption (the game2 oc2 verdict): at full CPU
 * saturation a latency-critical task that parks in a queue waits a
 * full slice behind the batch task running here, and at 2x
 * overcommit that wait is paid by every frame - the game's whole
 * frame-time distribution shifts right by one slice quantum. The tick
 * cuts the victim short instead, under these gates:
 *
 * - the victim is not itself latency-critical (classified by the
 *   wake-rate EWMA; homogeneous batch workers never preempt each
 *   other);
 * - a latency-critical task waits at a head this CPU serves - its own
 *   warm seat or the shared deadline queue. With an idle CPU anywhere
 *   the waiter would have been pulled already, so a waiting head
 *   encodes saturation on its own;
 * - the victim has held the CPU longer than the protect window, so a
 *   task that just got the CPU keeps it;
 * - for the shared-queue head, one CPU at a time: the synchronized
 *   per-CPU ticks would otherwise all preempt for the same single
 *   waiter, and only the first pull serves it. A global stamp with a
 *   deadline-length quiet window bounds the herd. Warm-seat waiters
 *   are per-CPU precise and need no stamp: the preempted victim's
 *   rotation pulls the waiter in the same scheduling cycle, which
 *   empties the queue head and disarms the gate.
 *
 * The kernel reschedules when ops.tick() leaves the slice at zero, and
 * the preempted victim re-enters through ops.enqueue() with its
 * deadline intact - behind the waiter that displaced it, which the
 * deadline order already prefers. The victim carries tick_preempted
 * so its requeue takes the base slice, not the deep-backlog rung it
 * did not earn.
 *
 * The waiting head is observed by peeking, not by a latch signaled
 * from ops.enqueue(): the enqueue sits at the verifier's
 * jump-complexity ceiling (adr/0003), and the peek -> lookup -> class
 * pattern is already verifier-proven in the starve-rescue timer.
 */
#define BABY_TICK_PREEMPT_PROTECT_NS	(200ULL * NSEC_PER_USEC)

/*
 * Fallback quiet window for the shared-queue claim, covering only the
 * tick -> resched -> dispatch flight of the preempting CPU - its
 * dispatch may be diverted to a warm-seat arrival and never pull the
 * waiter. The stamp is cleared the moment any CPU pulls the shared
 * head, so under wake bursts (multiple waiters microseconds apart) the
 * next staggered tick (>100us later) can serve the next waiter instead
 * of waiting out a whole slice.
 */
#define BABY_TICK_PREEMPT_FALLBACK_NS	(100ULL * NSEC_PER_USEC)

static u64 cpu_running_at[BABY_MAX_CPUS];
static u64 node_preempt_at;

/*
 * Depth-1 out-of-turn pull (the consumption-side wall round). The wlcri
 * instrument showed the lat-cri wakees at 2x waiting one deep - behind
 * a queue head that is not itself lat-cri: in a warm seat, where wakes
 * park (99.9%) but the tick gate peeks only the head, or in the node
 * queue, whose head at saturation is an overdue batch requeue. The wait
 * is two serialized pull cadences (~833us each); serving the waiter at
 * the head's own expiry removes one of them without adding a switch.
 *
 * The starvation bound is one bypass per head: when a pull succeeds, the
 * skipped head's pid is recorded per queue, and the next dispatch that
 * finds the same head consumes it. Under a lat-cri flood every other
 * batch dispatch goes to the head - no e13a-style starvation.
 */
static u32 node_skip_pid, seat_skip_pid[BABY_MAX_CPUS];

/*
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	mask = *cpumask;
	if (mask)
		return 0;

	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
}

/*
 * Pick a target CPU for a task which is being woken up, and dispatch it
 * straight to the CPU when the pick found an idle one. Placement is
 * delegated to the kernel's idle-CPU selection: SMT-aware, biased to
 * the previous CPU, spread across the LLCs - the cache warmth the
 * per-CPU queues used to pin comes from the kernel's own sense of the
 * topology.
 */
s32 BPF_STRUCT_OPS(baby_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	/*
	 * Don't trust userspace about the waker releasing the CPU: a
	 * waker that keeps running after the wake leaves the wakee
	 * stacked behind it on a hot core while other cores idle, and
	 * the sync hint is exactly how one hot core starves the rest.
	 */
	wake_flags &= ~SCX_WAKE_SYNC;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		struct task_ctx *tctx = try_lookup_task_ctx(p);

		__sync_fetch_and_add(&nr_wake_land[cpu_dist(prev_cpu, cpu)], 1);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
				   tctx ? task_slice(tctx) : deadline_ns, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	} else if (wake_flags & (SCX_WAKE_TTWU | SCX_WAKE_FORK)) {
		/*
		 * No idle CPU: the depth-0 wake-path preempt (the tick
		 * gate's IPI-fast twin). The tick gate serves a lat-cri
		 * SEAT head by cutting the victim at the first tick with
		 * 200us residency - mean ~700us of quantization wait on
		 * a 1000Hz kernel, which is the depth-0 lat wait the
		 * wlcri instrument read at 2x. This path serves the same
		 * pair the moment the wake happens: when the wakee is
		 * latency-critical, the victim is not, the wakee can
		 * only run here, both queues are empty and the victim
		 * has held the CPU for the same 200us floor, hand it
		 * the CPU now instead of waiting for a tick.
		 *
		 * The deadline-beat check of the enqueue-side gate is
		 * deliberately absent: the running victim renews its
		 * deadline forward while it runs (calc_deadline at the
		 * renewal points), so the beat binds only for victims
		 * deep into an un-renewed stretch - the A/B counters
		 * showed the old gate already fires ~1200/5s at 2x and
		 * the beat-drop recovers almost nothing. can_resched is
		 * likewise dropped: the tick gate cuts the same victims
		 * without it (its condition is !is_lat_cri + residency
		 * + head), and the pair gate plus the 200us residency
		 * floor bound the churn instead. What remains is the
		 * class pair (lat-cri wakee, non-lat-cri victim), the
		 * prio order and the residency floor.
		 *
		 * Kernel semantics (v6.12 ext.c, source-verified):
		 * SCX_ENQ_PREEMPT lands the wakee at the HEAD of the
		 * local DSQ, zeroes rq->curr's slice (the victim) and
		 * rescheds; the victim with remaining slice is kept by
		 * put_prev_task_scx at the local DSQ head via
		 * SCX_ENQ_HEAD - ops.enqueue() is NOT called for it, so
		 * the 4x deep-backlog rung (which ops.enqueue hands
		 * out) is not in play and no tick_preempted-style mark
		 * is needed. The victim resumes after the wakee's
		 * slice with its remainder intact.
		 */
		struct task_ctx *tctx = try_lookup_task_ctx(p);
		struct task_struct *curr;
		struct task_ctx *cctx;
		u64 ran_at;

		if (!tctx || !is_lat_cri(tctx))
			return cpu;
		if (!bpf_cpumask_test_cpu((u32)prev_cpu & (BABY_MAX_CPUS - 1),
					  p->cpus_ptr))
			return cpu;
		if (scx_bpf_dsq_nr_queued(cpu2dsq(prev_cpu)) ||
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cpu))
			return cpu;

		curr = __COMPAT_scx_bpf_cpu_curr(prev_cpu);
		if (!curr || curr == p || (curr->flags & PF_IDLE))
			return cpu;
		cctx = try_lookup_task_ctx(curr);
		if (!cctx || is_lat_cri(cctx) ||
		    p->static_prio > curr->static_prio)
			return cpu;

		ran_at = cpu_running_at[(u32)prev_cpu & (BABY_MAX_CPUS - 1)];
		if (!ran_at || bpf_ktime_get_ns() - ran_at <
				       BABY_TICK_PREEMPT_PROTECT_NS)
			return cpu;

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
				   task_slice(tctx), SCX_ENQ_PREEMPT);
		__sync_fetch_and_add(&nr_wake_preempts, 1);
		__sync_fetch_and_add(&nr_wake_land[cpu_dist(prev_cpu, prev_cpu)],
				     1);

		return prev_cpu;
	}

	return cpu;
}

/*
 * Number of tasks waiting in the node queue. scx_bpf_dsq_nr_queued()
 * fails verification inside an RCU read side section, so callers probe
 * it outside any.
 */
static u64 node_backlog(s32 cpu)
{
	return scx_bpf_dsq_nr_queued(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * The depth-1 pull proper: the first two entries of @dsq_id in deadline
 * order. Straight-line, no loop - two iterator steps only, so the
 * verifier sees a DAG. Returns true when the depth-1 task was moved to
 * this CPU's local queue; false leaves the head in place for the
 * caller's normal consumption.
 *
 * Always inlined, RCU scope owned here: a noinline callee's
 * bpf_rcu_read_unlock() demotes the caller's already-peeked task
 * pointers to untrusted (probe-verified on the 7.2.9 kernel), while a
 * same-frame lock/unlock pair leaves pointers peeked outside it
 * alone - the flow_drain_own() shape.
 *
 * A successful scx_bpf_dsq_move() is a shared-queue consumption: the
 * caller does the preempt-claim handback exactly as a move_to_local
 * would. The cpus_ptr read goes through bpf_task_from_pid() - the raw
 * iterated pointer does not verify for member access (the tickless
 * note); the pid read does, which is what the re-acquire is keyed on.
 */
static __always_inline bool depth1_pull(u64 dsq_id, s32 cpu,
					u32 *skip_pid,
					volatile u64 *counter)
{
	struct bpf_iter_scx_dsq it;
	struct task_struct *h, *w, *wp;
	struct task_ctx *hctx, *wctx;
	u32 h_pid;
	bool moved = false;

	/*
	 * Guard outside the RCU section: scx_bpf_dsq_nr_queued() does
	 * not verify inside one (the node_backlog note). One deep means
	 * only the head - nothing to serve past it, and no bypass was
	 * decided, so a stale skip record can be dropped here: the
	 * caller consumes the head and its next incarnation starts
	 * with a clean bound.
	 */
	if (scx_bpf_dsq_nr_queued(dsq_id) < 2) {
		*skip_pid = 0;
		return false;
	}

	bpf_rcu_read_lock();
	h = NULL;
	w = NULL;
	if (!bpf_iter_scx_dsq_new(&it, dsq_id, 0)) {
		h = bpf_iter_scx_dsq_next(&it);
		w = bpf_iter_scx_dsq_next(&it);
	}

	/*
	 * The head must not be the waiter we are serving for: a lat-cri
	 * head is either the tick gate's business or gets consumed
	 * first by deadline order anyway.
	 */
	hctx = h ? try_lookup_task_ctx(h) : NULL;
	if (!h || !w || (hctx && is_lat_cri(hctx))) {
		*skip_pid = 0;
	} else {
		h_pid = (u32)h->pid;

		/*
		 * The bound: this exact head was bypassed once already.
		 * Consume it now - the caller's move_to_local takes it -
		 * and clear the record so its next incarnation can be
		 * bypassed again.
		 */
		if (*skip_pid == h_pid) {
			*skip_pid = 0;
		} else {
			/*
			 * The waiter must be lat-cri and able to run here.
			 * The cpus_ptr read goes through the re-acquired
			 * pointer; the move re-locks the DSQ itself.
			 */
			wctx = try_lookup_task_ctx(w);
			wp = bpf_task_from_pid(w->pid);
			if (wctx && is_lat_cri(wctx) && wp &&
			    bpf_cpumask_test_cpu((u32)cpu & (BABY_MAX_CPUS - 1),
						 wp->cpus_ptr)) {
				moved = scx_bpf_dsq_move(&it, w, SCX_DSQ_LOCAL, 0);
				if (moved) {
					*skip_pid = h_pid;
					__sync_fetch_and_add(counter, 1);
				} else {
					*skip_pid = 0;
				}
			} else {
				*skip_pid = 0;
			}
			if (wp)
				bpf_task_release(wp);
		}
	}

	/*
	 * Destroy unconditionally, on the failed-new path too - the
	 * compat peek's proven shape; the verifier holds the iterator
	 * reference until the destroy regardless of the new outcome.
	 */
	bpf_iter_scx_dsq_destroy(&it);
	bpf_rcu_read_unlock();
	return moved;
}

__hidden bool depth1_pull_node(u64 dsq_id, s32 cpu)
{
	return depth1_pull(dsq_id, cpu, &node_skip_pid, &nr_depth1_pulls);
}

__hidden bool depth1_pull_seat(u64 dsq_id, s32 cpu)
{
	return depth1_pull(dsq_id, cpu, &seat_skip_pid[(u32)cpu & (BABY_MAX_CPUS - 1)],
			   &nr_depth1_pulls_seat);
}

/*
 * Enqueue a task that has no idle CPU to run on.
 *
 * The deadline order is the scheduling decision: tasks are placed in the
 * node queue by their deadline, and the earliest one is dispatched next.
 */
void BPF_STRUCT_OPS(baby_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 prev_cpu = scx_bpf_task_cpu(p);
	bool is_running = scx_bpf_task_running(p);
	u64 backlog, slice, now = bpf_ktime_get_ns();

	if (!tctx)
		return;

	tctx->last_acc_at = now;

	if (tctx->yield_pending) {
		/*
		 * yield_task_fair() marks the deadline so the task is
		 * picked last in the current round; push it behind every
		 * task queued in this round.
		 */
		tctx->yield_pending = false;
		tctx->deadline = now + deadline_ns + deadline_ns +
				 task_prio_factor(p, tctx);
	} else if (!(enq_flags & (SCX_ENQ_LAST | SCX_ENQ_WAKEUP |
				  SCX_ENQ_REENQ))) {
		/*
		 * Migrated and freshly created tasks are renormalized to
		 * a fresh deadline. Woken tasks keep the deadline they
		 * had when they went to sleep, which is what makes
		 * interactive tasks run first when they wake up, and a
		 * task that stopped but stays runnable keeps its
		 * deadline too, like the original put_prev_entity():
		 * ops.stopping() has already renewed it if it was
		 * reached. A task pushed back by ops.cpu_release()
		 * keeps its deadline as well: it was already runnable
		 * and waiting, and a fresh one would move it behind
		 * arrivals that queued after it.
		 */
		tctx->deadline = calc_deadline(p, tctx, now);
	}

	backlog = node_backlog(prev_cpu);

	/*
	 * check_preempt_wakeup(): preempt the task running on the
	 * previous CPU if the waker has an earlier deadline and does not
	 * have a lower priority, unless the running task is protecting
	 * its CPU burst or the CPU already holds a warm backlog - with
	 * one waiting, the preempted victim would trade places with a
	 * queue that is about to run anyway, and under deep
	 * oversubscription the preemptions alone are churn. The
	 * preempted victim warm-seats behind its own successor further
	 * down, so a preemption is a same-CPU alternation, not a cold
	 * displacement. Interactive and foreground tasks only: a task
	 * that never wakes has no latency to protect.
	 */
	if ((enq_flags & SCX_ENQ_WAKEUP) &&
	    !scx_bpf_dsq_nr_queued(cpu2dsq(prev_cpu)) &&
	    (is_interactive(tctx) || is_foreground(tctx))) {
		struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(prev_cpu);

		if (curr && curr != p && !(curr->flags & PF_IDLE)) {
			struct task_ctx *cctx = try_lookup_task_ctx(curr);

			if (cctx &&
			    (s64)(tctx->deadline - cctx->deadline) < 0 &&
			    p->static_prio <= curr->static_prio &&
			    can_resched(cctx)) {
				scx_bpf_dsq_insert(p,
						   SCX_DSQ_LOCAL_ON | prev_cpu,
						   task_slice(tctx),
						   enq_flags | SCX_ENQ_PREEMPT);
				__sync_fetch_and_add(&nr_preemptions, 1);
				return;
			}
		}
	}

	/*
	 * Warm seat, gated on oversubscription (see balance.bpf.c).
	 */
	if (balance_try_warm_seat(p, tctx, enq_flags, backlog, now))
		return;

	/*
	 * The task did not go through ops.select_cpu(), or nothing was
	 * idle when it did: grab a confirmed idle CPU if the machine
	 * still has one, which is also how a task that stopped on a
	 * fully-loaded core spreads to a core that went idle since.
	 */
	if (try_direct_dispatch(p, tctx, prev_cpu, enq_flags, is_running))
		return;

	/*
	 * Nothing idle anywhere: take a place in the deadline order.
	 * On an oversubscribed machine hand out longer slices, since
	 * the task will rotate anyway and every extra rotation costs a
	 * full switch.
	 */
	slice = backlog_deep(backlog) && !tctx->tick_preempted
		? 4 * deadline_ns : task_slice(tctx);

	scx_bpf_dsq_insert_vtime(p, __COMPAT_scx_bpf_cpu_node(prev_cpu),
				 slice, tctx->deadline, enq_flags);
	stamp_wait(tctx, now, backlog, true);
	__sync_fetch_and_add(&nr_arr_shared, 1);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	/*
	 * The task is placed without the wake side effect of
	 * ops.select_cpu(), so wake the CPU that will pull it if idle.
	 */
	if (!is_running && !__COMPAT_is_enq_cpu_selected(enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Dispatch the earliest-deadline task to the CPU.
 */
void BPF_STRUCT_OPS(baby_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_ctx *tctx = prev ? try_lookup_task_ctx(prev) : NULL;
	bool need_running = prev && is_queued(prev);
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);

	census_sample(cpu);

	if (need_running && tctx) {
		/*
		 * pick_next_entity() keeps the current task only while
		 * its deadline still beats the earliest head of both
		 * queues; ties go to the waiter. ops.stopping() has
		 * already renewed the deadline once it was reached, so
		 * the task competes with the same deadline it would
		 * carry into the queue - a sticky run in absolute
		 * deadlines. No continuous-runtime cap is needed: a task
		 * that keeps running renews its deadline every slice,
		 * and any waiting task's deadline is older the longer it
		 * has waited, so a hog yields the moment something
		 * waits.
		 */
		struct task_struct *wq = __COMPAT_scx_bpf_dsq_peek(cpu2dsq(cpu));
		struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(node);
		u64 best_dl = ULLONG_MAX;

		if (wq && wq->scx.dsq_vtime < best_dl)
			best_dl = wq->scx.dsq_vtime;
		if (q && q->scx.dsq_vtime < best_dl)
			best_dl = q->scx.dsq_vtime;

		if ((s64)(tctx->deadline - best_dl) < 0) {
			scx_bpf_task_set_slice(prev, task_slice(tctx));
			__sync_fetch_and_add(&nr_sticky, 1);
			return;
		}
	}

	/*
	 * Serve the earliest-deadline head of the two queues, with the
	 * warm queue winning ties: its tasks continue the work this CPU
	 * already paid the cache for. The arbitration is what keeps the
	 * warm queues honest - a self-sustaining warm queue must not
	 * starve the overflow, so the shared queue wins whenever its
	 * head is strictly earlier.
	 */
	{
		struct task_struct *wq = __COMPAT_scx_bpf_dsq_peek(cpu2dsq(cpu));
		struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(node);
		u64 wq_dl = wq ? wq->scx.dsq_vtime : ULLONG_MAX;
		u64 g_dl = q ? q->scx.dsq_vtime : ULLONG_MAX;

		if (g_dl < wq_dl) {
			/*
			 * The node head's origin, read while q is fresh: the
			 * pull below may enter an RCU scope, and pointers
			 * peeked before it keep their marks only as long as
			 * nothing re-reads them after the unlock.
			 */
			s32 from = q ? scx_bpf_task_cpu(q) : -1;
			/*
			 * Serve a lat-cri waiter one deep behind the node
			 * head first: the overdue-batch head cannot be
			 * re-ordered past by any deadline offset (the lcomp
			 * verdict), so the inversion is resolved here, at
			 * consumption. Bounded: this head is bypassed once.
			 */
			bool d1 = depth1_pull_node(node, cpu);
			bool pulled = d1 || scx_bpf_dsq_move_to_local(node, 0);

			if (pulled) {
				/*
				 * The waiter this tick's claim was made for
				 * is served (or another head took its place
				 * - either way the next staggered tick may
				 * claim again). Plain store: a racing tick
				 * CAS against the cleared stamp just fails
				 * and retries next tick. The depth-1 pull is
				 * counted in nr_depth1_pulls; nr_pull_land
				 * stays for the in-turn pulls it attributes.
				 */
				node_preempt_at = 0;
				if (!d1)
					__sync_fetch_and_add(
						&nr_pull_land[cpu_dist(cpu,
									       from)],
						1);
			}

			if (pulled ||
			    scx_bpf_dsq_move_to_local(cpu2dsq(cpu), 0))
				return;
		} else {
			/*
			 * Same depth-1 service for the warm queue: wakes
			 * park in seats (99.9%), so this is where a wake
			 * sits behind a non-lat-cri head. One skip per
			 * head, per seat.
			 */
			if (depth1_pull_seat(cpu2dsq(cpu), cpu))
				return;
			if (scx_bpf_dsq_move_to_local(cpu2dsq(cpu), 0))
				return;
			if (scx_bpf_dsq_move_to_local(node, 0)) {
				node_preempt_at = 0;
				return;
			}
		}
	}

	if (need_running) {
		/*
		 * Nothing is queued anywhere: keep the task running, as
		 * the original does across its deadline renewals.
		 */
		scx_bpf_task_set_slice(prev,
				       tctx ? task_slice(tctx) : deadline_ns);
	} else {
		/*
		 * The CPU is going idle: drop its performance level so
		 * that it clocks down until the next task runs. The
		 * write happens once, when the level actually changes -
		 * see the comment on perf_req for why the idle path must
		 * not churn the request either.
		 */
		cpuperf_on_idle(cpu);
	}
}

/*
 * The kernel took the CPU away for an RT or deadline task and has just
 * given it back. Tasks dispatch() already moved into the local DSQ
 * waited out the whole lease where no other CPU could see them; push
 * them back through ops.enqueue(), which lands each one on an idle
 * core or in the deadline order, where the rest of the machine can
 * reach it.
 */
void BPF_STRUCT_OPS(baby_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	/*
	 * scx_bpf_reenqueue_local() returns a count on some kernels and
	 * is shimmed to void through the compat layer on others; call it
	 * as void, the re-enqueue happens either way.
	 */
	scx_bpf_reenqueue_local();
}

/*
 * Periodic tick: account bursts, advance the CPU performance ledger and
 * renew the deadline once reached. The tick does not preempt: the
 * rotation order is the deadline order now, and a tick-driven
 * preemption would only add switches that the queue order does not
 * ask for.
 */
void BPF_STRUCT_OPS(baby_tick, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	update_bursts(tctx, now);

	cpuperf_on_tick(p, now,
			is_heavy_proven(tctx) || is_foreground(tctx));

	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	/*
	 * The saturation deferred-preemption gate (comment at the top of
	 * the file). The victim's residency is measured from its
	 * ops.running() stamp; the waiter is recognized at the head of
	 * whichever queue this CPU would pull from next.
	 */
	if (!is_lat_cri(tctx)) {
		s32 cpu = scx_bpf_task_cpu(p);
		u64 ran_at = cpu_running_at[(u32)cpu & (BABY_MAX_CPUS - 1)];

		if (now - ran_at >= BABY_TICK_PREEMPT_PROTECT_NS) {
			struct task_struct *head;
			struct task_ctx *hctx;
			bool cri = false;
			bool warm = false;

			head = __COMPAT_scx_bpf_dsq_peek(cpu2dsq(cpu));
			hctx = head ? try_lookup_task_ctx(head) : NULL;
			if (hctx && is_lat_cri(hctx)) {
				cri = true;
				warm = true;
			}

			if (!cri) {
				head = __COMPAT_scx_bpf_dsq_peek(
					__COMPAT_scx_bpf_cpu_node(cpu));
				hctx = head ? try_lookup_task_ctx(head) : NULL;
				if (hctx && is_lat_cri(hctx)) {
					u64 last = node_preempt_at;

					if (now - last >=
					    BABY_TICK_PREEMPT_FALLBACK_NS &&
					    __sync_bool_compare_and_swap(
						    &node_preempt_at,
						    last, now))
						cri = true;
				}
			}

			if (cri) {
				p->scx.slice = 0;
				tctx->tick_preempted = true;
				if (warm)
					__sync_fetch_and_add(
						&nr_tick_preempts_warm, 1);
				else
					__sync_fetch_and_add(&nr_tick_preempts,
							     1);
			}
		}
	}
}

/*
 * The task has stopped running, either to sleep or because its time slice
 * expired.
 */
void BPF_STRUCT_OPS(baby_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now;

	__sync_fetch_and_sub(&nr_running, 1);

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();

	/*
	 * Whatever enqueues this task next is a re-entry of a task that
	 * has run - slice expiry, preemption, an RT-lease reenqueue -
	 * not the wake that started the burst: drop the wake bit so the
	 * wait instrument files the requeues as rotation. A task going
	 * to sleep re-sets the bit in ops.runnable() on its wake.
	 */
	tctx->arrival_is_wake = 0;

	update_bursts(tctx, now);

	class_boost_on_sleep(p, tctx, runnable, now);

	/*
	 * update_curr(): roll the deadline forward once reached.
	 */
	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	/*
	 * Update CPU runtime for the performance scaling.
	 */
	cpuperf_on_stopping(scx_bpf_task_cpu(p), now);
}

/*
 * The task has become runnable: track how often it wakes. Frequent
 * wakers with real work to do are foreground tasks.
 */
void BPF_STRUCT_OPS(baby_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	class_on_runnable(tctx, enq_flags, now);
}

/*
 * The task has started to run on a CPU.
 */
void BPF_STRUCT_OPS(baby_running, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now = bpf_ktime_get_ns();

	__sync_fetch_and_add(&nr_running, 1);

	/*
	 * The victim-residency stamp for the tick preemption gate, and
	 * the point where a task that was cut short stops carrying the
	 * preempted mark: the requeue has happened by now.
	 */
	cpu_running_at[scx_bpf_task_cpu(p) & (BABY_MAX_CPUS - 1)] = now;

	if (!tctx)
		return;

	tctx->tick_preempted = false;
	tctx->last_acc_at = now;

	charge_wait(tctx, now);

	/*
	 * Adjust the target CPU frequency before the task starts to run.
	 * A proven consumer or a foreground task saturates the core for
	 * as long as it runs, so give it the boost clock at once instead
	 * of re-climbing the smoothing after every sleep.
	 */
	cpuperf_on_running(scx_bpf_task_cpu(p),
			   is_heavy_proven(tctx) || is_foreground(tctx));

	/*
	 * set_next_entity(): a task picked with a deadline that is already
	 * behind gets a fresh one (only for tasks at nice >= 0, as in the
	 * original).
	 */
	if (PRIO_TO_NICE(p->static_prio) >= 0 && reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);
}

/*
 * sched_yield(): give up the CPU for the rest of this round, like the
 * original YIELD_MARK. With nothing else queued there is nothing to yield
 * to.
 */
bool BPF_STRUCT_OPS(baby_yield, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (!tctx)
		return false;

	if (!scx_bpf_dsq_nr_queued(cpu2dsq(scx_bpf_task_cpu(p))) &&
	    !scx_bpf_dsq_nr_queued(__COMPAT_scx_bpf_cpu_node(
					   scx_bpf_task_cpu(p))))
		return false;

	tctx->yield_pending = true;

	return true;
}

s32 BPF_STRUCT_OPS(baby_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	u64 now;

	tctx = init_task_ctx(p);
	if (!tctx)
		return -ENOMEM;

	now = bpf_ktime_get_ns();
	class_init_task(tctx, p, now);

	return 0;
}

/*
 * A warm queue that no CPU can serve - an RT lease outlived it, or
 * affinity moved under it - strands its tasks where the rest of the
 * machine cannot see them. A head that has waited this long is overdue
 * by far more than any warm wait can be; hand its queue back to the
 * shared one. The kernel watchdog force-unloads the whole scheduler
 * five seconds after a queued task stops being consumable, so this
 * has to fire well before that.
 */
#define STARVE_RESCUE_NS	1000000000ull

struct rescue_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct rescue_timer);
} rescue_timer SEC(".maps");

static int rescue_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu;
	int err;

	if (__COMPAT_has_generic_reenq()) {
		bpf_for(cpu, 0, nr_cpu_ids) {
			struct task_struct *head;
			struct task_ctx *hctx;
			u64 dsq = cpu2dsq(cpu);

			if (!scx_bpf_dsq_nr_queued(dsq))
				continue;

			head = __COMPAT_scx_bpf_dsq_peek(dsq);
			if (!head)
				continue;

			hctx = try_lookup_task_ctx(head);
			if (hctx && now - hctx->last_acc_at > STARVE_RESCUE_NS)
				scx_bpf_dsq_reenq___compat(dsq, 0);
		}
	}

	err = bpf_timer_start(timer, STARVE_RESCUE_NS, 0);
	if (err)
		scx_bpf_error("failed to re-arm the rescue timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(baby_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	s32 node, cpu, err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Create the warm queues and the per-node deadline-ordered
	 * queues.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu2dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d",
				      cpu2dsq(cpu), err);
			return err;
		}
	}

	bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		err = scx_bpf_create_dsq(node, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", node, err);
			return err;
		}
	}

	timer = bpf_map_lookup_elem(&rescue_timer, &key);
	if (!timer) {
		scx_bpf_error("failed to lookup rescue timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &rescue_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, rescue_timerfn);
	err = bpf_timer_start(timer, STARVE_RESCUE_NS, 0);
	if (err) {
		scx_bpf_error("failed to arm the rescue timer");
		return err;
	}

	/* Initialize the CPU frequency performance level. */
	cpuperf_init();

	return 0;
}

void BPF_STRUCT_OPS(baby_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC("syscall")
int enable_core_class(struct core_arg *input)
{
	struct bpf_cpumask *mask;
	int err;

	err = init_cpumask(&big_cpumask);
	if (err)
		return err;
	err = init_cpumask(&little_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = input->big ? big_cpumask : little_cpumask;
	if (mask)
		bpf_cpumask_set_cpu(input->cpu_id, mask);
	bpf_rcu_read_unlock();

	return 0;
}

SCX_OPS_DEFINE(baby_ops,
	       .select_cpu		= (void *)baby_select_cpu,
	       .enqueue			= (void *)baby_enqueue,
	       .dispatch		= (void *)baby_dispatch,
	       .tick			= (void *)baby_tick,
	       .running			= (void *)baby_running,
	       .runnable		= (void *)baby_runnable,
		       .stopping		= (void *)baby_stopping,
		       .yield			= (void *)baby_yield,
		       .cpu_release		= (void *)baby_cpu_release,
		       .init_task		= (void *)baby_init_task,
		       .init			= (void *)baby_init,
	       .exit			= (void *)baby_exit,
	       .timeout_ms		= 5000,
	       .name			= "baby");
