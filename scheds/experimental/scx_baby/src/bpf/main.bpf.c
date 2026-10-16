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
	slice = backlog_deep(backlog) ? 4 * deadline_ns : task_slice(tctx);

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
			 * The pulled task is the node head; attribute the
			 * pull from where it last ran. The head is never
			 * NULL here: g_dl is finite only when q exists.
			 */
			s32 from = q ? scx_bpf_task_cpu(q) : -1;
			bool pulled = scx_bpf_dsq_move_to_local(node, 0);

			if (pulled)
				__sync_fetch_and_add(
					&nr_pull_land[cpu_dist(cpu, from)],
					1);
			if (pulled ||
			    scx_bpf_dsq_move_to_local(cpu2dsq(cpu), 0))
				return;
		} else {
			if (scx_bpf_dsq_move_to_local(cpu2dsq(cpu), 0) ||
			    scx_bpf_dsq_move_to_local(node, 0))
				return;
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

	if (!tctx)
		return;

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
