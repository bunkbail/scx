/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Task classification and deadline derivation. This module owns the
 * burst accounting behind the hog throttle, the wake-frequency EWMA
 * behind the foreground class, the class predicates, the per-class
 * slice and the nice-driven deadline shift.
 */
#include "baby.bpf.h"

/*
 * Deadline offset applied by the task's nice level: the original
 * prio_factor[40] table, rescaled to the configured deadline offset by
 * userspace and published as rodata. A nice value of 0 applies the
 * base offset; each step below 0 pulls the deadline earlier and each
 * step above 0 pushes it later, in the proportions of the original
 * table. Scaling is what keeps -d 500 (or -d 100) from producing a
 * deadline in the past when the table's -20 entry is applied.
 *
 * The table is padded to a power-of-two size and the index is masked, so
 * the verifier can always prove the array access in bounds.
 */
const volatile s64 prio_offset_ns[BABY_PRIO_OFFSET_NR];

/*
 * Return the task's effective nice level: its static nice level shifted by
 * the interactive boosts it has earned, floored at -20 (the original code
 * achieved this by decrementing the task's static priority on each early
 * sleep).
 */
static s32 task_nice(const struct task_struct *p, const struct task_ctx *tctx)
{
	s32 prio = p->static_prio;
	s32 nice;

	if (prio < MAX_RT_PRIO)
		prio = MAX_RT_PRIO;
	else if (prio > MAX_PRIO - 1)
		prio = MAX_PRIO - 1;

	nice = PRIO_TO_NICE(prio) - (s32)tctx->boost;
	if (nice < MIN_NICE)
		nice = MIN_NICE;

	return nice;
}

/*
 * Return the absolute deadline offset applied by the task's effective
 * nice level, including the base deadline.
 */
static __always_inline u64
task_deadline_offset(const struct task_struct *p, const struct task_ctx *tctx)
{
	s32 idx = (task_nice(p, tctx) + 20) & (BABY_PRIO_OFFSET_NR - 1);

	return (u64)prio_offset_ns[idx];
}

/*
 * Return the offset relative to the base deadline, for the yield push.
 */
__hidden s64 task_prio_factor(const struct task_struct *p,
		     const struct task_ctx *tctx)
{
	return (s64)task_deadline_offset(p, tctx) - (s64)deadline_ns;
}

/*
 * Return a fresh deadline for the task.
 */
__hidden u64
calc_deadline(const struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	return now + task_deadline_offset(p, tctx);
}

/*
 * Account @delta of runtime to the task's bursts, rolling the window over
 * once it exceeds TIME_PERIOD (original calc_bursts()).
 */
static void account_bursts(struct task_ctx *tctx, u64 delta, u64 now)
{
	if (now - tctx->start_time >= TIME_PERIOD) {
		tctx->start_time = now;
		tctx->prev_bursts = tctx->bursts;
		tctx->bursts = 0ULL;
	}

	tctx->bursts += delta;
}

/*
 * Account the runtime accumulated since the last call (original
 * update_curr() bookkeeping part).
 */
__hidden void update_bursts(struct task_ctx *tctx, u64 now)
{
	u64 delta = now - tctx->last_acc_at;

	if (delta) {
		account_bursts(tctx, delta, now);
		tctx->last_acc_at = now;
	}
}

/*
 * Return true if the current task may be preempted, false if it is a burst
 * hog (original can_resched_curr()).
 *
 * A task that used the CPU in the previous window cannot be preempted by
 * the next one until either the window is nearly over, the task's own
 * bursts caught up, or the task is close to completing its previous burst.
 */
__hidden bool can_resched(const struct task_ctx *tctx)
{
	u64 bursts = tctx->prev_bursts;
	u64 curr_bursts = tctx->bursts;

	if (!bursts)
		return true;

	if ((s64)(TIME_PERIOD - (bursts + RESCHED_DELTA)) <= 0)
		return true;

	if ((s64)(curr_bursts - bursts) >= 0)
		return true;

	if ((s64)(bursts - (curr_bursts + TO_COMPLETE)) > 0)
		return true;

	return false;
}

/*
 * A task is interactive when it used little CPU in its previous burst
 * window and has run long enough to complete one. Interactive and
 * foreground tasks are the eligible wakers for wakeup preemption; the
 * class bit is also stamped into the wait instrument. The boost counter
 * feeds the deadline, not the placement: almost every desktop task
 * sleeps early often enough to earn boost, so it cannot separate
 * latency-sensitive tasks from hogs.
 */
__hidden bool is_interactive(const struct task_ctx *tctx)
{
	return tctx->prev_bursts < TIME_PERIOD / 4 &&
	       tctx->prev_bursts + tctx->bursts > 0;
}

/*
 * The task has become runnable: stamp the class bits and the
 * arrival-type bit the wait instrument files waits under, then track
 * how often the task wakes. Frequent wakers with real work to do are
 * foreground tasks.
 */
__hidden void class_on_runnable(struct task_ctx *tctx, u64 enq_flags, u64 now)
{
	u64 delta = now - tctx->last_woke_at;

	/*
	 * The class bits the wait instrument files waits under. Stamped
	 * here, where the wake-path enqueue that follows sees this
	 * call's fresh EWMAs; a slice-expiry requeue reuses the verdict
	 * of the last runnable, which is one cycle old at worst.
	 */
	tctx->wait_cls = (is_interactive(tctx) ? 1 : 0) |
			 (is_foreground(tctx) ? 2 : 0);

	/*
	 * The arrival-type bit the wait instrument files waits under:
	 * SCX_ENQ_WAKEUP marks the handoff arrivals. Cleared in
	 * ops.stopping(), so a re-entry of a task that has run - slice
	 * expiry, preemption, an RT-lease reenqueue - files as rotation.
	 */
	tctx->arrival_is_wake = (enq_flags & SCX_ENQ_WAKEUP) ? 1 : 0;

	if (!delta)
		return;
	tctx->last_woke_at = now;

	/*
	 * Wakes per 100ms, smoothed (EWMA) and capped: a task that wakes
	 * every millisecond or faster saturates the counter. The peak
	 * hold remembers the historical maximum and bleeds only while
	 * the value sits above 64 (a shift of 6), so once a task has
	 * earned a wake rate past a class bar it keeps the credit: a
	 * frame-paced thread, throttled or not, does not fall out of
	 * its class in a slow patch.
	 */
	tctx->wakeup_freq = calc_avg(tctx->wakeup_freq,
				     (100 * NSEC_PER_MSEC) / delta);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, 100);

	if (tctx->wakeup_freq >= tctx->peak_freq)
		tctx->peak_freq = (u32)tctx->wakeup_freq;
	else
		tctx->peak_freq -= tctx->peak_freq >> 6;

	if (tctx->wake_samples < 255)
		tctx->wake_samples++;
}

/*
 * dequeue_entity(DEQUEUE_SLEEP): a task that goes to sleep before
 * consuming its deadline is treated as interactive and earns one
 * priority boost step.
 */
__hidden void class_boost_on_sleep(struct task_struct *p, struct task_ctx *tctx,
			  bool runnable, u64 now)
{
	/*
	 * Only ordinary fair tasks earn the boost: SCHED_IDLE and
	 * SCHED_BATCH asked for a lower share, and the boost is a fair
	 * scheduling construct, not a latency hint for every policy.
	 */
	if (!runnable && p->policy == BABY_SCHED_NORMAL &&
	    !reached_deadline(tctx, now) &&
	    task_nice(p, tctx) > MIN_NICE) {
		tctx->boost++;
		if (stats_enabled)
			__sync_fetch_and_add(&nr_boosts, 1);
	}
}

/*
 * set_next_entity(): a task picked with a deadline that is already behind
 * gets a fresh one, for tasks whose effective nice is zero or above.
 * The effective nice includes the earned boost; a boosted task is
 * already inside its shorter deadline and renewing it again at run
 * start would only push it behind the tasks the boost exists to beat.
 */
__hidden void class_on_running(struct task_struct *p, struct task_ctx *tctx,
			       u64 now)
{
	if (task_nice(p, tctx) >= 0 && reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);
}

/*
 * task_fork_fair(): start the task with a fresh deadline and an empty
 * burst history, except for a quarter of its parent's recent runtime.
 * The child of a busy task is likely busy too (a compiler, a build
 * worker), and without credit it would spend its first moments on a
 * little core. Children of light tasks inherit almost nothing. Tasks
 * that exist at attach have no parent context and seed nothing.
 */
__hidden void class_init_task(struct task_ctx *tctx, struct task_struct *p, u64 now)
{
	tctx->deadline = calc_deadline(p, tctx, now);
	tctx->start_time = now;
	tctx->last_acc_at = now;
	tctx->last_woke_at = now;
	tctx->last_cpu = -1;
	{
		struct task_struct *parent = p->real_parent;
		struct task_ctx *ptctx;

		ptctx = parent ? try_lookup_task_ctx(parent) : NULL;
		if (ptctx)
			tctx->bursts = (ptctx->prev_bursts +
					ptctx->bursts) >> 2;
	}
}
