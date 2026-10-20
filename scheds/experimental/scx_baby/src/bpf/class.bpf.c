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
 * Return a fresh deadline for the task.
 */
__hidden u64
calc_deadline(const struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	return now + task_deadline_offset(p, tctx);
}

/*
 * Account @delta of runtime to the task's bursts after rolling the
 * window to @now (original calc_bursts()).
 */
static void account_bursts(struct task_ctx *tctx, u64 delta, u64 now)
{
	roll_burst_window(tctx, now);
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
 * A task is interactive when it used some CPU in its previous burst
 * window but stayed under a quarter of one, and its current window has
 * not already crossed the same bar. The lower bound matters: a task
 * that was idle for a full window (prev_bursts == 0) is not
 * interactive, and the upper bound on the current window stops a hog
 * that has just started its first window from passing as one.
 * Interactive and foreground tasks are the eligible wakers for wakeup
 * preemption; the class bit is also stamped into the wait instrument.
 * The boost counter feeds the deadline, not the placement: almost every
 * desktop task sleeps early often enough to earn boost, so it cannot
 * separate latency-sensitive tasks from hogs.
 */
__hidden bool is_interactive(const struct task_ctx *tctx)
{
	/*
	 * A task that has just been sampled as a waker keeps the class
	 * through a window whose previous burst is zero (a fresh task, or
	 * a task that slept or waited through a window). Without the
	 * wake-sample arm, a waker would fall out of the class for the
	 * first window after every long wait.
	 */
	return (tctx->prev_bursts > 0 ||
		tctx->wake_samples >= WAKE_SANE_MIN) &&
	       tctx->prev_bursts < TIME_PERIOD / 4 &&
	       tctx->bursts < TIME_PERIOD / 4;
}

/*
 * The task has become runnable: stamp the arrival-type bit the wait
 * instrument files waits under, then track how often the task wakes.
 * Frequent wakers with real work to do are foreground tasks.
 */
__hidden void class_on_runnable(struct task_ctx *tctx, u64 enq_flags, u64 now)
{
	tctx->arrival_is_wake = (enq_flags & SCX_ENQ_WAKEUP) ? 1 : 0;

	/*
	 * Only a true sleep-to-wake transition samples the wake rate.
	 * Fork activation, affinity changes and priority changes are not
	 * wakes; counting a fork as one was what made the first post-fork
	 * interval - a few microseconds - read as a saturated rate.
	 */
	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;

	/*
	 * A wake that skipped ops.select_cpu() still needs the burst
	 * window rolled before the tier decision below reads it.
	 */
	roll_burst_window(tctx, now);

	/*
	 * The first wake seeds the interval clock: there is no interval
	 * to measure yet, and the fork-time stamp is not one.
	 */
	if (!tctx->last_woke_at) {
		tctx->last_woke_at = now;
		return;
	}

	{
		u64 delta = now - tctx->last_woke_at;
		u64 raw;

		tctx->last_woke_at = now;

		if (!delta)
			return;

		/*
		 * A wake after a second or more of sleep is not a sample
		 * of a wake cadence: restart the average but keep the
		 * peak. A task that has earned a class keeps it across a
		 * long sleep; a task that has not starts its warmup over.
		 */
		if (delta >= NSEC_PER_SEC) {
			tctx->wakeup_freq = 0;
			/*
			 * Keep the warmup done when a peak is preserved:
			 * a task that has earned a class keeps it across
			 * a long sleep and must not be hidden behind a
			 * fresh four-sample warmup. A task with no peak
			 * starts the warmup over.
			 */
			if (!tctx->peak_freq)
				tctx->wake_samples = 0;
			tctx->peak_freq -= tctx->peak_freq >> 6;
			return;
		}

		/*
		 * Wakes per 100ms, capped before the average: clamping
		 * after the blend lets one very short interval jump the
		 * average from zero straight to the cap.
		 */
		raw = MIN((100 * NSEC_PER_MSEC) / delta, 100);

		/*
		 * Warm up at 50/50 and settle at the documented 3:1. Both
		 * blends round up: a truncating 3:1 blend has a fixed
		 * point below the sample, so a 100Hz waker's average
		 * converges to 9 and never reaches the bar of 10.
		 */
		if (tctx->wake_samples < WAKE_SANE_MIN) {
			tctx->wakeup_freq =
				(tctx->wakeup_freq + raw + 1) >> 1;
			tctx->wake_samples++;
		} else {
			tctx->wakeup_freq =
				(3 * tctx->wakeup_freq + raw + 3) >> 2;
		}

		/*
		 * The peak is the latency credit. Decay it on every
		 * sample (a shift below 64 is zero, so the hold stays
		 * above the bar once earned), then let it rise once the
		 * four-sample warmup is done. The warmup itself rejects
		 * a single spike: one 100 sample followed by three slow
		 * ones blends down to 7, and the peak cannot arm before
		 * the fourth sample.
		 */
		tctx->peak_freq -= tctx->peak_freq >> 6;
		if (tctx->wake_samples >= WAKE_SANE_MIN) {
			u32 cand = (u32)tctx->wakeup_freq;

			if (cand > tctx->peak_freq)
				tctx->peak_freq = cand;
		}
	}
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
	tctx->last_cpu = -1;

	/*
	 * No wake interval exists at fork. A zero stamp is the "first
	 * wake seeds the clock" sentinel in ops.runnable(); seeding it
	 * with @now makes the first post-fork interval a few
	 * microseconds and saturates the average.
	 */
	tctx->last_woke_at = 0;
	tctx->wakeup_freq = 0;
	tctx->peak_freq = 0;
	tctx->wake_samples = 0;
	tctx->prev_bursts = 0;
	{
		struct task_struct *parent = p->real_parent;
		struct task_ctx *ptctx;

		ptctx = parent ? try_lookup_task_ctx(parent) : NULL;
		if (ptctx)
			tctx->bursts = (ptctx->prev_bursts +
					ptctx->bursts) >> 2;
	}
}
