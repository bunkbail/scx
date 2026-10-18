/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Copyright (C) 2026 bunkbail <nabildanial.93@gmail.com>
 *
 * Task classification and deadline derivation. This module owns the
 * burst accounting behind the hog throttle, the wake-frequency EWMA
 * behind the foreground class, the class predicates, the per-class
 * slice and the nice-driven deadline shift.
 */
#include "baby.bpf.h"

/*
 * Deadline shift applied by the task's nice level, carried over from the
 * original prio_factor[40] table. A nice value of 0 applies no shift; each
 * step below 0 pulls the deadline earlier (down to -1.08ms) and each step
 * above 0 pushes it later (up to +1.26ms).
 *
 * The table is padded to a power-of-two size and the index is masked, so
 * the verifier can always prove the array access in bounds.
 */
#define PRIO_FACTOR_NR		64

static const s64 prio_factor[PRIO_FACTOR_NR] = {
 /* -20 */  -1080000L,  -980000L,  -880000L,  -780000L,  -680000L,
 /* -15 */   -580000L,  -480000L,  -380000L,  -280000L,  -180000L,
 /* -10 */    -80000L,   -79000L,   -78000L,   -77000L,   -76000L,
 /*  -5 */    -75000L,   -74000L,   -73000L,   -72000L,   -71000L,
 /*   0 */         0L,  1080000L,  1090000L,  1100000L,  1110000L,
 /*   5 */   1120000L,  1130000L,  1140000L,  1150000L,  1160000L,
 /*  10 */   1170000L,  1180000L,  1190000L,  1200000L,  1210000L,
 /*  15 */   1220000L,  1230000L,  1240000L,  1250000L,  1260000L
};

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
 * Return the deadline offset applied by the task's nice level.
 */
__hidden s64 task_prio_factor(const struct task_struct *p,
		     const struct task_ctx *tctx)
{
	s32 idx = (task_nice(p, tctx) + 20) & (PRIO_FACTOR_NR - 1);

	return prio_factor[idx];
}

/*
 * Return a fresh deadline for the task.
 */
__hidden u64
calc_deadline(const struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	return now + deadline_ns + task_prio_factor(p, tctx);
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
 * class bit is also stamped into the wait instrument. The boost
 * counter feeds the deadline, not the placement: on a desktop almost
 * every task sleeps early often enough to earn boost, so it is
 * useless for telling latency-sensitive tasks apart from hogs.
 */
__hidden bool is_interactive(const struct task_ctx *tctx)
{
	return tctx->prev_bursts < TIME_PERIOD / 4 &&
	       tctx->prev_bursts + tctx->bursts > 0;
}

/*
 * A task is a proven CPU consumer once its recent burst accounting
 * holds more than a quarter of the period across the current and the
 * previous window. The accounting covers both windows so that a task
 * sharing a contended little core - and rolling windows with a fraction
 * of the core each - does not lose the status it has earned. On a
 * hybrid platform a proven consumer with no wake history pins a big
 * core while the wake path packs everything else onto the little tier
 * (docs/adr/0012); on a single-tier machine the sets are empty and the
 * predicate only shades the preemption and frequency decisions.
 */
__hidden bool is_heavy_proven(const struct task_ctx *tctx)
{
	return tctx->prev_bursts + tctx->bursts > TIME_PERIOD / 4;
}

/*
 * A task is foreground when it wakes frequently and does real work:
 * a browser renderer or an audio thread wakes dozens of times per
 * window with sizable bursts, a CPU hog never wakes, and a UI blip
 * barely uses the CPU. Foreground earns the fourfold slice, waker
 * eligibility, and precedence over the heavy pin in the compaction:
 * light workers cross the heavy bar with their mutex spins, and they
 * must keep the little-tier packing rather than spread onto the big
 * cores (docs/adr/0012).
 */
#define FOREGROUND_WAKE_FREQ	10

__hidden bool is_foreground(const struct task_ctx *tctx)
{
	return tctx->wake_samples >= 4 &&
	       tctx->peak_freq >= FOREGROUND_WAKE_FREQ &&
	       tctx->prev_bursts + tctx->bursts > TIME_PERIOD / 20;
}

/*
 * Per-class base slice. A latency-critical task always runs the base
 * quantum: in the dual-lane topology a longer slice buys it nothing its
 * lane order does not already give, and a resident the tick gate and
 * the wake-preempt both refuse to cut would hold the CPU for the whole
 * of it - the M1.1 game-cell lesson (a 4.72ms un-preemptible blocker,
 * p99 frame 4.98ms). The foreground fourfold slice is a bulk-class
 * privilege.
 */
__hidden u64 task_slice(const struct task_ctx *tctx)
{
	if (is_lat_cri(tctx))
		return deadline_ns;
	return is_foreground(tctx) ? 4 * deadline_ns : deadline_ns;
}

/*
 * A task is latency-critical when it wakes frequently enough to prove
 * it, whatever its burst size: game render threads, compositors and
 * submission workers wake per frame or per request, and under CPU
 * overcommit a game thread is heavy_proven too, so no burst bound can
 * gate this. Unlike is_foreground() there is no runtime floor either:
 * a task that wakes often but consumes almost nothing still has
	 * latency to protect. Wake-rate only: the foreground bit owns too
	 * small a share of the overcommit wait to gate
	 * anything on, and a task that never leaves runnable state (preempted,
	 * slice-expired) never re-runs this EWMA, so a preempted batch victim
	 * cannot pass as a waker here.
 */
__hidden bool is_lat_cri(const struct task_ctx *tctx)
{
	return tctx->wake_samples >= 4 &&
	       tctx->peak_freq >= FOREGROUND_WAKE_FREQ;
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
	if (!runnable && !reached_deadline(tctx, now) &&
	    task_nice(p, tctx) > MIN_NICE) {
		tctx->boost++;
		__sync_fetch_and_add(&nr_boosts, 1);
	}
}

/*
 * task_fork_fair(): start the task with a fresh deadline and an
 * empty burst history - except for a quarter of its parent's
 * recent runtime. The child of a busy task is likely busy too (a
 * compiler, a benchmark worker), and without credit it would
 * spend its first moments on a little core before the up-ramp
 * notices. Children of light tasks inherit almost nothing and
 * keep the compaction. This also covers the tasks that exist at
 * attach: their parents have no context yet and seed nothing.
 */
__hidden void class_init_task(struct task_ctx *tctx, struct task_struct *p, u64 now)
{
	tctx->deadline = calc_deadline(p, tctx, now);
	tctx->start_time = now;
	tctx->last_acc_at = now;
	tctx->last_woke_at = now;
	{
		struct task_struct *parent = p->real_parent;
		struct task_ctx *ptctx;

		ptctx = parent ? try_lookup_task_ctx(parent) : NULL;
		if (ptctx)
			tctx->bursts = (ptctx->prev_bursts +
					ptctx->bursts) >> 2;
	}
}
