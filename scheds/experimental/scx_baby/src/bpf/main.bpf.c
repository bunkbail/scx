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
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Every CPU owns a deadline-ordered queue, mirroring the original
 * per-CPU run lists. The base offset keeps the ids clear of the
 * kernel-reserved DSQ ids.
 */
#define BABY_CPU_DSQ_BASE	100ULL

static u64 nr_cpu_ids;
static u32 rr_cursor;

static u64 cpu2dsq(s32 cpu)
{
	return BABY_CPU_DSQ_BASE + cpu;
}

/*
 * Scheduling constants, carried over from the original bs.c.
 *
 * @TIME_PERIOD: window over which a task's runtime (bursts) is accounted.
 * @TO_COMPLETE: slack given to a task to complete its previous window.
 * @DEADLINE_NS: default deadline offset assigned to every task.
 */
#define TIME_PERIOD		(200ULL * NSEC_PER_MSEC)
#define TO_COMPLETE		(5ULL * NSEC_PER_MSEC)
#define RESCHED_DELTA		(25ULL * NSEC_PER_MSEC)
#define MIN_DEADLINE_NS		590000ULL
#define MIN_NICE		(-20)
#define MAX_NICE		19
#define MAX_RT_PRIO		100
#define MAX_PRIO		(MAX_RT_PRIO + 40)
#define PRIO_TO_NICE(prio)	((prio) - (MAX_RT_PRIO + 20))

/*
 * Default deadline offset (1.18ms, the original DEADLINE_NS).
 */
const volatile u64 deadline_ns = 1180000ULL;

 /* Report additional debugging information */
const volatile bool debug;

#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

/*
 * Scheduling statistics.
 */
volatile u64 nr_running, nr_direct_dispatches, nr_shared_dispatches;
volatile u64 nr_preemptions, nr_boosts;
volatile u64 nr_claims, nr_claim_misses;

/*
 * Exit information.
 */
UEI_DEFINE(uei);

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
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored. -1 selects the automatic
 * utilization-driven level; -2 leaves the platform governor entirely
 * alone.
 */
volatile s64 cpuperf_lvl;

/* True when the platform governor is left alone entirely. */
static bool cpuperf_offline(void)
{
	return cpuperf_lvl < -1;
}

/*
 * Thresholds for applying hysteresis to the CPU performance scaling:
 *  - below the low threshold, reduce performance to half
 *  - above the high threshold, raise performance to maximum
 *
 * Values between the two thresholds retain the smoothed performance level.
 */
#define CPUPERF_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUPERF_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 last_running;
	u64 tot_runtime;
	u64 prev_runtime;
	u64 perf_lvl;

	/*
	 * The performance level last requested from the platform.
	 * Redundant requests are suppressed: on an HWP platform every
	 * cpufreq update is also the hook that expires the intel_pstate
	 * iowait boost (it decays when an update arrives more than its
	 * hold time after the previous one), so a scheduler that writes
	 * the same level over and over keeps tearing down the boost its
	 * workload earned. Requesting a level only when it changed is
	 * what lets the boost latch for the duration of a burst.
	 */
	u64 perf_req;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

static struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;

	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Per-task local storage.
 *
 * This is the counterpart of the original struct bs_node, plus the boost
 * counter that emulates the original's static priority decrements.
 */
struct task_ctx {
	/*
	 * Absolute timestamp by which the task would like to run.
	 */
	u64 deadline;

	/*
	 * Runtime accumulated within the current and the previous
	 * TIME_PERIOD window (bursts), and when the current window began.
	 */
	u64 bursts;
	u64 prev_bursts;
	u64 start_time;

	/*
	 * Timestamp of the last burst accounting (while the task runs).
	 */
	u64 last_acc_at;

	/*
	 * Timestamp of when the task last started to run, used to honor
	 * the MIN_DEADLINE_NS floor before preempting it.
	 */
	u64 last_run_at;

	/*
	 * Set by ops.enqueue() to the CPU whose queue the task was
	 * placed in. The per-CPU queues are sticky, so this is where the
	 * task will run next; ops.dispatch() re-arms the running task
	 * only when this still matches the CPU it is running on.
	 */
	s32 cpu;

	/*
	 * Wake frequency: an EWMA of how often the task wakes, in wakes
	 * per 100ms (flash's update_freq()). High values mark foreground
	 * workers: tasks that wake constantly with real work to do, as
	 * opposed to CPU hogs that never wake and blips that use almost
	 * no CPU.
	 */
	u64 wakeup_freq;
	u64 last_woke_at;

	/*
	 * Peak hold of wakeup_freq with a slow leak (1/64 per wake): a
	 * task throttled by CPU overcommit keeps its high-wake credit
	 * for a long time, so the foreground class does not collapse
	 * exactly when it matters, while a task whose nature changed
	 * re-classifies within a few seconds.
	 */
	u32 peak_freq;

	/*
	 * Completed wake-frequency samples: foreground status requires a
	 * few samples so that the EWMA of a freshly forked task (whose
	 * first wakeup interval is tiny) cannot read as high frequency
	 * from one sample.
	 */
	u32 wake_samples;

	/*
	 * Number of interactive priority boosts the task has earned by
	 * sleeping before consuming its deadline.
	 */
	u32 boost;

	/*
	 * Set by sched_yield: the task is pushed behind every task queued
	 * in the current round, like the original YIELD_MARK.
	 */
	bool yield_pending;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

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
static s64 task_prio_factor(const struct task_struct *p,
			    const struct task_ctx *tctx)
{
	s32 idx = (task_nice(p, tctx) + 20) & (PRIO_FACTOR_NR - 1);

	return prio_factor[idx];
}

/*
 * Return a fresh deadline for the task.
 */
static u64
calc_deadline(const struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	return now + deadline_ns + task_prio_factor(p, tctx);
}

/*
 * Return true if the task's deadline is behind @now.
 */
static bool reached_deadline(const struct task_ctx *tctx, u64 now)
{
	return (s64)(tctx->deadline - now) <= 0;
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
static void update_bursts(struct task_ctx *tctx, u64 now)
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
static bool can_resched(const struct task_ctx *tctx)
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
 * Big and little CPU sets, built from the platform's core types by
 * userspace at startup. Everything prefers an idle little core so that
 * the big cores stay parked; interactive and foreground tasks fall back
 * to an idle big one, and a proven CPU consumer claims one when no
 * little core is free and on its slice-expiry requeues.
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
 * A task is interactive when it used little CPU in its previous burst
 * window and has run long enough to complete one: fresh tasks start on
 * the little cores and only move to a big core once their history shows
 * light usage, so that a spawn that turns into a CPU hog never touches
 * a big core. The boost counter feeds the deadline, not the placement:
 * on a desktop almost every task sleeps early often enough to earn
 * boost, so it is useless for telling latency-sensitive tasks apart
 * from hogs.
 */
static bool is_interactive(const struct task_ctx *tctx)
{
	return tctx->prev_bursts < TIME_PERIOD / 4 &&
	       tctx->prev_bursts + tctx->bursts > 0;
}

/*
 * A task is a proven CPU consumer once its recent burst accounting
 * holds more than a quarter of the period across the current and the
 * previous window. The accounting covers both windows so that a task
 * sharing a contended little core - and rolling windows with a fraction
 * of the core each - does not lose the status it has earned. The
 * history means the task will keep running for a while, so the fast
 * core finishes the work sooner and returns to sleep (race to idle),
 * while a blip with no history stays stacked on the little cores.
 */
static bool is_heavy_proven(const struct task_ctx *tctx)
{
	return tctx->prev_bursts + tctx->bursts > TIME_PERIOD / 4;
}

/*
 * A task is foreground when it wakes frequently and does real work:
 * a browser renderer or an audio thread wakes dozens of times per
 * window with sizable bursts, a CPU hog never wakes, and a UI blip
 * barely uses the CPU. Foreground tasks deserve the fast cores even
 * when their bursts are too large for the interactive class, which is
 * what breaks them under heavy overcommit otherwise.
 */
#define FOREGROUND_WAKE_FREQ	10

static bool is_foreground(const struct task_ctx *tctx)
{
	return tctx->wake_samples >= 4 &&
	       tctx->peak_freq >= FOREGROUND_WAKE_FREQ &&
	       tctx->prev_bursts + tctx->bursts > TIME_PERIOD / 20;
}

/*
 * Foreground tasks get a longer slice: their requests are memory-bound
 * and interleaving them with hog slices on a busy core multiplies the
 * wall time of each request.
 */
static u64 task_slice(const struct task_ctx *tctx)
{
	return is_foreground(tctx) ? 4 * deadline_ns : deadline_ns;
}

/*
 * Return the little CPUs round robin, spreading tasks that must wait
 * for a little core across the little queues.
 */
static s32 pick_rr_little(void)
{
	struct bpf_cpumask *little = little_cpumask;
	s32 cpu, picked = -1;
	u32 i, n, seen = 0;

	if (!little)
		return -1;

	bpf_rcu_read_lock();
	n = bpf_cpumask_weight(cast_mask(little));
	if (n) {
		u32 want = __sync_fetch_and_add(&rr_cursor, 1) % n;

		bpf_for(i, 0, nr_cpu_ids) {
			if (!bpf_cpumask_test_cpu(i, cast_mask(little)))
				continue;
			if (seen == want) {
				picked = i;
				break;
			}
			seen++;
		}
	}
	bpf_rcu_read_unlock();

	return picked;
}

/*
 * Return true if @cpu is one of the big cores.
 */
static bool is_big_cpu(s32 cpu);

/*
 * Return an idle CPU from @pref that @p is allowed to run on, or a
 * negative value if there is none. With @claim the CPU is taken out of
 * the idle set for a direct dispatch; without it the CPU stays idle,
 * for a caller that will only re-queue the task onto it.
 */
static s32 pick_idle_cpu_pref(struct task_struct *p,
			      const struct bpf_cpumask *pref, bool claim)
{
	const struct cpumask *idle;
	s32 cpu, picked = -1;
	u64 i;

	if (!pref)
		return -1;

	/*
	 * Take the lowest-numbered idle CPU of the preferred class:
	 * wakeups stack onto the same cores, so that at idle only a
	 * handful of cores are ever woken instead of the whole class
	 * rotating. The vtime order of the queues keeps interactive
	 * tasks at the front when a core does fill up.
	 */
	bpf_rcu_read_lock();
	idle = scx_bpf_get_idle_cpumask();
	bpf_for(i, 0, nr_cpu_ids) {
		cpu = i;
		if (!bpf_cpumask_test_cpu(cpu, cast_mask(pref)) ||
		    !bpf_cpumask_test_cpu(cpu, idle) ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (!claim || scx_bpf_test_and_clear_cpu_idle(cpu))
			picked = cpu;
		break;
	}
	scx_bpf_put_cpumask(idle);
	bpf_rcu_read_unlock();

	return picked;
}

/*
 * Pick a target CPU for a task which is being woken up: prefer an idle
 * big CPU for interactive tasks and an idle little CPU for the rest,
 * falling back to the built-in idle-CPU selection.
 */
s32 BPF_STRUCT_OPS(baby_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	bool is_idle = false;
	s32 cpu;

	/*
	 * Interactive tasks prefer the little cores and then the big
	 * ones, always taking the lowest-numbered idle CPU so that
	 * wakeups stack onto few cores. Everything else prefers the
	 * little cores too. A big core is woken only by a task with a
	 * proven light usage history once the little cores are all busy.
	 */
	if (tctx && (is_interactive(tctx) || is_foreground(tctx))) {
		bpf_rcu_read_lock();
		cpu = pick_idle_cpu_pref(p, little_cpumask, true);
		if (cpu < 0)
			cpu = pick_idle_cpu_pref(p, big_cpumask, true);
		bpf_rcu_read_unlock();
		if (cpu >= 0) {
			tctx->cpu = cpu;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(tctx), 0);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return cpu;
		}
	} else if (tctx) {
		bpf_rcu_read_lock();
		cpu = pick_idle_cpu_pref(p, little_cpumask, true);
		if (cpu < 0 && is_heavy_proven(tctx))
			cpu = pick_idle_cpu_pref(p, big_cpumask, true);
		bpf_rcu_read_unlock();
		if (cpu >= 0) {
			tctx->cpu = cpu;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(tctx), 0);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return cpu;
		}

		/*
		 * No idle little CPU: keep the task off the big cores
		 * by queueing it round robin on a little queue, unless
		 * the big cores are busy too (the system is then
		 * saturated and every core must work). Queueing behind a
		 * busy little core keeps the big cores free to sleep.
		 * A proven consumer skips this: with no idle little core
		 * anywhere it already claimed one of the idle big cores
		 * above, so this is only reached when the bigs are busy
		 * as well, and then the task waits where it ran.
		 */
		{
			bool idle_big = false;
			const struct cpumask *idle;
			s32 lc;

			bpf_rcu_read_lock();
			idle = scx_bpf_get_idle_cpumask();
			idle_big = big_cpumask &&
				bpf_cpumask_intersects(cast_mask(big_cpumask),
						       idle);
			scx_bpf_put_cpumask(idle);
			bpf_rcu_read_unlock();

			lc = idle_big && !is_heavy_proven(tctx) ?
			     pick_rr_little() : -1;
			if (lc >= 0 && bpf_cpumask_test_cpu(lc, p->cpus_ptr)) {
				tctx->cpu = lc;
				return lc;
			}
			tctx->cpu = prev_cpu;
			return prev_cpu;
		}
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		if (tctx)
			tctx->cpu = cpu;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, tctx ? task_slice(tctx) : deadline_ns, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}

	return cpu;
}

/*
 * Return the big core whose running task has the latest deadline among
 * the ones a foreground task may preempt, or -1 if there is none.
 * Foreground work is memory-bound and crawls on the low-power overflow
 * cores, so given no idle fast core it should still steal one.
 */
static s32 pick_foreground_target(struct task_struct *p,
				  struct task_ctx *tctx)
{
	struct task_struct *curr;
	struct task_ctx *cctx;
	s32 cpu, picked = -1;
	u64 i, best_dl = 0;

	bpf_for(i, 0, nr_cpu_ids) {
		cpu = i;

		if (!is_big_cpu(cpu))
			continue;

		curr = __COMPAT_scx_bpf_cpu_curr(cpu);
		if (!curr || curr == p || (curr->flags & PF_IDLE))
			continue;

		cctx = try_lookup_task_ctx(curr);
		if (!cctx || !can_resched(cctx))
			continue;

		if ((s64)(tctx->deadline - cctx->deadline) >= 0 ||
		    p->static_prio > curr->static_prio)
			continue;

		if (picked == -1 || (s64)(cctx->deadline - best_dl) > 0) {
			best_dl = cctx->deadline;
			picked = cpu;
		}
	}

	return picked;
}

/*
 * Enqueue a task that has no idle CPU to run on.
 *
 * The deadline order is the scheduling decision: tasks are placed in the
 * global queue by their deadline, and the earliest one is dispatched next.
 */
void BPF_STRUCT_OPS(baby_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 prev_cpu = scx_bpf_task_cpu(p);
	s32 target, cpu;
	u64 slice, now = bpf_ktime_get_ns();

	if (!tctx)
		return;

	tctx->last_acc_at = now;

	/*
	 * A heavy task that stopped on a big core gives it back when a
	 * little core is idle: the per-CPU queues are sticky, so without
	 * this the task would never leave the big core on its own.
	 */
	target = prev_cpu;

	/*
	 * ops.dispatch() may have just decided a still-runnable task's
	 * next core (the big-core claim): requeue it there verbatim and
	 * stay out of the placement below, none of which applies without
	 * a wake.
	 */
	if ((enq_flags & SCX_ENQ_LAST) && tctx->cpu >= 0 &&
	    tctx->cpu != prev_cpu)
		target = tctx->cpu;

	if (tctx->yield_pending) {
		/*
		 * yield_task_fair() marks the deadline so the task is
		 * picked last in the current round; push it behind every
		 * task queued in this round.
		 */
		tctx->yield_pending = false;
		tctx->deadline = now + deadline_ns + deadline_ns +
				 task_prio_factor(p, tctx);
	} else if (!(enq_flags & SCX_ENQ_LAST) &&
		   !(enq_flags & SCX_ENQ_WAKEUP)) {
		/*
		 * Migrated and freshly created tasks are renormalized to
		 * a fresh deadline. Woken tasks keep the deadline they
		 * had when they went to sleep, which is what makes
		 * interactive tasks run first when they wake up, and a
		 * task that stopped but stays runnable keeps its
		 * deadline too, like the original put_prev_entity():
		 * ops.stopping() has already renewed it if it was
		 * reached.
		 */
		tctx->deadline = calc_deadline(p, tctx, now);
	}

	/*
	 * Keep non-proven tasks off the big cores: redirect them to an
	 * idle little core, or round robin over the little queues while
	 * the big cores are idle. Without this a task that entered the
	 * scheduler on a big core (at attach, or forked on one) would
	 * stay there forever, since a CPU-bound task never wakes up to
	 * be re-placed. A proven consumer keeps its big core instead:
	 * the claim below would only win it straight back, and yanking a
	 * spinning task between core classes every slice is pure churn.
	 */
	if (!is_interactive(tctx) && !is_foreground(tctx) &&
	    !is_heavy_proven(tctx) && is_big_cpu(target)) {
		cpu = pick_idle_cpu_pref(p, little_cpumask, true);
		if (cpu < 0) {
			const struct cpumask *idle;
			bool idle_big = false;

			bpf_rcu_read_lock();
			idle = scx_bpf_get_idle_cpumask();
			idle_big = big_cpumask &&
				bpf_cpumask_intersects(cast_mask(big_cpumask),
						       idle);
			scx_bpf_put_cpumask(idle);
			bpf_rcu_read_unlock();

			if (idle_big)
				cpu = pick_rr_little();
		}
		if (cpu >= 0 && bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			target = cpu;
	}

	/*
	 * Saturation rebalance: with no idle CPU anywhere, a task that
	 * returns to a deep home queue waits out the whole rotation, and
	 * the idle steal cannot fix that, because a stolen task comes
	 * back to its home queue on the next wake. Move a wakeup whose
	 * home queue holds at least two tasks to the allowed queue with
	 * the fewest waiting ones when that queue is at least two
	 * shallower, so wake-driven load spreads over the rotation
	 * instead of piling up on the cores the tasks happened to land
	 * on while the machine was still idle. The lowest CPU wins ties,
	 * which keeps the wakeups stacked.
	 */
	if ((enq_flags & SCX_ENQ_WAKEUP) && !scx_bpf_task_running(p) &&
	    scx_bpf_dsq_nr_queued(cpu2dsq(target)) >= 2) {
		s32 best = -1;
		u64 best_nr = 0, i;

		bpf_for(i, 0, nr_cpu_ids) {
			u64 nr;

			if (!bpf_cpumask_test_cpu(i, p->cpus_ptr))
				continue;

			nr = scx_bpf_dsq_nr_queued(cpu2dsq(i));
			if (best < 0 || nr < best_nr) {
				best = i;
				best_nr = nr;
			}
		}

		if (best >= 0 && best_nr + 2 <=
		    scx_bpf_dsq_nr_queued(cpu2dsq(target))) {
			target = best;
			/*
			 * The shallowest queue can belong to an idle CPU,
			 * and this is the wake path: ops.select_cpu owns
			 * the placement and the insert below wakes nobody,
			 * so kick the target or the task waits for the
			 * next unrelated wake on that CPU. A busy CPU
			 * ignores the idle kick.
			 */
			scx_bpf_kick_cpu(best, SCX_KICK_IDLE);
		}
	}

	if ((enq_flags & SCX_ENQ_WAKEUP) &&
	    (is_interactive(tctx) || is_foreground(tctx))) {
		/*
		 * check_preempt_wakeup(): preempt the task running on the
		 * target CPU if the waker has an earlier deadline and does
		 * not have a lower priority, unless the running task is
		 * protecting its CPU burst. The waker is placed directly
		 * in front of the victim on the local DSQ, skipping the
		 * global deadline order like the original resched_curr().
		 * Non-interactive tasks skip this and take their place in
		 * the little-core queues instead. Foreground workers
		 * preempt on a big core even when they last ran elsewhere:
		 * their work is memory-bound and crawls on the low-power
		 * overflow cores.
		 */
		struct task_struct *curr;
		struct task_ctx *cctx;
		s32 target_cpu = prev_cpu;

		if (is_foreground(tctx) && !is_big_cpu(target_cpu)) {
			s32 big_cpu = pick_foreground_target(p, tctx);

			if (big_cpu >= 0)
				target_cpu = big_cpu;
		}

		curr = __COMPAT_scx_bpf_cpu_curr(target_cpu);

		if (curr && curr != p && !(curr->flags & PF_IDLE)) {
			cctx = try_lookup_task_ctx(curr);
			if (cctx &&
			    (s64)(tctx->deadline - cctx->deadline) < 0 &&
			    p->static_prio <= curr->static_prio &&
			    can_resched(cctx) &&
			    !scx_bpf_dsq_nr_queued(cpu2dsq(target_cpu))) {
				tctx->cpu = target_cpu;
				scx_bpf_dsq_insert(p,
						   SCX_DSQ_LOCAL_ON | target_cpu,
						   task_slice(tctx),
						   enq_flags | SCX_ENQ_PREEMPT);
				__sync_fetch_and_add(&nr_preemptions, 1);
				return;
			}
		}
	} else if (!scx_bpf_task_running(p) &&
		   !__COMPAT_is_enq_cpu_selected(enq_flags)) {
		/*
		 * The task is placed without the wakeup side effect of
		 * ops.select_cpu(), so wake the target CPU if it is idle.
		 */
		scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
	}

	tctx->cpu = target;

	/*
	 * Saturation slice: on a queue two or more deep the task will
	 * rotate anyway, and every extra rotation costs a full switch,
	 * so grant twice the slice while the queue stays deep. A queue
	 * of zero or one keeps the interactive slice.
	 */
	if (scx_bpf_dsq_nr_queued(cpu2dsq(target)) >= 2)
		slice = 2 * deadline_ns;
	else
		slice = task_slice(tctx);

	scx_bpf_dsq_insert_vtime(p, cpu2dsq(target), slice,
				 tctx->deadline, enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);
}

/*
 * Return true if @cpu is one of the big cores.
 */
static bool is_big_cpu(s32 cpu)
{
	bool big = false;

	bpf_rcu_read_lock();
	big = big_cpumask &&
	      bpf_cpumask_test_cpu(cpu, cast_mask(big_cpumask));
	bpf_rcu_read_unlock();

	return big;
}

/*
 * Dispatch the earliest-deadline task to the CPU.
 */
void BPF_STRUCT_OPS(baby_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_ctx *tctx = prev ? try_lookup_task_ctx(prev) : NULL;
	bool need_running = prev && is_queued(prev);

	if (need_running && tctx && tctx->cpu == cpu && !is_big_cpu(cpu) &&
	    is_heavy_proven(tctx)) {
		/*
		 * Big-core claim: a proven consumer being replenished on
		 * a little core hands itself to an idle big core instead.
		 * A CPU-bound task never wakes again after its initial
		 * placement, so the replenish is the only event that can
		 * still move it - and a task that is never descheduled
		 * outruns the continuous-runtime cap below within
		 * moments, so the claim has to sit ahead of it, on every
		 * replenish. The pick leaves the idle bit alone: the
		 * task starts running there once the kicked core pulls
		 * it in, and a losing race just means it queues behind
		 * the winner and retries on a later expiry.
		 *
		 * Handing the task away does not end the dispatch: a
		 * user queue insert wakes nobody, and the wake path
		 * never kicks its target CPU, so returning here would
		 * idle the CPU on top of its own queued backlog until
		 * an unrelated wake lands on it. Fall through and
		 * consume the queue - the keep-running check below no
		 * longer matches, the task is homed on the big core
		 * now.
		 */
		s32 big;

		__sync_fetch_and_add(&nr_claims, 1);

		bpf_rcu_read_lock();
		big = pick_idle_cpu_pref(prev, big_cpumask, false);
		bpf_rcu_read_unlock();

		if (big >= 0 && bpf_cpumask_test_cpu(big, prev->cpus_ptr)) {
			tctx->cpu = big;
			scx_bpf_dsq_insert_vtime(prev, cpu2dsq(big),
						 task_slice(tctx),
						 tctx->deadline, 0);
			scx_bpf_kick_cpu(big, SCX_KICK_IDLE);
		}

		__sync_fetch_and_add(&nr_claim_misses, 1);
	}

	if (need_running && tctx) {
		/*
		 * pick_next_entity() keeps the current task only when its
		 * deadline is strictly earlier than the queued one, and
		 * only while it actually runs where it is queued: ops-
		 * enqueue() may have moved the task to another CPU's
		 * queue, and then it must stop here and resume there.
		 *
		 * The queued task always wins when the queue is non-
		 * empty: the core interleaves the running task and the
		 * queued one fairly through the local queue FIFO, so a
		 * heavy task can never starve a waiting one. The
		 * continuous runtime cap is a second line of defense for
		 * anything this check cannot see.
		 */
		struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(cpu2dsq(cpu));
		u64 ran = bpf_ktime_get_ns() - tctx->last_run_at;

		if (tctx->cpu == cpu && !q && ran < 10 * deadline_ns) {
			scx_bpf_task_set_slice(prev, task_slice(tctx));
			return;
		}
	}

	if (scx_bpf_dsq_move_to_local(cpu2dsq(cpu), 0))
		return;

	/*
	 * newidle_balance(): the local queue is empty, pull a task from
	 * the most-loaded queue that can spare one. Little CPUs steal
	 * freely: an idle big CPU stays idle so that it can sleep, while
	 * a stealing little CPU also drains stray tasks off the big
	 * cores. An idle big CPU steals only a proven consumer, and only
	 * when one waits in a queue two or more deep: a queued heavy
	 * backlog while a fast core sleeps is throughput left on the
	 * table, but the gate keeps desktop blips from ever waking a
	 * big core.
	 */
	if (!is_big_cpu(cpu)) {
		u64 max_nr = 1;
		s32 src = -1;
		u64 i;

		bpf_for(i, 0, nr_cpu_ids) {
			u64 nr;

			if ((s32)i == cpu)
				continue;

			nr = scx_bpf_dsq_nr_queued(cpu2dsq(i));
			if (nr > max_nr) {
				max_nr = nr;
				src = i;
			}
		}

		if (src >= 0 && scx_bpf_dsq_move_to_local(cpu2dsq(src), 0))
			return;
	} else {
		u64 max_nr = 1;
		s32 src = -1;
		u64 i;

		bpf_for(i, 0, nr_cpu_ids) {
			struct task_struct *head;
			struct task_ctx *hctx;
			u64 nr;

			if ((s32)i == cpu)
				continue;

			nr = scx_bpf_dsq_nr_queued(cpu2dsq(i));
			if (nr <= max_nr)
				continue;

			head = __COMPAT_scx_bpf_dsq_peek(cpu2dsq(i));
			if (!head)
				continue;
			hctx = try_lookup_task_ctx(head);
			if (!hctx || !is_heavy_proven(hctx))
				continue;

			max_nr = nr;
			src = i;
		}

		if (src >= 0 && scx_bpf_dsq_move_to_local(cpu2dsq(src), 0))
			return;
	}

	if (need_running && tctx && tctx->cpu == cpu) {
		/*
		 * Nothing else is queued where the task is queued: keep
		 * it running, as the original does across its deadline
		 * renewals.
		 */
		scx_bpf_task_set_slice(prev, task_slice(tctx));
	} else if (!need_running && cpuperf_lvl < 0) {
		/*
		 * The CPU is going idle: drop its performance level so
		 * that it clocks down until the next task runs. The
		 * write happens once, when the level actually changes -
		 * see the comment on perf_req for why the idle path must
		 * not churn the request either.
		 */
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);

		if (cctx && cctx->perf_req) {
			scx_bpf_cpuperf_set(cpu, 0);
			cctx->perf_req = 0;
		}
	}
}

/*
 * Periodic tick: account bursts, renew the deadline once reached and
 * preempt the current task for an earlier-deadline one, unless it is a
 * burst hog (original entity_tick() / hrtick handling).
 */
static void update_cpuperf(struct cpu_ctx *cctx, s32 cpu, bool max_floor);

void BPF_STRUCT_OPS(baby_tick, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	struct task_struct *q;
	u64 now;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	update_bursts(tctx, now);

	/*
	 * The performance floor must not depend on ops.running() alone:
	 * a never-descheduling task fires it once, the idle drop has set
	 * the floor to zero, and nothing ever refreshes it - the core
	 * then sits at its base clock for as long as the task runs.
	 * Advance the CPU runtime ledger every tick and re-evaluate the
	 * floor from it, so sustained work boosts within a couple of
	 * ticks and the ledger stays consistent with ops.stopping(),
	 * which charges the time since the last advance.
	 */
	if (cpuperf_lvl < 0) {
		struct cpu_ctx *cctx;
		s32 cpu = scx_bpf_task_cpu(p);

		cctx = try_lookup_cpu_ctx(cpu);
		if (cctx) {
			cctx->tot_runtime += now - cctx->last_running;
			cctx->last_running = now;
			update_cpuperf(cctx, cpu,
				       is_heavy_proven(tctx) ||
				       is_foreground(tctx));
		}
	}

	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	if (!can_resched(tctx))
		return;

	/*
	 * hrtick: never preempt a task that has not run MIN_DEADLINE_NS
	 * yet; its deadline renewal is close enough.
	 */
	if (now - tctx->last_run_at < MIN_DEADLINE_NS)
		return;

	q = __COMPAT_scx_bpf_dsq_peek(cpu2dsq(scx_bpf_task_cpu(p)));
	if (!q || (s64)(q->scx.dsq_vtime - tctx->deadline) >= 0)
		return;

	/*
	 * Saturation preemption lag: with a queue two or more deep, the
	 * rotation peers carry deadlines within one renewal of each other
	 * and tick-preempting on every tick turns the run into a swap
	 * storm. Demand that the queued task be three offsets more
	 * overdue than the running deadline before it may preempt. A
	 * task that just woke with a slept-in deadline is overdue by its
	 * whole sleep and clears the bar at once; only the rotation
	 * peers are held off, and their chunks lengthen by roughly the
	 * lag.
	 */
	if (scx_bpf_dsq_nr_queued(cpu2dsq(scx_bpf_task_cpu(p))) >= 2 &&
	    (s64)(tctx->deadline - 3 * deadline_ns - q->scx.dsq_vtime) <= 0)
		return;

	__sync_fetch_and_add(&nr_preemptions, 1);
	scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
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
	update_bursts(tctx, now);

	/*
	 * dequeue_entity(DEQUEUE_SLEEP): a task that goes to sleep before
	 * consuming its deadline is treated as interactive and earns one
	 * priority boost step.
	 */
	if (!runnable && !reached_deadline(tctx, now) &&
	    task_nice(p, tctx) > MIN_NICE) {
		tctx->boost++;
		__sync_fetch_and_add(&nr_boosts, 1);
	}

	/*
	 * update_curr(): roll the deadline forward once reached.
	 */
	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	/*
	 * Update CPU runtime for the performance scaling.
	 */
	if (!cpuperf_offline()) {
		struct cpu_ctx *cctx;

		cctx = try_lookup_cpu_ctx(scx_bpf_task_cpu(p));
		if (cctx)
			cctx->tot_runtime += now - cctx->last_running;
	}
}

/*
 * Exponential weighted moving average (EWMA). Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update the CPU load and scale its target performance level accordingly,
 * using the utilization observed in the last window, smoothed and applied
 * with hysteresis. A caller that knows the CPU is about to be saturated
 * (@max_floor) skips the ramp: the utilization ledger reads near zero
 * across a brief sleep, and climbing back through the smoothing would
 * keep the core below its boost clock for the first windows of every
 * work chunk.
 */
static void update_cpuperf(struct cpu_ctx *cctx, s32 cpu, bool max_floor)
{
	u64 now = bpf_ktime_get_ns();
	u64 perf_lvl, delta_runtime, delta_t;

	delta_t = now - cctx->last_running;
	if (!delta_t)
		return;

	/*
	 * The utilization window cannot predate the last few slices:
	 * runtime charged before a sleep is recent history, not a load
	 * spike to average away. Without the cap a wake after a short
	 * sleep divides that runtime by the whole sleep and the floor
	 * collapses, so a task that blocks between chunks never holds
	 * its boost clock.
	 */
	if (delta_t > 4 * deadline_ns)
		delta_t = 4 * deadline_ns;

	/*
	 * Evaluate the CPU utilization of the last window, normalized in
	 * the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t,
		       SCX_CPUPERF_ONE);

	/*
	 * Smooth the target performance level, so that short spikes are
	 * absorbed while load variations still react quickly.
	 */
	cctx->perf_lvl = calc_avg(perf_lvl, cctx->perf_lvl);

	if (max_floor)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl >= CPUPERF_HIGH_THRESH)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl <= CPUPERF_LOW_THRESH)
		perf_lvl = SCX_CPUPERF_ONE / 4;
	else
		perf_lvl = cctx->perf_lvl;

	/*
	 * Request the level only when it changed. Beyond saving the
	 * write, the suppression is what keeps the platform's iowait
	 * boost latched: see the comment on perf_req.
	 */
	if (cctx->perf_req != perf_lvl) {
		scx_bpf_cpuperf_set(cpu, perf_lvl);
		cctx->perf_req = perf_lvl;
	}

	cctx->last_running = now;
	cctx->prev_runtime = cctx->tot_runtime;
}

/*
 * Initialize the CPU frequency performance level on all online CPUs.
 */
static void init_cpuperf_target(void)
{
	const struct cpumask *online_cpumask;
	u64 perf_lvl;
	s32 cpu;

	if (cpuperf_offline())
		return;

	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;

		if (cpuperf_lvl < 0)
			perf_lvl = SCX_CPUPERF_ONE;
		else
			perf_lvl = MIN(cpuperf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}
	scx_bpf_put_cpumask(online_cpumask);
}

/*
 * The task has become runnable: track how often it wakes. Frequent
 * wakers with real work to do are foreground tasks.
 */
void BPF_STRUCT_OPS(baby_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now, delta;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	delta = now - tctx->last_woke_at;
	if (!delta)
		return;
	tctx->last_woke_at = now;

	/*
	 * Wakes per 100ms, smoothed (EWMA) and capped: a task that wakes
	 * every millisecond or faster saturates the counter. The peak
	 * hold remembers the historical maximum with a slow leak, so a
	 * throttled task keeps its foreground credit.
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
 * The task has started to run on a CPU.
 */
void BPF_STRUCT_OPS(baby_running, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now = bpf_ktime_get_ns();

	__sync_fetch_and_add(&nr_running, 1);

	if (!tctx)
		return;

	tctx->last_run_at = now;
	tctx->last_acc_at = now;

	/*
	 * Adjust the target CPU frequency before the task starts to run.
	 * A proven consumer or a foreground task saturates the core for
	 * as long as it runs, so give it the boost clock at once instead
	 * of re-climbing the smoothing after every sleep.
	 */
	if (cpuperf_lvl < 0) {
		struct cpu_ctx *cctx;

		cctx = try_lookup_cpu_ctx(scx_bpf_task_cpu(p));
		if (cctx)
			update_cpuperf(cctx, scx_bpf_task_cpu(p),
				       is_heavy_proven(tctx) ||
				       is_foreground(tctx));
	}

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

	if (!scx_bpf_dsq_nr_queued(cpu2dsq(scx_bpf_task_cpu(p))))
		return false;

	tctx->yield_pending = true;

	return true;
}

s32 BPF_STRUCT_OPS(baby_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	u64 now;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

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
	now = bpf_ktime_get_ns();
	tctx->deadline = calc_deadline(p, tctx, now);
	tctx->start_time = now;
	tctx->last_acc_at = now;
	tctx->last_woke_at = now;
	tctx->cpu = -1;
	{
		struct task_struct *parent = p->real_parent;
		struct task_ctx *ptctx;

		ptctx = parent ? try_lookup_task_ctx(parent) : NULL;
		if (ptctx)
			tctx->bursts = (ptctx->prev_bursts +
					ptctx->bursts) >> 2;
	}

	return 0;
}

	s32 BPF_STRUCT_OPS_SLEEPABLE(baby_init)
	{
		u64 cpu;
		s32 err;

		nr_cpu_ids = scx_bpf_nr_cpu_ids();

		/*
		 * Create the per-CPU deadline-ordered queues.
		 */
		bpf_for(cpu, 0, nr_cpu_ids) {
			err = scx_bpf_create_dsq(cpu2dsq(cpu), -1);
			if (err) {
				scx_bpf_error("failed to create DSQ %llu: %d",
					      cpu2dsq(cpu), err);
				return err;
			}
		}

		/* Initialize the CPU frequency performance level. */
		init_cpuperf_target();

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
	       .init_task		= (void *)baby_init_task,
	       .init			= (void *)baby_init,
	       .exit			= (void *)baby_exit,
	       .timeout_ms		= 5000,
	       .name			= "baby");
