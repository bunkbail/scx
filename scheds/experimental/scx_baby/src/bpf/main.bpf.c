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
 * Deadline-ordered queue that holds every runnable task.
 */
#define BABY_DSQ_ID		4096ULL

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
 * Pick a target CPU for a task which is being woken up. If an idle CPU is
 * found, the task is dispatched directly to it and ops.enqueue() is
 * skipped.
 */
s32 BPF_STRUCT_OPS(baby_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, deadline_ns, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}

	return cpu;
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
	u64 now = bpf_ktime_get_ns();

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

	if (enq_flags & SCX_ENQ_WAKEUP) {
		/*
		 * check_preempt_wakeup(): preempt the task running on the
		 * target CPU if the waker has an earlier deadline and does
		 * not have a lower priority, unless the running task is
		 * protecting its CPU burst. The waker is placed directly
		 * in front of the victim on the local DSQ, skipping the
		 * global deadline order like the original resched_curr().
		 */
		struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(prev_cpu);
		struct task_ctx *cctx;

		if (curr && curr != p && !(curr->flags & PF_IDLE)) {
			cctx = try_lookup_task_ctx(curr);
			if (cctx &&
			    (s64)(tctx->deadline - cctx->deadline) < 0 &&
			    p->static_prio <= curr->static_prio &&
			    can_resched(cctx)) {
				scx_bpf_dsq_insert(p,
						   SCX_DSQ_LOCAL_ON | prev_cpu,
						   deadline_ns,
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
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
	}

	scx_bpf_dsq_insert_vtime(p, BABY_DSQ_ID, deadline_ns,
				 tctx->deadline, enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);
}

/*
 * Dispatch the earliest-deadline task to the CPU.
 */
void BPF_STRUCT_OPS(baby_dispatch, s32 cpu, struct task_struct *prev)
{
	bool need_running = prev && is_queued(prev);

	if (need_running) {
		/*
		 * pick_next_entity() keeps the current task only when its
		 * deadline is strictly earlier than the queued one.
		 */
		struct task_ctx *tctx = try_lookup_task_ctx(prev);
		struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(BABY_DSQ_ID);
		u64 q_dl = q ? q->scx.dsq_vtime : ~0ULL;

		if (tctx && (s64)(tctx->deadline - q_dl) < 0) {
			scx_bpf_task_set_slice(prev, deadline_ns);
			return;
		}
	}

	if (!scx_bpf_dsq_move_to_local(BABY_DSQ_ID, 0) && need_running) {
		/*
		 * Nothing else is queued: keep the task running, as the
		 * original does across its deadline renewals.
		 */
		scx_bpf_task_set_slice(prev, deadline_ns);
	}
}

/*
 * Periodic tick: account bursts, renew the deadline once reached and
 * preempt the current task for an earlier-deadline one, unless it is a
 * burst hog (original entity_tick() / hrtick handling).
 */
void BPF_STRUCT_OPS(baby_tick, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	struct task_struct *q;
	u64 now;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	update_bursts(tctx, now);

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

	q = __COMPAT_scx_bpf_dsq_peek(BABY_DSQ_ID);
	if (q && (s64)(q->scx.dsq_vtime - tctx->deadline) < 0) {
		__sync_fetch_and_add(&nr_preemptions, 1);
		scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
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

	if (!scx_bpf_dsq_nr_queued(BABY_DSQ_ID))
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
	 * empty burst history.
	 */
	now = bpf_ktime_get_ns();
	tctx->deadline = calc_deadline(p, tctx, now);
	tctx->start_time = now;
	tctx->last_acc_at = now;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(baby_init)
{
	s32 err;

	/*
	 * Create the global deadline-ordered queue.
	 */
	err = scx_bpf_create_dsq(BABY_DSQ_ID, -1);
	if (err) {
		scx_bpf_error("failed to create baby DSQ %llu: %d",
			      BABY_DSQ_ID, err);
		return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(baby_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(baby_ops,
	       .select_cpu		= (void *)baby_select_cpu,
	       .enqueue			= (void *)baby_enqueue,
	       .dispatch		= (void *)baby_dispatch,
	       .tick			= (void *)baby_tick,
	       .running			= (void *)baby_running,
	       .stopping		= (void *)baby_stopping,
	       .yield			= (void *)baby_yield,
	       .init_task		= (void *)baby_init_task,
	       .init			= (void *)baby_init,
	       .exit			= (void *)baby_exit,
	       .timeout_ms		= 5000,
	       .name			= "baby");
