/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Shared interface of the BPF modules. Every module includes this header:
 * it holds the shared types, the declarations of the tunables and counters
 * the skeleton publishes to userspace, the pure helpers and the
 * cross-module prototypes. Maps and globals are defined in exactly one
 * module and reached elsewhere only through what is declared here.
 */
#ifndef __BABY_H
#define __BABY_H

#include <scx/common.bpf.h>
#include "intf.h"

/*
 * The tasks wait in one deadline-ordered queue per NUMA node, mirroring
 * the original global run list. The DSQ id is the node id; on a
 * single-node machine there is exactly one queue. There is nothing to
 * steal: an idle CPU pulls the earliest-deadline task, so the queue
 * order IS the placement.
 *
 * Each CPU also owns a small warm queue, deadline-ordered like the
 * node one, that holds tasks continuing on that CPU (see the warm
 * seat in ops.enqueue). The warm queues are bounded - a deeper
 * backlog overflows into the node queue, where every idle CPU can
 * reach it - so they carry cache locality without becoming homes.
 */
#define BABY_CPU_DSQ_BASE	100ULL

extern u64 nr_cpu_ids;

static __always_inline u64 cpu2dsq(s32 cpu)
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
#define MIN_NICE		(-20)
#define MAX_NICE		19
#define MAX_RT_PRIO		100
#define MAX_PRIO		(MAX_RT_PRIO + 40)
#define PRIO_TO_NICE(prio)	((prio) - (MAX_RT_PRIO + 20))

/*
 * Default deadline offset (1.18ms, the original DEADLINE_NS).
 */
extern const volatile u64 deadline_ns;

 /* Report additional debugging information */
extern const volatile bool debug;

#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

/*
 * Cache-topology distance rank, as published by userspace from the sysfs
 * cache hierarchy. The rank of a pair is the deepest cache level the two
 * CPUs share: same lane < SMT sibling < same L2 < same LLC < same node <
 * beyond. It is an order, not a price - the placement decisions only ever
 * compare two candidates' ranks against each other.
 */
#define BABY_MAX_CPUS		128

#define BABY_DIST_SELF		0
#define BABY_DIST_SIBLING	1
#define BABY_DIST_L2		2
#define BABY_DIST_LLC		3
#define BABY_DIST_NODE		4
#define BABY_DIST_BEYOND	5
#define BABY_DIST_NR		8

extern const volatile u32 topo_node[BABY_MAX_CPUS];
extern const volatile u32 topo_llc[BABY_MAX_CPUS];
extern const volatile u32 topo_l2[BABY_MAX_CPUS];
extern const volatile u32 topo_core[BABY_MAX_CPUS];

/*
 * Scheduling statistics.
 */
extern volatile u64 nr_running, nr_direct_dispatches, nr_shared_dispatches;
extern volatile u64 nr_preemptions, nr_boosts, nr_sticky, nr_warmseats;
extern volatile u64 nr_coldspreads;

/*
 * Where placements land, by distance rank.
 */
extern volatile u64 nr_land[BABY_DIST_NR];
extern volatile u64 nr_wake_land[BABY_DIST_NR];
extern volatile u64 nr_seat_self;
extern volatile u64 nr_seat_move[BABY_DIST_NR];
extern volatile u64 nr_pull_land[BABY_DIST_NR];

/*
 * Wait-at-depth instrument: the wait a task actually served, filed by the
 * depth it waited behind (0, 1, 2, 3+).
 */
#define BABY_WDEPTH_NR	4

extern volatile u64 nr_wait_n[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_ns[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_max[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_slow[BABY_WDEPTH_NR];
extern volatile u64 nr_arr_seat, nr_arr_shared;

/*
 * The same charge, split by class: class-major, entry
 * class * BABY_WDEPTH_NR + depth.
 */
#define BABY_WCLS_NR	4

extern volatile u64 nr_wait_cls_n[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_ns[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_max[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_slow[BABY_WDEPTH_NR * BABY_WCLS_NR];

/*
 * The same charge, split by arrival type: type-major, entry
 * type * BABY_WDEPTH_NR + depth.
 */
#define BABY_WTYPE_NR	2

extern volatile u64 nr_wait_type_n[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_ns[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_max[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_slow[BABY_WDEPTH_NR * BABY_WTYPE_NR];

/*
 * Where each arrival type landed: wake or rotation, warm seat or
 * shared queue. Indexed type * 2 + shared.
 */
extern volatile u64 nr_arr_type[2 * 2];

/*
 * Consumption census: the queue state a lane sees when it comes to pick
 * work - the depth left in its warm seat and the shared backlog the
 * rotation turns on.
 */
#define BABY_CENSUS_NR	8

extern volatile u64 nr_census_seat[BABY_CENSUS_NR];
extern volatile u64 nr_census_shared[BABY_CENSUS_NR];

/*
 * Exit information (defined by UEI_DEFINE in util.bpf.c).
 */
extern struct user_exit_info uei;
extern char uei_dump[];
extern const volatile u32 uei_dump_len;

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

	/*
	 * Wait accounting: set when an enqueue parks the task in a warm
	 * seat or the shared queue, consumed by ops.running(). A stamp
	 * overwritten by a re-enqueue under-reports (a task bounced
	 * through an RT lease waits twice but is charged once).
	 */
	u64 wait_stamp;
	u8 wait_depth;
	u8 wait_cls;
	bool wait_shared;

	/*
	 * Set by ops.runnable() when the transition to runnable carried
	 * SCX_ENQ_WAKEUP, cleared by ops.stopping(). The wait instrument
	 * files each stamped arrival under it: a wake handoff charges
	 * the wake-type arrays, a requeue the rotation side.
	 */
	u8 arrival_is_wake;
};

/*
 * The node queue holds two or more waiting tasks: the task will rotate
 * behind them anyway, and every extra rotation costs a full switch, so
 * grant it twice the slice.
 */
static __always_inline bool backlog_deep(u64 backlog)
{
	return backlog >= 2;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static __always_inline bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static __always_inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if the task's deadline is behind @now.
 */
static __always_inline bool reached_deadline(const struct task_ctx *tctx,
					     u64 now)
{
	return (s64)(tctx->deadline - now) <= 0;
}

/*
 * Exponential weighted moving average (EWMA). Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static __always_inline u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * util.bpf.c: per-task context and the topology distance.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p);
struct task_ctx *init_task_ctx(struct task_struct *p);
u32 cpu_dist(s32 a, s32 b);

/*
 * stats.bpf.c: the wait-at-depth instrument and the consumption census.
 */
void stamp_wait(struct task_ctx *tctx, u64 now, u64 depth, bool shared);
void charge_wait(struct task_ctx *tctx, u64 now);
void census_sample(s32 cpu);

/*
 * class.bpf.c: bursts, wake frequency, class predicates and deadline math.
 */
void update_bursts(struct task_ctx *tctx, u64 now);
bool can_resched(const struct task_ctx *tctx);
bool is_interactive(const struct task_ctx *tctx);
bool is_heavy_proven(const struct task_ctx *tctx);
bool is_foreground(const struct task_ctx *tctx);
u64 task_slice(const struct task_ctx *tctx);
s64 task_prio_factor(const struct task_struct *p,
		     const struct task_ctx *tctx);
u64 calc_deadline(const struct task_struct *p, struct task_ctx *tctx,
		  u64 now);
void class_on_runnable(struct task_ctx *tctx, u64 enq_flags, u64 now);
void class_boost_on_sleep(struct task_struct *p, struct task_ctx *tctx,
			  bool runnable, u64 now);
void class_init_task(struct task_ctx *tctx, struct task_struct *p, u64 now);

/*
 * idle.bpf.c: idle-CPU acquisition and direct dispatch.
 */
s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
		  bool *is_idle);
bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
			 s32 prev_cpu, u64 enq_flags, bool is_running);

/*
 * power.bpf.c: CPU performance scaling.
 */
void cpuperf_init(void);
void cpuperf_on_tick(struct task_struct *p, u64 now, bool max_floor);
void cpuperf_on_running(s32 cpu, bool max_floor);
void cpuperf_on_stopping(s32 cpu, u64 now);
void cpuperf_on_idle(s32 cpu);

/*
 * balance.bpf.c: the warm-seat balance under oversubscription.
 */
bool balance_try_warm_seat(struct task_struct *p, struct task_ctx *tctx,
			   u64 enq_flags, u64 backlog, u64 now);

#endif /* __BABY_H */
