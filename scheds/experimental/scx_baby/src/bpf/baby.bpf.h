/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Copyright (C) 2026 bunkbail <nabildanial.93@gmail.com>
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
 *
 * The warm queues take the DSQ ids starting at BABY_CPU_DSQ_BASE
 * (intf.h, shared with userspace, which refuses to load a topology
 * with more nodes than that).
 */

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

/*
 * The wait/census instrument and the distance histograms run; set
 * from --stats at load.
 */
extern const volatile bool stats_enabled;

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
extern u64 nr_little_cpus, nr_big_cpus;

/*
 * Scheduling statistics. nr_running owns a cache line: it is a
 * control-plane input read on the hot paths, and the diagnostic
 * counters must not share its line (see stats.bpf.c).
 */
extern volatile u64 nr_running __attribute__((aligned(64)));
extern volatile u64 nr_direct_dispatches __attribute__((aligned(64))),
	nr_shared_dispatches;
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
 * The same charge, split by wake-rate latency-criticality (2 * 4
 * entries, lcri-major: lcri * BABY_WDEPTH_NR + depth). Latency-critical
 * waits are the schbench-2x question: whether the wakees the tick gate
 * serves actually wait, at what depth, and how long - or whether they
 * are served at depth 0 and the gap lives elsewhere.
 */
extern volatile u64 nr_wait_lcri_n[BABY_WDEPTH_NR * 2];
extern volatile u64 nr_wait_lcri_ns[BABY_WDEPTH_NR * 2];
extern volatile u64 nr_wait_lcri_max[BABY_WDEPTH_NR * 2];
extern volatile u64 nr_wait_lcri_slow[BABY_WDEPTH_NR * 2];

/*
 * The latency-critical charge, split by the wake-gate miss reason: why
 * the depth-0 wake preempt at ops.select_cpu() did not fire for the
 * task's most recent wake. Depth-major within each reason row, entry
 * depth * BABY_WG_NR + reason; a rotation requeue files reason 0. The
 * classes partition the wlcri lat bucket: per depth, the reason sums
 * equal the wlcri lat counts and ns.
 */
#define BABY_WG_NR	10

#define BABY_WG_NON_WAKE	0	/* rotation requeue, not a wake */
#define BABY_WG_NO_GATE		1	/* no wake-gate contact this cycle */
#define BABY_WG_M1_NOT_LAT	2	/* wakee not lat-cri at gate time */
#define BABY_WG_M2_AFFINITY	3	/* wakee cannot run on prev_cpu */
#define BABY_WG_M3_SEAT_BUSY	4	/* the wakee's seat holds a head */
#define BABY_WG_M3_LOCAL_BUSY	5	/* an in-flight wakee holds the local DSQ */
#define BABY_WG_M4_DEGEN	6	/* victim unusable: null/self/idle/no ctx */
#define BABY_WG_M4_VICTIM_LAT	7	/* the victim is lat-cri */
#define BABY_WG_M4_PRIO		8	/* the wakee loses on static_prio */
#define BABY_WG_M5_RESIDENCY	9	/* the victim is under the 200us floor */

extern volatile u64 nr_wait_wg_n[BABY_WDEPTH_NR * BABY_WG_NR];
extern volatile u64 nr_wait_wg_ns[BABY_WDEPTH_NR * BABY_WG_NR];
extern volatile u64 nr_wait_wg_max[BABY_WDEPTH_NR * BABY_WG_NR];
extern volatile u64 nr_wait_wg_slow[BABY_WDEPTH_NR * BABY_WG_NR];

/*
 * Saturation deferred-preemption instrument: the victims ops.tick() cut
 * short because a latency-critical task waited at a queue head, split
 * by where the waiter sat - the shared deadline queue or the CPU's own
 * warm seat.
 */
extern volatile u64 nr_tick_preempts, nr_tick_preempts_warm;

/*
 * Depth-1 out-of-turn pulls (the consumption-side wall round): the
 * latency-critical waiters ops.dispatch() served past a non-lat-cri
 * queue head, split by which queue held them - the shared deadline
 * queue or the CPU's own warm seat.
 */
extern volatile u64 nr_depth1_pulls, nr_depth1_pulls_seat;

/*
 * Depth-0 wake-path preempts (the IPI-fast twin of the tick gate): the
 * lat-cri wakees ops.select_cpu() handed a busy CPU to - preempting the
 * running non-lat-cri victim at wake time instead of waiting for the
 * tick gate's next cut window.
 */
extern volatile u64 nr_wake_preempts;

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

	/*
	 * Why the depth-0 wake preempt did not fire for the most recent
	 * wake: stamped at each ops.select_cpu() miss exit, reset at
	 * select_cpu entry and consumed by charge_wait() in ops.running().
	 * BABY_WG_* codes; a rotation files 0 (BABY_WG_NON_WAKE).
	 */
	u8 wake_gate_miss;

	/*
	 * Set by ops.tick() when it cuts the task's slice short to serve
	 * a waiting latency-critical task. ops.stopping() leaves it set
	 * so ops.enqueue() requeues the victim with the base slice (it
	 * did not exhaust its quantum, so the deep-backlog rung is not
	 * its due), and ops.running() clears it when the task next runs.
	 */
	bool tick_preempted;
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
__hidden struct task_ctx *try_lookup_task_ctx(const struct task_struct *p);
__hidden struct task_ctx *init_task_ctx(struct task_struct *p);
__hidden u32 cpu_dist(s32 a, s32 b);

/*
 * stats.bpf.c: the wait-at-depth instrument and the consumption census.
 */
__hidden void stamp_wait(struct task_ctx *tctx, u64 now, u64 depth, bool shared);
__hidden void charge_wait(struct task_ctx *tctx, u64 now);
__hidden void census_sample(s32 cpu);

/*
 * class.bpf.c: bursts, wake frequency, class predicates and deadline math.
 */
__hidden void update_bursts(struct task_ctx *tctx, u64 now);
__hidden bool can_resched(const struct task_ctx *tctx);
__hidden bool is_interactive(const struct task_ctx *tctx);
__hidden bool is_heavy_proven(const struct task_ctx *tctx);
__hidden bool is_foreground(const struct task_ctx *tctx);
__hidden bool is_lat_cri(const struct task_ctx *tctx);
__hidden u64 task_slice(const struct task_ctx *tctx);
__hidden s64 task_prio_factor(const struct task_struct *p,
		     const struct task_ctx *tctx);
__hidden u64 calc_deadline(const struct task_struct *p, struct task_ctx *tctx,
		  u64 now);
__hidden void class_on_runnable(struct task_ctx *tctx, u64 enq_flags, u64 now);
__hidden void class_boost_on_sleep(struct task_struct *p, struct task_ctx *tctx,
			  bool runnable, u64 now);
__hidden void class_init_task(struct task_ctx *tctx, struct task_struct *p, u64 now);

/*
 * idle.bpf.c: idle-CPU acquisition and direct dispatch.
 */
__hidden s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
		  bool *is_idle);
__hidden bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
			 s32 prev_cpu, u64 enq_flags, bool is_running);

/*
 * power.bpf.c: CPU performance scaling.
 */
__hidden void cpuperf_init(void);
__hidden void cpuperf_on_tick(struct task_struct *p, u64 now, bool max_floor);
__hidden void cpuperf_on_running(s32 cpu, u64 now, bool max_floor);
__hidden void cpuperf_on_stopping(s32 cpu, u64 now);
__hidden void cpuperf_on_idle(s32 cpu);

/*
 * balance.bpf.c: the warm-seat balance under oversubscription.
 */
__hidden bool balance_try_warm_seat(struct task_struct *p, struct task_ctx *tctx,
			   u64 enq_flags, u64 backlog, u64 now);

/*
 * main.bpf.c: the hybrid LP-island guard: re-pick a confirmed idle
 * pick that landed on an LP core inside the two tiers.
 */
__hidden s32 lp_guard_pick(struct task_struct *p, struct task_ctx *tctx,
			   s32 cpu);

/*
 * main.bpf.c: the depth-1 out-of-turn pull - serve a latency-critical
 * task waiting one deep behind a non-lat-cri head before the head
 * itself, bounded to one bypass per head (the starvation bound).
 */
__hidden bool depth1_pull_node(u64 dsq_id, s32 cpu);
__hidden bool depth1_pull_seat(u64 dsq_id, s32 cpu);

#endif /* __BABY_H */
