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
 * Tasks wait in one deadline-ordered queue per NUMA node, mirroring the
 * original global run list. The DSQ id is the node id; a single-node
 * machine has one queue. An idle CPU pulls the earliest-deadline task,
 * so queue order is the placement.
 *
 * Each CPU also owns a small warm queue, deadline-ordered like the node
 * queue, for tasks continuing on that CPU (see the warm seat in
 * balance.bpf.c). The warm queues take the DSQ ids starting at
 * BABY_CPU_DSQ_BASE (intf.h, shared with userspace, which refuses a
 * topology with more nodes than that).
 *
 * The latency-critical class runs on its own pair of queues with the
 * same layout one id space over (the fast lane): a per-node queue from
 * BABY_FL_NODE_DSQ_BASE and per-CPU seats from BABY_FL_CPU_DSQ_BASE.
 * Keeping the class out of the bulk seats lets the wake-path preempt
 * fire past an occupied bulk seat, and a per-CPU dispatch quota bounds
 * what the fast lane can take from a contended CPU.
 */

/*
 * Topology constants, published by userspace before load. They are
 * rodata: the verifier can fold every bound check and prune the hybrid
 * arms on a machine without a tier split. ops.init() asserts that they
 * match the kernel's own counts.
 */
extern const volatile u64 nr_cpu_ids;
extern const volatile u64 nr_node_ids;

static __always_inline u64 cpu2dsq(s32 cpu)
{
	return BABY_CPU_DSQ_BASE + cpu;
}

static __always_inline u64 fl_cpu2dsq(s32 cpu)
{
	return BABY_FL_CPU_DSQ_BASE + cpu;
}

static __always_inline u64 fl_node2dsq(s32 node)
{
	return BABY_FL_NODE_DSQ_BASE + node;
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

/*
 * Wakes per 100ms that separate the wake-rate classes from the rest.
 *
 * The latency-critical bar is 5: a 60Hz frame thread or a 59Hz request
 * probe wakes about every 17ms, and the integer rate of that interval
 * is 5. The foreground bar is 10: that class also earns the fourfold
 * slice, so it stays a true 100Hz signal. Four consecutive samples at
 * or above the latency bar arm the peak hold; four at or above the
 * foreground bar are needed before the peak can reach 10.
 */
#define LAT_CRI_WAKE_FREQ	5
#define FOREGROUND_WAKE_FREQ	10
#define WAKE_SANE_MIN		4
#define MIN_NICE		(-20)
#define MAX_NICE		19
#define MAX_RT_PRIO		100
#define MAX_PRIO		(MAX_RT_PRIO + 40)
#define PRIO_TO_NICE(prio)	((prio) - (MAX_RT_PRIO + 20))

/*
 * Default deadline offset (1.18ms, the original DEADLINE_NS).
 */
extern const volatile u64 deadline_ns;

/* Report additional debugging information. */
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
#define BABY_DIST_SELF		0
#define BABY_DIST_SIBLING	1
#define BABY_DIST_L2		2
#define BABY_DIST_LLC		3
#define BABY_DIST_NODE		4
#define BABY_DIST_BEYOND	5

extern const volatile u32 topo_node[BABY_MAX_CPUS];
extern const volatile u32 topo_llc[BABY_MAX_CPUS];
extern const volatile u32 topo_l2[BABY_MAX_CPUS];
extern const volatile u32 topo_core[BABY_MAX_CPUS];
extern const volatile u64 nr_little_cpus, nr_big_cpus;

_Static_assert(BABY_CPU_DSQ_BASE + BABY_MAX_CPUS <= BABY_FL_CPU_DSQ_BASE,
	       "per-CPU DSQ id space overlaps the fast-lane seats");
_Static_assert(BABY_FL_NODE_DSQ_BASE + BABY_MAX_NODES <= BABY_CPU_DSQ_BASE,
	       "per-node DSQ id space overlaps the bulk seats");

/*
 * Per-CPU running-class residency, stamped in ops.running() and cleared
 * in ops.stopping(). Queue depth cannot answer whether a CPU runs a
 * tick-cuttable bulk resident: CPU-bound workers never queue, so bulk
 * depth can read zero while bulk residency is total. The warm gate and
 * the relocation filter read this instead.
 */
extern bool cpu_is_lat[BABY_MAX_CPUS];

/*
 * Per-queue service clocks for the starve rescue (see main.bpf.c). They
 * are shared with the seat insertion path in balance.bpf.c. The node
 * table is padded to a power of two so the node id can be masked, and
 * the init-time bound check keeps every real node id inside it.
 */
#define BABY_NODE_CLOCK_NR	64

extern u64 seat_service_at[2][BABY_MAX_CPUS];
extern u64 node_service_at[2][BABY_NODE_CLOCK_NR];

/*
 * Per-CPU warm-seat occupancy hints, indexed by lane (0 bulk, 1 fast).
 * A seat is probed only while its hint is set, so an empty seat costs
 * no queue-depth kfunc in the warm-seat scan. The hint is deliberately
 * conservative: a racing pull can clear it while an insertion lands,
 * which costs that arrival one missed probe, never a stranded task.
 */
extern u8 seat_used[2][BABY_MAX_CPUS];

/*
 * Scheduling statistics. nr_running owns a cache line: it is a
 * control-plane input read on the hot paths, and the diagnostic
 * counters must not share its line (see stats.bpf.c).
 */
extern volatile u64 nr_running __attribute__((aligned(64)));
extern volatile u64 nr_direct_dispatches;
extern volatile u64 nr_preemptions, nr_boosts, nr_sticky;
extern volatile u64 nr_coldspreads;

/*
 * Class census at run start (class composition and lane), behind the
 * same --stats flag as the rest of the instrument.
 */
extern volatile u64 nr_class[BABY_WCLS_NR];
extern volatile u64 nr_lane[2];

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
extern volatile u64 nr_wait_n[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_ns[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_max[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_slow[BABY_WDEPTH_NR];

/*
 * The same charge, split by class: class-major, entry
 * class * BABY_WDEPTH_NR + depth.
 */
extern volatile u64 nr_wait_cls_n[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_ns[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_max[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_slow[BABY_WDEPTH_NR * BABY_WCLS_NR];

/*
 * The same charge, split by arrival type: type-major, entry
 * type * BABY_WDEPTH_NR + depth.
 */
extern volatile u64 nr_wait_type_n[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_ns[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_max[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_slow[BABY_WDEPTH_NR * BABY_WTYPE_NR];

/*
 * The same charge, split by wake-rate latency-criticality (2 * 4
 * entries, lcri-major: lcri * BABY_WDEPTH_NR + depth). It answers
 * whether latency-critical wakees actually wait, at what depth, and
 * for how long, or whether they are served at depth 0.
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
 * Saturation preemption instrument: the victims ops.tick() cut short
 * because a latency-critical task waited at a queue head, split by
 * where the waiter sat (the shared queue or the CPU's own seat).
 */
extern volatile u64 nr_tick_preempts, nr_tick_preempts_warm;

/*
 * Fast-lane services under bulk pressure: dispatches that served the
 * fast lane while the CPU's bulk queue held waiting work, each spending
 * a quota unit, split by which fast-lane queue held the task.
 */
extern volatile u64 nr_depth1_pulls, nr_depth1_pulls_seat;

/*
 * Wake-path preempts: latency-critical wakees handed a busy CPU at wake
 * time, preempting a non-latency-critical victim instead of waiting for
 * the tick.
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
	 * per 100ms. High values mark foreground workers: tasks that wake
	 * constantly with real work to do, as opposed to CPU hogs that
	 * never wake and blips that use almost no CPU.
	 */
	u64 wakeup_freq;
	u64 last_woke_at;

	/*
	 * Peak hold of wakeup_freq, the latency-critical credit. The
	 * EWMA is blended 50/50 until four samples exist and 3:1 after
	 * that, and the peak rises only after four consecutive samples
	 * at or above the latency bar (5). The hold then decays by 1/64
	 * per wake only while above 64 (a shift of a value below 64 is
	 * zero), so it falls from a spike to 63 and stays there. 63 is
	 * far above both class bars (5 and 10): the latency class
	 * latches once earned, by design. A real decay would strip the
	 * class from a frame-paced thread the moment overcommit throttles
	 * its frame rate, which is the state the credit exists for.
	 */
	u32 peak_freq;

	/*
	 * Wake-frequency samples taken (warmup ends at WAKE_SANE_MIN),
	 * the current run of samples at or above the latency bar, and
	 * the current run at or above the foreground bar. The peak may
	 * rise only once the latency run is armed; its candidate is
	 * capped at 9 while the foreground run is not four, so a 50-60Hz
	 * task hit by one or two spikes cannot cross the 10 bar and earn
	 * the fourfold slice.
	 */
	u32 wake_samples;
	u8 wake_sane;
	u8 fg_sane;

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

	/*
	 * The CPU the task last entered ops.running() on. ops.stopping()
	 * can run on the task's new CPU after a migration, so the
	 * per-CPU state the run stamped must be cleared through the CPU
	 * that stamped it, not through scx_bpf_task_cpu().
	 */
	s32 last_cpu;
};

/*
 * Roll the 200ms burst window to the window @now falls in. A task that
 * slept through at least two windows has no runtime in the last
 * completed one, so its previous burst is zero; a shorter sleep keeps
 * the runtime it did accumulate. Callers run this at every wake path
 * (select_cpu, runnable) and at the runtime accounting, so a predicate
 * never reads a window that ended during a sleep.
 */
static __always_inline void roll_burst_window(struct task_ctx *tctx, u64 now)
{
	u64 elapsed = now - tctx->start_time;

	if (elapsed >= 2 * TIME_PERIOD) {
		tctx->prev_bursts = 0;
		tctx->bursts = 0;
		tctx->start_time = now;
	} else if (elapsed >= TIME_PERIOD) {
		tctx->prev_bursts = tctx->bursts;
		tctx->bursts = 0;
		tctx->start_time += TIME_PERIOD;
	}
}

/*
 * The class predicates are pure functions of the task context and the
 * rodata deadline, so they live in the header as inlines: clang can
 * fold the combinations its callers test, and no cross-module call
 * frame is emitted on paths that only ask one of them. The
 * multi-branch helpers (can_resched, task_nice, update_bursts) stay in
 * class.bpf.c; see the verifier notes there before moving them.
 */
/*
 * A proven CPU consumer used more than a quarter of the window across
 * its current and previous windows. Covering both keeps the status on
 * a task that shares a contended core and rolls windows with a
 * fraction of the core each. On a hybrid platform a proven consumer
 * with no wake history pins a big core.
 */
static __always_inline bool is_heavy_proven(const struct task_ctx *tctx)
{
	return tctx->prev_bursts + tctx->bursts > TIME_PERIOD / 4;
}

/*
 * A task is latency-critical when it wakes frequently enough to prove
 * it, whatever its burst size: game render threads, compositors and
 * submission workers wake per frame or per request, and under CPU
 * overcommit a game thread is heavy_proven too, so no burst bound can
 * gate this. There is no runtime floor: a task that wakes often but
 * consumes almost nothing still has latency to protect. A task that
 * never leaves runnable state (preempted, slice-expired) never re-runs
 * the wake-rate EWMA, so a preempted batch victim cannot pass as a
 * waker.
 */
static __always_inline bool is_lat_cri(const struct task_ctx *tctx)
{
	return tctx->wake_samples >= WAKE_SANE_MIN &&
	       tctx->peak_freq >= LAT_CRI_WAKE_FREQ;
}

/*
 * A task is foreground when it wakes frequently and does real work: a
 * browser renderer or an audio thread wakes dozens of times per window
 * with sizable bursts, a CPU hog never wakes, and a UI blip barely
 * uses the CPU. Foreground earns the fourfold slice, waker eligibility
 * and precedence over the heavy pin in the compaction, so light
 * workers that cross the heavy bar with their mutex spins keep the
 * little-tier packing.
 */
static __always_inline bool is_foreground(const struct task_ctx *tctx)
{
	return tctx->wake_samples >= WAKE_SANE_MIN &&
	       tctx->peak_freq >= FOREGROUND_WAKE_FREQ &&
	       tctx->prev_bursts + tctx->bursts > TIME_PERIOD / 20;
}

/*
 * Foreground tasks get a longer slice: their requests are memory-bound,
 * and interleaving them with hog slices on a busy core multiplies the
 * wall time of each request. Every foreground task is also
 * latency-critical (its 10-wake bar is above the latency bar of 5;
 * foreground only adds the runtime floor), so a latency-critical check
 * above the foreground test would make the fourfold slice dead code.
 * There is no upper burst bound: a heavy waker that also does real work
 * stays foreground, so the hybrid compaction still lets foreground beat
 * the heavy pin.
 */
static __always_inline u64 task_slice(const struct task_ctx *tctx)
{
	return is_foreground(tctx) ? 4 * deadline_ns : deadline_ns;
}

/*
 * Class census value at run start: 0 bulk normal, 1 bulk heavy,
 * 2 fast lane on the base slice, 3 fast lane on the fourfold slice.
 * Foreground implies latency-critical, so testing latency first and
 * foreground second keeps the fourfold class from being shadowed; class
 * 2 plus class 3 is the fast-lane run count.
 */
static __always_inline u32 task_nr_class(const struct task_ctx *tctx)
{
	if (is_lat_cri(tctx))
		return is_foreground(tctx) ? 3 : 2;
	return is_heavy_proven(tctx) ? 1 : 0;
}

/*
 * The node queue holds two or more waiting tasks: the task will rotate
 * behind them anyway, and every extra rotation costs a full switch, so
 * the callers grant four times the deadline as the slice.
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
 * Return true if the task can only run on a single CPU, false otherwise.
 */
static __always_inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * The CPU a task must fall back to when no idle CPU was found. A
 * previous CPU outside the task's affinity mask is not a placement: a
 * node queue keyed on it would be unreachable from every CPU that can
 * run the task. Return an allowed CPU instead, preferring the previous
 * one when it still is.
 */
static __always_inline s32 any_allowed_cpu(const struct task_struct *p,
					   s32 prev_cpu)
{
	u32 cpu;

	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		return prev_cpu;

	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
	return cpu < nr_cpu_ids ? (s32)cpu : prev_cpu;
}

/*
 * Peek a shared queue for @cpu and hide a head the CPU cannot run.
 * An affinity-restricted head otherwise poisons the lane for every CPU
 * that can reach it: dispatch treats it as the lane's next deadline,
 * and the tick preempts bulk work for a waiter the CPU cannot pull.
 */
static __always_inline struct task_struct *dsq_peek_allowed(u64 dsq, s32 cpu)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(dsq);

	if (!p || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return NULL;
	return p;
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
__hidden u64 calc_deadline(const struct task_struct *p, struct task_ctx *tctx,
		  u64 now);
__hidden void class_on_runnable(struct task_ctx *tctx, u64 enq_flags, u64 now);
__hidden void class_on_running(struct task_struct *p, struct task_ctx *tctx,
			       u64 now);
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
			   u64 enq_flags, u64 bulk_backlog, u64 fl_backlog,
			   u64 now);

/*
 * main.bpf.c: the kernel idle-CPU selection restricted to the non-LP
 * mask while the tier masks exist.
 */
__hidden s32 select_cpu_no_lp(struct task_struct *p, s32 prev_cpu,
			      u64 wake_flags);

#endif /* __BABY_H */
