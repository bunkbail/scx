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

static u64 nr_cpu_ids;

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
volatile u64 nr_preemptions, nr_boosts, nr_sticky, nr_warmseats;
volatile u64 nr_coldspreads;

/*
 * Cache-topology distance, as published by userspace from the sysfs
 * cache hierarchy: the physical core id groups SMT siblings, the L2
 * and LLC ids group the shared-cache tiers, the node id the socket.
 * Every table holds a nonzero id per CPU, so an unfilled entry never
 * compares equal to a filled one.
 *
 * The rank of a pair is the deepest cache level the two CPUs share:
 * same lane < SMT sibling < same L2 < same LLC < same node < beyond.
 * It is an order, not a price - the placement decisions below only
 * ever compare two candidates' ranks against each other.
 */
#define BABY_MAX_CPUS		128

#define BABY_DIST_SELF		0
#define BABY_DIST_SIBLING	1
#define BABY_DIST_L2		2
#define BABY_DIST_LLC		3
#define BABY_DIST_NODE		4
#define BABY_DIST_BEYOND	5
#define BABY_DIST_NR		8

const volatile u32 topo_node[BABY_MAX_CPUS];
const volatile u32 topo_llc[BABY_MAX_CPUS];
const volatile u32 topo_l2[BABY_MAX_CPUS];
const volatile u32 topo_core[BABY_MAX_CPUS];

/*
 * A single cached comparison per queue in the warm-seat scan keeps the
 * verifier's state space flat: cpu_dist(prev, i) recomputed on both
 * arms of a three-way compare would branch the scan's exploration and
 * blow past the jump-complexity limit (observed 8193-jump blowup).
 */
static u32 cpu_dist(s32 a, s32 b)
{
	u32 ia, ib;

	if (a < 0 || b < 0 || (u32)a >= nr_cpu_ids || (u32)b >= nr_cpu_ids)
		return BABY_DIST_BEYOND;

	if (a == b)
		return BABY_DIST_SELF;

	ia = (u32)a & (BABY_MAX_CPUS - 1);
	ib = (u32)b & (BABY_MAX_CPUS - 1);

	if (topo_core[ia] && topo_core[ia] == topo_core[ib])
		return BABY_DIST_SIBLING;
	if (topo_l2[ia] && topo_l2[ia] == topo_l2[ib])
		return BABY_DIST_L2;
	if (topo_llc[ia] && topo_llc[ia] == topo_llc[ib])
		return BABY_DIST_LLC;
	if (topo_node[ia] == topo_node[ib])
		return BABY_DIST_NODE;

	return BABY_DIST_BEYOND;
}

/*
 * Where placements land, by distance rank. The counters tell the warm
 * paths apart: the run-start histogram covers every path's outcome at
 * the point of truth, the wake-pick one covers ops.select_cpu(), and
 * the seat-move one covers the warm-seat rebalance.
 */
volatile u64 nr_land[BABY_DIST_NR];
volatile u64 nr_wake_land[BABY_DIST_NR];
volatile u64 nr_seat_self;
volatile u64 nr_seat_move[BABY_DIST_NR];
volatile u64 nr_pull_land[BABY_DIST_NR];

/*
 * Wait-at-depth instrument. When an enqueue parks a task in a warm
 * seat or the shared queue, it stamps the arrival time and the depth
 * the task will wait behind (0, 1, 2, 3+). ops.running() charges the
 * realized wait to that bucket. The overcommit tail can then be
 * attributed to the depth it waited at: waits behind nothing (depth
 * 0) point at consumption, waits at depth point at rotation cost.
 */
#define BABY_WDEPTH_NR	4

volatile u64 nr_wait_n[BABY_WDEPTH_NR];
volatile u64 nr_wait_ns[BABY_WDEPTH_NR];
volatile u64 nr_wait_max[BABY_WDEPTH_NR];
volatile u64 nr_wait_slow[BABY_WDEPTH_NR];
volatile u64 nr_arr_seat, nr_arr_shared;

#define BABY_WAIT_SLOW_NS	(5ULL * NSEC_PER_MSEC)

/*
 * The same charge, split by class. Each stamped task carries two
 * class bits, derived in ops.runnable() where the burst and
 * wake-frequency EWMAs they read are fresh: bit 0 interactive, bit 1
 * foreground. ops.running() files the wait into class-major 4x4
 * arrays, entry class * BABY_WDEPTH_NR + depth, so the overcommit
 * wait can be attributed to the classes a deadline-ordering change
 * would prioritize.
 */
#define BABY_WCLS_NR	4

volatile u64 nr_wait_cls_n[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_ns[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_max[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_slow[BABY_WDEPTH_NR * BABY_WCLS_NR];

/*
 * The same charge, split by arrival type. Type 1 is a wake handoff:
 * the arrival became runnable with SCX_ENQ_WAKEUP (ops.runnable()
 * stamps the bit, ops.stopping() clears it). The complement is the
 * rotation - slice-expiry and preemption requeues, which re-enter
 * without a runnable transition. The split prices the handoff the
 * overcommit tail is blamed on separately from the rotation that
 * dominates the charge counts. Type-major: type * BABY_WDEPTH_NR +
 * depth.
 */
#define BABY_WTYPE_NR	2

volatile u64 nr_wait_type_n[BABY_WDEPTH_NR * BABY_WTYPE_NR];
volatile u64 nr_wait_type_ns[BABY_WDEPTH_NR * BABY_WTYPE_NR];
volatile u64 nr_wait_type_max[BABY_WDEPTH_NR * BABY_WTYPE_NR];
volatile u64 nr_wait_type_slow[BABY_WDEPTH_NR * BABY_WTYPE_NR];

/*
 * Where each arrival type landed: wake or rotation, warm seat or
 * shared queue. Indexed type * 2 + shared.
 */
volatile u64 nr_arr_type[2 * 2];

/*
 * Consumption census: sampled in ops.dispatch(), the queue state a
 * lane sees when it comes to pick work - the depth left in its warm
 * seat and the shared backlog the rotation turns on. Eight buckets,
 * the last one 7 or deeper; clamped by assignment and masked at use,
 * like the wait depth.
 */
#define BABY_CENSUS_NR	8

volatile u64 nr_census_seat[BABY_CENSUS_NR];
volatile u64 nr_census_shared[BABY_CENSUS_NR];

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
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Stamp a waiting arrival for the wait-at-depth instrument. The depth
 * is clamped here by assignment through the u8 field and masked again
 * at the charging site, so the verifier can prove the bucket index.
 */
static void stamp_wait(struct task_ctx *tctx, u64 now, u64 depth, bool shared)
{
	u8 type = tctx->arrival_is_wake & 1;

	tctx->wait_stamp = now;
	tctx->wait_depth = (u8)MIN(depth, BABY_WDEPTH_NR - 1);
	tctx->wait_shared = shared;
	if (shared)
		__sync_fetch_and_add(&nr_arr_type[type * 2 + 1], 1);
	else
		__sync_fetch_and_add(&nr_arr_type[type * 2], 1);
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
 * Find an idle CPU for @p through the kernel's selector, which knows
 * the SMT topology and spreads wakeups across the LLCs. Returns the
 * CPU, with @is_idle set when it was picked idle.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
			 u64 wake_flags, bool *is_idle)
{
	s32 cpu;

	/*
	 * Compatibility with older kernels.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		if (wake_flags)
			return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags,
						      is_idle);

		return prev_cpu;
	}

	cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
	if (cpu < 0)
		return prev_cpu;

	*is_idle = true;

	return cpu;
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
 * Attempt to dispatch a task directly to an idle CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
static bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				s32 prev_cpu, u64 enq_flags, bool is_running)
{
	bool is_idle = false;
	s32 cpu = prev_cpu;

	/*
	 * A task that is running, or whose placement ops.select_cpu()
	 * already decided, has had its chance at an idle CPU. A
	 * reenqueued task is worth another scan: its CPU just came back
	 * from an RT lease and the rest of the machine has moved
	 * meanwhile.
	 */
	if (!is_running && __COMPAT_is_enq_cpu_selected(enq_flags) &&
	    !(enq_flags & SCX_ENQ_REENQ))
		return false;

	/*
	 * Migrate only to a confirmed idle CPU: a task pushed onto a
	 * busy core would wait behind whatever runs there, which is
	 * exactly the stranding the per-CPU queues used to create.
	 */
	if (!is_pcpu_task(p)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0, &is_idle);
		if (!is_idle)
			return false;
	} else {
		if (!scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return false;
	}

	__sync_fetch_and_add(&nr_land[cpu_dist(prev_cpu, cpu)], 1);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(tctx), 0);
	__sync_fetch_and_add(&nr_direct_dispatches, 1);

	if (cpu != prev_cpu || !is_running)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	return true;
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
 * The node queue holds two or more waiting tasks: the task will rotate
 * behind them anyway, and every extra rotation costs a full switch, so
 * grant it twice the slice.
 */
static bool backlog_deep(u64 backlog)
{
	return backlog >= 2;
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
	 * Warm seat, gated on oversubscription. On a machine with more
	 * runnable work than CPUs, a task that has nowhere to run right
	 * now waits on the CPU it last ran on, right behind whatever
	 * runs there: its cache and TLB are still warm, and the CPU
	 * serves it at its next slice end. The shared queue would pull
	 * it to whichever CPU expires first, which is how a machine at
	 * oversubscription turns every rotation into a cold migration -
	 * the medium rig loses 11% to that and pure flash, with no warm
	 * path at all, loses 14%.
	 *
	 * At the wall the seat is poison: with every lane holding one
	 * task, the seat freezes whatever lane skew exists - overloaded
	 * lanes rotate internally while the lanes whose task blocked
	 * starve, and the instrumentation shows the argon2 run then
	 * burns its wall clock at 68% utilization where the cold path
	 * holds 97%. The discriminator is the machine's outstanding
	 * runnable work - running lanes plus everything queued, shared
	 * or warm. It is conserved across the running-to-queued
	 * transitions that race a bare nr_running gate (the E5 lesson:
	 * workers block between chunks and the counter dips), and it
	 * reads 12-13 at the wall against 14+ under oversubscription.
	 * One lane of margin keeps the wall's transient two-deep queue
	 * from flipping the mode back.
	 */
		if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
			s32 target = prev_cpu;
			u64 target_nr = scx_bpf_dsq_nr_queued(cpu2dsq(target));
			u64 warm_total = 0, best_nr = target_nr, i;
			u32 best_rank = BABY_DIST_SELF, rank;
			s32 best = target;

			bpf_for(i, 0, nr_cpu_ids) {
				u64 nr = scx_bpf_dsq_nr_queued(cpu2dsq(i));

				warm_total += nr;

				/*
				 * The warm-seat balance: a wake whose previous CPU
				 * already holds two more waiting tasks than the
				 * shallowest warm queue seats the shallowest one
				 * instead, the way the old saturation rebalance
				 * evened the home queues out. Without it the seats
				 * drift into a skew that no idle CPU can heal,
				 * since a warm queue is invisible to the other
				 * CPUs; the shared queue only sees what spills
				 * into it.
				 *
				 * Depth dominates, distance breaks ties: among
				 * queues at the same depth, the one nearest the
				 * task's previous CPU - SMT sibling before a
				 * farther core - keeps the refill cost down
				 * without giving up any of the balance. The
				 * distance is computed once per queue into a
				 * variable (see the note on cpu_dist): two
				 * inlined evaluations in the comparison below
				 * explode the verifier's state space.
				 */
				if (!(enq_flags & SCX_ENQ_WAKEUP) ||
				    !bpf_cpumask_test_cpu((s32)i, p->cpus_ptr))
					continue;

				rank = cpu_dist(prev_cpu, i);
				if (nr < best_nr ||
				    (nr == best_nr && rank < best_rank)) {
					best = (s32)i;
					best_nr = nr;
					best_rank = rank;
				}
			}

			if (nr_running + backlog + warm_total > nr_cpu_ids + 1) {
				/*
				 * On a deep backlog - shared or local - the
				 * task will rotate anyway and every extra
				 * rotation costs a full switch, so grant four
				 * times the slice: the upward rung of the
				 * E11 ladder, untried there, run here as the
				 * negative control on the rotation-rhythm
				 * reading.
				 */
				slice = (backlog_deep(backlog) || target_nr >= 2) ?
					4 * deadline_ns : task_slice(tctx);

				if (best != target && best_nr + 2 <= target_nr) {
					target = best;
					target_nr = best_nr;
					__sync_fetch_and_add(
						&nr_seat_move[cpu_dist(prev_cpu,
								       target)],
						1);
				} else {
					__sync_fetch_and_add(&nr_seat_self, 1);
				}

				scx_bpf_dsq_insert_vtime(p, cpu2dsq(target), slice,
							 tctx->deadline, 0);
				stamp_wait(tctx, now, target_nr, false);
				__sync_fetch_and_add(&nr_arr_seat, 1);
				__sync_fetch_and_add(&nr_warmseats, 1);
				scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
				return;
			}

		/*
		 * Not oversubscribed: leave the seat open and let the
		 * cold path run - a requeue re-scans for an idle lane
		 * before joining the shared queue, which is what keeps
		 * the wall's load distribution flowing.
		 */
		__sync_fetch_and_add(&nr_coldspreads, 1);
	}

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

	/*
	 * Consumption census: the queue state this lane came to pick
	 * work from - the depth left in its warm seat and the shared
	 * backlog the rotation turns on. Sampled at every dispatch, so
	 * the distribution carries the consumption-rate weighting the
	 * arrival-time wait stamp lacks.
	 */
	{
		u64 seat = scx_bpf_dsq_nr_queued(cpu2dsq(cpu));
		u64 backlog = scx_bpf_dsq_nr_queued(node);
		u8 s = (u8)MIN(seat, BABY_CENSUS_NR - 1);
		u8 g = (u8)MIN(backlog, BABY_CENSUS_NR - 1);

		__sync_fetch_and_add(&nr_census_seat[s & (BABY_CENSUS_NR - 1)], 1);
		__sync_fetch_and_add(&nr_census_shared[g & (BABY_CENSUS_NR - 1)], 1);
	}

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
	} else if (cpuperf_lvl < 0) {
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
static void update_cpuperf(struct cpu_ctx *cctx, s32 cpu, bool max_floor);

void BPF_STRUCT_OPS(baby_tick, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
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

	tctx->last_acc_at = now;

	/*
	 * Charge the wait the task actually served to the depth bucket
	 * its arrival was stamped with. The index is masked because a
	 * reloaded u8 proves nothing to the verifier; the stored value
	 * is already clamped, so the mask only ever matters for a
	 * corrupted stamp.
	 */
	if (tctx->wait_stamp) {
		u64 wait = now - tctx->wait_stamp;
		u32 b = tctx->wait_depth & (BABY_WDEPTH_NR - 1);
		u32 c = tctx->wait_cls & (BABY_WCLS_NR - 1);
		u32 i = c * BABY_WDEPTH_NR + b;

		tctx->wait_stamp = 0;
		__sync_fetch_and_add(&nr_wait_n[b], 1);
		__sync_fetch_and_add(&nr_wait_ns[b], wait);
		if (wait > nr_wait_max[b])
			nr_wait_max[b] = wait;
		if (wait > BABY_WAIT_SLOW_NS)
			__sync_fetch_and_add(&nr_wait_slow[b], 1);
		__sync_fetch_and_add(&nr_wait_cls_n[i], 1);
		__sync_fetch_and_add(&nr_wait_cls_ns[i], wait);
		if (wait > nr_wait_cls_max[i])
			nr_wait_cls_max[i] = wait;
		if (wait > BABY_WAIT_SLOW_NS)
			__sync_fetch_and_add(&nr_wait_cls_slow[i], 1);

		u32 t = tctx->arrival_is_wake & 1;
		u32 ti = t * BABY_WDEPTH_NR + b;

		__sync_fetch_and_add(&nr_wait_type_n[ti], 1);
		__sync_fetch_and_add(&nr_wait_type_ns[ti], wait);
		if (wait > nr_wait_type_max[ti])
			nr_wait_type_max[ti] = wait;
		if (wait > BABY_WAIT_SLOW_NS)
			__sync_fetch_and_add(&nr_wait_type_slow[ti], 1);
	}

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
		       .cpu_release		= (void *)baby_cpu_release,
		       .init_task		= (void *)baby_init_task,
		       .init			= (void *)baby_init,
	       .exit			= (void *)baby_exit,
	       .timeout_ms		= 5000,
	       .name			= "baby");
