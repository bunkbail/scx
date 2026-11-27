/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Umbrella header of the BPF modules: every module includes this one, and
 * this one includes the scoped headers. It keeps the shared types, the
 * tunables and counters the skeleton publishes to userspace, the pure
 * helpers and the cross-module prototypes. The queue counters and the
 * statistics sit in stats.bpf.h and dispatch.bpf.h, the preemption floor
 * in preempt.bpf.h, the idle and direct-dispatch interface in idle.bpf.h
 * and the game pin in pin.bpf.h. Maps and globals are defined in exactly
 * one module and reached elsewhere only through what is declared here.
 */
#ifndef __BABY_H
#define __BABY_H

#include <scx/common.bpf.h>
#include "intf.h"

/*
 * The tier masks and the pin worker mask. Each is allocated once in
 * ops.init() and replaced only through bpf_kptr_xchg, so the storage
 * lives in .data.BABY in main.bpf.c and every other module reads it
 * through these declarations. A module that accidentally gets its own
 * definition compiles and loads, but starts NULL, and every reader
 * treats a NULL mask as "no restriction".
 */
extern struct bpf_cpumask __kptr *big_cpumask;
extern struct bpf_cpumask __kptr *little_cpumask;
extern struct bpf_cpumask __kptr *non_lp_cpumask;
extern struct bpf_cpumask __kptr *pin_worker_cpumask;

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
 * fire past an occupied bulk seat, and a per-CPU time budget bounds
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

/*
 * Distinct LLC ids on the machine, from the same dump that fills
 * topo_llc. The seat-steal walk reads it to drop its node ring on a
 * single-LLC machine, where the LLC ring already covers every CPU and
 * the outer rings only re-read the occupancy hints.
 */
extern const volatile u64 nr_llc_ids;

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

/*
 * The two bars are a hierarchy, not independent knobs: the foreground
 * class also earns the fourfold slice, so it has to stay strictly
 * narrower than the latency class, and no bar may sit above the wake
 * sample's cap (100 wakes per 100ms), or no task could ever reach it.
 */
_Static_assert(FOREGROUND_WAKE_FREQ > LAT_CRI_WAKE_FREQ,
	       "the foreground bar must stay above the latency bar");
_Static_assert(FOREGROUND_WAKE_FREQ <= 100,
	       "the wake sample is capped at 100, so a higher bar is unreachable");

/*
 * CPU runtime, since the last wake, a seat-guarded task may accumulate
 * before its latency credit is dropped.
 *
 * The peak hold latches by design (see struct task_ctx), and a task that
 * bursts once and then runs continuously never re-enters
 * class_on_runnable() to decay it, so the hold alone keeps a burst-then-
 * hog in the latency class forever. One quarter window is the heavy bar,
 * and it sits above the interval of a task at the latency bar, so a
 * waker that still meets the bar is never demoted between two wakes.
 */
#define WAKELESS_DEMOTE_NS	(TIME_PERIOD / 4)
_Static_assert(WAKELESS_DEMOTE_NS > 100ULL * NSEC_PER_MSEC / LAT_CRI_WAKE_FREQ,
	       "a task at the latency bar must not be demoted between wakes");
#define MIN_NICE		(-20)
#define MAX_RT_PRIO		100
#define MAX_PRIO		(MAX_RT_PRIO + 40)
#define PRIO_TO_NICE(prio)	((prio) - (MAX_RT_PRIO + 20))

/*
 * Default deadline offset (1.18ms, the original DEADLINE_NS).
 */
extern const volatile u64 deadline_ns;

/*
 * Plain EDF baseline (--plain): no warm seats, no two-lane split and no
 * lane arbitration. It exists for scheduler comparisons, not for
 * production.
 *
 * The seat guard is this flag's complement, so the reduced programs read
 * `!plain` where the full scheduler tested a second rodata bool: a
 * warm-seat placement has to earn its preemption and its deep rung, and
 * a CPU about to idle may take one task off another CPU's seat. The
 * guard exists because the two defaults it changes are only safe under
 * the full scheduler: a latency-critical arrival seated behind any
 * resident is handed a preemption kick, and a deep queue grants four
 * slices to whatever joins the shared queue. --game implies plain, so
 * every plain profile and --game prune the guarded branches and their
 * rodata stays inert.
 */
extern const volatile bool plain;

/* Plain mode on the base slice (--plain-1x). */
extern const volatile bool plain_1x;

/* Bounded wake preemption on top of --plain-1x (--plain-wake). */
extern const volatile bool plain_wake;

/*
 * Virtual-time ordering on top of --plain-1x (--plain-vtime): the node
 * queue is keyed by the task's weighted runtime instead of an absolute
 * deadline, with wake-frequency bounded credit.
 */
extern const volatile bool plain_vtime;
extern const volatile u64 vtime_lag_ns;

/*
 * The wait/census instrument and the distance histograms run; set
 * from --stats at load.
 */
extern const volatile bool stats_enabled;

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
extern const volatile u32 topo_sibling[BABY_MAX_CPUS];
extern const volatile u64 nr_little_cpus, nr_big_cpus;

_Static_assert(BABY_CPU_DSQ_BASE + BABY_MAX_CPUS <= BABY_FL_CPU_DSQ_BASE,
	       "per-CPU DSQ id space overlaps the fast-lane seats");
_Static_assert(BABY_FL_NODE_DSQ_BASE + BABY_MAX_NODES <= BABY_CPU_DSQ_BASE,
	       "per-node DSQ id space overlaps the bulk seats");

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
	 * Virtual time (--plain-vtime): runtime consumed, inversely
	 * scaled by weight, so a heavy task's second of CPU buys the
	 * same place that a light task's fraction does. Lifted to the
	 * node's credit floor on each wake (vtime_encode).
	 */
	u64 vtime;

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
	 * that, and the peak rises only once the four-sample warmup is
	 * done. The hold then decays by 1/64 per wake only while above
	 * 64 (a shift of a value below 64 is zero), so it falls from a
	 * spike to 63 and stays there. 63 is far above the class bar
	 * (5): on wakes alone the latency class latches once earned, by
	 * design. A real wake-rate decay would strip the class from a
	 * frame-paced thread the moment overcommit throttles its frame
	 * rate, which is the state the credit exists for. The latch is
	 * only safe while the task keeps waking: one that stops is
	 * demoted by update_bursts() after WAKELESS_DEMOTE_NS of runtime
	 * (seat guard only), so a burst-then-hog cannot keep the class.
	 */
	u32 peak_freq;

	/*
	 * Wake-frequency samples taken (warmup ends at WAKE_SANE_MIN).
	 * The peak may rise only after the warmup, so one startup spike
	 * cannot arm it.
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

	/*
	 * The CPU the task last ran on, or the CPU an RT lease or a wake
	 * preempt requeued it from. baby_dispatch() serves a displaced
	 * latency-critical task back there while its budget allows it and
	 * the task can run on another CPU. ops.stopping() can run on the
	 * task's new CPU after a migration, so the per-CPU state the run
	 * stamped must be cleared through the CPU that stamped it, not
	 * through scx_bpf_task_cpu().
	 */
	s32 last_cpu;

	/* The previous run's length, and the stamp it started at. */
	u64 last_run_ns;
	u64 run_start_ns;

	/*
	 * The queued arrival this task still owes its pending count to: a
	 * tag naming the queue's kind, lane and index, or zero when the
	 * task is in no tagged queue. baby_insert_vtime() sets it and
	 * baby_untag() clears it where the task is next seen running or
	 * enqueued, so the count is lowered exactly once per insert.
	 */
	u32 queued_tag;

	/*
	 * Game pin: the task's CPU duty, in q10 of a core, as an EWMA
	 * over the closed 200ms windows, the run of windows that held
	 * it at the second-slot bar, and the start_time of the window
	 * this duty last sampled. The window stamp makes the sampling
	 * a no-op on every tick inside a window.
	 */
	u32 duty_q10;
	u8 pin_streak;
	u64 pin_window;

	/*
	 * CPU runtime since the last wake, seat guard only: a value above
	 * WAKELESS_DEMOTE_NS drops the peak hold, which is how a task that
	 * burst once and then became a continuous hog loses its latency
	 * credit. Reset on every wake, so only a task that stopped waking
	 * accumulates it.
	 */
	u64 wakeless_ns;
};

/* Virtual-time key encoding for --plain-vtime (main.bpf.c). */
__hidden u64 vtime_encode(const struct task_struct *p, struct task_ctx *tctx,
			  s32 node);

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
 * waker, and one that burst once and then ran continuously drops the
 * credit once it has run WAKELESS_DEMOTE_NS since its last wake.
 */
static __always_inline bool is_lat_cri(const struct task_ctx *tctx)
{
	return tctx->wake_samples >= WAKE_SANE_MIN &&
	       tctx->peak_freq >= LAT_CRI_WAKE_FREQ;
}

/*
 * A task is foreground when it wakes at the class bar and does real
 * work: a browser renderer, an audio thread or a game renderer wakes
 * tens of times per window with sizable bursts, a CPU hog never wakes,
 * and a UI blip barely uses the CPU. Foreground earns the fourfold
 * slice, waker eligibility and precedence over the heavy pin in the
 * compaction, so light workers that cross the heavy bar with their
 * mutex spins keep the little-tier packing.
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
 * latency-critical (it clears the same wake bar; foreground only adds
 * the runtime floor), so a latency-critical check above the foreground
 * test would make the fourfold slice dead code. There is no upper burst
 * bound: a heavy waker that also does real work stays foreground, so
 * the hybrid compaction still lets foreground beat the heavy pin.
 */
static __always_inline u64 task_slice(const struct task_ctx *tctx)
{
	return !plain_1x && is_foreground(tctx) ? 4 * deadline_ns :
						  deadline_ns;
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
/*
 * The first task in @dsq that can run on @cpu. A plain peek stops at
 * the head, so an affinity-restricted head hides every task behind it:
 * a CPU that could run one of them reads the lane as empty, dispatches
 * nothing and goes idle, and the stranded work waits for an unrelated
 * wakeup. Peek the head locklessly first; only a head this CPU cannot
 * run needs the bounded scan, which keeps the verifier's trip count
 * constant and leaves work past the bound to the pull.
 */
#define BABY_DSQ_PEEK_NR	16

static __always_inline struct task_struct *dsq_peek_allowed(u64 dsq, s32 cpu)
{
	struct task_struct *p;
	u32 scanned = 0;

	p = __COMPAT_scx_bpf_dsq_peek(dsq);
	if (!p)
		return NULL;
	if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return p;

	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return p;
		if (++scanned >= BABY_DSQ_PEEK_NR)
			break;
	}
	return NULL;
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
u32 balance_cpu_dist(s32 a, s32 b);

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
 * The scoped headers. Nothing above this point depends on them; each one
 * reads the core types and macros defined before it.
 */
#include "stats.bpf.h"
#include "dispatch.bpf.h"
#include "preempt.bpf.h"
#include "idle.bpf.h"
#include "pin.bpf.h"

#endif /* __BABY_H */
