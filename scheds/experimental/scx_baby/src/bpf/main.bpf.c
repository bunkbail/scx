/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Every runnable task owns an absolute deadline and each CPU runs the
 * earliest one it can reach. Tasks that sleep before consuming their
 * deadline are treated as interactive and earn a nice boost; CPU hogs
 * are throttled by a burst tracker over a 200ms window.
 */
#include "baby.bpf.h"

char _license[] SEC("license") = "GPL";

/*
 * Default deadline offset and base slice, in nanoseconds (1.18ms from
 * the original DEADLINE_NS).
 */
const volatile u64 deadline_ns = 1180000ULL;

/* Report additional debugging information. */
const volatile bool debug;

/*
 * Big and little CPU sets, published by userspace at startup. They drive
 * the hybrid compaction below; both stay empty on a single-tier machine,
 * which disables every hybrid path.
 */
private(BABY) struct bpf_cpumask __kptr *big_cpumask;
private(BABY) struct bpf_cpumask __kptr *little_cpumask;

/*
 * Every CPU outside the LP islands: the mask the kernel selector may
 * pick from. scx_bpf_select_cpu_and() clears the chosen CPU's kernel
 * idle bit, and there is no helper to put it back, so an idle CPU this
 * scheduler does not dispatch to must never be picked in the first
 * place. The full task mask remains the fallback for a task whose
 * affinity allows only LP cores.
 */
private(BABY) struct bpf_cpumask __kptr *non_lp_cpumask;

/*
 * Saturation preemption: at full saturation a latency-critical waiter
 * parks behind a batch task for a full slice. The tick cuts the holder
 * short instead, under these gates:
 *
 * - the victim is not latency-critical, so batch workers never preempt
 *   each other;
 * - a latency-critical task waits at a head this CPU serves (its warm
 *   seat or the shared queue). With an idle CPU anywhere that task
 *   would have been pulled already, so a waiting head implies
 *   saturation;
 * - the victim has held the CPU for at least the protect window, so a
 *   task that just got the CPU keeps it;
 * - for a shared-queue head, one CPU at a time claims it: the per-CPU
 *   ticks would otherwise all preempt for the same waiter. The claim
 *   is per node and carries the waiter's pid, so it neither suppresses
 *   another node nor blocks a different head, and a successful pull
 *   from that node's fast-lane queue clears it. Warm-seat waiters are
 *   per-CPU precise; the victim's rotation pulls the waiter in the
 *   same scheduling cycle.
 *
 * The victim requeues with its deadline intact, behind the waiter, on
 * the base slice rather than the deep-backlog rung it did not earn.
 *
 * The waiting head is found by peeking, not by a latch signaled from
 * enqueue: the enqueue path sits at the verifier's jump-complexity
 * ceiling, and the peek/lookup/class pattern is already verifier-proven
 * in the rescue timer.
 */
/*
 * How long a victim must have held a CPU before a waiting task may
 * preempt it. The floor exists so two waiters cannot ping-pong one CPU:
 * a victim that just started makes progress before it is displaced
 * again. On a saturated CPU the floor is also the extra wait every
 * wake-side handoff pays on top of the victim's rotation, and a frame
 * producer at several hundred frames per second runs for only about a
 * millisecond per frame: a victim that has already held the CPU for
 * 200us covers a fifth of that frame, and waiting it out costs a whole
 * frame period. Fifty microseconds still gives a displaced task its
 * first slice of progress; the per-node claim and the latency-critical
 * victim refusal bound the churn on top of it.
 */
#define BABY_TICK_PREEMPT_PROTECT_NS	(50ULL * NSEC_PER_USEC)

/*
 * Fallback quiet window for the shared-queue claim. It covers the
 * tick -> resched -> dispatch flight, which may be diverted to a
 * warm-seat arrival and never pull the waiter. The claim is cleared by
 * a successful pull from the same fast-lane queue, so a later
 * staggered tick can serve the next waiter instead of waiting out a
 * slice; a new head may also claim without waiting for the window,
 * because the claim names the waiter it was made for.
 */
#define BABY_TICK_PREEMPT_FALLBACK_NS	(100ULL * NSEC_PER_USEC)

static u64 cpu_running_at[BABY_MAX_CPUS];
bool cpu_is_lat[BABY_MAX_CPUS];

/*
 * One anti-herd claim per node: the high 32 bits hold the waiter's pid,
 * the low 32 bits the claim time with its low bit forced to one, so a
 * zero word means unclaimed. A claim suppresses another CPU's tick only
 * for the same waiter; a different head may claim immediately. The
 * claim is cleared by a successful pull from that node's fast-lane
 * queue, not by a bulk pull or a seat pull, which serve other work.
 */
static u64 node_preempt_claim[BABY_NODE_CLOCK_NR];

/*
 * Per-queue service clocks for the starve rescue, indexed by lane
 * (0 bulk, 1 fast lane). A queue that has held work for a second
 * without a successful pull is re-enqueued. The clock is seeded when
 * the queue becomes non-empty and advanced on every successful pull,
 * so a continuously served queue never looks starved and a newly
 * populated one does not inherit the clock of the queue's birth. The
 * node clocks are shared by every CPU on the node, so their pulls
 * advance them at most once per millisecond; the one-second window
 * cannot tell. The per-CPU seat clocks stay exact.
 */
u64 seat_service_at[2][BABY_MAX_CPUS];
u64 node_service_at[2][BABY_NODE_CLOCK_NR];
u8 seat_used[2][BABY_MAX_CPUS];

/*
 * Fast-lane time budget, per CPU. The bucket accrues two thirds of
 * wall time as fast-lane credit and holds at most four base slices.
 * It is charged the span a fast-lane interval covers: the run itself,
 * not the slice it is granted, plus the stop-to-run gap to the next
 * run on the same CPU while bulk waits, charged before that run starts
 * whether it is bulk or fast-lane work. A task that sleeps early pays
 * only for what it used, a 50-60Hz frame thread keeps its share, and
 * the scheduling overhead between two fast-lane runs is not credited
 * for free. While a fast-lane interval runs the
 * net rate is +2/3 - 1 = -1/3 of wall time; while bulk runs it is
 * +2/3. The steady state is therefore a two thirds fast-lane and one
 * third bulk share of a contended CPU, independent of how long each
 * slice runs.
 *
 * A bulk run or an idle dispatch breaks the interval: the CPU was
 * doing other work, so the run that follows charges no gap for it.
 * An RT lease does the same; its time belongs to the RT task.
 *
 * The budget is consulted only while bulk work waits; on an
 * otherwise idle CPU the fast lane runs freely. The debt floor bounds
 * how far one burst can push bulk ahead, not how long the fast lane
 * may run.
 */
static s64 fl_budget_ns[BABY_MAX_CPUS];
static u64 fl_budget_at[BABY_MAX_CPUS];
static u64 cpu_fl_running_at[BABY_MAX_CPUS];

/*
 * Bulk backstop: the longest a CPU may run nothing but the fast lane
 * while bulk work keeps waiting for it. The time budget alone cannot
 * bound this: its credit is wall time, so a supply of fast-lane work
 * that switches often enough keeps the credit ahead of the charges. A
 * bulk task pinned to the CPU then waits behind a lane no other CPU can
 * pull, and the kernel's runnable-task watchdog unloads the scheduler
 * after five seconds. When the stamp is older than the bound, the
 * dispatcher serves bulk whatever the budget says.
 *
 * The stamp means "bulk last ran here, or had nothing to wait for
 * here": a quiet period refreshes it, so a burst that arrives after
 * 20ms of no bulk starts the clock instead of inheriting the idle time
 * and displacing a latency-critical resident at once.
 */
#define BABY_BULK_BACKSTOP_NS	(20ULL * NSEC_PER_MSEC)

static u64 cpu_bulk_at[BABY_MAX_CPUS];

static __always_inline void refill_fl_budget(u32 idx, u64 now)
{
	u64 elapsed = now - fl_budget_at[idx];
	s64 credit;

	if (!elapsed)
		return;
	/*
	 * Cap the credit window: a CPU that has been idle for a long
	 * time may start with a full bucket, not an unbounded one.
	 */
	if (elapsed > 100 * NSEC_PER_MSEC)
		elapsed = 100 * NSEC_PER_MSEC;
	credit = (s64)(elapsed * 2 / 3);
	fl_budget_ns[idx] = MIN(fl_budget_ns[idx] + credit,
				(s64)(4 * deadline_ns));
	fl_budget_at[idx] = now;
}

/*
 * Whether bulk work waits for a CPU: its own seat or the node queue.
 */
static __always_inline bool bulk_waiting(s32 cpu)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);

	/*
	 * Probe the seat directly: a pull can clear the seat hint while
	 * a concurrent enqueue has already set it and not yet committed
	 * the insert, and the hint would then hide a waiting task.
	 */
	return scx_bpf_dsq_nr_queued(cpu2dsq(cpu)) ||
	       scx_bpf_dsq_nr_queued(node);
}

/*
 * Charge the fast-lane runtime consumed since the last accounting
 * point. Only a contested interval debits the bucket: while no bulk
 * work waits, the fast lane runs freely and must not bank debt that
 * would stall it the moment bulk appears. The charge is capped at one
 * fourfold slice, the longest a fast-lane task can run without a tick,
 * so a stale stamp cannot clear the bucket in one go. The debt floor
 * is two base slices.
 */
static __always_inline void charge_fl_runtime(u32 idx, u64 now,
					      bool contended)
{
	u64 started = cpu_fl_running_at[idx];
	s64 floor = -(s64)(2 * deadline_ns);
	u64 ran;

	if (!started) {
		cpu_fl_running_at[idx] = now;
		return;
	}
	ran = now - started;
	if (ran > 4 * deadline_ns)
		ran = 4 * deadline_ns;
	if (contended)
		fl_budget_ns[idx] = MAX(fl_budget_ns[idx] - (s64)ran, floor);
	cpu_fl_running_at[idx] = now;
}

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
 * Pick the lowest-numbered idle CPU of the given tier, preferring a
 * wholly idle physical core and then the previous CPU. Stacking
 * wakeups on the same few cores lets the rest of the tier idle at its
 * boost floor; the first pass keeps two heavy tasks from landing on the
 * two threads of one physical core while other cores sit idle, and
 * the previous-CPU preference avoids a cold migration to an equally
 * shallow seat. The idle bit is claimed atomically; a lost race tries
 * the next bit of the tier instead of spilling to the kernel's
 * spread-first path.
 */
static __always_inline s32 pick_idle_pref(struct task_struct *p,
					  s32 prev_cpu,
					  struct bpf_cpumask *pref)
{
	const struct cpumask *idle_smt, *idle;
	s32 cpu = -1;
	s32 i;

	bpf_rcu_read_lock();
	idle_smt = scx_bpf_get_idle_smtmask();
	idle = scx_bpf_get_idle_cpumask();
	if (pref && idle_smt && idle) {
		/*
		 * Pass 1: a wholly idle physical core, previous CPU first.
		 */
		if (bpf_cpumask_test_cpu(prev_cpu, cast_mask(pref)) &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smt) &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			cpu = prev_cpu;

		if (cpu < 0) {
			bpf_for(i, 0, nr_cpu_ids) {
				if (!bpf_cpumask_test_cpu(i, cast_mask(pref)) ||
				    !bpf_cpumask_test_cpu(i, idle_smt) ||
				    !bpf_cpumask_test_cpu(i, p->cpus_ptr))
					continue;
				if (scx_bpf_test_and_clear_cpu_idle(i)) {
					cpu = i;
					break;
				}
			}
		}

		/*
		 * Pass 2: any idle CPU in the tier, previous CPU first.
		 */
		if (cpu < 0) {
			if (bpf_cpumask_test_cpu(prev_cpu, cast_mask(pref)) &&
			    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
			    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
				cpu = prev_cpu;

			if (cpu < 0) {
				bpf_for(i, 0, nr_cpu_ids) {
					if (!bpf_cpumask_test_cpu(i, cast_mask(pref)) ||
					    !bpf_cpumask_test_cpu(i, idle) ||
					    !bpf_cpumask_test_cpu(i, p->cpus_ptr))
						continue;
					if (scx_bpf_test_and_clear_cpu_idle(i)) {
						cpu = i;
						break;
					}
				}
			}
		}
	}
	if (idle_smt)
		scx_bpf_put_cpumask(idle_smt);
	if (idle)
		scx_bpf_put_cpumask(idle);
	bpf_rcu_read_unlock();
	return cpu;
}

/*
 * The kernel idle-CPU selection, restricted to the non-LP mask while
 * the tiers exist. scx_bpf_select_cpu_and() clears the chosen CPU's
 * kernel idle bit, and there is no helper that puts it back, so an LP
 * core picked here and then abandoned would stay marked busy and never
 * be picked again. The full task mask remains the fallback for a task
 * whose affinity allows only LP cores, and the CPU it returns is used.
 */
__hidden s32 select_cpu_no_lp(struct task_struct *p, s32 prev_cpu,
			      u64 wake_flags)
{
	struct bpf_cpumask *mask = non_lp_cpumask;
	s32 cpu = -1;

	/*
	 * Load the mask once, as scx_beerland does: a re-load after the
	 * helper could race an ops.init() replacement and give the
	 * verifier a different trusted state. The scheduling callbacks
	 * are non-sleepable, so the kptr read is already covered by the
	 * verifier's RCU rules.
	 */
	if (mask && !bpf_cpumask_empty(cast_mask(mask)))
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
					     cast_mask(mask), 0);

	if (cpu < 0)
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
					     p->cpus_ptr, 0);
	return cpu;
}

/*
 * Pick a target CPU for a waking task and dispatch it straight to the
 * pick when that CPU is idle. Placement is delegated to the kernel's
 * idle-CPU selection: SMT-aware, previous-CPU biased and spread across
 * LLCs.
 */
s32 BPF_STRUCT_OPS(baby_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	bool is_idle = false;
	s32 cpu;
	u64 now = bpf_ktime_get_ns();

	/*
	 * The miss reason always describes the most recent wake. Reset it
	 * at entry, before any early return; charge_wait() files it for a
	 * wake that actually waits.
	 *
	 * The burst window is rolled here, before the tier decision:
	 * ops.select_cpu() runs before ops.runnable(), so a task waking
	 * from a sleep would otherwise be classified on the window that
	 * ended during the sleep.
	 */
	if (tctx) {
		tctx->wake_gate_miss = BABY_WG_NO_GATE;
		roll_burst_window(tctx, now);
	}

	/*
	 * Don't trust the sync hint: a waker that keeps running after the
	 * wake would stack the wakee behind it while other CPUs idle.
	 */
	wake_flags &= ~SCX_WAKE_SYNC;

	/*
	 * Light-placement compaction: at light load the kernel selector is
	 * previous-CPU biased and spreads across LLCs, which parks short
	 * workers on whichever core they first touched and scatters them
	 * across tiers. Below the saturation line, pack wakeups
	 * lowest-idle-first onto the little tier instead: foreground and
	 * interactive tasks stack there, a proven consumer with no wake
	 * history pins a big core, and a proven consumer that is also
	 * foreground starts little and falls back to big. The gates are
	 * statically false on a single-tier machine and disengage before
	 * saturation.
	 */
	if (tctx && nr_little_cpus && nr_big_cpus &&
	    nr_running <= nr_little_cpus + 2) {
		bool big_pin = is_heavy_proven(tctx) && !is_foreground(tctx);

		cpu = big_pin ? pick_idle_pref(p, prev_cpu, big_cpumask)
			      : pick_idle_pref(p, prev_cpu, little_cpumask);
		if (cpu < 0 && !big_pin && is_heavy_proven(tctx))
			cpu = pick_idle_pref(p, prev_cpu, big_cpumask);
		if (cpu >= 0) {
			if (stats_enabled)
				__sync_fetch_and_add(
					&nr_wake_land[cpu_dist(prev_cpu,
								       cpu)],
					1);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
					   task_slice(tctx), 0);
			if (stats_enabled)
				__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return cpu;
		}
	}

	/*
	 * A waking latency-critical task keeps its own CPU when that CPU is
	 * usable, before the idle selector is asked at all. The selector
	 * spreads across idle cores, which parks a frame producer on a cold
	 * core whenever its own is momentarily busy with a helper, and a
	 * frame producer woken every millisecond pays the refill on every
	 * move. Its cache-warm CPU is the placement the spread has to beat,
	 * not the other way around.
	 *
	 * Usable means idle and allowed, or busy with a cuttable bulk
	 * resident: the same preempt the wake gate below performs, but
	 * reached before an idle CPU elsewhere wins the wake. A latency-
	 * critical resident keeps its CPU, and the wakee spreads instead,
	 * so two pipeline stages cannot stack on one CPU by this path.
	 * The miss reasons are left to the gate below; this block only
	 * returns where it has already placed the task.
	 */
	if (tctx && is_lat_cri(tctx) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		u32 pidx = (u32)prev_cpu & (BABY_MAX_CPUS - 1);
		bool allowed = true;
		struct bpf_cpumask *mask = non_lp_cpumask;

		if (mask && !bpf_cpumask_empty(cast_mask(mask)))
			allowed = bpf_cpumask_test_cpu(prev_cpu,
						       cast_mask(mask));

		if (allowed) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
						   task_slice(tctx), 0);
				if (stats_enabled)
					__sync_fetch_and_add(
						&nr_direct_dispatches, 1);
				return prev_cpu;
			}

			if (!scx_bpf_dsq_nr_queued(fl_cpu2dsq(prev_cpu)) &&
			    !scx_bpf_dsq_nr_queued(cpu2dsq(prev_cpu)) &&
			    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON |
						   prev_cpu)) {
				struct task_struct *curr =
					__COMPAT_scx_bpf_cpu_curr(prev_cpu);
				struct task_ctx *cctx = curr ?
					try_lookup_task_ctx(curr) : NULL;
				u64 ran_at = cpu_running_at[pidx];

				if (curr && curr != p &&
				    !(curr->flags & PF_IDLE) && cctx &&
				    !is_lat_cri(cctx) && !is_pcpu_task(curr) &&
				    p->static_prio <= curr->static_prio &&
				    ran_at &&
				    now - ran_at >=
					    BABY_TICK_PREEMPT_PROTECT_NS) {
					scx_bpf_dsq_insert(p,
							   SCX_DSQ_LOCAL_ON |
							   prev_cpu,
							   task_slice(tctx),
							   SCX_ENQ_PREEMPT);
					if (stats_enabled)
						__sync_fetch_and_add(
							&nr_wake_preempts, 1);
					return prev_cpu;
				}
			}
		}
	}

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		if (stats_enabled)
			__sync_fetch_and_add(
				&nr_wake_land[cpu_dist(prev_cpu, cpu)], 1);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
				   tctx ? task_slice(tctx) : deadline_ns, 0);
		if (stats_enabled)
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
	} else if (wake_flags & (SCX_WAKE_TTWU | SCX_WAKE_FORK)) {
		/*
		 * No idle CPU: the depth-0 wake-path preempt, the
		 * wake-time twin of the tick gate. If the wakee is
		 * latency-critical and its previous CPU runs a
		 * non-latency-critical victim, hand it the CPU now
		 * instead of waiting for the tick.
		 *
		 * The deadline-beat check and can_resched() are
		 * deliberately absent. The victim renews its deadline
		 * while it runs, so the beat rarely binds, and the tick
		 * gate cuts the same victims without either check. The
		 * class pair, the priority order and the residency floor
		 * bound the churn.
		 *
		 * SCX_ENQ_PREEMPT puts the wakee at the head of the local
		 * DSQ, zeroes the victim's slice and reschedules. The
		 * victim goes through ops.enqueue() with its running bit
		 * still set, so it takes the natural-expiry path there: a
		 * fresh deadline, and the deep-backlog rung when the bulk
		 * backlog is deep. Only a preemption by a higher sched
		 * class leaves the victim parked at the local DSQ head
		 * without an enqueue.
		 */
		struct task_struct *curr;
		struct task_ctx *cctx;
		u32 pcpu_idx = (u32)prev_cpu & (BABY_MAX_CPUS - 1);
		u64 ran_at;

		if (!tctx)
			return cpu;
		if (!is_lat_cri(tctx)) {
			tctx->wake_gate_miss = BABY_WG_M1_NOT_LAT;
			return cpu;
		}
		if (!bpf_cpumask_test_cpu(pcpu_idx, p->cpus_ptr)) {
			tctx->wake_gate_miss = BABY_WG_M2_AFFINITY;
			return cpu;
		}
		/*
		 * A bulk head in the warm seat cannot hide the wakee: it
		 * runs on its own fast-lane seat, so only a fast-lane
		 * waiter blocks the preempt. Repetition is bounded by the
		 * latency-critical victim refusal below and by the
		 * residency stamp; the displaced victim is requeued
		 * through the natural-expiry path in ops.enqueue(). The
		 * time budget takes no part here: the preempt happens
		 * between dispatches.
		 */
		if (scx_bpf_dsq_nr_queued(fl_cpu2dsq(prev_cpu))) {
			tctx->wake_gate_miss = BABY_WG_M3_SEAT_BUSY;
			return cpu;
		}
		if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cpu)) {
			tctx->wake_gate_miss = BABY_WG_M3_LOCAL_BUSY;
			return cpu;
		}

		curr = __COMPAT_scx_bpf_cpu_curr(prev_cpu);
		if (!curr || curr == p || (curr->flags & PF_IDLE)) {
			tctx->wake_gate_miss = BABY_WG_M4_DEGEN;
			return cpu;
		}
		cctx = try_lookup_task_ctx(curr);
		if (!cctx) {
			tctx->wake_gate_miss = BABY_WG_M4_DEGEN;
			return cpu;
		}
		if (is_lat_cri(cctx)) {
			tctx->wake_gate_miss = BABY_WG_M4_VICTIM_LAT;
			/*
			 * The previous CPU runs another latency-critical
			 * task. The miss stamp makes balance_try_warm_seat()
			 * spread the wakee to the nearest CPU with an empty
			 * fast-lane seat instead of stacking it here.
			 */
			return cpu;
		}
		if (p->static_prio > curr->static_prio) {
			tctx->wake_gate_miss = BABY_WG_M4_PRIO;
			return cpu;
		}

		ran_at = cpu_running_at[pcpu_idx];
		if (!ran_at ||
		    now - ran_at < BABY_TICK_PREEMPT_PROTECT_NS) {
			tctx->wake_gate_miss = BABY_WG_M5_RESIDENCY;
			return cpu;
		}

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
				   task_slice(tctx), SCX_ENQ_PREEMPT);
		if (stats_enabled) {
			__sync_fetch_and_add(&nr_wake_preempts, 1);
			__sync_fetch_and_add(
				&nr_wake_land[cpu_dist(prev_cpu, prev_cpu)],
				1);
		}

		return prev_cpu;
	}

	return cpu;
}

/*
 * Enqueue a task with no idle CPU to run on. The node queue is ordered
 * by deadline, and dispatch takes the earliest one.
 */
void BPF_STRUCT_OPS(baby_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 prev_cpu = scx_bpf_task_cpu(p);
	s32 node = __COMPAT_scx_bpf_cpu_node(prev_cpu);
	bool is_running = scx_bpf_task_running(p);
	u64 bulk_backlog, fl_backlog, slice, now = bpf_ktime_get_ns();

	if (!tctx)
		return;

	tctx->last_acc_at = now;

	/*
	 * The two lanes are counted separately: a fast-lane backlog must
	 * not open a bulk seat or grant a bulk arrival the deep rung, and
	 * a bulk backlog must not open a fast-lane seat. The probe cannot
	 * run inside an RCU read-side section; enqueue is outside one.
	 */
	bulk_backlog = scx_bpf_dsq_nr_queued(node);
	fl_backlog = scx_bpf_dsq_nr_queued(fl_node2dsq(node));

	/*
	 * Consume the yield mark on every enqueue: a mark that survived
	 * into an unrelated enqueue would push the wrong arrival behind
	 * the round. The push applies only to the rotation requeue that
	 * follows the yield, never to a wake, which keeps the sleep-time
	 * deadline.
	 */
	bool yielded = tctx->yield_pending;

	tctx->yield_pending = false;

	if (yielded && !(enq_flags & SCX_ENQ_WAKEUP)) {
		/*
		 * yield_task_fair() marks the deadline so the task is
		 * picked last in the current round; push it behind every
		 * task queued in its lane in this round. A fixed two-slice
		 * push skipped at most two of them.
		 */
		u64 lane_backlog = is_lat_cri(tctx) ? fl_backlog :
						      bulk_backlog;

		tctx->deadline = now + (lane_backlog + 1) * deadline_ns;
	} else if ((!is_running || !tctx->tick_preempted) &&
		   !(enq_flags & (SCX_ENQ_LAST | SCX_ENQ_WAKEUP |
				  SCX_ENQ_REENQ))) {
		/*
		 * A migrated or freshly created task gets a fresh deadline,
		 * and so does a rotation whose slice expired naturally: it
		 * consumed the slice it was granted, so the fresh deadline
		 * is its next turn. Only a task cut short by the tick keeps
		 * the deadline ops.stopping() left it with, so its
		 * remaining turn ages instead of being recomputed. Woken
		 * tasks keep the sleep-time deadline, a cpu_release()
		 * requeue keeps its place, and SCX_ENQ_LAST is the same
		 * task re-entering after an empty dispatch.
		 */
		tctx->deadline = calc_deadline(p, tctx, now);
	}

	/*
	 * A latency-critical task that is requeued while it still owns the
	 * CPU (a wake-preempt or a timer cut) or comes back from an RT
	 * lease keeps that CPU as its home. baby_dispatch() serves it back
	 * there while the budget has overdraw left, provided the task can
	 * run on another CPU: a pinned task's take-back would leave bulk
	 * work pinned to the same CPU with nowhere else to run.
	 */
	if (is_lat_cri(tctx) &&
	    (is_running || (enq_flags & SCX_ENQ_REENQ))) {
		tctx->last_cpu = prev_cpu;
		if ((enq_flags & SCX_ENQ_REENQ) && stats_enabled)
			__sync_fetch_and_add(&nr_lease_requeues, 1);
	}

	/*
	 * check_preempt_wakeup(): preempt the previous CPU's task when the
	 * waker has an earlier deadline and no lower priority, provided
	 * the CPU has no warm backlog and the running task passes
	 * can_resched(). A preemption into a deep queue would only trade
	 * places with work that runs anyway, and a burst hog must not be
	 * preempted. Only interactive and foreground wakers are eligible:
	 * a task that never wakes has no latency to protect. The victim
	 * warm-seats behind its successor, so this is a same-CPU
	 * alternation.
	 *
	 * The guards mirror ops.select_cpu()'s wake gate: the wakee must
	 * be allowed on the target, no in-flight wakee may hold the local
	 * DSQ (the insert would queue behind it), and the deadline order
	 * arbitrates between two latency-critical tasks as it does between
	 * bulk ones.
	 */
	if ((enq_flags & SCX_ENQ_WAKEUP) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    !scx_bpf_dsq_nr_queued(fl_cpu2dsq(prev_cpu)) &&
	    !scx_bpf_dsq_nr_queued(cpu2dsq(prev_cpu)) &&
	    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cpu) &&
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
				if (stats_enabled)
					__sync_fetch_and_add(&nr_preemptions, 1);
				return;
			}
		}
	}

	/*
	 * Grab a confirmed idle CPU if the machine still has one: a task
	 * that stopped on a loaded core spreads to a core that went idle
	 * since, and a reenqueued task rescans after an RT lease. This
	 * runs before the warm seat so a requeue or rescue never parks on
	 * a busy seat while a lane sits idle.
	 */
	if (try_direct_dispatch(p, tctx, prev_cpu, enq_flags, is_running))
		return;

	/*
	 * Warm seat, gated on oversubscription (see balance.bpf.c).
	 */
	if (balance_try_warm_seat(p, tctx, enq_flags, bulk_backlog,
				  fl_backlog, now))
		return;

	/*
	 * No idle CPU: join the deadline order. A deep backlog grants the
	 * fourfold slice; a tick-preempted victim keeps the base slice.
	 * Latency-critical tasks use their own node queue, which dispatch
	 * serves ahead of bulk while the time budget allows.
	 */
	{
		bool lat = is_lat_cri(tctx);
		u64 lane_backlog = lat ? fl_backlog : bulk_backlog;
		u64 dsq = lat ? fl_node2dsq(node) : (u64)node;

		/*
		 * Seed the rescue clock when the lane's shared queue was
		 * empty; a queue that is already served does not need it.
		 */
		if (!lane_backlog)
			node_service_at[lat & 1][node &
						 (BABY_NODE_CLOCK_NR - 1)] = now;

		slice = backlog_deep(lane_backlog) && !tctx->tick_preempted
			? 4 * deadline_ns : task_slice(tctx);

		scx_bpf_dsq_insert_vtime(p, dsq, slice, tctx->deadline,
					 enq_flags);
		stamp_wait(tctx, now, lane_backlog, true);
	}

	/*
	 * The task is placed without the wake side effect of
	 * ops.select_cpu(), so wake the CPU that will pull it if idle.
	 */
	if (!is_running && !__COMPAT_is_enq_cpu_selected(enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Dispatch the earliest-deadline task to the CPU.
 *
 * The lanes arbitrate per dispatch: the fast lane is served whenever it
 * holds work and the CPU's time budget allows it, the bulk lane
 * otherwise. The budget accrues two thirds of wall time, so bulk keeps
 * at least a third of a contended CPU no matter how long the fast
 * lane's slices are.
 */
void BPF_STRUCT_OPS(baby_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_ctx *tctx = prev ? try_lookup_task_ctx(prev) : NULL;
	bool need_running = prev && is_queued(prev);
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);
	u32 nidx = (u32)node & (BABY_NODE_CLOCK_NR - 1);
	u64 fl_seat_dsq = fl_cpu2dsq(cpu);
	u64 fl_node_dsq = fl_node2dsq(node);
	u64 bulk_seat_dsq = cpu2dsq(cpu);
	struct task_struct *fl_wq, *fl_q, *wq, *q;
	u64 fl_wq_dl, fl_g_dl, wq_dl, g_dl, fl_dl, bulk_dl, best_dl;
	u64 now = bpf_ktime_get_ns();
	bool has_fl, has_bulk, fl_allowed, serve_fl;
	/*
	 * The budget carried into this dispatch, before its own credit.
	 * The take-back below is bounded by this value, not by the
	 * refilled one: the dispatch credit would otherwise lift the
	 * budget off the debt floor on every call and the exemption would
	 * be granted forever.
	 */
	s64 fl_budget_in = fl_budget_ns[idx];

	census_sample(cpu);
	refill_fl_budget(idx, now);

	/*
	 * One peek of each lane per dispatch: the sticky check and the
	 * arbitration read the same heads, and the peeked pointers stay
	 * valid until the pulls enter their own RCU scope. The shared
	 * heads are the first task this CPU can run, not the queue head:
	 * an affinity-restricted head must neither read as the lane's
	 * next deadline here nor hide the tasks behind it.
	 */
	fl_wq = __COMPAT_scx_bpf_dsq_peek(fl_seat_dsq);
	fl_q = dsq_peek_allowed(fl_node_dsq, cpu);
	wq = __COMPAT_scx_bpf_dsq_peek(bulk_seat_dsq);
	q = dsq_peek_allowed(node, cpu);

	fl_wq_dl = fl_wq ? fl_wq->scx.dsq_vtime : ULLONG_MAX;
	fl_g_dl = fl_q ? fl_q->scx.dsq_vtime : ULLONG_MAX;
	wq_dl = wq ? wq->scx.dsq_vtime : ULLONG_MAX;
	g_dl = q ? q->scx.dsq_vtime : ULLONG_MAX;

	/*
	 * Lane emptiness reads off the deadline sentinels, not the peeked
	 * pointers: an OR of two pointer null-tests compiles to
	 * pointer|pointer, which the verifier rejects. No vtime reaches
	 * ULLONG_MAX, so the sentinel means an empty lane.
	 */
	fl_dl = MIN(fl_wq_dl, fl_g_dl);
	bulk_dl = MIN(wq_dl, g_dl);
	has_fl = fl_dl != ULLONG_MAX;
	has_bulk = bulk_dl != ULLONG_MAX;
	/*
	 * An uncontested interval must not leave debt behind: the fast
	 * lane ran freely, so clear what an earlier contention left.
	 */
	if (!has_bulk && fl_budget_ns[idx] < 0)
		fl_budget_ns[idx] = 0;
	fl_allowed = !has_bulk || fl_budget_ns[idx] > 0;
	serve_fl = has_fl && fl_allowed;

	/*
	 * The bulk clock starts when bulk work arrives, not when the last
	 * bulk task ran: refresh it while no bulk waits (and on a CPU that
	 * has never recorded a run), so a burst after a quiet period does
	 * not fire the backstop on its first dispatch.
	 */
	if (!has_bulk || !cpu_bulk_at[idx])
		cpu_bulk_at[idx] = now;

	/*
	 * Bulk backstop (see cpu_bulk_at): a CPU that has run nothing but
	 * the fast lane for a full bound serves bulk now, whatever the
	 * budget or a home head says. Pinned bulk work has no other CPU
	 * to run on, so the alternative is the kernel's stall watchdog.
	 */
	if (has_bulk && now - cpu_bulk_at[idx] > BABY_BULK_BACKSTOP_NS) {
		if (stats_enabled &&
		    (has_fl || (need_running && tctx && is_lat_cri(tctx))))
			__sync_fetch_and_add(&nr_bulk_backstop, 1);
		fl_allowed = false;
		serve_fl = false;
	} else if (has_fl && !fl_allowed &&
		   fl_budget_in > -(s64)(2 * deadline_ns)) {
		/*
		 * A fast-lane head this CPU was running when it was
		 * displaced is served back even with the budget spent: the
		 * CPU takes back its own resident instead of making it
		 * wait for another CPU's tick. The exemption spends only
		 * credit the CPU banked while not running the fast lane:
		 * once the debt reaches the two-slice floor the runtime
		 * charge enforces, the next dispatch carries no overdraw
		 * left and serves bulk.
		 *
		 * The task must be able to run elsewhere. A pinned
		 * fast-lane task would otherwise take its CPU back for as
		 * long as it keeps arriving, and bulk work pinned to the
		 * same CPU would never run there; such a task waits in the
		 * shared queue like any other.
		 */
		struct task_struct *head = (fl_g_dl < fl_wq_dl) ? fl_q : fl_wq;
		struct task_ctx *hctx = head ? try_lookup_task_ctx(head) : NULL;

		if (hctx && hctx->last_cpu == cpu && !is_pcpu_task(head)) {
			fl_allowed = true;
			serve_fl = true;
			if (stats_enabled)
				__sync_fetch_and_add(&nr_home_takebacks, 1);
		}
	}

	/*
	 * The tick cut this CPU's resident for a fast-lane waiter, but
	 * the arbitration above will not serve that waiter: the tick
	 * gate claims a head without consulting this CPU's budget.
	 */
	if (tctx && tctx->tick_preempted && has_fl && !serve_fl) {
		if (stats_enabled)
			__sync_fetch_and_add(&nr_tick_cut_refused, 1);
	}

	if (need_running && tctx && !tctx->yield_pending) {
		/*
		 * Keep the current task only while its deadline beats the
		 * earliest head of the lane that would run next; ties go to
		 * the waiter. A yielding task has given the round up. The
		 * budget has the last word over a latency-critical resident:
		 * when it is spent and bulk work waits, the resident rotates
		 * like any other task. A bulk task cannot keep the CPU out of
		 * turn when the fast lane is served either.
		 */
		bool keep_ok;

		if (is_lat_cri(tctx)) {
			keep_ok = fl_allowed;
			best_dl = has_fl ? fl_dl : 0;
		} else {
			keep_ok = !serve_fl;
			best_dl = bulk_dl;
		}

		if (keep_ok) {
			/*
			 * Compare before renewing: a resident whose
			 * deadline is due still owns its turn against a
			 * later waiter, and renewing first would move it
			 * past that waiter and kill the keep. A keep skips
			 * ops.stopping(), so renew the deadline and
			 * restamp the per-CPU state inside the branch.
			 */
			if (!best_dl ||
			    (s64)(tctx->deadline - best_dl) < 0) {
				if (reached_deadline(tctx, now))
					tctx->deadline = calc_deadline(prev, tctx, now);
				/*
				 * The victim kept its CPU, so the tick's
				 * cut did not happen: consume the mark
				 * here, where no ops.running() will run to
				 * clear it, or its next natural requeue
				 * would take the deep-backlog rung it did
				 * not earn.
				 */
				update_bursts(tctx, now);
				tctx->tick_preempted = false;
				tctx->last_cpu = cpu;
				cpu_running_at[idx] = now;
				cpu_is_lat[idx] = is_lat_cri(tctx);
				if (!cpu_is_lat[idx])
					cpu_bulk_at[idx] = now;
				/*
				 * The cpuperf ledger is deliberately left
				 * alone: ticks advance it, and charging the
				 * slice here would be counted again by the
				 * next tick.
				 */
				{
					u64 grant = task_slice(tctx);

					if (is_lat_cri(tctx))
						charge_fl_runtime(idx, now,
								  has_bulk);
					scx_bpf_task_set_slice(prev, grant);
				}
				if (stats_enabled)
					__sync_fetch_and_add(&nr_sticky, 1);
				return;
			}
		}
	}

	/*
	 * Serve the fast lane: the node queue first when its head beats
	 * the seat's (the seat wins ties), then the seat, then the node
	 * queue again for a raced first try. The service's runtime is
	 * charged when the task runs, not at the pull.
	 */
	if (serve_fl) {
		if (fl_g_dl < fl_wq_dl) {
			s32 from = fl_q ? scx_bpf_task_cpu(fl_q) : -1;

			if (scx_bpf_dsq_move_to_local(fl_node_dsq, 0)) {
				if (node_preempt_claim[nidx])
					node_preempt_claim[nidx] = 0;
				if (now - node_service_at[1][nidx] >
				    NSEC_PER_MSEC)
					node_service_at[1][nidx] = now;
				if (has_bulk) {
					if (stats_enabled)
						__sync_fetch_and_add(
							&nr_depth1_pulls, 1);
				} else if (stats_enabled) {
					__sync_fetch_and_add(
						&nr_pull_land[cpu_dist(cpu,
								       from)],
						1);
				}
				return;
			}
		}
		if (scx_bpf_dsq_move_to_local(fl_seat_dsq, 0)) {
			seat_service_at[1][idx] = now;
			if (seat_used[1][idx] &&
			    !scx_bpf_dsq_nr_queued(fl_seat_dsq))
				seat_used[1][idx] = 0;
			if (has_bulk) {
				if (stats_enabled)
					__sync_fetch_and_add(
						&nr_depth1_pulls_seat, 1);
			}
			return;
		}
		if (scx_bpf_dsq_move_to_local(fl_node_dsq, 0)) {
			if (node_preempt_claim[nidx])
				node_preempt_claim[nidx] = 0;
			if (now - node_service_at[1][nidx] >
			    NSEC_PER_MSEC)
				node_service_at[1][nidx] = now;
			if (has_bulk) {
				if (stats_enabled)
					__sync_fetch_and_add(
						&nr_depth1_pulls, 1);
			}
			return;
		}
	}

	/*
	 * Serve the bulk lane: the fast lane is empty, its move raced, or
	 * the budget is spent. The shared queue wins when its head is
	 * strictly earlier, so a self-sustaining warm queue cannot starve
	 * the overflow.
	 */
	if (g_dl < wq_dl) {
		/*
		 * Read the node head's CPU while q is fresh: the pull below
		 * may enter an RCU scope, and a pointer peeked before it
		 * cannot be re-read after the unlock.
		 */
		s32 from = q ? scx_bpf_task_cpu(q) : -1;

		if (scx_bpf_dsq_move_to_local(node, 0)) {
			if (now - node_service_at[0][nidx] >
			    NSEC_PER_MSEC)
				node_service_at[0][nidx] = now;
			if (stats_enabled)
				__sync_fetch_and_add(
					&nr_pull_land[cpu_dist(cpu, from)], 1);
			return;
		}
		if (scx_bpf_dsq_move_to_local(bulk_seat_dsq, 0)) {
			seat_service_at[0][idx] = now;
			if (seat_used[0][idx] &&
			    !scx_bpf_dsq_nr_queued(bulk_seat_dsq))
				seat_used[0][idx] = 0;
			return;
		}
	} else {
		if (scx_bpf_dsq_move_to_local(bulk_seat_dsq, 0)) {
			seat_service_at[0][idx] = now;
			if (seat_used[0][idx] &&
			    !scx_bpf_dsq_nr_queued(bulk_seat_dsq))
				seat_used[0][idx] = 0;
			return;
		}
		if (scx_bpf_dsq_move_to_local(node, 0)) {
			if (now - node_service_at[0][nidx] >
			    NSEC_PER_MSEC)
				node_service_at[0][nidx] = now;
			return;
		}
	}

	/*
	 * Fallback: if all bulk moves failed (e.g. affinity mismatch on
	 * the peeked head) while the fast lane still had work held back
	 * by the budget, drain the fast lane rather than idling the CPU.
	 * The service's runtime is charged when the task runs, so the
	 * drain needs no charge of its own; the bucket stays where the
	 * last accounting left it and bulk waits its turn afterwards.
	 */
	if (has_fl && !serve_fl) {
		if (scx_bpf_dsq_move_to_local(fl_seat_dsq, 0)) {
			seat_service_at[1][idx] = now;
			if (seat_used[1][idx] &&
			    !scx_bpf_dsq_nr_queued(fl_seat_dsq))
				seat_used[1][idx] = 0;
			return;
		}
		if (scx_bpf_dsq_move_to_local(fl_node_dsq, 0)) {
			if (node_preempt_claim[nidx])
				node_preempt_claim[nidx] = 0;
			if (now - node_service_at[1][nidx] >
			    NSEC_PER_MSEC)
				node_service_at[1][nidx] = now;
			return;
		}
	}

	if (need_running) {
		/*
		 * Nothing queued: keep the task running. Consume a pending
		 * tick mark, since the queues the waiter was seen in
		 * emptied under the mark and the cut never happened, and a
		 * yield mark, since there was nothing to yield to. This is
		 * another slice grant that skips stopping/running, so
		 * charge the runtime of the slice that just ended and
		 * restamp the per-CPU state here.
		 */
		if (tctx) {
			update_bursts(tctx, now);
			if (reached_deadline(tctx, now))
				tctx->deadline = calc_deadline(prev, tctx, now);
			tctx->tick_preempted = false;
			tctx->yield_pending = false;
			tctx->last_cpu = cpu;
			cpu_running_at[idx] = now;
			cpu_is_lat[idx] = is_lat_cri(tctx);
			if (cpu_is_lat[idx])
				charge_fl_runtime(idx, now, has_bulk);
			else
				cpu_bulk_at[idx] = now;
		}
		scx_bpf_task_set_slice(prev,
				       tctx ? task_slice(tctx) : deadline_ns);
	} else {
		/*
		 * Never idle while a shared queue holds a task this CPU can
		 * run: the bounded peek above may stop at a run of heads
		 * its affinity excludes, and scx_bpf_dsq_move_to_local()
		 * skips them itself. The bulk lane's else branch has
		 * already pulled its node queue; the fast lane's serve and
		 * fallback both require the peek, so a task past the bound
		 * would otherwise leave this CPU idle.
		 */
		if (scx_bpf_dsq_move_to_local(fl_node_dsq, 0)) {
			if (node_preempt_claim[nidx])
				node_preempt_claim[nidx] = 0;
			if (now - node_service_at[1][nidx] > NSEC_PER_MSEC)
				node_service_at[1][nidx] = now;
			return;
		}
		if (scx_bpf_dsq_move_to_local(node, 0)) {
			if (now - node_service_at[0][nidx] > NSEC_PER_MSEC)
				node_service_at[0][nidx] = now;
			return;
		}
		/*
		 * The CPU is going idle: drop its performance level. The
		 * write happens once, when the level changes; see the
		 * comment on perf_req. An idle dispatch breaks the
		 * fast-lane interval, so the next run charges no gap.
		 */
		cpu_fl_running_at[idx] = 0;
		cpu_bulk_at[idx] = 0;
		cpuperf_on_idle(cpu);
	}
}

/*
 * The kernel took the CPU for an RT or deadline task and has given it
 * back. Tasks that dispatch() had moved into the local DSQ waited out
 * the lease where no other CPU could see them; push them back through
 * enqueue, where they land on an idle core or in the deadline order.
 * The lease time belongs to the RT task: it breaks the fast-lane
 * interval, so the budget does not charge it.
 */
void BPF_STRUCT_OPS(baby_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	/*
	 * scx_bpf_reenqueue_local() returns a count on some kernels and
	 * is shimmed to void through the compat layer on others; call it
	 * as void, the re-enqueue happens either way.
	 */
	cpu_fl_running_at[(u32)cpu & (BABY_MAX_CPUS - 1)] = 0;
	scx_bpf_reenqueue_local();
}

/*
 * Periodic tick: account bursts, advance the CPU performance ledger and
 * renew the deadline once reached. The only tick-driven preemption is
 * the saturation gate below; the rotation order stays the deadline
 * order.
 */
void BPF_STRUCT_OPS(baby_tick, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();

	/*
	 * Keep the fast-lane budget current: a tick inside a long
	 * fast-lane slice accounts the contested runtime since the last
	 * charge point, so the stop that follows charges only the
	 * remainder.
	 */
	if (is_lat_cri(tctx)) {
		s32 cpu = scx_bpf_task_cpu(p);
		u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);

		refill_fl_budget(idx, now);
		charge_fl_runtime(idx, now, bulk_waiting(cpu));
	}

	update_bursts(tctx, now);

	cpuperf_on_tick(p, now,
			is_heavy_proven(tctx) || is_foreground(tctx));

	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	/*
	 * The saturation preemption gate (see the top of the file). The
	 * victim's residency comes from its ops.running() stamp; the
	 * waiter is any non-empty fast lane: this CPU's seat, or the
	 * fast-lane node queue under the one-CPU-at-a-time stamp. The
	 * time budget takes no part: the tick fires between dispatches,
	 * and counting it would black the lane out with no dispatch to
	 * reset it. baby_dispatch() owns the budget.
	 */
	if (!is_lat_cri(tctx)) {
		s32 cpu = scx_bpf_task_cpu(p);
		u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);
		u64 ran_at = cpu_running_at[idx];

		if (now - ran_at >= BABY_TICK_PREEMPT_PROTECT_NS) {
			s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
			bool cri = false;
			bool warm = false;

			if (scx_bpf_dsq_nr_queued(fl_cpu2dsq(cpu))) {
				cri = true;
				warm = true;
			} else {
				/*
				 * Only a head this CPU can pull justifies
				 * cutting its resident: a pinned waiter
				 * would otherwise have every CPU on the
				 * node preempt for work none of them can
				 * serve.
				 */
				struct task_struct *head =
					dsq_peek_allowed(fl_node2dsq(node), cpu);

				if (head) {
					u32 idx = (u32)node &
						  (BABY_NODE_CLOCK_NR - 1);
					u32 pid = (u32)head->pid;
					u64 now32 = (u32)now | 1;
					u64 claim = ((u64)pid << 32) | now32;
					u64 old = node_preempt_claim[idx];

					/*
					 * Same waiter and inside the
					 * quiet window: another CPU is
					 * already in flight for it.
					 * A new head, or a stale claim,
					 * may claim at once.
					 */
					if (old == 0 ||
					    (u32)(old >> 32) != pid ||
					    (u32)(now32 - (u32)old) >=
						    BABY_TICK_PREEMPT_FALLBACK_NS) {
						if (__sync_bool_compare_and_swap(
							    &node_preempt_claim[idx],
							    old, claim))
							cri = true;
					}
				}
			}

			if (cri) {
				p->scx.slice = 0;
				tctx->tick_preempted = true;
				if (stats_enabled) {
					if (warm)
						__sync_fetch_and_add(
							&nr_tick_preempts_warm,
							1);
					else
						__sync_fetch_and_add(
							&nr_tick_preempts, 1);
				}
			}
		}
	}
}

/*
 * The task has stopped running, either to sleep or because its time slice
 * expired.
 */
void BPF_STRUCT_OPS(baby_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 last_cpu;
	u64 now;

	__sync_fetch_and_sub(&nr_running, 1);

	/*
	 * The CPU's running-class residency lapses with the resident;
	 * ops.running() re-stamps it when the next task is served.
	 * ops.stopping() can run after a migration, so the stamp to
	 * clear is the CPU the task ran on, not its current one.
	 */
	last_cpu = (tctx && tctx->last_cpu >= 0) ? tctx->last_cpu :
						  scx_bpf_task_cpu(p);
	now = bpf_ktime_get_ns();
	{
		u32 idx = (u32)last_cpu & (BABY_MAX_CPUS - 1);

		/*
		 * Account the contested fast-lane runtime actually
		 * consumed and refill the elapsed-time credit before the
		 * residency lapses; under contention the two together
		 * leave the bucket one third of the interval lower, the
		 * bulk share the budget promises. A latency-critical stop
		 * keeps its stamp, so the next run on this CPU charges the
		 * stop-to-run gap before it starts, bulk or fast-lane; a
		 * bulk stop clears the stamp.
		 */
		if (cpu_is_lat[idx]) {
			refill_fl_budget(idx, now);
			charge_fl_runtime(idx, now, bulk_waiting(last_cpu));
		} else {
			cpu_fl_running_at[idx] = 0;
		}
		cpu_is_lat[idx] = false;
	}

	if (!tctx)
		return;

	/*
	 * Whatever enqueues this task next is a re-entry of a task that
	 * has run - slice expiry, preemption, an RT-lease reenqueue -
	 * not the wake that started the burst: drop the wake bit so the
	 * wait instrument files the requeues as rotation. A task going
	 * to sleep re-sets the bit in ops.runnable() on its wake.
	 */
	tctx->arrival_is_wake = 0;

	/*
	 * A task that sleeps with an unconsumed yield mark would fire
	 * the push at its wake; a wake is a fresh arrival and keeps its
	 * sleep-time deadline, so drop the mark with the task.
	 */
	if (!runnable)
		tctx->yield_pending = false;

	update_bursts(tctx, now);

	class_boost_on_sleep(p, tctx, runnable, now);

	/*
	 * update_curr(): roll the deadline forward once reached.
	 */
	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	/*
	 * Update CPU runtime for the performance scaling.
	 */
	cpuperf_on_stopping(last_cpu, now);
}

/*
 * The task has become runnable: track how often it wakes. Frequent
 * wakers with real work to do are foreground tasks.
 */
void BPF_STRUCT_OPS(baby_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	class_on_runnable(tctx, enq_flags, now);
}

/*
 * The task has started to run on a CPU.
 */
void BPF_STRUCT_OPS(baby_running, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now = bpf_ktime_get_ns();

	__sync_fetch_and_add(&nr_running, 1);

	/*
	 * The victim-residency stamp for the tick gate, and the point where
	 * a task that was cut short stops carrying the preempted mark: the
	 * requeue has happened by now. The running class feeds the warm
	 * gate and the relocation filter (see cpu_is_lat).
	 */
	{
		s32 cpu = scx_bpf_task_cpu(p);
		u32 cpu_idx = (u32)cpu & (BABY_MAX_CPUS - 1);

		cpu_running_at[cpu_idx] = now;
		cpu_is_lat[cpu_idx] = tctx && is_lat_cri(tctx);
		if (!cpu_is_lat[cpu_idx])
			cpu_bulk_at[cpu_idx] = now;
		/*
		 * The fast-lane clock. A non-zero stamp means the CPU's last
		 * run was fast-lane work and no bulk run or idle dispatch
		 * came between; the switch back is overhead the budget was
		 * crediting without charging, so charge it before this run
		 * starts, whether it is bulk or fast-lane work. A bulk run
		 * or an idle dispatch clears the stamp.
		 */
		if (cpu_fl_running_at[cpu_idx]) {
			refill_fl_budget(cpu_idx, now);
			charge_fl_runtime(cpu_idx, now, bulk_waiting(cpu));
		}
		cpu_fl_running_at[cpu_idx] = cpu_is_lat[cpu_idx] ? now : 0;
		if (tctx)
			tctx->last_cpu = cpu;
	}

	if (!tctx)
		return;

	tctx->tick_preempted = false;
	tctx->last_acc_at = now;

	charge_wait(tctx, now);

	/*
	 * Class census at the point of truth: 0 bulk normal, 1 bulk
	 * heavy, 2 fast lane base slice, 3 fast lane fourfold slice.
	 * Class 2 plus class 3 is the fast-lane run count.
	 */
	if (stats_enabled) {
		u32 cls = task_nr_class(tctx);

		__sync_fetch_and_add(&nr_class[cls & (BABY_WCLS_NR - 1)], 1);
		__sync_fetch_and_add(&nr_lane[is_lat_cri(tctx) ? 1 : 0], 1);
	}

	/*
	 * Adjust the target CPU frequency before the task starts to run.
	 * A proven consumer or a foreground task saturates the core for
	 * as long as it runs, so give it the boost clock at once instead
	 * of re-climbing the smoothing after every sleep.
	 */
	cpuperf_on_running(scx_bpf_task_cpu(p), now,
			   is_heavy_proven(tctx) || is_foreground(tctx));

	class_on_running(p, tctx, now);
}

/*
 * sched_yield(): give up the CPU for the rest of this round, like the
 * original YIELD_MARK. With nothing this CPU can run there is nothing
 * to yield to: a queued head its affinity excludes is not a successor,
 * and honouring the yield for it would cost the caller its slice and
 * re-pick the caller. The kernel leaves the slice alone when ops.yield
 * is defined, so zero it here; only then does the task re-enter
 * through enqueue, where the mark is consumed.
 */
bool BPF_STRUCT_OPS(baby_yield, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 cpu, node;

	if (!tctx)
		return false;

	cpu = scx_bpf_task_cpu(p);
	node = __COMPAT_scx_bpf_cpu_node(cpu);

	if (!dsq_peek_allowed(cpu2dsq(cpu), cpu) &&
	    !dsq_peek_allowed(fl_cpu2dsq(cpu), cpu) &&
	    !dsq_peek_allowed(node, cpu) &&
	    !dsq_peek_allowed(fl_node2dsq(node), cpu))
		return false;

	tctx->yield_pending = true;
	scx_bpf_task_set_slice(p, 0);

	return true;
}

s32 BPF_STRUCT_OPS(baby_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	u64 now;

	tctx = init_task_ctx(p);
	if (!tctx)
		return -ENOMEM;

	now = bpf_ktime_get_ns();
	class_init_task(tctx, p, now);

	return 0;
}

/*
 * A queue that no CPU can serve, behind an RT lease or with affinity
 * moved under it, strands its tasks where the rest of the machine
 * cannot see them. A queue that has held work this long without a
 * successful pull is overdue by far more than a warm wait; re-enqueue
 * it. This does not save a task pinned to a queue no CPU can pull: the
 * re-enqueue lands it in the same queue. Dispatch's bulk backstop
 * keeps such a CPU serving bulk, and this timer only returns work
 * whose queue lost its server.
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

/*
 * One queue's rescue: a queue that has held work past the starve
 * window without a successful pull is re-enqueued. The service clock
 * is the queue's own, not the head task's arrival stamp: the seats and
 * node queues are ordered by deadline, so a newly arrived sleeper
 * with an older preserved deadline can sort ahead of a task that has
 * waited longer, and a head-based check would mask the stranded task.
 *
 * The clock is seeded when the queue becomes non-empty and written on
 * every successful pull, so a queue that is being served never looks
 * starved. A zero clock means the queue was never populated through
 * the seeded paths; wait for the first insertion rather than rescue a
 * queue that has merely existed since boot.
 */
static bool rescue_one_dsq(u64 dsq, u64 last_service, u64 now)
{
	if (__COMPAT_has_generic_reenq() && last_service &&
	    now - last_service > STARVE_RESCUE_NS &&
	    scx_bpf_dsq_nr_queued(dsq)) {
		scx_bpf_dsq_reenq___compat(dsq, 0);
		return true;
	}
	return false;
}

static int rescue_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = bpf_ktime_get_ns();
	s32 node, cpu;
	int err;

	if (__COMPAT_has_generic_reenq()) {
		bpf_for(cpu, 0, nr_cpu_ids) {
			u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);

			if (rescue_one_dsq(cpu2dsq(cpu),
					   seat_service_at[0][idx], now))
				seat_used[0][idx] = 0;
			if (rescue_one_dsq(fl_cpu2dsq(cpu),
					   seat_service_at[1][idx], now))
				seat_used[1][idx] = 0;
		}
		bpf_for(node, 0, nr_node_ids) {
			u32 idx = (u32)node & (BABY_NODE_CLOCK_NR - 1);

			rescue_one_dsq(node, node_service_at[0][idx], now);
			rescue_one_dsq(fl_node2dsq(node),
				       node_service_at[1][idx], now);
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

	/*
	 * The DSQ ids are laid out from the two topology counts, and the
	 * per-CPU arrays are sized for BABY_MAX_CPUS. Userspace publishes
	 * both as rodata before load; assert them against the kernel's own
	 * counts here so a mismatch can never alias two CPUs or two node
	 * queues onto one id.
	 */
	if (!nr_cpu_ids || nr_cpu_ids > BABY_MAX_CPUS ||
	    nr_cpu_ids != scx_bpf_nr_cpu_ids()) {
		scx_bpf_error("CPU count mismatch: rodata %llu, kernel %u, max %u",
			      nr_cpu_ids, scx_bpf_nr_cpu_ids(), BABY_MAX_CPUS);
		return -EINVAL;
	}
	if (!nr_node_ids || nr_node_ids > BABY_MAX_NODES ||
	    nr_node_ids != __COMPAT_scx_bpf_nr_node_ids()) {
		scx_bpf_error("node count mismatch: rodata %llu, kernel %u, max %u",
			      nr_node_ids, __COMPAT_scx_bpf_nr_node_ids(),
			      BABY_MAX_NODES);
		return -EINVAL;
	}

	/*
	 * Create the per-CPU seats and the per-node deadline queues for
	 * both lanes.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu2dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d",
				      cpu2dsq(cpu), err);
			return err;
		}

		err = scx_bpf_create_dsq(fl_cpu2dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d",
				      fl_cpu2dsq(cpu), err);
			return err;
		}
	}

	bpf_for(node, 0, nr_node_ids) {
		err = scx_bpf_create_dsq(node, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", node, err);
			return err;
		}

		err = scx_bpf_create_dsq(fl_node2dsq(node), node);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d",
				      fl_node2dsq(node), err);
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
	cpuperf_init();

	return 0;
}

void BPF_STRUCT_OPS(baby_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Publish one CPU's tier. Userspace counts the tiers before load and
 * writes the counts as rodata, so this program only fills the masks;
 * calling it twice for the same CPU is a no-op, and the counts cannot
 * double.
 */
SEC("syscall")
int enable_core_class(struct core_arg *input)
{
	struct bpf_cpumask *mask;
	s32 cpu = input->cpu_id;
	s32 tier = input->tier;
	int err;

	if (cpu < 0 || (u32)cpu >= nr_cpu_ids ||
	    tier < CORE_TIER_BIG || tier > CORE_TIER_LP)
		return -EINVAL;

	err = init_cpumask(&big_cpumask);
	if (err)
		return err;
	err = init_cpumask(&little_cpumask);
	if (err)
		return err;
	err = init_cpumask(&non_lp_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	if (tier != CORE_TIER_LP) {
		mask = non_lp_cpumask;
		if (mask)
			bpf_cpumask_set_cpu(cpu, mask);
	}
	if (tier == CORE_TIER_BIG)
		mask = big_cpumask;
	else if (tier == CORE_TIER_LITTLE)
		mask = little_cpumask;
	else
		mask = NULL;
	if (mask)
		bpf_cpumask_set_cpu(cpu, mask);
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
