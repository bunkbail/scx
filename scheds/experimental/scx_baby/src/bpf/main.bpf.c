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
 *   ticks would otherwise all preempt for the same waiter. A global
 *   stamp with a short quiet window bounds the herd. Warm-seat waiters
 *   are per-CPU precise; the victim's rotation pulls the waiter in the
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
#define BABY_TICK_PREEMPT_PROTECT_NS	(200ULL * NSEC_PER_USEC)

/*
 * Fallback quiet window for the shared-queue claim. It covers the
 * tick -> resched -> dispatch flight, which may be diverted to a
 * warm-seat arrival and never pull the waiter. The stamp is cleared
 * when any CPU pulls the shared head, so a later staggered tick can
 * serve the next waiter instead of waiting out a slice.
 */
#define BABY_TICK_PREEMPT_FALLBACK_NS	(100ULL * NSEC_PER_USEC)

static u64 cpu_running_at[BABY_MAX_CPUS];
bool cpu_is_lat[BABY_MAX_CPUS];
static u64 node_preempt_at;

/*
 * Per-queue service clocks for the starve rescue, indexed by lane
 * (0 bulk, 1 fast lane). A queue that has held work for a second
 * without a successful pull is re-enqueued. The clock is seeded when
 * the queue becomes non-empty and advanced on every successful pull,
 * so a continuously served queue never looks starved and a newly
 * populated one does not inherit the clock of the queue's birth.
 */
u64 seat_service_at[2][BABY_MAX_CPUS];
u64 node_service_at[2][BABY_NODE_CLOCK_NR];

/*
 * Maximum consecutive fast-lane dispatches a CPU may serve while its
 * bulk queue holds waiting work. When fl_streak reaches the quota, the
 * next dispatch serves bulk and resets the streak, so bulk keeps at
 * least 1 / (BABY_FL_QUOTA + 1) of a contended CPU. The quota is
 * counted only in ops.dispatch(): wake and tick preemptions happen
 * between dispatches and are self-bounded, and counting them would
 * black the lane out without a dispatch to reset the streak.
 */
#define BABY_FL_QUOTA	2

static u8 fl_streak[BABY_MAX_CPUS];

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
 * Pick the lowest-numbered idle CPU of the given tier. Stacking
 * wakeups on the same few cores lets the rest of the tier idle at its
 * boost floor. The idle bit is claimed atomically; a lost race tries
 * the next bit of the tier instead of spilling to the kernel's
 * spread-first path.
 */
static __always_inline s32 pick_idle_pref(struct task_struct *p,
					  struct bpf_cpumask *pref)
{
	const struct cpumask *idle;
	s32 cpu = -1;
	s32 i;

	bpf_rcu_read_lock();
	idle = scx_bpf_get_idle_cpumask();
	if (pref && idle) {
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
	scx_bpf_put_cpumask(idle);
	bpf_rcu_read_unlock();
	return cpu;
}

/*
 * Re-pick off a core outside both tiers, in practice an LP core the
 * kernel selector chose. Callers ask for the big tier first for a
 * heavy non-foreground consumer and the little tier first otherwise.
 * A task pinned to LP cores by affinity finds nothing in either tier
 * and keeps its pick.
 */
static __always_inline s32 pick_idle_tier(struct task_struct *p,
					  bool big_first)
{
	s32 alt;

	if (big_first)
		alt = pick_idle_pref(p, big_cpumask);
	else
		alt = pick_idle_pref(p, little_cpumask);
	if (alt >= 0)
		return alt;
	return big_first ? pick_idle_pref(p, little_cpumask)
			 : pick_idle_pref(p, big_cpumask);
}

/*
 * The LP guard: the kernel selector can return an LP core, whose low
 * clock and absent L3 the previous-CPU bias would then keep for the
 * task's lifetime. While the tier masks exist, re-pick inside them and
 * keep the LP only when both tiers are full or affinity allows nothing
 * else. Callers apply this to a confirmed idle pick.
 */
__hidden s32 lp_guard_pick(struct task_struct *p, struct task_ctx *tctx,
			   s32 cpu)
{
	struct bpf_cpumask *l, *b;
	bool on_tier;

	if (!nr_little_cpus || !nr_big_cpus)
		return cpu;

	bpf_rcu_read_lock();
	l = little_cpumask;
	b = big_cpumask;
	on_tier = l && b &&
		  (bpf_cpumask_test_cpu(cpu, cast_mask(l)) ||
		   bpf_cpumask_test_cpu(cpu, cast_mask(b)));
	bpf_rcu_read_unlock();

	if (!on_tier) {
		bool big_first = tctx && is_heavy_proven(tctx) &&
				 !is_foreground(tctx);
		s32 alt = pick_idle_tier(p, big_first);

		if (alt >= 0)
			cpu = alt;
	}

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

	/*
	 * The miss reason always describes the most recent wake. Reset it
	 * at entry, before any early return; charge_wait() files it for a
	 * wake that actually waits.
	 */
	if (tctx)
		tctx->wake_gate_miss = BABY_WG_NO_GATE;

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

		cpu = big_pin ? pick_idle_pref(p, big_cpumask)
			      : pick_idle_pref(p, little_cpumask);
		if (cpu < 0 && !big_pin && is_heavy_proven(tctx))
			cpu = pick_idle_pref(p, big_cpumask);
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

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle)
		cpu = lp_guard_pick(p, tctx, cpu);
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
		 * class pair, the priority order and the 200us residency
		 * floor bound the churn.
		 *
		 * SCX_ENQ_PREEMPT puts the wakee at the head of the local
		 * DSQ, zeroes the victim's slice and reschedules. The
		 * victim keeps its remaining slice at the local DSQ head
		 * through SCX_ENQ_HEAD; ops.enqueue() is not called for
		 * it, so the deep-backlog slice and the tick_preempted
		 * mark do not apply.
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
		 * waiter blocks the preempt. Starvation is self-bounded:
		 * the displaced victim sits in SCX_DSQ_LOCAL (blocking a
		 * second preempt via LOCAL_BUSY) and gets a fresh 200us
		 * residency stamp when it resumes. The quota takes no
		 * part here: the preempt happens between dispatches.
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
		if (!ran_at || bpf_ktime_get_ns() - ran_at <
				       BABY_TICK_PREEMPT_PROTECT_NS) {
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
 * Waiting work in this node's bulk and fast-lane queues. The queue
 * probe cannot run inside an RCU read-side section, so callers call
 * this outside one.
 */
static u64 node_backlog(s32 cpu)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);

	return scx_bpf_dsq_nr_queued(node) +
	       scx_bpf_dsq_nr_queued(fl_node2dsq(node));
}

/*
 * Enqueue a task with no idle CPU to run on. The node queue is ordered
 * by deadline, and dispatch takes the earliest one.
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
		 * task queued in this round.
		 */
		tctx->deadline = now + deadline_ns + deadline_ns +
				 task_prio_factor(p, tctx);
	} else if (!(enq_flags & (SCX_ENQ_LAST | SCX_ENQ_WAKEUP |
				  SCX_ENQ_REENQ))) {
		/*
		 * Migrated and freshly created tasks get a fresh deadline.
		 * Woken tasks keep the deadline they had when they went to
		 * sleep. A task that stopped but stayed runnable also
		 * keeps its own; ops.stopping() renewed it if it was
		 * reached. A task pushed back by cpu_release() keeps it
		 * too: it was already waiting, and a fresh deadline would
		 * move it behind later arrivals.
		 */
		tctx->deadline = calc_deadline(p, tctx, now);
	}

	backlog = node_backlog(prev_cpu);

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
	 */
	if ((enq_flags & SCX_ENQ_WAKEUP) &&
	    !scx_bpf_dsq_nr_queued(fl_cpu2dsq(prev_cpu)) &&
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
	if (balance_try_warm_seat(p, tctx, enq_flags, backlog, now))
		return;

	/*
	 * No idle CPU: join the deadline order. A deep backlog grants the
	 * fourfold slice; a tick-preempted victim keeps the base slice.
	 * Latency-critical tasks use their own node queue, which dispatch
	 * serves ahead of bulk under the quota.
	 */
	{
		s32 node = __COMPAT_scx_bpf_cpu_node(prev_cpu);
		bool lat = is_lat_cri(tctx);
		u64 dsq = lat ? fl_node2dsq(node) : (u64)node;

		/*
		 * Seed the rescue clock when the lane's shared queue was
		 * empty; a queue that is already served does not need it.
		 */
		if (!scx_bpf_dsq_nr_queued(dsq))
			node_service_at[lat & 1][node &
						 (BABY_NODE_CLOCK_NR - 1)] = now;

		slice = backlog_deep(backlog) && !tctx->tick_preempted
			? 4 * deadline_ns : task_slice(tctx);

		scx_bpf_dsq_insert_vtime(p, dsq, slice, tctx->deadline,
					 enq_flags);
	}
	stamp_wait(tctx, now, backlog, true);

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
 * holds work and the CPU's quota allows it, the bulk lane otherwise.
 * Serving bulk resets the fast-lane streak, so bulk keeps at least one
 * in BABY_FL_QUOTA + 1 dispatches on a contended CPU.
 */
void BPF_STRUCT_OPS(baby_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_ctx *tctx = prev ? try_lookup_task_ctx(prev) : NULL;
	bool need_running = prev && is_queued(prev);
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);
	u64 fl_seat_dsq = fl_cpu2dsq(cpu);
	u64 fl_node_dsq = fl_node2dsq(node);
	u64 bulk_seat_dsq = cpu2dsq(cpu);
	struct task_struct *fl_wq, *fl_q, *wq, *q;
	u64 fl_wq_dl, fl_g_dl, wq_dl, g_dl, fl_dl, bulk_dl, best_dl;
	u64 now = bpf_ktime_get_ns();
	bool has_fl, has_bulk, serve_fl;

	census_sample(cpu);

	/*
	 * One peek of each lane per dispatch: the sticky check and the
	 * arbitration read the same heads, and the peeked pointers stay
	 * valid until the pulls enter their own RCU scope. The shared
	 * heads are filtered by this CPU's affinity: a head it cannot
	 * pull must not read as the lane's next deadline here.
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
	serve_fl = has_fl && (!has_bulk || fl_streak[idx] < BABY_FL_QUOTA);

	if (need_running && tctx && !tctx->yield_pending) {
		/*
		 * Keep the current task only while its deadline beats the
		 * earliest head of the lane that would run next; ties go to
		 * the waiter. ops.stopping() renewed the deadline once it
		 * was reached, so this is a sticky run in absolute
		 * deadlines. A yielding task has given the round up. A bulk
		 * task cannot keep the CPU out of turn when the fast lane
		 * is served: that is the quota's business.
		 */
		if (serve_fl && !is_lat_cri(tctx)) {
			best_dl = 0;
		} else if (serve_fl) {
			best_dl = fl_dl;
		} else {
			best_dl = bulk_dl;
		}

		if (best_dl && (s64)(tctx->deadline - best_dl) < 0) {
			/*
			 * The victim kept its CPU, so the tick's cut did
			 * not happen: consume the mark here, where no
			 * ops.running() will run to clear it, or its next
			 * natural requeue would take the deep-backlog
			 * rung it did not earn.
			 */
			tctx->tick_preempted = false;
			scx_bpf_task_set_slice(prev, task_slice(tctx));
			if (stats_enabled)
				__sync_fetch_and_add(&nr_sticky, 1);
			return;
		}
	}

	/*
	 * Serve the fast lane: the node queue first when its head beats
	 * the seat's (the seat wins ties), then the seat, then the node
	 * queue again for a raced first try. Under bulk pressure a serve
	 * spends one quota unit.
	 */
	if (serve_fl) {
		if (fl_g_dl < fl_wq_dl) {
			s32 from = fl_q ? scx_bpf_task_cpu(fl_q) : -1;

			if (scx_bpf_dsq_move_to_local(fl_node_dsq, 0)) {
				node_preempt_at = 0;
				node_service_at[1][node &
						  (BABY_NODE_CLOCK_NR - 1)] = now;
				if (has_bulk) {
					fl_streak[idx]++;
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
			if (has_bulk) {
				fl_streak[idx]++;
				if (stats_enabled)
					__sync_fetch_and_add(
						&nr_depth1_pulls_seat, 1);
			}
			return;
		}
		if (scx_bpf_dsq_move_to_local(fl_node_dsq, 0)) {
			node_preempt_at = 0;
			node_service_at[1][node & (BABY_NODE_CLOCK_NR - 1)] = now;
			if (has_bulk) {
				fl_streak[idx]++;
				if (stats_enabled)
					__sync_fetch_and_add(
						&nr_depth1_pulls, 1);
			}
			return;
		}
	}

	/*
	 * Serve the bulk lane: the fast lane is empty, its move raced, or
	 * the quota is spent. Serving bulk resets the fast-lane streak.
	 * The shared queue wins when its head is strictly earlier, so a
	 * self-sustaining warm queue cannot starve the overflow.
	 */
	if (g_dl < wq_dl) {
		/*
		 * Read the node head's CPU while q is fresh: the pull below
		 * may enter an RCU scope, and a pointer peeked before it
		 * cannot be re-read after the unlock.
		 */
		s32 from = q ? scx_bpf_task_cpu(q) : -1;

		if (scx_bpf_dsq_move_to_local(node, 0)) {
			fl_streak[idx] = 0;
			node_service_at[0][node & (BABY_NODE_CLOCK_NR - 1)] = now;
			/*
			 * The waiter this claim was made for is served, or
			 * another head took its place; either way the next
			 * staggered tick may claim again. A racing tick CAS
			 * against the cleared stamp fails and retries next
			 * tick.
			 */
			node_preempt_at = 0;
			if (stats_enabled)
				__sync_fetch_and_add(
					&nr_pull_land[cpu_dist(cpu, from)], 1);
			return;
		}
		if (scx_bpf_dsq_move_to_local(bulk_seat_dsq, 0)) {
			fl_streak[idx] = 0;
			seat_service_at[0][idx] = now;
			return;
		}
	} else {
		if (scx_bpf_dsq_move_to_local(bulk_seat_dsq, 0)) {
			fl_streak[idx] = 0;
			seat_service_at[0][idx] = now;
			return;
		}
		if (scx_bpf_dsq_move_to_local(node, 0)) {
			fl_streak[idx] = 0;
			node_service_at[0][node & (BABY_NODE_CLOCK_NR - 1)] = now;
			node_preempt_at = 0;
			return;
		}
	}

	/*
	 * Fallback: if all bulk moves failed (e.g. affinity mismatch on
	 * the peeked head) while the fast lane still had work held back
	 * by the quota, drain the fast lane rather than idling the CPU.
	 */
	if (has_fl && !serve_fl) {
		if (scx_bpf_dsq_move_to_local(fl_seat_dsq, 0)) {
			seat_service_at[1][idx] = now;
			return;
		}
		if (scx_bpf_dsq_move_to_local(fl_node_dsq, 0)) {
			node_service_at[1][node &
					  (BABY_NODE_CLOCK_NR - 1)] = now;
			return;
		}
	}

	if (need_running) {
		/*
		 * Nothing queued: keep the task running. Consume a pending
		 * tick mark, since the queues the waiter was seen in
		 * emptied under the mark and the cut never happened, and a
		 * yield mark, since there was nothing to yield to. A bulk
		 * task also restores the quota.
		 */
		if (tctx) {
			tctx->tick_preempted = false;
			tctx->yield_pending = false;
			if (!is_lat_cri(tctx))
				fl_streak[idx] = 0;
		}
		scx_bpf_task_set_slice(prev,
				       tctx ? task_slice(tctx) : deadline_ns);
	} else {
		/*
		 * The CPU is going idle: drop its performance level. The
		 * write happens once, when the level changes; see the
		 * comment on perf_req.
		 */
		fl_streak[idx] = 0;
		cpuperf_on_idle(cpu);
	}
}

/*
 * The kernel took the CPU for an RT or deadline task and has given it
 * back. Tasks that dispatch() had moved into the local DSQ waited out
 * the lease where no other CPU could see them; push them back through
 * enqueue, where they land on an idle core or in the deadline order.
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
	 * quota takes no part: the tick fires between dispatches, and
	 * counting it would black the lane out with no dispatch to reset
	 * it. baby_dispatch() owns the quota.
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
					u64 last = node_preempt_at;

					if (now - last >=
					    BABY_TICK_PREEMPT_FALLBACK_NS &&
					    __sync_bool_compare_and_swap(
						    &node_preempt_at, last,
						    now))
						cri = true;
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
	u64 now;

	__sync_fetch_and_sub(&nr_running, 1);

	/*
	 * The CPU's running-class residency lapses with the resident;
	 * ops.running() re-stamps it when the next task is served.
	 */
	cpu_is_lat[scx_bpf_task_cpu(p) & (BABY_MAX_CPUS - 1)] = false;

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
	cpuperf_on_stopping(scx_bpf_task_cpu(p), now);
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
		u32 cpu_idx = scx_bpf_task_cpu(p) & (BABY_MAX_CPUS - 1);

		cpu_running_at[cpu_idx] = now;
		cpu_is_lat[cpu_idx] = tctx && is_lat_cri(tctx);
	}

	if (!tctx)
		return;

	tctx->tick_preempted = false;
	tctx->last_acc_at = now;

	charge_wait(tctx, now);

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
 * it. The kernel watchdog unloads the scheduler five seconds after a
 * queued task stops being consumable, so this fires well before that.
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
static void rescue_one_dsq(u64 dsq, u64 last_service, u64 now)
{
	if (__COMPAT_has_generic_reenq() && last_service &&
	    now - last_service > STARVE_RESCUE_NS &&
	    scx_bpf_dsq_nr_queued(dsq))
		scx_bpf_dsq_reenq___compat(dsq, 0);
}

static int rescue_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = bpf_ktime_get_ns();
	s32 node, cpu;
	int err;

	if (__COMPAT_has_generic_reenq()) {
		bpf_for(cpu, 0, nr_cpu_ids) {
			u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);

			rescue_one_dsq(cpu2dsq(cpu), seat_service_at[0][idx],
				       now);
			rescue_one_dsq(fl_cpu2dsq(cpu), seat_service_at[1][idx],
				       now);
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
