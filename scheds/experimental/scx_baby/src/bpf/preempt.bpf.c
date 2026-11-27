/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * The wake gate and the tick gate: ops.select_cpu() places a wake and
 * may cut a victim for it, and ops.tick() does the same for a
 * saturated CPU. The saturation preemption the tick enforces is
 * described below.
 */
#include "baby.bpf.h"

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
 * Fallback quiet window for the shared-queue claim. It covers the
 * tick -> resched -> dispatch flight, which may be diverted to a
 * warm-seat arrival and never pull the waiter. The claim is cleared by
 * a successful pull from the same fast-lane queue, so a later
 * staggered tick can serve the next waiter instead of waiting out a
 * slice; a new head may also claim without waiting for the window,
 * because the claim names the waiter it was made for.
 */
#define BABY_TICK_PREEMPT_FALLBACK_NS	(100ULL * NSEC_PER_USEC)

static __always_inline void
tick_charge_fast_lane(struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	/*
	 * Keep the fast-lane budget current: a tick inside a long
	 * fast-lane slice accounts the contested runtime since the last
	 * charge point, so the stop that follows charges only the
	 * remainder.
	 */
	if (!plain && is_lat_cri(tctx)) {
		s32 cpu = scx_bpf_task_cpu(p);
		u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);

		refill_fl_budget(idx, now);
		charge_fl_runtime(idx, now, bulk_waiting(cpu));
	}
}

static __always_inline void
tick_saturation_gate(struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	/*
	 * The saturation preemption gate (see the top of the file). The
	 * victim's residency comes from its ops.running() stamp; the
	 * waiter is any non-empty fast lane: this CPU's seat, or the
	 * fast-lane node queue under the one-CPU-at-a-time stamp. The
	 * time budget takes no part: the tick fires between dispatches,
	 * and counting it would black the lane out with no dispatch to
	 * reset it. baby_dispatch() owns the budget.
	 *
	 * A latency-critical resident is normally exempt: it is the class
	 * the lane exists for, and a tick that cut it would trade two
	 * protected tasks against each other. The exemption survives only
	 * in the bare --plain baseline. Under the default profile the seat
	 * guard may legally park a latency-critical arrival behind a
	 * latency-critical resident whose slice it also bounds, and without
	 * the gate that arrival waits out the fourfold slice with no rung
	 * left to cut it; --plain-1x takes the tick for its own
	 * bookkeeping. The gate is therefore plain_1x || !plain.
	 */
	if (plain_1x || !plain) {
		s32 cpu = scx_bpf_task_cpu(p);
		u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);
		u64 ran_at = cpu_running_at[idx];

		if (now - ran_at >= BABY_TICK_PREEMPT_PROTECT_NS) {
			s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
			bool cri = false;
			bool warm = false;

			if (plain_1x &&
			    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu)) {
				cri = true;
			} else if (!plain_1x &&
				   scx_bpf_dsq_nr_queued(fl_cpu2dsq(cpu))) {
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
					dsq_peek_allowed(plain_1x ? (u64)node :
							 fl_node2dsq(node), cpu);

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

	tick_charge_fast_lane(p, tctx, now);

	update_bursts(tctx, now);

	/*
	 * The game pin samples the window the burst tracker just rolled:
	 * inside a window this returns on the stamp, so the tick pays
	 * nothing until the next 200ms boundary.
	 */
	if (game_pin)
		pin_account(p, tctx, now);

	cpuperf_on_tick(p, now,
			is_heavy_proven(tctx) || is_foreground(tctx));

	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	tick_saturation_gate(p, tctx, now);
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
	 * A pinned thread wakes straight onto its own core: the slot
	 * survives the short sleeps between frames, and while the home
	 * is busy the wake is placed there instead of being spread. The
	 * pin parks the task without touching a queue in that case, and
	 * the enqueue that follows decides how the home is taken.
	 */
	if (game_pin && READ_ONCE(pin_shield_n) && tctx &&
	    pin_select_pinned(p, tctx, now, &cpu))
		return cpu;

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
	if (!plain && tctx && nr_little_cpus && nr_big_cpus &&
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
	 * The warm CPU is worth keeping only when its sibling is idle too.
	 * An idle CPU whose SMT sibling runs another task is half a core,
	 * and a wakee placed there loses a large share of the core's
	 * execution units, far more than a refill costs. A shared core is
	 * left to the kernel selector below, which knows the SMT topology
	 * and prefers a wholly idle core.
	 *
	 * Usable means idle and allowed, or busy with a cuttable bulk
	 * resident: the same preempt the wake gate below performs, but
	 * reached before an idle CPU elsewhere wins the wake. A latency-
	 * critical resident keeps its CPU, and the wakee spreads instead,
	 * so two pipeline stages cannot stack on one CPU by this path.
	 * The miss reasons are left to the gate below; this block only
	 * returns where it has already placed the task.
	 */
	if (!plain && tctx && is_lat_cri(tctx) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    !cpu_smt_shared(prev_cpu)) {
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

			/*
			 * The residency floor cannot change while the
			 * queues are probed, and it vetoes the cut on its
			 * own. Test it first: a wakee that arrives inside
			 * the floor leaves every queue and the resident's
			 * context untouched.
			 */
			{
				u64 ran_at = cpu_running_at[pidx];

				if (ran_at &&
				    now - ran_at >=
					    BABY_TICK_PREEMPT_PROTECT_NS &&
				    (!READ_ONCE(seat_used[1][pidx]) ||
				     !scx_bpf_dsq_nr_queued(
					     fl_cpu2dsq(prev_cpu))) &&
				    (!READ_ONCE(seat_used[0][pidx]) ||
				     !scx_bpf_dsq_nr_queued(
					     cpu2dsq(prev_cpu))) &&
				    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON |
							   prev_cpu)) {
					struct task_struct *curr =
						__COMPAT_scx_bpf_cpu_curr(prev_cpu);
					struct task_ctx *cctx = curr ?
						try_lookup_task_ctx(curr) : NULL;

					if (curr && curr != p &&
					    !(curr->flags & PF_IDLE) && cctx &&
					    !is_lat_cri(cctx) &&
					    !is_pcpu_task(curr) &&
					    p->static_prio <= curr->static_prio) {
						scx_bpf_dsq_insert(p,
								   SCX_DSQ_LOCAL_ON |
								   prev_cpu,
								   task_slice(tctx),
								   SCX_ENQ_PREEMPT);
						if (stats_enabled)
							__sync_fetch_and_add(
								&nr_wake_preempts,
								1);
						return prev_cpu;
					}
				}
			}
		}
	}

	/*
	 * While a pin shield holds a core, the wake selector must not
	 * hand a non-pinned task that core. The kernel selector runs on
	 * the pin worker mask, which is the non-LP set minus the
	 * shielded homes and siblings. A direct dispatch returns its own
	 * pick; otherwise the depth-0 wake preempt below still applies,
	 * on the unshielded warm seat or the nearest allowed CPU.
	 */
	if (plain && game_pin && READ_ONCE(pin_shield_n)) {
		cpu = pin_select_cpu_and(p, prev_cpu, wake_flags);
		if (cpu >= 0)
			return cpu;

		/*
		 * No idle CPU inside the pin worker mask. Keep the warm
		 * seat when the shield does not own it, so the depth-0
		 * wake preempt below can still cut a bulk resident; a
		 * shielded CPU never takes that preempt, because the pin
		 * holds it. When the shield owns prev_cpu, step forward
		 * from it to the nearest unshielded allowed CPU.
		 */
		if (prev_cpu < 0 ||
		    (u32)prev_cpu >= nr_cpu_ids ||
		    !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) ||
		    is_cpu_shielded(prev_cpu, now)) {
			cpu = pin_next_unshielded(p, prev_cpu, now);
			/*
			 * ops.select_cpu() has to name a valid CPU: the
			 * kernel rejects anything else and aborts the
			 * scheduler. prev_cpu is not allowed on every arm
			 * above, so fall back through the affinity mask.
			 * A task wholly inside the shield reaches
			 * ops.enqueue(), where the stranded park serves it.
			 */
			return cpu >= 0 ? cpu : any_allowed_cpu(p, prev_cpu);
		}

		cpu = prev_cpu;
	} else {
		cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
		/*
		 * A shield published after the gate above can make the
		 * selector decline. Fall back through the affinity mask:
		 * a negative return aborts, and an out-of-mask CPU is no
		 * placement, its node queue unreachable from the CPUs
		 * that can run the task.
		 */
		if (cpu < 0)
			return any_allowed_cpu(p, prev_cpu);
	}
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
		if (is_lat_cri(cctx) &&
		    !(plain_wake && plain_wake_cut(tctx, cctx))) {
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
		    now - ran_at < (plain_wake ? PLAIN_WAKE_PROTECT_NS :
					BABY_TICK_PREEMPT_PROTECT_NS)) {
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
