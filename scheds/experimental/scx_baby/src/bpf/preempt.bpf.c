/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * The tick: burst accounting, the CPU performance ledger, the deadline
 * renewal and the saturation preemption gate described below.
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
	if (!plain && is_lat_cri(tctx)) {
		s32 cpu = scx_bpf_task_cpu(p);
		u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);

		refill_fl_budget(idx, now);
		charge_fl_runtime(idx, now, bulk_waiting(cpu));
	}

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
	 * protected tasks against each other. The seat guard makes the
	 * exemption conditional, because under the guard a guarded seat
	 * placement may legally park a latency-critical arrival behind a
	 * latency-critical resident whose slice the guard also bounds;
	 * without the gate that arrival waits out the fourfold slice with
	 * no rung left to cut it.
	 */
	if (plain_1x || (!plain && (!is_lat_cri(tctx) || seat_guard))) {
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
