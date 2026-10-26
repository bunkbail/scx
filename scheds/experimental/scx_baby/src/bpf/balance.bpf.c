/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * The warm-seat balance under oversubscription: the sum gate, the
 * shallowest-nearest seat scan and the slice an arrival receives.
 * Returns true when the task was seated, so the caller can fall through
 * to direct dispatch and the shared queue otherwise.
 */
#include "baby.bpf.h"

/*
 * Warm seat, gated on oversubscription. When runnable work exceeds the
 * CPU count, an arrival waits on the CPU it last ran on, behind
 * whatever runs there: its cache and TLB are still warm, and the CPU
 * serves it at its next slice end. Pulling it to whichever CPU expires
 * first turns every rotation into a cold migration.
 *
 * At full saturation the seat is harmful: with every CPU holding one
 * task, it freezes lane skew. Overloaded lanes rotate internally while
 * CPUs whose task blocked starve. The discriminator is the machine's
 * outstanding runnable work, per lane: running lanes plus that lane's
 * shared backlog and warm seats. The sum is conserved across the
 * running-to-queued transitions that race a bare nr_running gate,
 * because a worker can block between chunks and make nr_running dip.
 * One lane of margin keeps a transient two-deep queue at saturation
 * from flipping the mode back.
 *
 * Returns true when the task was seated on a warm queue; false leaves
 * the enqueue to the direct dispatch and the shared queue.
 */
__hidden bool balance_try_warm_seat(struct task_struct *p, struct task_ctx *tctx,
			   u64 enq_flags, u64 bulk_backlog, u64 fl_backlog,
			   u64 now)
{
	s32 prev_cpu = scx_bpf_task_cpu(p);

	/*
	 * A rescued or RT-released task is a task the machine could not
	 * serve where it sat: seating it straight back into the same
	 * warm queue would reset its clock and strand it there. It has
	 * already had its idle-CPU rescan in ops.enqueue(); anything
	 * still waiting joins the shared queue, which every CPU can
	 * pull.
	 */
	if (enq_flags & SCX_ENQ_REENQ)
		return false;

	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		bool lat = is_lat_cri(tctx);
		bool vlat = lat && tctx->wake_gate_miss == BABY_WG_M4_VICTIM_LAT;
		s32 target = prev_cpu;
		u64 target_nr = scx_bpf_dsq_nr_queued(lat ?
						      fl_cpu2dsq(target) :
						      cpu2dsq(target));
		u64 b_warm = 0, q_warm = 0, lat_running = 0;
		u64 best_nr = BABY_MAX_CPUS, i, n_running = 0;
		u32 best_rank = BABY_DIST_NR, rank;
		s32 best = target;

		bpf_for(i, 0, nr_cpu_ids) {
			u32 ci = (u32)i & (BABY_MAX_CPUS - 1);
			/*
			 * The scan is the only reader of the runnable
			 * count, so it counts the per-CPU residency here
			 * instead of the switch path paying a global
			 * read-modify-write for it.
			 */
			if (cpu_running[ci])
				n_running++;
			/*
			 * Probe only seats the occupancy hint marks as
			 * possibly non-empty. At saturation most seats
			 * are empty, and the two queue-depth kfuncs per
			 * CPU were the scan's cost.
			 */
			u64 b_nr = seat_used[0][ci] ?
					   scx_bpf_dsq_nr_queued(cpu2dsq(i)) : 0;
			u64 q_nr = seat_used[1][ci] ?
					   scx_bpf_dsq_nr_queued(fl_cpu2dsq(i)) : 0;
			u64 nr = lat ? q_nr : b_nr;
			bool i_lat = cpu_is_lat[ci];

			b_warm += b_nr;
			q_warm += q_nr;
			if (i_lat)
				lat_running++;

			if ((s32)i == target ||
			    (target_nr < 2 && !vlat) ||
			    !(enq_flags & SCX_ENQ_WAKEUP) ||
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

		/*
		 * Per-lane oversubscription. The bulk clause is the
		 * single-lane gate: running lanes, shared backlog and bulk
		 * seats, plus a latency-critical arrival's own seat depth.
		 * The fast-lane clause opens seats when the fast lane
		 * itself is oversubscribed: latency-critical residents,
		 * shared backlog and fast-lane seats. A single summed gate
		 * cannot serve both cases: counting fast-lane backlog
		 * against bulk saturation seats wakes warm when they should
		 * not be, and counting bulk residency against a
		 * fast-lane-only workload closes the seats.
		 */
		if (n_running + bulk_backlog + b_warm +
			    (lat ? target_nr : 0) > nr_cpu_ids + 1 ||
		    lat_running + fl_backlog + q_warm > nr_cpu_ids + 1) {
			/*
			 * A waking latency-critical task whose previous
			 * CPU runs another latency-critical task gets an
			 * effective depth of two and relocates to the
			 * nearest CPU with a shallow fast-lane seat and a
			 * cuttable bulk resident. A pure latency-critical
			 * swarm filters out every CPU, so no relocation
			 * happens there.
			 */
			u64 eff_nr = target_nr + (vlat ? 2 : 0);
			u64 dsq, slice;

			if (best != target && best_nr + 2 <= eff_nr) {
				target = best;
				target_nr = best_nr;
				if (stats_enabled)
					__sync_fetch_and_add(
						&nr_seat_move[cpu_dist(
							prev_cpu, target)],
						1);
			} else if (stats_enabled) {
				__sync_fetch_and_add(&nr_seat_self, 1);
			}

			/*
			 * The depth rung is bulk-only and is decided on the
			 * seat the task actually joins: a non-foreground
			 * latency-critical arrival granted four slices
			 * becomes a long fast-lane resident that neither
			 * the tick gate, the wake-path preempt nor a seat
			 * relocation can cut, and a tick-preempted victim
			 * did not earn the rung. Foreground tasks get the
			 * fourfold slice from task_slice() anyway.
			 */
			slice = (!lat && !tctx->tick_preempted &&
				 (backlog_deep(bulk_backlog) ||
				  target_nr >= 2)) ?
				4 * deadline_ns : task_slice(tctx);

			dsq = lat ? fl_cpu2dsq(target) : cpu2dsq(target);
						/*
			 * Seed the rescue clock when the target seat was
			 * empty; a seat that is being served needs none.
			 * Mark the seat for the scan's occupancy hint on
			 * every insertion, idempotently.
			 */
			{
				u32 tidx = (u32)target & (BABY_MAX_CPUS - 1);
				u32 lane = lat ? 1 : 0;

				if (!target_nr)
					seat_service_at[lane][tidx] = now;
				/*
				 * Publish the occupancy hint after the
				 * insert. A reader that sees a clear hint
				 * may then be sure the seat was empty when
				 * the writer committed; an insert that
				 * lands after the reader's peek carries the
				 * kick that brings the CPU back.
				 */
				baby_insert_vtime(p, tctx, dsq, slice,
						  tctx->deadline, 0,
						  baby_tag(0, lane, target));
				WRITE_ONCE(seat_used[lane][tidx], 1);
			}
			stamp_wait(tctx, now, target_nr, false);
			/*
			 * A latency-critical arrival seated on a busy CPU
			 * needs a preemption kick, not an idle one. A seat
			 * is a per-CPU queue: only that CPU pulls it, and
			 * only when it reaches its dispatcher. An idle kick
			 * is a no-op while the CPU runs a task, so the
			 * arrival would wait out the resident's slice (up
			 * to the fourfold one); SCX_KICK_PREEMPT makes the
			 * CPU reschedule and hand over now.
			 *
			 * Two arrivals keep the idle kick. A bulk arrival
			 * waits its turn. A latency-critical arrival whose
			 * target already runs another latency-critical task
			 * does too: preempting it would trade one protected
			 * task for the other, and a cell where every task
			 * wakes often would then displace its resident on
			 * every seat placement. That is the churn the
			 * wake-side gate refuses to start, so the seat path
			 * refuses it as well.
			 */
			struct task_struct *res = __COMPAT_scx_bpf_cpu_curr(target);
			struct task_ctx *rctx = res ? try_lookup_task_ctx(res) : NULL;
			bool preempt = lat && (!rctx || !is_lat_cri(rctx));

			scx_bpf_kick_cpu(target, preempt ? SCX_KICK_PREEMPT
							 : SCX_KICK_IDLE);
			return true;
		}

		/*
		 * Not oversubscribed: leave the seat open and let the
		 * cold path run. A requeue re-scans for an idle lane
		 * before joining the shared queue, which keeps the load
		 * distribution flowing at saturation.
		 */
		if (stats_enabled)
			__sync_fetch_and_add(&nr_coldspreads, 1);
	}

	return false;
}
