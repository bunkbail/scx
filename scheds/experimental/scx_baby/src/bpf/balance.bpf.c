/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Copyright (C) 2026 bunkbail <nabildanial.93@gmail.com>
 *
 * The warm-seat balance under oversubscription: the sum-gate
 * discriminator, the shallowest-nearest seat scan and the slice the
 * rotation grants. Returns whether the task was seated, so the caller
 * can fall through to direct dispatch and the shared queue otherwise.
 */
#include "baby.bpf.h"

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
 *
 * Returns true when the task was seated on a warm queue; false
 * leaves the enqueue to the direct dispatch and the shared queue.
 */
__hidden bool balance_try_warm_seat(struct task_struct *p, struct task_ctx *tctx,
			   u64 enq_flags, u64 backlog, u64 now)
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
		u64 best_nr = BABY_MAX_CPUS, i;
		u32 best_rank = BABY_DIST_NR, rank;
		s32 best = target;

		bpf_for(i, 0, nr_cpu_ids) {
			u64 b_nr = scx_bpf_dsq_nr_queued(cpu2dsq(i));
			u64 q_nr = scx_bpf_dsq_nr_queued(fl_cpu2dsq(i));
			u64 nr = lat ? q_nr : b_nr;
			bool i_lat = cpu_is_lat[i & (BABY_MAX_CPUS - 1)];

			b_warm += b_nr;
			q_warm += q_nr;
			if (i_lat)
				lat_running++;

			if ((s32)i == target ||
			    (target_nr < 2 && (!vlat || i_lat)) ||
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
		 * Per-lane oversubscription. One gate summing
		 * bulk_running (inside nr_running) with fast-lane backlog
		 * seats game wakes warm whenever bulk sits at its 1x
		 * wall and the frame threads burst - 12.6pp of game2
		 * (the M1.6 law). The bulk clause is the single-lane
		 * gate: queue depth plus the task's own seat. The lat
		 * clause opens warm seats only when the lat lane
		 * itself is oversubscribed (the ab5600 swarm, whose
		 * bulk lane is empty).
		 */
		if (nr_running + backlog + b_warm + (lat ? target_nr : 0) >
			    nr_cpu_ids + 1 ||
		    lat_running + backlog + q_warm > nr_cpu_ids + 1) {
			/*
			 * A waking lat-cri task whose prev_cpu is running
			 * another lat-cri task (BABY_WG_M4_VICTIM_LAT) gets
			 * an effective depth of two and relocates to the
			 * nearest CPU whose fast-lane seat is shallow AND whose
			 * resident is cuttable bulk: for shallow seats the
			 * scan skips lat-resident CPUs, since a relocation
			 * onto an un-cuttable lat resident is a pure
			 * migration (the M1.6a lesson, which cost 2x its
			 * p99.9). A pure lat swarm filters out every CPU,
			 * so M4 stays off there.
			 */
			u64 eff_nr = target_nr + (vlat ? 2 : 0);
			/*
			 * The depth rung is bulk-only: a slice above
			 * task_slice() must exclude the lat lane, because a
			 * non-foreground lat-cri arrival granted 4x becomes a
			 * 4.72ms fast-lane resident that neither the tick gate, the
			 * wake-preempt gates nor a seat relocation can cut -
			 * and game threads stack two-deep on exactly those
			 * seats (the M1.1/M1.4 lesson). Foreground tasks earn
			 * the fourfold slice from task_slice() itself, so the
			 * exclusion is a no-op wherever every lat-cri task is
			 * foreground (ab5600 med/sat).
			 */
			u64 slice = (!lat && (backlog_deep(backlog) ||
					      target_nr >= 2)) ?
				    4 * deadline_ns : task_slice(tctx);
			u64 dsq;

			if (best != target && best_nr + 2 <= eff_nr) {
				target = best;
				target_nr = best_nr;
				if (stats_enabled)
					__sync_fetch_and_add(
						&nr_seat_move[cpu_dist(
							prev_cpu, target)],
						1);
			} else {
				__sync_fetch_and_add(&nr_seat_self, 1);
			}

			dsq = lat ? fl_cpu2dsq(target) : cpu2dsq(target);
			scx_bpf_dsq_insert_vtime(p, dsq, slice,
						 tctx->deadline, 0);
			stamp_wait(tctx, now, target_nr, false);
			__sync_fetch_and_add(&nr_arr_seat, 1);
			__sync_fetch_and_add(&nr_warmseats, 1);
			scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
			return true;
		}

		/*
		 * Not oversubscribed: leave the seat open and let the
		 * cold path run - a requeue re-scans for an idle lane
		 * before joining the shared queue, which is what keeps
		 * the wall's load distribution flowing.
		 */
		__sync_fetch_and_add(&nr_coldspreads, 1);
	}

	return false;
}
