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
			/*
			 * The rebalance needs a seat already two deep:
			 * below that, no queue satisfies the
			 * shallowest-nearest bound and the scan body can
			 * never move the task. Keep only the warm_total
			 * accounting.
			 */
			if (target_nr < 2 || !(enq_flags & SCX_ENQ_WAKEUP) ||
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
			u64 slice = (backlog_deep(backlog) || target_nr >= 2) ?
				    4 * deadline_ns : task_slice(tctx);

			if (best != target && best_nr + 2 <= target_nr) {
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

			scx_bpf_dsq_insert_vtime(p, cpu2dsq(target), slice,
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
