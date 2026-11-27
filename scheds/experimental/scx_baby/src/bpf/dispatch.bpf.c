/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * ops.dispatch(): the per-CPU lane arbitration, the warm-seat steal an
 * about-to-idle CPU performs, and the idle tail that hands the CPU back.
 */
#include "baby.bpf.h"

/*
 * Take one task off another CPU's warm seat (seat guard).
 *
 * A seat is a per-CPU queue: only its owner pulls it. A CPU whose own
 * queues are empty therefore idles while a sibling's seat holds a
 * queue, and the enqueue that would have pulled the task to the idle
 * CPU has already parked it. The steal is the other half of that
 * bargain - the CPU about to stop takes one task instead of waiting for
 * the owner's slice to end.
 *
 * The lane order is the enqueue's: the fast-lane seat first, the bulk
 * seat second. A seat whose hint is clear is skipped, and a hinted seat
 * whose queue reads empty clears its own hint, exactly as the owner's
 * pull would. A move that fails - an affinity the CPU cannot serve, or
 * the owner's own pull winning the race - leaves the task where it is;
 * the steal is an opportunity, never a reservation.
 */
static __noinline bool seat_steal_one(s32 other, u32 lane, u64 now)
{
	u32 oidx = (u32)other & (BABY_MAX_CPUS - 1);
	u64 dsq = lane ? fl_cpu2dsq(other) : cpu2dsq(other);

	if (!READ_ONCE(seat_used[lane][oidx]))
		return false;
	if (!scx_bpf_dsq_nr_queued(dsq)) {
		seat_used[lane][oidx] = 0;
		return false;
	}
	if (!scx_bpf_dsq_move_to_local(dsq, 0))
		return false;

	seat_service_at[lane][oidx] = now;
	if (!scx_bpf_dsq_nr_queued(dsq))
		seat_used[lane][oidx] = 0;
	return true;
}

/*
 * Walk every other CPU once, starting one past @cpu so that the same
 * seat is not the first one every idle CPU looks at. @reach narrows the
 * walk to a ring: the caller's own LLC, its node, or anywhere. The
 * caller runs the rings nearest first, so a steal keeps the task in the
 * cache domain the enqueue placed it in whenever an inner ring can serve
 * it. On a single-LLC machine the LLC ring is the whole walk and the
 * outer rings only re-read the occupancy hints. The bound is nr_cpu_ids
 * clamped to the table width, so the walk and the masked index visit the
 * same set.
 */
#define SEAT_REACH_LLC	0
#define SEAT_REACH_NODE	1
#define SEAT_REACH_ANY	2

static __noinline bool seat_steal_scan(s32 cpu, u64 now, u32 reach)
{
	u32 nr = (u32)MIN((u64)BABY_MAX_CPUS, nr_cpu_ids);
	u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);
	u32 own_node = topo_node[idx];
	u32 own_llc = topo_llc[idx];
	u32 off;

	if (nr < 2)
		return false;

	bpf_for(off, 0, nr) {
		u32 other = (u32)cpu + off + 1;
		u32 oidx;

		if (other >= nr)
			other -= nr;
		oidx = other & (BABY_MAX_CPUS - 1);
		if (reach == SEAT_REACH_LLC && topo_llc[oidx] != own_llc)
			continue;
		if (reach == SEAT_REACH_NODE &&
		    (topo_node[oidx] != own_node ||
		     topo_llc[oidx] == own_llc))
			continue;
		if (seat_steal_one((s32)other, 1, now) ||
		    seat_steal_one((s32)other, 0, now))
			return true;
	}

	return false;
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
	struct task_ctx *tctx;
	bool need_running = prev && is_queued(prev);
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);
	u32 nidx = (u32)node & (BABY_NODE_CLOCK_NR - 1);
	u64 fl_seat_dsq = fl_cpu2dsq(cpu);
	u64 fl_node_dsq = fl_node2dsq(node);
	u64 bulk_seat_dsq = cpu2dsq(cpu);
	struct task_struct *fl_wq, *fl_q, *wq, *q;
	u64 fl_wq_dl, fl_g_dl, wq_dl, g_dl, fl_dl, bulk_dl, best_dl;
	u64 seat_bulk, seat_fast, node_bulk, node_fast;
	u64 now = bpf_ktime_get_ns();
	bool has_fl, has_bulk, fl_allowed, serve_fl;
	/*
	 * The budget carried into this dispatch, before its own credit.
	 * The take-back below is bounded by this value, not by the
	 * refilled one: the dispatch credit would otherwise lift the
	 * budget off the debt floor on every call and the exemption would
	 * be granted forever.
	 */
	s64 fl_budget_in = cpu_state[idx].fl_budget_ns;

	/*
	 * Only the keep paths and the stats counters read the previous
	 * task's context. A dispatch where prev is blocking, the common
	 * case on a wake-heavy workload, skips the storage lookup.
	 */
	tctx = (need_running || stats_enabled) && prev ?
		try_lookup_task_ctx(prev) : NULL;

	/*
	 * Plain mode (--plain): the minimal EDF dispatcher. One shared
	 * deadline queue per node feeds the CPU; the fast lane, the bulk
	 * seats, the lane budget and the lane arbitration stay out of the
	 * path entirely. A running task that finds the queue empty keeps
	 * the CPU with a renewed deadline, which is the same rotation the
	 * full dispatcher performs without any of its placement rules.
	 */
	if (plain) {
		bool pinned = false;

		/*
		 * Game pin: a shielded CPU drains its two seats before
		 * it looks at anything else, because the seats are where
		 * the pin parks a pinned arrival and a stranded one. The
		 * drains are unconditional so that no arrival can sit in a
		 * seat while the CPU idles, and they cost an empty-queue
		 * lookup when no pin is claimed. Everything that asks a
		 * slot a question is gated on a shield existing, so a run
		 * with the flag but no claim touches no map here.
		 */
		if (game_pin) {
			if (scx_bpf_dsq_move_to_local(cpu2dsq(cpu), 0)) {
				seat_service_at[0][idx] = now;
				return;
			}
			if (scx_bpf_dsq_move_to_local(fl_cpu2dsq(cpu), 0)) {
				seat_service_at[1][idx] = now;
				return;
			}
			if (!READ_ONCE(pin_shield_n)) {
				if (scx_bpf_dsq_move_to_local(node, 0))
					return;
			} else {
				/*
				 * A pinned prev keeps running without the
				 * node pull ahead of it; any other prev
				 * yields a core the pin is holding.
				 */
				pinned = need_running && prev &&
					 pin_owns_cpu(cpu, prev);
				if (!pinned) {
					if (is_cpu_shielded(cpu, now)) {
						struct task_struct *head, *q;

						need_running = false;
						/*
						 * A shielded CPU still serves a
						 * task that can run nowhere
						 * else, and it must take THAT
						 * task: a plain pull pops queue
						 * position 0, which may be a
						 * task this CPU cannot run.
						 */
						head = dsq_peek_allowed(node,
									cpu);
						if (head && (is_pcpu_task(head) ||
							     pin_wholly_shielded(head))) {
							bpf_for_each(scx_dsq, q, node, 0) {
								if (q != head)
									continue;
								if (scx_bpf_dsq_move(
								    BPF_FOR_EACH_ITER,
								    q,
								    SCX_DSQ_LOCAL, 0))
									return;
								break;
							}
						}
					} else if (scx_bpf_dsq_move_to_local(
							   node, 0)) {
						return;
					}
				}
			}
		} else if (scx_bpf_dsq_move_to_local(node, 0)) {
			return;
		}

		/*
		 * --plain-vtime refuses in-place renewal on a contended
		 * SMT core, as cosmos's keep_running does, unless the task
		 * can only run here: a pinned task would come straight back
		 * to the same half core. A game-pinned prev is exempt: the
		 * core is held for it.
		 */
		if (plain_vtime && need_running && !pinned &&
		    !is_pcpu_task(prev) && cpu_smt_shared(cpu))
			need_running = false;

		if (!need_running) {
			cpuperf_on_idle(cpu);
			return;
		}
		if (tctx) {
			update_bursts(tctx, now);
			if (reached_deadline(tctx, now))
				tctx->deadline =
					calc_deadline(prev, tctx, now);
			tctx->tick_preempted = false;
			tctx->yield_pending = false;
			tctx->last_cpu = cpu;
			cpu_state[idx].running_at = now;
		}
		scx_bpf_task_set_slice(prev,
				       tctx ? task_slice(tctx) : deadline_ns);
		return;
	}

	if (stats_enabled)
		census_sample(cpu);
	refill_fl_budget(idx, now);

	/*
	 * One peek of each lane per dispatch: the sticky check and the
	 * arbitration read the same heads, and the peeked pointers stay
	 * valid until the pulls enter their own RCU scope. The shared
	 * heads are the first task this CPU can run, not the queue head:
	 * an affinity-restricted head must neither read as the lane's
	 * next deadline here nor hide the tasks behind it.
	 *
	 * A lane whose pending count is zero held nothing when this
	 * dispatch read it, so its peek is skipped: on a machine that
	 * spreads wakeups across idle CPUs both lanes read zero on almost
	 * every dispatch, and the peek is a queue lookup. A count a
	 * departure the scheduler never observed left high costs the peek
	 * and changes nothing else.
	 */
	seat_bulk = READ_ONCE(seat_pending[0][idx]);
	seat_fast = READ_ONCE(seat_pending[1][idx]);
	node_bulk = READ_ONCE(node_pending[0][nidx]);
	node_fast = READ_ONCE(node_pending[1][nidx]);

	fl_wq = seat_fast ? __COMPAT_scx_bpf_dsq_peek(fl_seat_dsq) : NULL;
	fl_q = node_fast ? dsq_peek_allowed(fl_node_dsq, cpu) : NULL;
	wq = seat_bulk ? __COMPAT_scx_bpf_dsq_peek(bulk_seat_dsq) : NULL;
	q = node_bulk ? dsq_peek_allowed(node, cpu) : NULL;

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
	if (!has_bulk && cpu_state[idx].fl_budget_ns < 0)
		cpu_state[idx].fl_budget_ns = 0;
	fl_allowed = !has_bulk || cpu_state[idx].fl_budget_ns > 0;
	serve_fl = has_fl && fl_allowed;

	/*
	 * The bulk clock starts when bulk work arrives, not when the last
	 * bulk task ran: refresh it while no bulk waits (and on a CPU that
	 * has never recorded a run), so a burst after a quiet period does
	 * not fire the backstop on its first dispatch.
	 */
	if (!has_bulk || !cpu_state[idx].bulk_at)
		cpu_state[idx].bulk_at = now;

	/*
	 * Bulk backstop (see state.bpf.h): a CPU that has run nothing but
	 * the fast lane for a full bound serves bulk now, whatever the
	 * budget or a home head says. Pinned bulk work has no other CPU
	 * to run on, so the alternative is the kernel's stall watchdog.
	 */
	if (has_bulk && now - cpu_state[idx].bulk_at > BABY_BULK_BACKSTOP_NS) {
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
				cpu_state[idx].running_at = now;
				cpu_state[idx].is_lat = is_lat_cri(tctx);
				if (!cpu_state[idx].is_lat)
					cpu_state[idx].bulk_at = now;
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

		if (node_bulk && scx_bpf_dsq_move_to_local(node, 0)) {
			if (now - node_service_at[0][nidx] >
			    NSEC_PER_MSEC)
				node_service_at[0][nidx] = now;
			if (stats_enabled)
				__sync_fetch_and_add(
					&nr_pull_land[cpu_dist(cpu, from)], 1);
			return;
		}
		if (seat_bulk && scx_bpf_dsq_move_to_local(bulk_seat_dsq, 0)) {
			seat_service_at[0][idx] = now;
			if (seat_used[0][idx] &&
			    !scx_bpf_dsq_nr_queued(bulk_seat_dsq))
				seat_used[0][idx] = 0;
			return;
		}
	} else {
		if (seat_bulk && scx_bpf_dsq_move_to_local(bulk_seat_dsq, 0)) {
			seat_service_at[0][idx] = now;
			if (seat_used[0][idx] &&
			    !scx_bpf_dsq_nr_queued(bulk_seat_dsq))
				seat_used[0][idx] = 0;
			return;
		}
		if (node_bulk && scx_bpf_dsq_move_to_local(node, 0)) {
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
			cpu_state[idx].running_at = now;
			cpu_state[idx].is_lat = is_lat_cri(tctx);
			if (cpu_state[idx].is_lat)
				charge_fl_runtime(idx, now, has_bulk);
			else
				cpu_state[idx].bulk_at = now;
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
		 *
		 * These two pulls are the last thing before the CPU idles,
		 * so they stay unconditional even when the pending counts
		 * above said both lanes were empty: they are what closes the
		 * one race a count cannot, an insert that commits between
		 * the count's read and this point. A pull with nothing
		 * behind it costs a queue lookup, which is what the counts
		 * save on every other dispatch.
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
		 * Seat steal (seat guard): the enqueue path parks a warm
		 * arrival on a CPU's own seat, and only that CPU pulls
		 * its seat, so work can wait there while this CPU stops.
		 * Take one task off another seat before idling, nearest
		 * ring first: an LLC-local steal keeps the task in its
		 * cache domain, and a hybrid or multi-LLC machine then
		 * tries the rest of the node before it hops, so no cross-
		 * node move is paid while same-node work waits.
		 *
		 * The walk is worth nothing when no seat can hold work,
		 * so the stamp of the newest seat insertion gates it: a
		 * machine that has not seated anything for the window
		 * skips the scan on one read-mostly load, which is what
		 * perf pipe and a quiet desktop pay instead of three
		 * queue probes per CPU. The window is the stamp's own
		 * throttle plus a margin, so an empty-seat run pays
		 * neither the probes nor the store.
		 *
		 * The rings are then ordered by what the topology can
		 * reach. The LLC ring is the whole walk on a single-LLC
		 * machine, so the node ring runs only when a second LLC
		 * exists, and the catch-all ring only when a second node
		 * does.
		 *
		 * An LP core never steals. The seats it reaches hold work
		 * the enqueue placed on a non-LP CPU, and pulling it down
		 * to a little core trades that placement's throughput for
		 * a migration. The tier counters are zero on a machine
		 * without tiers, so the test folds away there, and an
		 * empty mask means no tier has been published yet: the
		 * steal stays allowed rather than closing on a guess.
		 *
		 * A big core at light load does not steal either. The
		 * wake path packs sub-saturation work onto the little
		 * tier, so a big core that stops has nothing waiting
		 * that belongs on it: a steal would pull a little-placed
		 * task back up a tier, undo the compaction and hold the
		 * core out of C3 while xz or a desktop idles. Once the
		 * little tier is oversubscribed by more than its own
		 * depth, the steal is worth the migration again.
		 */
		if (!plain &&
		    now - READ_ONCE(seat_last_enq_ns) <= BABY_SEAT_FRESH_NS) {
			bool multi_llc = nr_llc_ids > 1;
			bool multi_node = nr_node_ids > 1;
			bool no_steal = false;

			if (nr_little_cpus && nr_big_cpus) {
				struct bpf_cpumask *mask = non_lp_cpumask;
				struct bpf_cpumask *big = big_cpumask;

				if (mask &&
				    !bpf_cpumask_empty(cast_mask(mask)))
					no_steal = !bpf_cpumask_test_cpu(
						cpu, cast_mask(mask));
				if (!no_steal &&
				    nr_running <= nr_little_cpus + 2 &&
				    big && !bpf_cpumask_empty(cast_mask(big)) &&
				    bpf_cpumask_test_cpu(cpu, cast_mask(big)))
					no_steal = true;
			}

			if (!no_steal &&
			    (seat_steal_scan(cpu, now, SEAT_REACH_LLC) ||
			     (multi_llc &&
			      seat_steal_scan(cpu, now, SEAT_REACH_NODE)) ||
			     (multi_node &&
			      seat_steal_scan(cpu, now, SEAT_REACH_ANY))))
				return;
		}
		/*
		 * The CPU is going idle: drop its performance level. The
		 * write happens once, when the level changes; see the
		 * comment on perf_req. An idle dispatch breaks the
		 * fast-lane interval, so the next run charges no gap.
		 */
		cpu_state[idx].fl_running_at = 0;
		cpu_state[idx].bulk_at = 0;
		cpu_state[idx].bulk_wait = false;
		cpuperf_on_idle(cpu);
	}
}
