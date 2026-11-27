/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the queue occupancy and pending counts, the tag encoding, the
 * fast-lane budget accounting and the dispatch.bpf.c prototypes.
 *
 * Scoped header: baby.bpf.h includes it, and it includes nothing
 * itself, so it reads the core types and macros defined there.
 */
#ifndef __BABY_DISPATCH_H
#define __BABY_DISPATCH_H

#ifndef __BABY_H
#error "dispatch.bpf.h is included by baby.bpf.h, not on its own"
#endif

/*
 * The fast-lane credit a CPU holds after the refill its next dispatch
 * would perform, computed without mutating the bucket: the seat guard
 * asks whether the fast lane can still pay before it takes a seat, and
 * a helper that refilled would grant the credit it is testing for.
 * Same window cap and two-thirds rate as refill_fl_budget(), capped at
 * the bucket's own ceiling, so the forecast and the real refill agree.
 */
static __always_inline s64 fl_budget_avail(u32 idx, u64 now)
{
	u32 i = idx & (BABY_MAX_CPUS - 1);
	u64 at = READ_ONCE(cpu_state[i].fl_budget_at);
	u64 elapsed = now > at ? now - at : 0;
	s64 avail = cpu_state[i].fl_budget_ns;

	if (elapsed > 100 * NSEC_PER_MSEC)
		elapsed = 100 * NSEC_PER_MSEC;
	avail += (s64)(elapsed * 2 / 3);

	return MIN(avail, (s64)(4 * deadline_ns));
}

/*
 * Per-queue service clocks for the starve rescue (see main.bpf.c). They
 * are shared with the seat insertion path in balance.bpf.c. The node
 * table is padded to a power of two so the node id can be masked, and
 * the init-time bound check keeps every real node id inside it.
 */
#define BABY_NODE_CLOCK_NR	64

extern u64 seat_service_at[2][BABY_MAX_CPUS];
extern u64 node_service_at[2][BABY_NODE_CLOCK_NR];

/*
 * Per-CPU warm-seat occupancy hints, indexed by lane (0 bulk, 1 fast).
 * A seat is probed only while its hint is set, so an empty seat costs
 * no queue-depth kfunc in the warm-seat scan. The hint is deliberately
 * conservative: a racing pull can clear it while an insertion lands,
 * which costs that arrival one missed probe, never a stranded task.
 */
extern u8 seat_used[2][BABY_MAX_CPUS];

/*
 * Wall-clock time of the newest warm-seat insertion, written by the
 * enqueue path with the throttle below. It is a lower bound on the true
 * time of that insert, and ops.dispatch() reads it once before the
 * steal walk: a seat holds work only while the enqueue keeps filling
 * one, so a machine that has stopped seating has nothing to steal and
 * the walk can be skipped outright. A seat is then served by its owner
 * on its next slice end, and the starve rescue still covers one that
 * outlives its queue clock.
 */
extern u64 seat_last_enq_ns;

/*
 * The stamp throttle and the window it feeds. Ten milliseconds keeps
 * the enqueue's store off a line every CPU would otherwise bounce,
 * which is far below the window that decides whether to scan at all. A
 * throttled stamp can fire the window up to one period early, so the
 * window is a fresh-work test, not a proof that every seat is empty.
 */
#define BABY_SEAT_STAMP_NS		(10ULL * NSEC_PER_MSEC)
#define BABY_SEAT_FRESH_NS		(50ULL * NSEC_PER_MSEC)

/*
 * Per-queue pending counts, indexed by lane (0 bulk, 1 fast): the number
 * of arrivals the scheduler inserted into that queue and has not yet
 * seen leave it. A zero count is a fact about the queue when the reader
 * looked, not a hint: it lets ops.dispatch() and the contention
 * accounting skip the peeks and pull attempts a lane would otherwise
 * cost on every switch, and only the arrival-side work that fills the
 * queue raises it. An insert raises the count before it commits and
 * rolls a refusal back, so a queue a reader finds at zero holds no work
 * that has committed. A departure the scheduler never observes - a
 * kernel-side pop, a task exiting while queued - leaves the count high,
 * which costs a probe and never strands work.
 */
extern u64 seat_pending[2][BABY_MAX_CPUS];
extern u64 node_pending[2][BABY_NODE_CLOCK_NR];

/*
 * A granted slice and the tag it needs share no storage: the tick, the
 * yield and the dispatch keep path all rewrite p->scx.slice, and every
 * caller of the helpers below already holds the task context. The tag
 * names one of the four tagged queues, seat or node queue in one of the
 * two lanes, plus one so that zero reads as "not queued".
 */
#define BABY_TAG_LANE_SHIFT	7	/* one bit, above the 7-bit index */
#define BABY_TAG_NODE_SHIFT	8	/* 0 seat, 1 node queue */
#define BABY_TAG_NODE_BIT	(1U << BABY_TAG_NODE_SHIFT)

static __always_inline u32 baby_tag(u32 node, u32 lane, u32 idx)
{
	idx &= node ? (BABY_NODE_CLOCK_NR - 1) : (BABY_MAX_CPUS - 1);

	return ((node << BABY_TAG_NODE_SHIFT) | (lane << BABY_TAG_LANE_SHIFT) |
		idx) + 1;
}

static __always_inline void baby_pending_add(u32 tag)
{
	u32 t = tag - 1;

	if (t & BABY_TAG_NODE_BIT)
		__sync_fetch_and_add(
			&node_pending[(t >> BABY_TAG_LANE_SHIFT) & 1]
				     [t & (BABY_NODE_CLOCK_NR - 1)], 1);
	else
		__sync_fetch_and_add(
			&seat_pending[(t >> BABY_TAG_LANE_SHIFT) & 1]
				     [t & (BABY_MAX_CPUS - 1)], 1);
}

static __always_inline void baby_pending_sub(u32 tag)
{
	u32 t = tag - 1;

	if (t & BABY_TAG_NODE_BIT)
		__sync_fetch_and_sub(
			&node_pending[(t >> BABY_TAG_LANE_SHIFT) & 1]
				     [t & (BABY_NODE_CLOCK_NR - 1)], 1);
	else
		__sync_fetch_and_sub(
			&seat_pending[(t >> BABY_TAG_LANE_SHIFT) & 1]
				     [t & (BABY_MAX_CPUS - 1)], 1);
}

/*
 * Account that the task has visibly left the queue its tag names. The
 * tag is cleared here, so a second call is a no-op and a stale tag
 * cannot lower a count twice.
 */
static __always_inline void baby_untag(struct task_ctx *tctx)
{
	u32 tag = tctx->queued_tag;

	if (!tag)
		return;
	tctx->queued_tag = 0;
	baby_pending_sub(tag);
}

/*
 * Insert an arrival into one of the tagged queues. The count is raised
 * before the insert commits so that a reader cannot see zero while an
 * insert that will land is in flight, and a refused insert rolls the
 * raise back so the count never outlives a task that did not join.
 */
static __always_inline bool baby_insert_vtime(struct task_struct *p,
					      struct task_ctx *tctx, u64 dsq,
					      u64 slice, u64 deadline,
					      u64 enq_flags, u32 tag)
{
	baby_untag(tctx);
	baby_pending_add(tag);
	if (!scx_bpf_dsq_insert_vtime(p, dsq, slice, deadline, enq_flags)) {
		baby_pending_sub(tag);
		return false;
	}
	tctx->queued_tag = tag;
	return true;
}

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

static __always_inline void refill_fl_budget(u32 idx, u64 now)
{
	u64 elapsed = now - cpu_state[idx].fl_budget_at;
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
	cpu_state[idx].fl_budget_ns = MIN(cpu_state[idx].fl_budget_ns + credit,
					  (s64)(4 * deadline_ns));
	cpu_state[idx].fl_budget_at = now;
}

/*
 * Whether bulk work waits for a CPU: its own seat or the node queue.
 */
static __always_inline bool bulk_waiting(s32 cpu)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);
	u32 nidx = (u32)node & (BABY_NODE_CLOCK_NR - 1);

	/*
	 * Both counts at zero prove nothing was waiting on either bulk
	 * queue when the reader looked, so the probes below are skipped on
	 * the uncontended case. A count that a departure the scheduler
	 * never observed left high only costs the probes.
	 */
	if (!READ_ONCE(seat_pending[0][idx]) &&
	    !READ_ONCE(node_pending[0][nidx]))
		return false;

	return (READ_ONCE(seat_pending[0][idx]) &&
		scx_bpf_dsq_nr_queued(cpu2dsq(cpu))) ||
	       (READ_ONCE(node_pending[0][nidx]) &&
		scx_bpf_dsq_nr_queued(node));
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
	u64 started = cpu_state[idx].fl_running_at;
	s64 floor = -(s64)(2 * deadline_ns);
	u64 ran;

	if (!started) {
		cpu_state[idx].fl_running_at = now;
		return;
	}
	ran = now - started;
	if (ran > 4 * deadline_ns)
		ran = 4 * deadline_ns;
	if (contended)
		cpu_state[idx].fl_budget_ns =
			MAX(cpu_state[idx].fl_budget_ns - (s64)ran, floor);
	cpu_state[idx].fl_running_at = now;
}

#endif /* __BABY_DISPATCH_H */
