/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the queue occupancy and pending counts, the tag encoding, the
 * fast-lane budget forecast and the dispatch.bpf.c prototypes.
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
 * Per-CPU running-class residency, stamped in ops.running() and cleared
 * in ops.stopping(). Queue depth cannot answer whether a CPU runs a
 * tick-cuttable bulk resident: CPU-bound workers never queue, so bulk
 * depth can read zero while bulk residency is total. The fast-lane
 * oversubscription gate, the fast-lane budget and the dispatch keep
 * read this instead.
 */
extern bool cpu_is_lat[BABY_MAX_CPUS];
extern bool cpu_running[BABY_MAX_CPUS];

/*
 * The residency stamp and the fast-lane budget, defined in main.bpf.c.
 * The guarded warm-seat preemption in balance.bpf.c reads them without
 * owning them: it asks the same questions the tick gate asks, so a seat
 * placement and a tick cut cannot disagree about whether a victim is
 * past the floor or whether the fast lane can still pay.
 */
extern u64 cpu_running_at[BABY_MAX_CPUS];
extern s64 fl_budget_ns[BABY_MAX_CPUS];
extern u64 fl_budget_at[BABY_MAX_CPUS];

/*
 * The fast-lane interval stamps: when this CPU's fast-lane run started,
 * whether bulk work waited at the stop that ended it, and the bulk
 * backstop clock. Defined in main.bpf.c, which stamps them from
 * ops.dispatch() and ops.stopping().
 */
extern u64 cpu_fl_running_at[BABY_MAX_CPUS];
extern bool cpu_bulk_wait[BABY_MAX_CPUS];
extern u64 cpu_bulk_at[BABY_MAX_CPUS];

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
	u64 at = READ_ONCE(fl_budget_at[i]);
	u64 elapsed = now > at ? now - at : 0;
	s64 avail = fl_budget_ns[i];

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

#endif /* __BABY_DISPATCH_H */
