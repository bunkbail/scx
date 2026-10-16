/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Scheduling statistics and the measurement instruments: the placement
 * histograms, the wait-at-depth instrument and the consumption census.
 * The counters are read by userspace through the skeleton, so their
 * names and shapes are part of the interface with src/stats.rs.
 */
#include "baby.bpf.h"

/*
 * Scheduling statistics.
 */
volatile u64 nr_running, nr_direct_dispatches, nr_shared_dispatches;
volatile u64 nr_preemptions, nr_boosts, nr_sticky, nr_warmseats;
volatile u64 nr_coldspreads;

/*
 * Saturation deferred-preemption instrument: the victims ops.tick() cut
 * short because a latency-critical task waited at a queue head, split
 * by where the waiter sat - the shared deadline queue or the CPU's own
 * warm seat.
 */
volatile u64 nr_tick_preempts, nr_tick_preempts_warm;

/*
 * Where placements land, by distance rank. The counters tell the warm
 * paths apart: the run-start histogram covers every path's outcome at
 * the point of truth, the wake-pick one covers ops.select_cpu(), and
 * the seat-move one covers the warm-seat rebalance.
 */
volatile u64 nr_land[BABY_DIST_NR];
volatile u64 nr_wake_land[BABY_DIST_NR];
volatile u64 nr_seat_self;
volatile u64 nr_seat_move[BABY_DIST_NR];
volatile u64 nr_pull_land[BABY_DIST_NR];

/*
 * Wait-at-depth instrument. When an enqueue parks a task in a warm
 * seat or the shared queue, it stamps the arrival time and the depth
 * the task will wait behind (0, 1, 2, 3+). ops.running() charges the
 * realized wait to that bucket. The overcommit tail can then be
 * attributed to the depth it waited at: waits behind nothing (depth
 * 0) point at consumption, waits at depth point at rotation cost.
 */
volatile u64 nr_wait_n[BABY_WDEPTH_NR];
volatile u64 nr_wait_ns[BABY_WDEPTH_NR];
volatile u64 nr_wait_max[BABY_WDEPTH_NR];
volatile u64 nr_wait_slow[BABY_WDEPTH_NR];
volatile u64 nr_arr_seat, nr_arr_shared;

#define BABY_WAIT_SLOW_NS	(5ULL * NSEC_PER_MSEC)

/*
 * The same charge, split by class. Each stamped task carries two
 * class bits, derived in ops.runnable() where the burst and
 * wake-frequency EWMAs they read are fresh: bit 0 interactive, bit 1
 * foreground. ops.running() files the wait into class-major 4x4
 * arrays, entry class * BABY_WDEPTH_NR + depth, so the overcommit
 * wait can be attributed to the classes a deadline-ordering change
 * would prioritize.
 */
volatile u64 nr_wait_cls_n[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_ns[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_max[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_slow[BABY_WDEPTH_NR * BABY_WCLS_NR];

/*
 * The same charge, split by arrival type. Type 1 is a wake handoff:
 * the arrival became runnable with SCX_ENQ_WAKEUP (ops.runnable()
 * stamps the bit, ops.stopping() clears it). The complement is the
 * rotation - slice-expiry and preemption requeues, which re-enter
 * without a runnable transition. The split prices the handoff the
 * overcommit tail is blamed on separately from the rotation that
 * dominates the charge counts. Type-major: type * BABY_WDEPTH_NR +
 * depth.
 */
volatile u64 nr_wait_type_n[BABY_WDEPTH_NR * BABY_WTYPE_NR];
volatile u64 nr_wait_type_ns[BABY_WDEPTH_NR * BABY_WTYPE_NR];
volatile u64 nr_wait_type_max[BABY_WDEPTH_NR * BABY_WTYPE_NR];
volatile u64 nr_wait_type_slow[BABY_WDEPTH_NR * BABY_WTYPE_NR];

/*
 * Where each arrival type landed: wake or rotation, warm seat or
 * shared queue. Indexed type * 2 + shared.
 */
volatile u64 nr_arr_type[2 * 2];

/*
 * Consumption census: sampled in ops.dispatch(), the queue state a
 * lane sees when it comes to pick work - the depth left in its warm
 * seat and the shared backlog the rotation turns on. Eight buckets,
 * the last one 7 or deeper; clamped by assignment and masked at use,
 * like the wait depth.
 */
volatile u64 nr_census_seat[BABY_CENSUS_NR];
volatile u64 nr_census_shared[BABY_CENSUS_NR];

/*
 * Stamp a waiting arrival for the wait-at-depth instrument. The depth
 * is clamped here by assignment through the u8 field and masked again
 * at the charging site, so the verifier can prove the bucket index.
 */
__hidden void stamp_wait(struct task_ctx *tctx, u64 now, u64 depth, bool shared)
{
	u8 type = tctx->arrival_is_wake & 1;

	tctx->wait_stamp = now;
	tctx->wait_depth = (u8)MIN(depth, BABY_WDEPTH_NR - 1);
	tctx->wait_shared = shared;
	if (shared)
		__sync_fetch_and_add(&nr_arr_type[type * 2 + 1], 1);
	else
		__sync_fetch_and_add(&nr_arr_type[type * 2], 1);
}

/*
 * Charge the wait a task actually served to the depth bucket its
 * arrival was stamped with. The index is masked because a reloaded u8
 * proves nothing to the verifier; the stored value is already clamped,
 * so the mask only ever matters for a corrupted stamp.
 */
__hidden void charge_wait(struct task_ctx *tctx, u64 now)
{
	if (tctx->wait_stamp) {
		u64 wait = now - tctx->wait_stamp;
		u32 b = tctx->wait_depth & (BABY_WDEPTH_NR - 1);
		u32 c = tctx->wait_cls & (BABY_WCLS_NR - 1);
		u32 i = c * BABY_WDEPTH_NR + b;

		tctx->wait_stamp = 0;
		__sync_fetch_and_add(&nr_wait_n[b], 1);
		__sync_fetch_and_add(&nr_wait_ns[b], wait);
		if (wait > nr_wait_max[b])
			nr_wait_max[b] = wait;
		if (wait > BABY_WAIT_SLOW_NS)
			__sync_fetch_and_add(&nr_wait_slow[b], 1);
		__sync_fetch_and_add(&nr_wait_cls_n[i], 1);
		__sync_fetch_and_add(&nr_wait_cls_ns[i], wait);
		if (wait > nr_wait_cls_max[i])
			nr_wait_cls_max[i] = wait;
		if (wait > BABY_WAIT_SLOW_NS)
			__sync_fetch_and_add(&nr_wait_cls_slow[i], 1);

		u32 t = tctx->arrival_is_wake & 1;
		u32 ti = t * BABY_WDEPTH_NR + b;

		__sync_fetch_and_add(&nr_wait_type_n[ti], 1);
		__sync_fetch_and_add(&nr_wait_type_ns[ti], wait);
		if (wait > nr_wait_type_max[ti])
			nr_wait_type_max[ti] = wait;
		if (wait > BABY_WAIT_SLOW_NS)
			__sync_fetch_and_add(&nr_wait_type_slow[ti], 1);
	}
}

/*
 * Consumption census: the queue state a lane came to pick work from -
 * the depth left in its warm seat and the shared backlog the rotation
 * turns on. Sampled at every dispatch, so the distribution carries the
 * consumption-rate weighting the arrival-time wait stamp lacks.
 */
__hidden void census_sample(s32 cpu)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	u64 seat = scx_bpf_dsq_nr_queued(cpu2dsq(cpu));
	u64 backlog = scx_bpf_dsq_nr_queued(node);
	u8 s = (u8)MIN(seat, BABY_CENSUS_NR - 1);
	u8 g = (u8)MIN(backlog, BABY_CENSUS_NR - 1);

	__sync_fetch_and_add(&nr_census_seat[s & (BABY_CENSUS_NR - 1)], 1);
	__sync_fetch_and_add(&nr_census_shared[g & (BABY_CENSUS_NR - 1)], 1);
}
