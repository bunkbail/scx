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
 * The wait/census instrument and the distance histograms run only when
 * userspace asked for stats at load; the flag is rodata, fixed with
 * --stats. The wait stamps stay unconditional: the starve-rescue timer
 * reads them as its queue-arrival clock.
 */
const volatile bool stats_enabled;

/*
 * Scheduling statistics. nr_running is a control-plane input read by
 * ops.select_cpu() and the warm-seat gate on every wake and enqueue;
 * it is always maintained. Every other counter in this file is
 * diagnostic and is written only when --stats enabled the instrument,
 * so the default hot path carries no global atomics and the verifier
 * prunes the increments outright.
 */
__attribute__((aligned(64))) volatile u64 nr_running;
__attribute__((aligned(64))) volatile u64 nr_direct_dispatches;
volatile u64 nr_preemptions, nr_boosts, nr_sticky, nr_coldspreads;

/*
 * Class census at run start: the class composition and the lane of
 * every dispatched task. "Measured, not declared" classification needs
 * to be countable, or a latched class is invisible.
 */
volatile u64 nr_class[BABY_WCLS_NR];
volatile u64 nr_lane[2];

/*
 * Saturation preemption instrument: victims ops.tick() cut short
 * because a latency-critical task waited at a queue head, split by
 * where the waiter sat.
 */
volatile u64 nr_tick_preempts, nr_tick_preempts_warm;

/*
 * Fast-lane services under bulk pressure: dispatches that served the
 * fast lane while the bulk queue held waiting work, split by queue.
 */
volatile u64 nr_depth1_pulls, nr_depth1_pulls_seat;

/*
 * Dispatches where the bulk backstop withheld a fast-lane task because
 * the CPU had served only the fast lane for the whole bound.
 */
volatile u64 nr_bulk_backstop;

/*
 * Wake-path preempts: latency-critical wakees handed a busy CPU at wake
 * time, preempting a non-latency-critical victim instead of waiting for
 * the tick.
 */
volatile u64 nr_wake_preempts;

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
 * Wait-at-depth instrument. An enqueue that parks a task in a seat or
 * the shared queue stamps the arrival time and the depth it waits
 * behind (0, 1, 2, 3+). ops.running() charges the realized wait to that
 * bucket, so a tail can be attributed to consumption (depth 0) or
 * rotation cost.
 */
volatile u64 nr_wait_n[BABY_WDEPTH_NR];
volatile u64 nr_wait_ns[BABY_WDEPTH_NR];
volatile u64 nr_wait_max[BABY_WDEPTH_NR];
volatile u64 nr_wait_slow[BABY_WDEPTH_NR];

#define BABY_WAIT_SLOW_NS	(5ULL * NSEC_PER_MSEC)

/*
 * The same charge, split by class. Each stamped task carries two class
 * bits from ops.runnable(), where the burst and wake-frequency EWMAs
 * are fresh: bit 0 interactive, bit 1 foreground. ops.running() files
 * the wait into class-major 4x4 arrays, entry class * BABY_WDEPTH_NR +
 * depth.
 */
volatile u64 nr_wait_cls_n[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_ns[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_max[BABY_WDEPTH_NR * BABY_WCLS_NR];
volatile u64 nr_wait_cls_slow[BABY_WDEPTH_NR * BABY_WCLS_NR];

/*
 * The same charge, split by arrival type. Type 1 is a wake handoff, an
 * arrival that became runnable with SCX_ENQ_WAKEUP (ops.runnable()
 * stamps the bit, ops.stopping() clears it). The complement is the
 * rotation: slice-expiry and preemption requeues. Type-major: type *
 * BABY_WDEPTH_NR + depth.
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
 * The same charge, split by wake-rate latency-criticality (lcri-major,
 * lcri * 4 + depth; is_lat_cri() evaluated at charge time in
 * ops.running(), where the EWMA is current).
 */
volatile u64 nr_wait_lcri_n[BABY_WDEPTH_NR * 2];
volatile u64 nr_wait_lcri_ns[BABY_WDEPTH_NR * 2];
volatile u64 nr_wait_lcri_max[BABY_WDEPTH_NR * 2];
volatile u64 nr_wait_lcri_slow[BABY_WDEPTH_NR * 2];

/*
 * The latency-critical charge, split by the wake-gate miss reason (see
 * baby.bpf.h for the codes). A wake files the reason its most recent
 * ops.select_cpu() pass recorded; a rotation files 0. The reason is
 * consumed at charge, so a charge never describes an earlier wake, and
 * the per-depth reason sums equal the wlcri lat counts and ns.
 */
volatile u64 nr_wait_wg_n[BABY_WDEPTH_NR * BABY_WG_NR];
volatile u64 nr_wait_wg_ns[BABY_WDEPTH_NR * BABY_WG_NR];
volatile u64 nr_wait_wg_max[BABY_WDEPTH_NR * BABY_WG_NR];
volatile u64 nr_wait_wg_slow[BABY_WDEPTH_NR * BABY_WG_NR];

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
	if (stats_enabled) {
		/*
		 * Stamp the class at the arrival, where the wake-rate
		 * EWMAs and the burst window are current. Stamping it
		 * from ops.runnable() filed a wake under the class it
		 * held before that call's update, and filed a rotation
		 * under the class of a wake that could be long past.
		 */
		tctx->wait_cls = (is_interactive(tctx) ? 1 : 0) |
				 (is_foreground(tctx) ? 2 : 0);
		if (shared)
			__sync_fetch_and_add(&nr_arr_type[type * 2 + 1], 1);
		else
			__sync_fetch_and_add(&nr_arr_type[type * 2], 1);
	}
}

/*
 * Charge the wait a task actually served to the depth bucket its
 * arrival was stamped with. The index is masked because a reloaded u8
 * proves nothing to the verifier; the stored value is already clamped,
 * so the mask only ever matters for a corrupted stamp.
 */
__hidden void charge_wait(struct task_ctx *tctx, u64 now)
{
	u64 stamp = tctx->wait_stamp;
	u8 miss = tctx->wake_gate_miss;

	/*
	 * The stamp is consumed whether or not the instrument runs:
	 * a stale stamp must never outlive the run that paid for it.
	 */
	tctx->wait_stamp = 0;

	/*
	 * The wake-gate miss reason is a control-plane input to the
	 * warm-seat relocation filter, not just a histogram key. It
	 * describes the most recent wake and must not outlive the run
	 * that consumed it, whether or not --stats was enabled.
	 */
	tctx->wake_gate_miss = BABY_WG_NO_GATE;

	if (!stats_enabled || !stamp)
		return;

	{
		u64 wait = now - stamp;
		u32 b = tctx->wait_depth & (BABY_WDEPTH_NR - 1);
		u32 c = tctx->wait_cls & (BABY_WCLS_NR - 1);
		u32 i = c * BABY_WDEPTH_NR + b;

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

		u32 l = is_lat_cri(tctx) ? 1 : 0;
		u32 li = l * BABY_WDEPTH_NR + b;

		__sync_fetch_and_add(&nr_wait_lcri_n[li], 1);
		__sync_fetch_and_add(&nr_wait_lcri_ns[li], wait);
		if (wait > nr_wait_lcri_max[li])
			nr_wait_lcri_max[li] = wait;
		if (wait > BABY_WAIT_SLOW_NS)
			__sync_fetch_and_add(&nr_wait_lcri_slow[li], 1);

		if (l) {
			u32 r = (tctx->arrival_is_wake & 1) ?
				       (u32)miss : (u32)BABY_WG_NON_WAKE;

			if (r >= BABY_WG_NR)
				r = BABY_WG_NO_GATE;

			u32 wi = b * BABY_WG_NR + r;

			__sync_fetch_and_add(&nr_wait_wg_n[wi], 1);
			__sync_fetch_and_add(&nr_wait_wg_ns[wi], wait);
			if (wait > nr_wait_wg_max[wi])
				nr_wait_wg_max[wi] = wait;
			if (wait > BABY_WAIT_SLOW_NS)
				__sync_fetch_and_add(&nr_wait_wg_slow[wi], 1);
		}
	}
}

/*
 * Consumption census: the queue state a lane came to pick work from -
 * the depth left in its warm seats (both lanes) and the shared backlog
 * the rotation turns on. Sampled at every dispatch, so the
 * distribution carries the consumption-rate weighting the arrival-time
 * wait stamp lacks.
 */
__hidden void census_sample(s32 cpu)
{
	if (!stats_enabled)
		return;

	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	u64 seat = scx_bpf_dsq_nr_queued(cpu2dsq(cpu)) +
		   scx_bpf_dsq_nr_queued(fl_cpu2dsq(cpu));
	u64 backlog = scx_bpf_dsq_nr_queued(node) +
		      scx_bpf_dsq_nr_queued(fl_node2dsq(node));
	u8 s = (u8)MIN(seat, BABY_CENSUS_NR - 1);
	u8 g = (u8)MIN(backlog, BABY_CENSUS_NR - 1);

	__sync_fetch_and_add(&nr_census_seat[s & (BABY_CENSUS_NR - 1)], 1);
	__sync_fetch_and_add(&nr_census_shared[g & (BABY_CENSUS_NR - 1)], 1);
}
