/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the scheduling counters, the wait-at-depth instrument and the
 * stats.bpf.c prototypes.
 *
 * Scoped header: baby.bpf.h includes it, and it includes nothing
 * itself, so it reads the core types and macros defined there.
 */
#ifndef __BABY_STATS_H
#define __BABY_STATS_H

#ifndef __BABY_H
#error "stats.bpf.h is included by baby.bpf.h, not on its own"
#endif

/*
 * Scheduling statistics. nr_running owns a cache line: it is a
 * control-plane input read on the hot paths, and the diagnostic
 * counters must not share its line (see stats.bpf.c).
 */
extern volatile u64 nr_running __attribute__((aligned(64)));
extern volatile u64 nr_direct_dispatches __attribute__((aligned(64)));
extern volatile u64 nr_preemptions, nr_boosts, nr_sticky;
extern volatile u64 nr_preempt_refused_lat;
extern volatile u64 nr_coldspreads;

/*
 * Class census at run start (class composition and lane), behind the
 * same --stats flag as the rest of the instrument.
 */
extern volatile u64 nr_class[BABY_WCLS_NR];
extern volatile u64 nr_lane[2];

/*
 * Where placements land, by distance rank.
 */
extern volatile u64 nr_land[BABY_DIST_NR];
extern volatile u64 nr_wake_land[BABY_DIST_NR];
extern volatile u64 nr_seat_self;
extern volatile u64 nr_seat_move[BABY_DIST_NR];
extern volatile u64 nr_pull_land[BABY_DIST_NR];

/*
 * Wait-at-depth instrument: the wait a task actually served, filed by the
 * depth it waited behind (0, 1, 2, 3+).
 */
extern volatile u64 nr_wait_n[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_ns[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_max[BABY_WDEPTH_NR];
extern volatile u64 nr_wait_slow[BABY_WDEPTH_NR];

/*
 * The same charge, split by class: class-major, entry
 * class * BABY_WDEPTH_NR + depth.
 */
extern volatile u64 nr_wait_cls_n[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_ns[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_max[BABY_WDEPTH_NR * BABY_WCLS_NR];
extern volatile u64 nr_wait_cls_slow[BABY_WDEPTH_NR * BABY_WCLS_NR];

/*
 * The same charge, split by arrival type: type-major, entry
 * type * BABY_WDEPTH_NR + depth.
 */
extern volatile u64 nr_wait_type_n[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_ns[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_max[BABY_WDEPTH_NR * BABY_WTYPE_NR];
extern volatile u64 nr_wait_type_slow[BABY_WDEPTH_NR * BABY_WTYPE_NR];

/*
 * The same charge, split by wake-rate latency-criticality (2 * 4
 * entries, lcri-major: lcri * BABY_WDEPTH_NR + depth). It answers
 * whether latency-critical wakees actually wait, at what depth, and
 * for how long, or whether they are served at depth 0.
 */
extern volatile u64 nr_wait_lcri_n[BABY_WDEPTH_NR * 2];
extern volatile u64 nr_wait_lcri_ns[BABY_WDEPTH_NR * 2];
extern volatile u64 nr_wait_lcri_max[BABY_WDEPTH_NR * 2];
extern volatile u64 nr_wait_lcri_slow[BABY_WDEPTH_NR * 2];

/*
 * The latency-critical charge, split by the wake-gate miss reason: why
 * the depth-0 wake preempt at ops.select_cpu() did not fire for the
 * task's most recent wake. Depth-major within each reason row, entry
 * depth * BABY_WG_NR + reason; a rotation requeue files reason 0. The
 * classes partition the wlcri lat bucket: per depth, the reason sums
 * equal the wlcri lat counts and ns.
 */
#define BABY_WG_NON_WAKE	0	/* rotation requeue, not a wake */
#define BABY_WG_NO_GATE		1	/* no wake-gate contact this cycle */
#define BABY_WG_M1_NOT_LAT	2	/* wakee not lat-cri at gate time */
#define BABY_WG_M2_AFFINITY	3	/* wakee cannot run on prev_cpu */
#define BABY_WG_M3_SEAT_BUSY	4	/* the wakee's seat holds a head */
#define BABY_WG_M3_LOCAL_BUSY	5	/* an in-flight wakee holds the local DSQ */
#define BABY_WG_M4_DEGEN	6	/* victim unusable: null/self/idle/no ctx */
#define BABY_WG_M4_VICTIM_LAT	7	/* the victim is lat-cri */
#define BABY_WG_M4_PRIO		8	/* the wakee loses on static_prio */
#define BABY_WG_M5_RESIDENCY	9	/* the victim is under the 200us floor */

extern volatile u64 nr_wait_wg_n[BABY_WDEPTH_NR * BABY_WG_NR];
extern volatile u64 nr_wait_wg_ns[BABY_WDEPTH_NR * BABY_WG_NR];
extern volatile u64 nr_wait_wg_max[BABY_WDEPTH_NR * BABY_WG_NR];
extern volatile u64 nr_wait_wg_slow[BABY_WDEPTH_NR * BABY_WG_NR];

/*
 * Saturation preemption instrument: the victims ops.tick() cut short
 * because a latency-critical task waited at a queue head, split by
 * where the waiter sat (the shared queue or the CPU's own seat).
 */
extern volatile u64 nr_tick_preempts, nr_tick_preempts_warm;

/*
 * Tick cuts whose waiter the following dispatch did not serve: the
 * tick gate claimed a waiter without consulting the CPU's budget.
 */
extern volatile u64 nr_tick_cut_refused;

/*
 * RT-lease take-back instrument: latency-critical tasks requeued from
 * an RT lease, and the dispatches that served one back on its home CPU.
 */
extern volatile u64 nr_lease_requeues, nr_home_takebacks;

/*
 * Fast-lane services under bulk pressure: dispatches that served the
 * fast lane while the CPU's bulk queue held waiting work, each served
 * under the CPU's time budget, split by which fast-lane queue held the
 * task.
 */
extern volatile u64 nr_depth1_pulls, nr_depth1_pulls_seat;

/*
 * Dispatches where the bulk backstop withheld a fast-lane task: the
 * CPU had served only the fast lane for the whole bound while bulk
 * work waited for it.
 */
extern volatile u64 nr_bulk_backstop;

/*
 * Wake-path preempts: latency-critical wakees handed a busy CPU at wake
 * time, preempting a non-latency-critical victim instead of waiting for
 * the tick.
 */
extern volatile u64 nr_wake_preempts;

/*
 * Where each arrival type landed: wake or rotation, warm seat or
 * shared queue. Indexed type * 2 + shared.
 */
extern volatile u64 nr_arr_type[2 * 2];

/*
 * Consumption census: the queue state a lane sees when it comes to pick
 * work - the depth left in its warm seat and the shared backlog the
 * rotation turns on.
 */
extern volatile u64 nr_census_seat[BABY_CENSUS_NR];
extern volatile u64 nr_census_shared[BABY_CENSUS_NR];

/*
 * stats.bpf.c: the wait-at-depth instrument and the consumption census.
 */
__hidden void stamp_wait(struct task_ctx *tctx, u64 now, u64 depth, bool shared);
__hidden void charge_wait(struct task_ctx *tctx, u64 now);
__hidden void census_sample(s32 cpu);

#endif /* __BABY_STATS_H */
