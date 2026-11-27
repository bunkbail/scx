/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the per-CPU state the scheduler writes, one cache line per
 * CPU.
 *
 * The eight words answer the same questions about one CPU - what runs
 * there, whether it is latency-critical, when it last ran, and what
 * fast-lane budget it holds - and every reader already masked the CPU id
 * to BABY_MAX_CPUS, so one array of a padded struct replaces eight
 * parallel arrays. The padding and the 64-byte alignment keep each CPU's
 * record on its own line, so a writer on one CPU does not invalidate
 * another CPU's record.
 *
 * The record is not owner-written. ops.stopping() can run after a
 * migration and resolves the CPU the task actually ran on
 * (tctx->last_cpu), then clears that CPU's figures from another CPU. The
 * fields stay independent words written without ordering between them,
 * exactly as the separate arrays were: the struct is a layout change, not
 * a concurrency protocol.
 */
#ifndef __BABY_STATE_H
#define __BABY_STATE_H

#ifndef __BABY_H
#error "state.bpf.h is included by baby.bpf.h, not on its own"
#endif

struct cpu_state {
	/* When this CPU last started a task (the residency stamp). */
	u64 running_at;
	/*
	 * The fast-lane interval stamp: when this CPU's fast-lane run
	 * started, zero when bulk work or an idle dispatch ended it.
	 */
	u64 fl_running_at;
	/* When bulk last ran here, or last had nothing to wait for. */
	u64 bulk_at;
	/*
	 * The fast-lane bucket. It accrues two thirds of wall time as
	 * fast-lane credit and holds at most four base slices; it is
	 * charged the span a fast-lane interval covers, the run itself
	 * plus the stop-to-run gap to the next run on this CPU while bulk
	 * waits. Under contention the two together leave the bucket one
	 * third of the interval lower, the bulk share the budget
	 * promises, independent of how long each slice runs.
	 */
	s64 fl_budget_ns;
	/* When the bucket last earned credit. */
	u64 fl_budget_at;
	/* The CPU's resident is latency-critical. */
	bool is_lat;
	/* The CPU has a resident (counted by the warm-seat scan). */
	bool running;
	/*
	 * Bulk work waited at the stop that ended this CPU's last
	 * fast-lane run. The next run on this CPU reuses the stop's probe
	 * instead of taking a second one a few hundred nanoseconds later.
	 */
	bool bulk_wait;
	/* Pad to the line so no two CPUs share one. */
	u8 __pad[21];
};

_Static_assert(sizeof(struct cpu_state) == 64, "one line per CPU");

extern struct cpu_state cpu_state[BABY_MAX_CPUS];

#endif /* __BABY_STATE_H */
