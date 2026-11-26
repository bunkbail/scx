/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the preemption floor the tick gate and the warm-seat placement
 * read, and the plain wake gate.
 *
 * Scoped header: baby.bpf.h includes it, and it includes nothing
 * itself, so it reads the core types and macros defined there.
 */
#ifndef __BABY_PREEMPT_H
#define __BABY_PREEMPT_H

#ifndef __BABY_H
#error "preempt.bpf.h is included by baby.bpf.h, not on its own"
#endif

/*
 * How long a victim must have held a CPU before a waiting task may
 * preempt it. The floor exists so two waiters cannot ping-pong one CPU:
 * a victim that just started makes progress before it is displaced
 * again. On a saturated CPU the floor is also the extra wait every
 * wake-side handoff pays on top of the victim's rotation, and a frame
 * producer at several hundred frames per second runs for only about a
 * millisecond per frame: a victim that has already held the CPU for
 * 200us covers a fifth of that frame, and waiting it out costs a whole
 * frame period. Fifty microseconds still gives a displaced task its
 * first slice of progress; the per-node claim and the latency-critical
 * victim refusal bound the churn on top of it.
 */
#define BABY_TICK_PREEMPT_PROTECT_NS	(50ULL * NSEC_PER_USEC)

/*
 * The anti-herd claim the tick gate sets per node and a successful pull
 * from that node's fast-lane queue clears. Defined in main.bpf.c; the
 * tick, the enqueue and the dispatch all test it.
 */
extern u64 node_preempt_claim[BABY_NODE_CLOCK_NR];

/* Plain wake gate: the residency floor and the short-burst bound. */
#define PLAIN_WAKE_PROTECT_NS		(200ULL * NSEC_PER_USEC)
#define PLAIN_WAKE_SHORT_NS		(500ULL * NSEC_PER_USEC)

/* Whether a plain-mode wake may cut @victim for @wakee. */
static __always_inline bool plain_wake_cut(const struct task_ctx *wakee,
					   const struct task_ctx *victim)
{
	if ((s64)(victim->deadline - wakee->deadline) >
	    (s64)(deadline_ns / 2))
		return true;

	return !is_foreground(wakee) &&
	       wakee->last_run_ns < PLAIN_WAKE_SHORT_NS;
}

#endif /* __BABY_PREEMPT_H */
