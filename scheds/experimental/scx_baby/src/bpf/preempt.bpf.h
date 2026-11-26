/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the preemption floor the tick gate and the warm-seat placement
 * both read.
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

#endif /* __BABY_PREEMPT_H */
