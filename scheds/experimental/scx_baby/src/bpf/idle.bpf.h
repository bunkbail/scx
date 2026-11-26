/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the idle-CPU acquisition and direct-dispatch interface.
 *
 * Scoped header: baby.bpf.h includes it, and it includes nothing
 * itself, so it reads the core types and macros defined there.
 */
#ifndef __BABY_IDLE_H
#define __BABY_IDLE_H

#ifndef __BABY_H
#error "idle.bpf.h is included by baby.bpf.h, not on its own"
#endif

/*
 * idle.bpf.c: idle-CPU acquisition and direct dispatch.
 */
__hidden s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
			  bool *is_idle);
__hidden bool cpu_smt_shared(s32 cpu);
__hidden s32 cpu_smt_sibling(s32 cpu);
__hidden bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				 s32 prev_cpu, u64 enq_flags, bool is_running);

/*
 * idle.bpf.c: the kernel idle-CPU selection restricted to the non-LP
 * mask while the tier masks exist.
 */
__hidden s32 select_cpu_no_lp(struct task_struct *p, s32 prev_cpu,
			      u64 wake_flags);

#endif /* __BABY_IDLE_H */
