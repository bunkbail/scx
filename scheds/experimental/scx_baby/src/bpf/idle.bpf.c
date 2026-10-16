/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Idle-CPU acquisition. Placement is delegated to the kernel's idle-CPU
 * selection: SMT-aware, biased to the previous CPU, spread across the
 * LLCs - the cache warmth the per-CPU queues used to pin comes from
 * the kernel's own sense of the topology.
 */
#include "baby.bpf.h"

/*
 * Find an idle CPU for @p through the kernel's selector, which knows
 * the SMT topology and spreads wakeups across the LLCs. Returns the
 * CPU, with @is_idle set when it was picked idle.
 */
s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
		  u64 wake_flags, bool *is_idle)
{
	s32 cpu;

	/*
	 * Compatibility with older kernels.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		if (wake_flags)
			return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags,
						      is_idle);

		return prev_cpu;
	}

	cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
	if (cpu < 0)
		return prev_cpu;

	*is_idle = true;

	return cpu;
}

/*
 * Attempt to dispatch a task directly to an idle CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
			 s32 prev_cpu, u64 enq_flags, bool is_running)
{
	bool is_idle = false;
	s32 cpu = prev_cpu;

	/*
	 * A task that is running, or whose placement ops.select_cpu()
	 * already decided, has had its chance at an idle CPU. A
	 * reenqueued task is worth another scan: its CPU just came back
	 * from an RT lease and the rest of the machine has moved
	 * meanwhile.
	 */
	if (!is_running && __COMPAT_is_enq_cpu_selected(enq_flags) &&
	    !(enq_flags & SCX_ENQ_REENQ))
		return false;

	/*
	 * Migrate only to a confirmed idle CPU: a task pushed onto a
	 * busy core would wait behind whatever runs there, which is
	 * exactly the stranding the per-CPU queues used to create.
	 */
	if (!is_pcpu_task(p)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0, &is_idle);
		if (!is_idle)
			return false;
	} else {
		if (!scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return false;
	}

	__sync_fetch_and_add(&nr_land[cpu_dist(prev_cpu, cpu)], 1);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(tctx), 0);
	__sync_fetch_and_add(&nr_direct_dispatches, 1);

	if (cpu != prev_cpu || !is_running)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	return true;
}
