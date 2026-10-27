/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Idle-CPU acquisition. Placement is delegated to the kernel's idle-CPU
 * selection: SMT-aware, previous-CPU biased and spread across LLCs.
 */
#include "baby.bpf.h"

/*
 * Find an idle CPU for @p through the kernel's selector, which knows
 * the SMT topology and spreads wakeups across the LLCs. Returns the
 * CPU, with @is_idle set when it was picked idle.
 */
__hidden s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
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

		return any_allowed_cpu(p, prev_cpu);
	}

	cpu = select_cpu_no_lp(p, prev_cpu, wake_flags);
	if (cpu < 0)
		return any_allowed_cpu(p, prev_cpu);

	*is_idle = true;

	return cpu;
}

/*
 * Is @cpu sharing its physical core with a running task?
 *
 * A CPU whose SMT sibling is busy is only half a core: a task placed
 * there executes alongside the sibling's resident and loses a large
 * share of the core's execution units. That costs more than the cache
 * refill of a migration, so the warm-seat fast paths must check it
 * before keeping a wakee on its previous CPU.
 *
 * Platforms without SMT, and CPUs whose topology is not published, have
 * no sibling and report false.
 */
__hidden bool cpu_smt_shared(s32 cpu)
{
	const struct cpumask *idle;
	bool shared = false;
	s32 i;

	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return false;

	idle = scx_bpf_get_idle_cpumask();
	if (!idle)
		return false;

	bpf_for(i, 0, nr_cpu_ids) {
		if (i == cpu || cpu_dist(cpu, i) != BABY_DIST_SIBLING)
			continue;
		if (!bpf_cpumask_test_cpu(i, idle)) {
			shared = true;
			break;
		}
	}

	scx_bpf_put_cpumask(idle);

	return shared;
}

/*
 * Attempt to dispatch a task directly to an idle CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
__hidden bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
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
	 * Migrate only to a confirmed idle CPU: a task pushed onto a busy
	 * core would wait behind whatever runs there.
	 */
	if (!is_pcpu_task(p)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0, &is_idle);
		if (!is_idle)
			return false;
	} else {
		/*
		 * A migration-disabled task can only use the CPU it is
		 * on. A single-CPU task may have had its affinity moved
		 * to another CPU since it last ran, so prev_cpu is not
		 * necessarily its lane.
		 */
		s32 only = is_migration_disabled(p) ?
				   prev_cpu :
				   (s32)bpf_cpumask_first(p->cpus_ptr);

		if ((u32)only >= nr_cpu_ids ||
		    !bpf_cpumask_test_cpu(only, p->cpus_ptr) ||
		    !scx_bpf_test_and_clear_cpu_idle(only))
			return false;
		cpu = only;
	}

	if (stats_enabled) {
		__sync_fetch_and_add(&nr_land[cpu_dist(prev_cpu, cpu)], 1);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(tctx), 0);

	if (cpu != prev_cpu || !is_running)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	return true;
}
