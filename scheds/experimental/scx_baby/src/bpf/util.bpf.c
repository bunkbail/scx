/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Copyright (C) 2026 bunkbail <nabildanial.93@gmail.com>
 *
 * Per-task context and the cache-topology distance. This module owns the
 * task storage map, the topology tables userspace publishes and the
 * distance rank they define.
 */
#include "baby.bpf.h"

u64 nr_cpu_ids;

/*
 * Tier sizes as published by userspace at init (enable_core_class),
 * counted locklessly. On a platform without a capacity split the
 * little set is empty and the hybrid gates below are statically
 * false: the compaction never engages there.
 */
u64 nr_little_cpus, nr_big_cpus;

/*
 * Cache-topology distance tables, as published by userspace from the
 * sysfs cache hierarchy: the physical core id groups SMT siblings, the
 * L2 and LLC ids group the shared-cache tiers, the node id the socket.
 * Every table holds a nonzero id per CPU, so an unfilled entry never
 * compares equal to a filled one.
 */
const volatile u32 topo_node[BABY_MAX_CPUS];
const volatile u32 topo_llc[BABY_MAX_CPUS];
const volatile u32 topo_l2[BABY_MAX_CPUS];
const volatile u32 topo_core[BABY_MAX_CPUS];

/*
 * A single cached comparison per queue in the warm-seat scan keeps the
 * verifier's state space flat: cpu_dist(prev, i) recomputed on both
 * arms of a three-way compare would branch the scan's exploration and
 * blow past the jump-complexity limit (observed 8193-jump blowup).
 */
__hidden u32 cpu_dist(s32 a, s32 b)
{
	u32 ia, ib;

	if (a < 0 || b < 0 || (u32)a >= nr_cpu_ids || (u32)b >= nr_cpu_ids)
		return BABY_DIST_BEYOND;

	if (a == b)
		return BABY_DIST_SELF;

	ia = (u32)a & (BABY_MAX_CPUS - 1);
	ib = (u32)b & (BABY_MAX_CPUS - 1);

	if (topo_core[ia] && topo_core[ia] == topo_core[ib])
		return BABY_DIST_SIBLING;
	if (topo_l2[ia] && topo_l2[ia] == topo_l2[ib])
		return BABY_DIST_L2;
	if (topo_llc[ia] && topo_llc[ia] == topo_llc[ib])
		return BABY_DIST_LLC;
	if (topo_node[ia] == topo_node[ib])
		return BABY_DIST_NODE;

	return BABY_DIST_BEYOND;
}

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Cross-module functions are __hidden: the visibility makes clang emit
 * their BTF FUNC entries as static, so the verifier inlines them at load
 * instead of applying the kernel's global-function ABI checks (which on
 * 6.12-era kernels reject pointer returns and mis-walk trusted
 * task_struct arguments).
 */
__hidden struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Create the task context of @p, or return the one it already holds.
 */
__hidden struct task_ctx *init_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Exit information.
 */
UEI_DEFINE(uei);
