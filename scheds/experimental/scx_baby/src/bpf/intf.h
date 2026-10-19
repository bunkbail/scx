/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),

	/*
	 * DSQ ID layout. FL marks the fast lane, the latency-critical
	 * class's own queues:
	 *   [0 .. BABY_FL_NODE_DSQ_BASE)          : bulk per-node DSQs
	 *   [BABY_FL_NODE_DSQ_BASE .. BABY_CPU_DSQ_BASE) : FL per-node DSQs
	 *   [BABY_CPU_DSQ_BASE .. BABY_FL_CPU_DSQ_BASE)  : bulk per-CPU warm seats
	 *   [BABY_FL_CPU_DSQ_BASE .. )            : FL per-CPU warm seats
	 *
	 * The node id ranges bound the id spaces: a machine with more node
	 * ids than the gap between the bases would alias a fast-lane node
	 * queue onto a bulk one, and a CPU id past BABY_MAX_CPUS would
	 * alias two CPUs onto one warm seat.
	 */
	BABY_FL_NODE_DSQ_BASE = 50,
	BABY_CPU_DSQ_BASE = 100,
	BABY_FL_CPU_DSQ_BASE = 300,

	BABY_MAX_CPUS = 128,
	BABY_MAX_NODES = (BABY_CPU_DSQ_BASE - BABY_FL_NODE_DSQ_BASE),

	/*
	 * Instrumentation widths, shared with src/stats.rs through bindgen
	 * so the Rust side cannot drift from the BPF arrays it reads.
	 */
	BABY_DIST_NR = 8,
	BABY_WDEPTH_NR = 4,
	BABY_WCLS_NR = 4,
	BABY_WTYPE_NR = 2,
	BABY_WG_NR = 10,
	BABY_CENSUS_NR = 8,

	/*
	 * The nice-offset table is padded to a power of two so the nice
	 * index can be masked; entries past nice +19 are unused.
	 */
	BABY_PRIO_OFFSET_NR = 64,

	/*
	 * SCHED_NORMAL is 0 but is not emitted into vmlinux BTF, so the
	 * policy test carries the value.
	 */
	BABY_SCHED_NORMAL = 0,
};

/*
 * Core tier as published by userspace. The LP tier is excluded from the
 * non-LP cpumask the kernel selector is allowed to pick from.
 */
enum core_tier {
	CORE_TIER_BIG = 0,
	CORE_TIER_LITTLE = 1,
	CORE_TIER_LP = 2,
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif /* __VMLINUX_H__ */

struct core_arg {
	s32 cpu_id;
	s32 tier;
};

#endif /* __INTF_H */
