/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Game pin: the two claims on a core and its SMT sibling, the mask and
 * the hot-path shield copy that keep non-pinned work off them, and the
 * enqueue, wake and dispatch paths that place the pinned task.
 */
#include "baby.bpf.h"

/*
 * The slot table itself lives in main.bpf.c.  This declaration has to
 * repeat its type exactly: libbpf's linker compares the two BTF map
 * definitions, and a second definition instead of an extern would give
 * this translation unit its own map that no reader ever fills.
 */
extern struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, struct pin_slot);
} pin_slots SEC(".maps");

/*
 * Restart the grace window of a slot this task owns. ops.stopping() is
 * the instant the task leaves the CPU, so this is where a 20 ms window
 * that must cover an inter-frame gap has to start; the enqueue and wake
 * stamps that follow keep it open while the thread is busy.
 */
__hidden __noinline void pin_stopping_stamp(struct task_struct *p, u64 now)
{
	struct pin_slot *slot;
	u32 key = 0, pid = (u32)p->pid;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && READ_ONCE(slot->pid) == pid)
		slot->active_until = now + pin_grace_ns;

	key = 1;
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && READ_ONCE(slot->pid) == pid)
		slot->active_until = now + pin_grace_ns;
}
