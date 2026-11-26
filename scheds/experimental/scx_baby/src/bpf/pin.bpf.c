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

/*
 * Rebuild the shield state after a slot change: the mask the wake
 * selector is restricted to, the per-CPU byte array the dispatch and
 * enqueue paths test, and the count that gates them. Only a claim, a
 * takeover or a release calls this; the hot paths read what it left.
 *
 * The byte array and the count come first, from the two slots, and the
 * mask is then written once per CPU to its final value: eligible and
 * not shielded. Setting every bit and clearing the shielded ones
 * afterwards would leave a window in which a concurrent wake sees a
 * home as available, and two racing rebuilds could each clear only
 * their own slot's bits and leave the other's home in the mask.
 *
 * The mask is re-derived from non_lp_cpumask rather than from a full
 * set, so the LP exclusion the tier masks encode survives a rebuild
 * that re-admits a released home. Without tiers non_lp_cpumask is
 * empty and every CPU stays eligible, which is what the plain
 * selector would use.
 *
 * The new record is built in a local array and published at the end,
 * so the shield never reads as absent for the length of the rebuild.
 */
__hidden __noinline void pin_mask_rebuild(void)
{
	struct bpf_cpumask *mask;
	const struct cpumask *non_lp;
	struct pin_slot *slot;
	u8 next_shield[BABY_MAX_CPUS];
	bool use_non_lp;
	u32 key = 0, i, next_n = 0;

	bpf_rcu_read_lock();
	mask = pin_worker_cpumask;
	non_lp = cast_mask(non_lp_cpumask);
	use_non_lp = non_lp && !bpf_cpumask_empty(non_lp);

	__builtin_memset(next_shield, 0, sizeof(next_shield));

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && slot->pid) {
		if (slot->home_cpu >= 0 && (u32)slot->home_cpu < nr_cpu_ids) {
			next_shield[(u32)slot->home_cpu &
				    (BABY_MAX_CPUS - 1)] = 1;
			next_n++;
		}
		if (slot->sib_cpu >= 0 && (u32)slot->sib_cpu < nr_cpu_ids) {
			next_shield[(u32)slot->sib_cpu &
				    (BABY_MAX_CPUS - 1)] = 1;
			next_n++;
		}
	}

	key = 1;
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && slot->pid) {
		if (slot->home_cpu >= 0 && (u32)slot->home_cpu < nr_cpu_ids) {
			next_shield[(u32)slot->home_cpu &
				    (BABY_MAX_CPUS - 1)] = 1;
			next_n++;
		}
		if (slot->sib_cpu >= 0 && (u32)slot->sib_cpu < nr_cpu_ids) {
			next_shield[(u32)slot->sib_cpu &
				    (BABY_MAX_CPUS - 1)] = 1;
			next_n++;
		}
	}

	if (mask) {
		bpf_for(i, 0, BABY_MAX_CPUS) {
			if ((!use_non_lp ||
			     (i < nr_cpu_ids &&
			      bpf_cpumask_test_cpu(i, non_lp))) &&
			    !next_shield[i])
				bpf_cpumask_set_cpu(i, mask);
			else
				bpf_cpumask_clear_cpu(i, mask);
		}
	}

	/*
	 * Publish the record only once it is complete, bytes first and
	 * the count last: clearing the count for the length of the
	 * rebuild takes the shield down between two wakeups, which is
	 * exactly the window a worker needs to land on a held core.
	 */
	bpf_for(i, 0, BABY_MAX_CPUS)
		pin_shield_cpu[i] = next_shield[i];
	WRITE_ONCE(pin_shield_n, next_n);
	bpf_rcu_read_unlock();
}

/*
 * Whether @cpu is a legal home for @p: allowed by its affinity, on the
 * big set while a tier split uses one, and on a different physical
 * core than @other_home (the first slot's home) when there is one.
 * The topology cores are stored offset by one, so an unfilled entry
 * compares unequal to nothing: two unfilled entries are both zero and
 * fail the distinctness test, which is the conservative answer.
 */
static __noinline bool pin_cpu_usable(const struct task_struct *p, s32 cpu,
				      s32 other_home)
{
	struct bpf_cpumask *big = big_cpumask;
	u32 core, other;

	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return false;
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return false;
	if (nr_big_cpus && big && !bpf_cpumask_empty(cast_mask(big)) &&
	    !bpf_cpumask_test_cpu(cpu, cast_mask(big)))
		return false;
	if (other_home >= 0) {
		core = topo_core[(u32)cpu & (BABY_MAX_CPUS - 1)];
		other = topo_core[(u32)other_home & (BABY_MAX_CPUS - 1)];
		if (core == other)
			return false;
	}
	return true;
}

/*
 * The home CPU of a fresh claim: the one the task is running on when
 * it qualifies, otherwise the first that does. -1 when none does, and
 * the claim is then not made.
 */
static __noinline s32 pin_home_pick(const struct task_struct *p,
				    s32 other_home)
{
	s32 cpu = scx_bpf_task_cpu(p);

	if (pin_cpu_usable(p, cpu, other_home))
		return cpu;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (pin_cpu_usable(p, cpu, other_home))
			return cpu;
	}
	return -1;
}

/*
 * The share of the machine that is not idle, in q10. The stamp gate
 * lets one CPU take the sample per 200ms window and makes every other
 * caller read the value that one stored: the scan walks every CPU and
 * every task that rolls a window at once would otherwise repeat it.
 */
static u64 pin_busy_at;

static __noinline u32 pin_busy_sample(u64 now)
{
	const struct cpumask *idle, *non_lp;
	u64 old = READ_ONCE(pin_busy_at);
	u32 total = 0, nr_idle = 0, q10, prev;
	bool use_non_lp;
	s32 cpu;

	if (now - old < TIME_PERIOD ||
	    !__sync_bool_compare_and_swap(&pin_busy_at, old, now))
		return READ_ONCE(machine_busy_q10);

	bpf_rcu_read_lock();
	non_lp = cast_mask(non_lp_cpumask);
	use_non_lp = non_lp && !bpf_cpumask_empty(non_lp);
	total = use_non_lp ? bpf_cpumask_weight(non_lp) : (u32)nr_cpu_ids;
	idle = scx_bpf_get_idle_cpumask();
	/*
	 * Plain bounded loops, not bpf_for: the bound is the rodata CPU
	 * count, so the verifier proves the induction variable directly.
	 * An open-coded iterator also carries the scalars the body
	 * writes, and this scan's idle count changes every iteration, so
	 * its loop state never converges and the verifier walks it to
	 * its state limit. Each arm is branch-free: a member test per
	 * CPU would make every iteration a distinct state too.
	 */
	if (idle && use_non_lp) {
		for (cpu = 0; cpu < (s32)nr_cpu_ids; cpu++)
			nr_idle += (u32)bpf_cpumask_test_cpu(cpu, idle) &
				   (u32)bpf_cpumask_test_cpu(cpu, non_lp);
	} else if (idle) {
		for (cpu = 0; cpu < (s32)nr_cpu_ids; cpu++)
			nr_idle += bpf_cpumask_test_cpu(cpu, idle);
	}
	if (idle)
		scx_bpf_put_cpumask(idle);
	bpf_rcu_read_unlock();

	if (!total)
		return READ_ONCE(machine_busy_q10);

	q10 = ((total - nr_idle) * 1024) / total;
	prev = READ_ONCE(machine_busy_q10);
	machine_busy_q10 = prev ? (3 * prev + q10 + 2) >> 2 : q10;
	return machine_busy_q10;
}

/*
 * Claim @slot for @p. A free slot is taken at once; a live one only by
 * a task whose duty beats the owner's by the challenger margin across
 * the whole streak window, and a stale one by anyone. The margin is a
 * single window's figure, so requiring it once would let two tasks of
 * nearly equal weight trade the slot every window while a game ramps,
 * and every trade costs a mask rebuild and a migration. The CAS is what
 * arbitrates between competing claimants: it must still hold the pid
 * this reader saw, or the claim is lost and the caller stops.
 */
static __noinline bool pin_slot_take(struct pin_slot *slot,
				     struct task_struct *p,
				     struct task_ctx *tctx, u64 now,
				     u32 busy, s32 other_home)
{
	u32 pid = (u32)p->pid;
	u32 old = READ_ONCE(slot->pid);
	s32 home, sib;

	if (old == pid)
		return false;
	if (old != 0 && now - READ_ONCE(slot->last_seen_ns) <= pin_stale_ns &&
	    (tctx->duty_q10 <= READ_ONCE(slot->duty_q10) + pin_challenger ||
	     tctx->pin_streak < pin_streak_need))
		return false;

	home = pin_home_pick(p, other_home);
	if (home < 0)
		return false;
	sib = cpu_smt_sibling(home);

	if (__sync_val_compare_and_swap(&slot->pid, old, pid) != old)
		return false;

	/*
	 * The claim is ours; fill the rest. A reader that matched the pid
	 * between the CAS and the stores may take one placement from the
	 * old fields, which is why home_cpu is always a CPU id this
	 * scheduler wrote and every reader bounds-checks it.
	 */
	slot->tgid = (u32)p->tgid;
	slot->home_cpu = home;
	slot->sib_cpu = sib;
	slot->duty_q10 = tctx->duty_q10;
	slot->busy_q10 = busy;
	slot->core_id = topo_core[(u32)home & (BABY_MAX_CPUS - 1)];
	slot->last_seen_ns = now;
	slot->active_until = now + pin_grace_ns;
	slot->nr_enq = 0;

	pin_mask_rebuild();

	/*
	 * A claim can shield the only CPU some waiting task can run on.
	 * Dispatch withholds the node queue on a shielded CPU, and the
	 * arrival path only parks a task whose affinity is already inside
	 * the shield when it is enqueued, so a task that was queued
	 * before this claim would wait there until the watchdog. The
	 * re-enqueue runs every arrival through ops.enqueue() again,
	 * where the park catches it.
	 */
	if (__COMPAT_has_generic_reenq())
		scx_bpf_dsq_reenq___compat(
			(u64)__COMPAT_scx_bpf_cpu_node(home), 0);

	/*
	 * An idle CPU does not call dispatch() until something wakes it,
	 * so the CPU this claim just shielded has to be woken once: a
	 * task parked in its seat by an earlier claim would otherwise sit
	 * there unwatched.
	 */
	scx_bpf_kick_cpu(home, SCX_KICK_IDLE);
	if (sib >= 0)
		scx_bpf_kick_cpu(sib, SCX_KICK_IDLE);
	return true;
}

/*
 * Try to give @p a slot. Slot 0 goes to a task over the promotion bar
 * whose duty has held across pin_streak_need windows: two windows at
 * pin_promote1 is 400 ms of sustained 60% duty, so a one-window
 * plasmashell spike cannot claim a core. Slot 1 is reserved for a
 * second thread of the process that owns slot 0: a game's render
 * thread and its submission thread are the pair, and letting two
 * unrelated processes hold the slots would pin a helper over the game.
 * The second claim also waits for the first thread's duty to hold
 * across windows and for the machine to have headroom, so a saturated
 * box does not spend two cores on one game.
 */
static __noinline void pin_try_promote(struct task_struct *p,
				       struct task_ctx *tctx, u64 now)
{
	struct pin_slot *slot0, *slot1;
	u32 busy, key = 0;
	s32 other;

	busy = pin_busy_sample(now);

	slot0 = bpf_map_lookup_elem(&pin_slots, &key);
	key = 1;
	slot1 = bpf_map_lookup_elem(&pin_slots, &key);

	/*
	 * A slot 0 claim has to keep off the core slot 1 holds, or the
	 * pair collapses onto one physical core and the second core the
	 * pin paid for goes unused. Slot 1 is only ever claimed against
	 * slot 0's home, so without this the two claims do not see each
	 * other.
	 */
	other = (slot1 && READ_ONCE(slot1->pid)) ? slot1->home_cpu : -1;
	if (slot0 && tctx->pin_streak >= pin_streak_need &&
	    pin_slot_take(slot0, p, tctx, now, busy, other))
		return;

	if (pin_max < 2 || !slot0 || !slot1)
		return;
	if (!READ_ONCE(slot0->pid) ||
	    READ_ONCE(slot0->tgid) != (u32)p->tgid ||
	    tctx->pin_streak < pin_streak_need || busy > pin_busy_max)
		return;

	other = slot0->home_cpu;
	pin_slot_take(slot1, p, tctx, now, busy, other);
}

/*
 * Sample a closed 200ms window into the task's duty. Called from the
 * tick right after the burst tracker rolls the window, so the sample
 * is the runtime the task accumulated in the window that just closed;
 * every tick inside a window returns on the stamp. The duty is the
 * same 3:1 EWMA the wake rate uses, rounded up so a steady 65% reads
 * the promotion bar exactly.
 */
__hidden __noinline void pin_account(struct task_struct *p,
				     struct task_ctx *tctx, u64 now)
{
	struct pin_slot *slot;
	u64 raw;
	u32 duty, key = 0;

	if (tctx->pin_window == tctx->start_time)
		return;
	tctx->pin_window = tctx->start_time;

	raw = (tctx->prev_bursts * 1024) / TIME_PERIOD;
	if (raw > 1024)
		raw = 1024;
	duty = tctx->duty_q10 ?
	       (u32)((3 * tctx->duty_q10 + raw + 2) >> 2) : (u32)raw;
	tctx->duty_q10 = duty;
	tctx->pin_streak = duty >= pin_promote1 ?
			   (u8)MIN((u32)tctx->pin_streak + 1, 255) : 0;

	/*
	 * The owner refreshes its slot, or gives it back once its duty
	 * falls under the release bar. A duty of zero releases at once:
	 * a task that has stopped using its window must not keep the
	 * core, and the first sample of a task with no history is the
	 * raw window rather than a blend, so the test binds from the
	 * first window on.
	 */
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (!slot || slot->pid != (u32)p->pid) {
		key = 1;
		slot = bpf_map_lookup_elem(&pin_slots, &key);
		if (!slot || slot->pid != (u32)p->pid)
			slot = NULL;
	}
	if (slot) {
		/*
		 * Slot 1 is reserved for a second thread of slot 0's
		 * process. When slot 0 changes hands to another process
		 * the pair no longer describes one game, so the second
		 * slot's owner gives it back at its next window instead of
		 * holding a core for a process that no longer owns the
		 * first.
		 */
		bool pair_lost = false;

		if (key == 1) {
			u32 zero = 0;
			struct pin_slot *slot0 =
				bpf_map_lookup_elem(&pin_slots, &zero);

			pair_lost = slot0 && READ_ONCE(slot0->pid) &&
				    READ_ONCE(slot0->tgid) != (u32)p->tgid;
		}

		if (duty < pin_release0 || pair_lost) {
			__sync_val_compare_and_swap(&slot->pid, (u32)p->pid,
						    0);
			pin_mask_rebuild();
		} else {
			slot->duty_q10 = duty;
			slot->last_seen_ns = now;
			slot->active_until = now + pin_grace_ns;
		}
		return;
	}

	/*
	 * The first sample of a task carries no history: the raw window
	 * is its duty, so a thread that spent the window on the CPU
	 * qualifies at once and one that did not cannot.
	 */
	if (duty >= pin_promote0)
		pin_try_promote(p, tctx, now);
}

/*
 * Whether @cpu is the home of @p's active slot.
 */
__hidden bool pin_owns_cpu(s32 cpu, const struct task_struct *p)
{
	struct pin_slot *slot;
	u32 key = 0;

	if (cpu < 0)
		return false;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && slot->pid == (u32)p->pid && slot->home_cpu == cpu)
		return true;

	key = 1;
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && slot->pid == (u32)p->pid && slot->home_cpu == cpu)
		return true;
	return false;
}

/*
 * Whether @cpu must be kept for a pinned thread: it is a slot's home or
 * SMT sibling and the slot's owner either stamped it inside the grace
 * window or is running on the home CPU right now.
 */
__hidden __noinline bool is_cpu_shielded(s32 cpu, u64 now)
{
	struct task_struct *curr;
	struct pin_slot *slot;
	u32 key = 0;

	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return false;
	/*
	 * The byte array names every CPU some live slot owns, so a zero
	 * answers here without touching the map. It is the same fact the
	 * two tests below re-derive, which is what makes the shortcut
	 * sound.
	 */
	if (!pin_shield_cpu[(u32)cpu & (BABY_MAX_CPUS - 1)])
		return false;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && slot->pid && (slot->home_cpu == cpu || slot->sib_cpu == cpu)) {
		if ((s64)(now - slot->active_until) <= 0)
			return true;
		/*
		 * The home is bounds-checked before it reaches the helper:
		 * a slot's fields are written after its pid, so a racy
		 * snapshot can pair a live pid with a home the previous
		 * owner wrote, and an out-of-range CPU there would make
		 * the kernel abort the scheduler.
		 */
		if ((u32)slot->home_cpu < nr_cpu_ids) {
			curr = __COMPAT_scx_bpf_cpu_curr(slot->home_cpu);
			if (curr && (u32)curr->pid == slot->pid)
				return true;
		}
	}

	key = 1;
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && slot->pid && (slot->home_cpu == cpu || slot->sib_cpu == cpu)) {
		if ((s64)(now - slot->active_until) <= 0)
			return true;
		if ((u32)slot->home_cpu < nr_cpu_ids) {
			curr = __COMPAT_scx_bpf_cpu_curr(slot->home_cpu);
			if (curr && (u32)curr->pid == slot->pid)
				return true;
		}
	}
	return false;
}

/*
 * Whether @pid owns either slot. The preempt path uses it to leave
 * another pinned thread alone: two pinned threads must not evict each
 * other, or the pair ping-pongs its two cores.
 */
static __noinline bool pin_pid_active(u32 pid)
{
	struct pin_slot *slot;
	u32 key = 0;

	if (!pid)
		return false;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && slot->pid == pid)
		return true;
	key = 1;
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	return slot && slot->pid == pid;
}

/*
 * Place a pinned arrival on its home CPU, ahead of every shared queue:
 * an idle home takes it directly, a home that runs a cuttable task is
 * preempted, and anything else parks in the home's own seat, whose
 * dispatch drains it first. The slot is stamped here so a burst of
 * arrivals keeps the grace window open without the tick.
 */
__hidden __noinline bool pin_enqueue_pinned(struct task_struct *p,
					    struct task_ctx *tctx,
					    u64 enq_flags, u64 now)
{
	struct task_struct *curr;
	struct pin_slot *slot;
	bool is_running = scx_bpf_task_running(p);
	u64 slice = tctx ? task_slice(tctx) : deadline_ns;
	u32 key = 0, pid = (u32)p->pid;
	s32 home;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (!slot || slot->pid != pid) {
		key = 1;
		slot = bpf_map_lookup_elem(&pin_slots, &key);
		if (!slot || slot->pid != pid)
			return false;
	}

	/*
	 * A home the task's affinity no longer allows is not a
	 * placement: fall back to the shared queue and let the next
	 * window drop the slot.
	 */
	home = slot->home_cpu;
	if (home < 0 || (u32)home >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(home, p->cpus_ptr))
		return false;

	slot->active_until = now + pin_grace_ns;
	__sync_fetch_and_add(&slot->nr_enq, 1);

	if (!is_running && !__COMPAT_is_enq_cpu_selected(enq_flags) &&
	    scx_bpf_test_and_clear_cpu_idle(home)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | home, slice,
				   enq_flags);
		scx_bpf_kick_cpu(home, SCX_KICK_IDLE);
		return true;
	}

	if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | home)) {
		curr = __COMPAT_scx_bpf_cpu_curr(home);
		if (curr && curr != p && !(curr->flags & PF_IDLE) &&
		    !is_pcpu_task(curr) && !pin_pid_active((u32)curr->pid)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | home, slice,
					   enq_flags | SCX_ENQ_PREEMPT);
			return true;
		}
	}

	/*
	 * The home runs a task the direct preempt could not displace,
	 * so the arrival waits in the home's own seat until the home
	 * reschedules. PREEMPT alone forces that; SCX_KICK_IDLE is
	 * mutually exclusive with it and setting both aborts the
	 * scheduler.
	 */
	scx_bpf_dsq_insert(p, fl_cpu2dsq(home), slice, enq_flags);
	scx_bpf_kick_cpu(home, SCX_KICK_PREEMPT);
	return true;
}

/*
 * Whether every CPU @p may run on is inside the shield. The byte array
 * is the shield's authoritative record, so this predicate and the
 * per-CPU test in is_cpu_shielded() can never disagree. The affinity
 * width is a fast reject: a task allowed on more CPUs than the shield
 * covers always has one outside it.
 */
__hidden __noinline bool pin_wholly_shielded(const struct task_struct *p)
{
	u32 shielded = READ_ONCE(pin_shield_n);
	bool outside = false;
	s32 cpu;

	if (!shielded)
		return false;
	if ((u32)p->nr_cpus_allowed > shielded)
		return false;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    !pin_shield_cpu[(u32)cpu & (BABY_MAX_CPUS - 1)]) {
			outside = true;
			break;
		}
	}
	return !outside;
}

/*
 * The stranded-arrival safety valve. Dispatch withholds the node queue
 * on a shielded CPU, so a task whose whole affinity lies inside the
 * shield can never be served from there: every CPU it is allowed on
 * refuses the queue, and no other CPU may run it. A single-CPU task is
 * the common case (a pinned kthread, or an engine thread the launcher
 * bound to one CPU), but a two-CPU affinity covering one pin's home and
 * sibling is just as stuck, and it would wait until the watchdog
 * unloaded the scheduler.
 *
 * Park such a task in the seat of one of its own allowed CPUs instead:
 * every shielded CPU drains its two seats before it looks at the node
 * queue, so that is the one queue which always reaches it.
 */
__hidden __noinline bool pin_stranded_enqueue(struct task_struct *p,
					      u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 slice;
	s32 only;

	if (!pin_wholly_shielded(p))
		return false;

	only = scx_bpf_task_cpu(p);
	if (!bpf_cpumask_test_cpu(only, p->cpus_ptr))
		only = (s32)bpf_cpumask_first(p->cpus_ptr);
	if ((u32)only >= nr_cpu_ids)
		return false;

	tctx = try_lookup_task_ctx(p);
	slice = tctx ? task_slice(tctx) : deadline_ns;
	scx_bpf_dsq_insert(p, cpu2dsq(only), slice, enq_flags);
	scx_bpf_kick_cpu(only, SCX_KICK_IDLE);
	return true;
}

/*
 * The wake path of a pinned thread: home if it is idle, and the home
 * as the placement either way. A busy home is left untouched here; the
 * enqueue that follows decides between the direct preempt and the
 * home's seat, and the selector never spreads a pinned thread off its
 * core in the meantime.
 */
__hidden __noinline bool pin_select_pinned(struct task_struct *p,
					   struct task_ctx *tctx,
					   u64 now, s32 *out_cpu)
{
	struct pin_slot *slot;
	u32 key = 0, pid = (u32)p->pid;
	s32 home;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (!slot || slot->pid != pid) {
		key = 1;
		slot = bpf_map_lookup_elem(&pin_slots, &key);
		if (!slot || slot->pid != pid)
			return false;
	}

	home = slot->home_cpu;
	if (home < 0 || (u32)home >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(home, p->cpus_ptr))
		return false;

	slot->active_until = now + pin_grace_ns;

	if (scx_bpf_test_and_clear_cpu_idle(home)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(tctx), 0);
		if (stats_enabled)
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}
	*out_cpu = home;
	return true;
}

/*
 * The wake selector while a shield is up: the kernel selector runs on
 * the pin worker mask and a pick is dispatched straight to its idle
 * CPU. Anything else returns -1, so the caller keeps the warm seat or
 * steps forward to the nearest unshielded CPU.
 */
__hidden __noinline s32 pin_select_cpu_and(struct task_struct *p, s32 prev_cpu,
					   u64 wake_flags)
{
	struct bpf_cpumask *mask = pin_worker_cpumask;
	struct task_ctx *tctx;
	s32 cpu = -1;

	/*
	 * Older kernels lack the helper. The branch has to fold to this
	 * return, or the unresolved call fails the whole load: --game
	 * arms the pin by default, so the call site is live.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and)
		return -1;

	if (mask && !bpf_cpumask_empty(cast_mask(mask)))
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
					     cast_mask(mask), 0);
	if (cpu >= 0) {
		tctx = try_lookup_task_ctx(p);
		if (stats_enabled)
			__sync_fetch_and_add(
				&nr_wake_land[cpu_dist(prev_cpu, cpu)], 1);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
				   tctx ? task_slice(tctx) : deadline_ns, 0);
		if (stats_enabled)
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return cpu;
	}
	return -1;
}

/*
 * The first CPU after @prev_cpu that @p may run on and that no shield
 * holds. Only a wake whose previous CPU the shield owns needs this: the
 * warm seat is gone, so stepping forward finds the nearest usable CPU
 * without the CPU-0 restart that would throw the locality away.
 */
__hidden __noinline s32 pin_next_unshielded(struct task_struct *p,
					    s32 prev_cpu, u64 now)
{
	u32 nr = (u32)nr_cpu_ids;
	u32 i;

	if (!nr)
		return -1;

	bpf_for(i, 0, nr_cpu_ids) {
		s32 cpu = (s32)(((u32)prev_cpu + 1 + i) % nr);

		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    !is_cpu_shielded(cpu, now))
			return cpu;
	}
	return -1;
}

/*
 * Release a slot whose owner has not refreshed it for the stale window.
 * Nothing else does: a slot is given back by its own owner at a window
 * roll, and taken over only by a task that reaches the promotion bar.
 * When a game exits or a thread blocks for good, neither happens, so the
 * claim would outlive its process and keep the home and sibling out of
 * the wake selector's mask; a reused pid would also inherit the claim,
 * because the pid is the claim word. The rescue timer is the one path
 * that runs while the machine is too quiet to promote anything, which
 * makes it the right place for this.
 */
__hidden __noinline bool pin_release_stale(u64 now)
{
	struct pin_slot *slot;
	bool released = false;
	u32 key = 0, pid;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot) {
		pid = READ_ONCE(slot->pid);
		if (pid && now - READ_ONCE(slot->last_seen_ns) > pin_stale_ns &&
		    __sync_val_compare_and_swap(&slot->pid, pid, 0) == pid)
			released = true;
	}

	key = 1;
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot) {
		pid = READ_ONCE(slot->pid);
		if (pid && now - READ_ONCE(slot->last_seen_ns) > pin_stale_ns &&
		    __sync_val_compare_and_swap(&slot->pid, pid, 0) == pid)
			released = true;
	}

	if (released)
		pin_mask_rebuild();
	return released;
}

/*
 * Whether either slot has an owner. The rescue timer uses it to decide
 * whether a rebuild is worth its cost: the count alone cannot answer
 * this, because a lost rebuild is exactly the case where the record says
 * zero while a slot is live.
 */
__hidden __noinline bool pin_slot_live(void)
{
	struct pin_slot *slot;
	u32 key = 0;

	slot = bpf_map_lookup_elem(&pin_slots, &key);
	if (slot && READ_ONCE(slot->pid))
		return true;

	key = 1;
	slot = bpf_map_lookup_elem(&pin_slots, &key);
	return slot && READ_ONCE(slot->pid);
}
