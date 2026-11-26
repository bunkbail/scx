/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: the game pin: the rodata knobs, the slot layout, the shielded-CPU
 * state and the pin.bpf.c prototypes.
 *
 * Scoped header: baby.bpf.h includes it, and it includes nothing
 * itself, so it reads the core types and macros defined there.
 */
#ifndef __BABY_PIN_H
#define __BABY_PIN_H

#ifndef __BABY_H
#error "pin.bpf.h is included by baby.bpf.h, not on its own"
#endif

/*
 * Game pin: the plain virtual-time queue with one or two SMT pairs
 * held for the busiest threads of the game process. --game and
 * --profile gaming arm it by default, and --no-game-pin clears it
 * again. It exists only on top of the plain virtual-time queue;
 * userspace clears game_pin when the run does not select it, and every
 * branch below it is pruned by the verifier otherwise. The pin's
 * rodata knobs publish zero when it is off.
 *
 * @pin_grace_ns: how long a slot keeps shielding its home after its
 *		  owner was last seen enqueued or woken.
 * @pin_promote0: duty, in q10 of a core, that a task must have held
 *		  across its last window to claim a slot.
 * @pin_release0: duty below which the owner gives its slot back.
 * @pin_promote1: duty a window must hold to extend the streak that
 *		  @pin_streak_need counts.
 * @pin_streak_need: consecutive windows at @pin_promote1 that either
 *		  slot needs before it is claimed.
 * @pin_busy_max: machine-wide busy share, in q10, above which the
 *		  second slot stays unclaimed.
 * @pin_stale_ns: age at which a slot's owner is presumed gone and
 *		  any task may take the slot over.
 * @pin_challenger: duty margin by which a live slot can still be
 *		  taken over by a busier task.
 */
extern const volatile bool game_pin;
extern const volatile u64 pin_grace_ns;
extern const volatile u32 pin_max;
extern const volatile u32 pin_promote0;
extern const volatile u32 pin_release0;
extern const volatile u64 pin_stale_ns;
extern const volatile u32 pin_promote1;
extern const volatile u32 pin_streak_need;
extern const volatile u32 pin_busy_max;
extern const volatile u32 pin_challenger;

/*
 * The game pin (--game-pin): a game's render thread and its submission
 * thread each keep one physical core to themselves. Under the plain
 * virtual-time queue every task competes in one shared order, so a
 * helper that woke first can hold the core the render thread needs at
 * the next frame deadline. The pin gives the two busiest threads of a
 * process a private home CPU and keeps every other task off it.
 *
 * Duty is an EWMA over the burst tracker's 200ms window, in q10 of one
 * core, so a thread that holds most of a core across windows qualifies
 * while a bursty helper does not. A slot is claimed by an atomic CAS
 * on its pid word, refreshed by its owner on every window roll, and
 * released when the owner's duty falls under the release bar. The two
 * slots each hold one SMT pair: slot 0 is open to the busiest thread, slot
 * 1 is held for a second thread of the same process once the first has
 * proven its duty and the machine has headroom, and its home must be a
 * different physical core so the pair lands on two cores rather than
 * two threads of one.
 *
 * A slot's shielding outlives its owner's sleep by the grace window,
 * so the short gaps between two frames do not hand the core away and
 * buy a migration on every wake. A slot whose owner has gone stale, or
 * whose duty a live challenger now beats by the challenger margin, can
 * be taken over, so a process that stops using the pin does not hold
 * the core forever.
 *
 * A slot's pid word is its claim word: 0 is free, a nonzero pid is the
 * owner. Every other field is written only by the owner, so a reader
 * that matched the pid may see one field still holding the previous
 * owner's value for the few instructions the new owner takes to fill
 * the slot. Such a snapshot costs one misplacement, never an unsafe
 * CPU id or a stranded task.
 */
struct pin_slot {
	u32 pid;
	u32 tgid;
	s32 home_cpu;
	s32 sib_cpu;
	u32 duty_q10;
	u32 busy_q10;
	u32 core_id;
	u32 pad_;
	u64 last_seen_ns;
	u64 active_until;
	u64 nr_enq;
	u64 pad2_;
};

/*
 * The shielded CPUs as a byte test (the dispatch and wake paths ask
 * per CPU) and their count, rebuilt only when a slot changes. The
 * busy share of the machine, in q10, gates the second slot.
 */
extern u8 pin_shield_cpu[BABY_MAX_CPUS];
extern u32 pin_shield_n;
extern volatile u32 machine_busy_q10;

/*
 * pin.bpf.c: the game pin's accounting, placement and dispatch hooks.
 */

__hidden void pin_mask_rebuild(void);
__hidden void pin_account(struct task_struct *p, struct task_ctx *tctx,
			  u64 now);
__hidden void pin_stopping_stamp(struct task_struct *p, u64 now);
__hidden bool pin_enqueue_pinned(struct task_struct *p, struct task_ctx *tctx,
				 u64 enq_flags, u64 now);
__hidden bool pin_select_pinned(struct task_struct *p, struct task_ctx *tctx,
				u64 now, s32 *out_cpu);
__hidden s32 pin_select_cpu_and(struct task_struct *p, s32 prev_cpu,
				u64 wake_flags);
__hidden s32 pin_next_unshielded(struct task_struct *p, s32 prev_cpu, u64 now);
__hidden bool pin_owns_cpu(s32 cpu, const struct task_struct *p);
__hidden bool is_cpu_shielded(s32 cpu, u64 now);
__hidden bool pin_wholly_shielded(const struct task_struct *p);
__hidden bool pin_stranded_enqueue(struct task_struct *p, u64 enq_flags);
__hidden bool pin_release_stale(u64 now);
__hidden bool pin_slot_live(void);

#endif /* __BABY_PIN_H */
