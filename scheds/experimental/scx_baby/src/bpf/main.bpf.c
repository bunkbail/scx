/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * Every runnable task owns an absolute deadline and each CPU runs the
 * earliest one it can reach. Tasks that sleep before consuming their
 * deadline are treated as interactive and earn a nice boost; CPU hogs
 * are throttled by a burst tracker over a 200ms window.
 */
#include "baby.bpf.h"

char _license[] SEC("license") = "GPL";

/*
 * Default deadline offset and base slice, in nanoseconds (1.18ms from
 * the original DEADLINE_NS).
 */
const volatile u64 deadline_ns = 1180000ULL;

/* Report additional debugging information. */
const volatile bool debug;

/*
 * Gaming profile: the plain virtual-time queue on an 800us slice. There
 * are no warm seats and no fast lane under it; a latency-critical wake
 * waits in the node's virtual-time queue like any other task.
 */
const volatile bool gaming;

/*
 * Plain EDF baseline (--plain): no warm seats, no two-lane split and no
 * lane arbitration. Every task waits in its node's deadline queue.
 */
const volatile bool plain;

/* Plain base slice (--plain-1x) and bounded wake preemption (--plain-wake). */
const volatile bool plain_1x;
const volatile bool plain_wake;

/*
 * Plain virtual time (--plain-vtime, implies --plain-1x): the node
 * queue is keyed by the runtime each task has consumed, inversely
 * scaled by its weight, instead of by an absolute deadline. A waking
 * task is lifted to `vtime_now - vtime_lag_ns * wakeup_freq` scaled by
 * its weight, which is cosmos's slice_lag model: frequent wakers sort
 * ahead by a bounded amount of virtual time, CPU hogs do not.
 */
const volatile bool plain_vtime;
const volatile u64 vtime_lag_ns = 20000000ULL;

/*
 * Seat guard: the default profile's alone. It bounds the preemption and
 * the deep rung a warm-seat placement gets, and lets an about-to-idle
 * CPU take one task off another seat. baby.bpf.h carries the rationale
 * and the branches; userspace publishes false for every plain profile
 * and for --game, where the verifier prunes them.
 */
const volatile bool seat_guard;

/*
 * The game pin, armed by --game/--profile gaming and cleared by
 * --no-game-pin or any run that does not select the plain virtual-time
 * queue. Userspace rewrites only game_pin, pin_grace_ns and pin_max;
 * the rest are tuned here, where the comments in baby.bpf.h explain
 * what each bar means.
 */
const volatile bool game_pin;
const volatile u64 pin_grace_ns = 20000000ULL;
const volatile u32 pin_max = 2;
const volatile u32 pin_promote0 = 665;		/* ~65% of a core in 0..1024 */
const volatile u32 pin_release0 = 500;		/* ~49% */
const volatile u64 pin_stale_ns = 600ULL * NSEC_PER_MSEC;
const volatile u32 pin_promote1 = 615;		/* ~60% */
const volatile u32 pin_streak_need = 2;
const volatile u32 pin_busy_max = 563;		/* 55% in q10 */
const volatile u32 pin_challenger = 100;	/* ~10% */

/* cosmos's MAX_WAKEUP_FREQ cap on the credit multiplier. */
#define BABY_VTIME_WAKE_FREQ_MAX	1024

/*
 * The largest run one stop may charge: a task renewed in place
 * accumulates across the renewals, and the weight division multiplies
 * by a hundred before it divides.
 */
#define BABY_VTIME_CHARGE_MAX_NS	NSEC_PER_SEC

/*
 * Big and little CPU sets, published by userspace at startup. They drive
 * the hybrid compaction below; both stay empty on a single-tier machine,
 * which disables every hybrid path.
 */
private(BABY) struct bpf_cpumask __kptr *big_cpumask;
private(BABY) struct bpf_cpumask __kptr *little_cpumask;

/*
 * Every CPU outside the LP islands: the mask the kernel selector may
 * pick from. scx_bpf_select_cpu_and() clears the chosen CPU's kernel
 * idle bit, and there is no helper to put it back, so an idle CPU this
 * scheduler does not dispatch to must never be picked in the first
 * place. The full task mask remains the fallback for a task whose
 * affinity allows only LP cores.
 */
private(BABY) struct bpf_cpumask __kptr *non_lp_cpumask;

/*
 * The game pin (armed by --game/--profile gaming, cleared by
 * --no-game-pin or a run that does not select the plain virtual-time
 * queue; the mechanism is described in baby.bpf.h).
 *
 * pin_slots holds the two claims. Its pid word is the claim word: 0 is
 * free, a nonzero pid is the owner, and a takeover is an atomic CAS
 * from the pid the reader saw. Nothing else is ever compare-exchanged,
 * and every other field has its owner as its only writer, so no
 * bpf_spin_lock is needed: a reader that matched the pid tolerates one
 * field still carrying the previous owner's value.
 *
 * pin_shield_cpu[] is the hot-path copy of the slots' homes and
 * siblings, because the dispatch, wake and enqueue paths ask about one
 * CPU and a byte test beats a map lookup. It and the mask are rebuilt
 * only when a slot changes (claim, takeover, release), never on the
 * hot path. machine_busy_q10 is the sampled busy share of the machine
 * that gates the second slot.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, struct pin_slot);
} pin_slots SEC(".maps");

u8 pin_shield_cpu[BABY_MAX_CPUS];
u32 pin_shield_n;
volatile u32 machine_busy_q10;

/*
 * The CPUs a non-pinned task may be placed on while a pin is active:
 * the non-LP set minus the shielded homes and siblings. Held as a
 * cpumask because scx_bpf_select_cpu_and() takes the mask directly.
 * Every CPU starts eligible; the tier syscall clears the LP ones, so
 * without a pin claimed the mask is the non-LP set the plain selector
 * already uses.
 */
private(BABY) struct bpf_cpumask __kptr *pin_worker_cpumask;

u64 cpu_running_at[BABY_MAX_CPUS];
bool cpu_is_lat[BABY_MAX_CPUS];

/*
 * One anti-herd claim per node: the high 32 bits hold the waiter's pid,
 * the low 32 bits the claim time with its low bit forced to one, so a
 * zero word means unclaimed. A claim suppresses another CPU's tick only
 * for the same waiter; a different head may claim immediately. The
 * claim is cleared by a successful pull from that node's fast-lane
 * queue, not by a bulk pull or a seat pull, which serve other work.
 */
u64 node_preempt_claim[BABY_NODE_CLOCK_NR];

/*
 * The per-node virtual clock (--plain-vtime). It advances to the
 * virtual time of every task the node dispatches and never goes back,
 * so a task that slept while the node made progress wakes to a credit
 * floor set by how far that node has come, not by its own idle time.
 */
static u64 node_vtime_now[BABY_NODE_CLOCK_NR];

/*
 * Per-queue service clocks for the starve rescue, indexed by lane
 * (0 bulk, 1 fast lane). A queue that has held work for a second
 * without a successful pull is re-enqueued. The clock is seeded when
 * the queue becomes non-empty and advanced on every successful pull,
 * so a continuously served queue never looks starved and a newly
 * populated one does not inherit the clock of the queue's birth. The
 * node clocks are shared by every CPU on the node, so their pulls
 * advance them at most once per millisecond; the one-second window
 * cannot tell. The per-CPU seat clocks stay exact.
 */
u64 seat_service_at[2][BABY_MAX_CPUS];
u64 node_service_at[2][BABY_NODE_CLOCK_NR];
u8 seat_used[2][BABY_MAX_CPUS];
u64 seat_pending[2][BABY_MAX_CPUS];
u64 node_pending[2][BABY_NODE_CLOCK_NR];

/*
 * The newest warm-seat insertion, stamped by balance.bpf.c under a
 * ten-millisecond throttle. The idle fall-through in ops.dispatch()
 * reads it once to decide whether any seat can hold work at all.
 */
u64 seat_last_enq_ns;

/*
 * Whether a task runs on each CPU, counted by the warm-seat scan into
 * its own per-lane sum. The scan already walks every CPU, so one load
 * per CPU there replaces a pair of global read-modify-writes on the
 * switch path.
 */
bool cpu_running[BABY_MAX_CPUS];

/*
 * Fast-lane time budget, per CPU. The bucket accrues two thirds of
 * wall time as fast-lane credit and holds at most four base slices.
 * It is charged the span a fast-lane interval covers: the run itself,
 * not the slice it is granted, plus the stop-to-run gap to the next
 * run on the same CPU while bulk waits, charged before that run starts
 * whether it is bulk or fast-lane work. A task that sleeps early pays
 * only for what it used, a 50-60Hz frame thread keeps its share, and
 * the scheduling overhead between two fast-lane runs is not credited
 * for free. While a fast-lane interval runs the
 * net rate is +2/3 - 1 = -1/3 of wall time; while bulk runs it is
 * +2/3. The steady state is therefore a two thirds fast-lane and one
 * third bulk share of a contended CPU, independent of how long each
 * slice runs.
 *
 * A bulk run or an idle dispatch breaks the interval: the CPU was
 * doing other work, so the run that follows charges no gap for it.
 * An RT lease does the same; its time belongs to the RT task.
 *
 * The budget is consulted only while bulk work waits; on an
 * otherwise idle CPU the fast lane runs freely. The debt floor bounds
 * how far one burst can push bulk ahead, not how long the fast lane
 * may run.
 */
s64 fl_budget_ns[BABY_MAX_CPUS];
u64 fl_budget_at[BABY_MAX_CPUS];
u64 cpu_fl_running_at[BABY_MAX_CPUS];

/*
 * The contention state stamped by the stop that ended this CPU's last
 * fast-lane run. The run that follows charges the stop-to-run gap
 * against the bulk work that waited when the run ended, so it reuses
 * the stop's probe instead of taking a second one a few hundred
 * nanoseconds later. A bulk run or an idle dispatch clears the stamp
 * with the fast-lane clock.
 */
bool cpu_bulk_wait[BABY_MAX_CPUS];

/* See dispatch.bpf.h. */
u64 cpu_bulk_at[BABY_MAX_CPUS];

/*
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	mask = *cpumask;
	if (mask)
		return 0;

	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
}

/*
 * Encode the virtual-time key of a task for its node's queue
 * (--plain-vtime): cosmos's task_dl(), with the clock kept per node.
 * The lift only ever raises the key, so a wake cannot buy back runtime
 * the task has already been charged for.
 */
__hidden u64 vtime_encode(const struct task_struct *p, struct task_ctx *tctx,
			  s32 node)
{
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 vsleep_max, vtime_now, vmin;

	if (lag_scale > BABY_VTIME_WAKE_FREQ_MAX)
		lag_scale = BABY_VTIME_WAKE_FREQ_MAX;

	vtime_now = node_vtime_now[(u32)node & (BABY_NODE_CLOCK_NR - 1)];

	/*
	 * First sight of this task: start it at the node clock, as cosmos
	 * does in ops.enable(). Starting at zero would hand a new task the
	 * full wake credit and let a burst of fresh tasks jump the queue.
	 */
	if (!tctx->vtime)
		tctx->vtime = vtime_now;

	vsleep_max = scale_by_task_weight(p, vtime_lag_ns * lag_scale);
	vmin = vtime_now > vsleep_max ? vtime_now - vsleep_max : 0;

	if (tctx->vtime < vmin)
		tctx->vtime = vmin;

	return tctx->vtime;
}

/*
 * Enqueue a task with no idle CPU to run on. The node queue is ordered
 * by deadline, and dispatch takes the earliest one.
 */
void BPF_STRUCT_OPS(baby_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 prev_cpu = scx_bpf_task_cpu(p);
	s32 node = __COMPAT_scx_bpf_cpu_node(prev_cpu);
	bool is_running = scx_bpf_task_running(p);
	u64 bulk_backlog, fl_backlog, slice, now = bpf_ktime_get_ns();

	if (!tctx)
		return;

	/*
	 * Whatever queued this task next, it is not in a tagged queue any
	 * more: the wake, the preemption requeue and the rescue reenqueue
	 * all re-enter here, and the pending count of the queue it left
	 * must fall with the first of them or with the run that follows.
	 */
	baby_untag(tctx);

	tctx->last_acc_at = now;

	/*
	 * The two lanes are counted separately: a fast-lane backlog must
	 * not open a bulk seat or grant a bulk arrival the deep rung, and
	 * a bulk backlog must not open a fast-lane seat. The probe cannot
	 * run inside an RCU read-side section; enqueue is outside one.
	 */
	bulk_backlog = scx_bpf_dsq_nr_queued(node);
	fl_backlog = scx_bpf_dsq_nr_queued(fl_node2dsq(node));

	/*
	 * Consume the yield mark on every enqueue: a mark that survived
	 * into an unrelated enqueue would push the wrong arrival behind
	 * the round. The push applies only to the rotation requeue that
	 * follows the yield, never to a wake, which keeps the sleep-time
	 * deadline.
	 */
	bool yielded = tctx->yield_pending;

	tctx->yield_pending = false;

	if (yielded && !(enq_flags & SCX_ENQ_WAKEUP)) {
		/*
		 * yield_task_fair() marks the deadline so the task is
		 * picked last in the current round; push it behind every
		 * task queued in its lane in this round. A fixed two-slice
		 * push skipped at most two of them.
		 */
		u64 lane_backlog = is_lat_cri(tctx) ? fl_backlog :
						      bulk_backlog;

		tctx->deadline = now + (lane_backlog + 1) * deadline_ns;
	} else if ((!is_running || !tctx->tick_preempted) &&
		   !(enq_flags & (SCX_ENQ_LAST | SCX_ENQ_WAKEUP |
				  SCX_ENQ_REENQ))) {
		/*
		 * A migrated or freshly created task gets a fresh deadline,
		 * and so does a rotation whose slice expired naturally: it
		 * consumed the slice it was granted, so the fresh deadline
		 * is its next turn. Only a task cut short by the tick keeps
		 * the deadline ops.stopping() left it with, so its
		 * remaining turn ages instead of being recomputed. Woken
		 * tasks keep the sleep-time deadline, a cpu_release()
		 * requeue keeps its place, and SCX_ENQ_LAST is the same
		 * task re-entering after an empty dispatch.
		 */
		tctx->deadline = calc_deadline(p, tctx, now);
	}

	/*
	 * A latency-critical task that is requeued while it still owns the
	 * CPU (a wake-preempt or a timer cut) or comes back from an RT
	 * lease keeps that CPU as its home. baby_dispatch() serves it back
	 * there while the budget has overdraw left, provided the task can
	 * run on another CPU: a pinned task's take-back would leave bulk
	 * work pinned to the same CPU with nowhere else to run.
	 */
	if (is_lat_cri(tctx) &&
	    (is_running || (enq_flags & SCX_ENQ_REENQ))) {
		tctx->last_cpu = prev_cpu;
		if ((enq_flags & SCX_ENQ_REENQ) && stats_enabled)
			__sync_fetch_and_add(&nr_lease_requeues, 1);
	}

	/*
	 * A pinned arrival goes to its own core before the idle scan:
	 * the core is the placement, and try_direct_dispatch() would
	 * spread the task to the first idle CPU instead. A task whose
	 * whole affinity lies inside the shield parks in the seat of one
	 * of its own CPUs, so it can never wait in the node queue behind
	 * the shield. Both tests are gated on a shield existing, so a
	 * run with the flag but no claim pays neither.
	 */
	if (plain && game_pin && READ_ONCE(pin_shield_n) &&
	    (pin_enqueue_pinned(p, tctx, enq_flags, now) ||
	     pin_stranded_enqueue(p, enq_flags, now)))
		return;

	/*
	 * Place the arrival before considering a preemption.
	 *
	 * A wakee that can run now on a CPU that went idle since
	 * ops.select_cpu() has no reason to evict a running task, and an
	 * idle CPU is what the fan-out would have to beat anyway. A
	 * reenqueued task rescans here for the same reason. The scan runs
	 * before the warm seat so a requeue or rescue never parks on a
	 * busy seat while a lane sits idle.
	 */
	{
		if (try_direct_dispatch(p, tctx, prev_cpu, enq_flags,
					is_running))
			return;

		/*
		 * check_preempt_wakeup(): preempt the previous CPU's task
		 * when the waker has an earlier deadline and no lower
		 * priority, provided the CPU has no warm backlog and the
		 * running task can be cut. A preemption into a deep queue
		 * would only trade places with work that runs anyway, and a
		 * burst hog must not be preempted. Only interactive and
		 * foreground wakers are eligible: a task that never wakes
		 * has no latency to protect.
		 *
		 * The victim rules mirror ops.select_cpu()'s wake gate: a
		 * latency-critical resident keeps its CPU (two pipeline
		 * stages must not take turns on one), a victim pinned to a
		 * single CPU has nowhere else to go, and a resident still
		 * inside the residency floor has not had a turn worth
		 * taking. The wakee must be allowed on the target, and no
		 * in-flight wakee may hold the local DSQ (the insert would
		 * queue behind it). The deadline order arbitrates between
		 * two bulk tasks as before.
		 */
		if ((plain_wake || !plain) && (enq_flags & SCX_ENQ_WAKEUP) &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    (plain_wake ? !scx_bpf_dsq_nr_queued(node) :
		     (!scx_bpf_dsq_nr_queued(fl_cpu2dsq(prev_cpu)) &&
		      !scx_bpf_dsq_nr_queued(cpu2dsq(prev_cpu)))) &&
		    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cpu) &&
		    (plain_wake || is_interactive(tctx) || is_foreground(tctx))) {
			u32 pidx = (u32)prev_cpu & (BABY_MAX_CPUS - 1);
			u64 ran_at = cpu_running_at[pidx];
			struct task_struct *curr =
				__COMPAT_scx_bpf_cpu_curr(prev_cpu);

			if (curr && curr != p && !(curr->flags & PF_IDLE)) {
				struct task_ctx *cctx =
					try_lookup_task_ctx(curr);

				if (!plain_wake && cctx && is_lat_cri(cctx)) {
					if (stats_enabled)
						__sync_fetch_and_add(
							&nr_preempt_refused_lat,
							1);
				} else if (cctx && !is_pcpu_task(curr) &&
					   ran_at &&
					   (s64)(now - ran_at) >=
						   (s64)(plain_wake ?
							 PLAIN_WAKE_PROTECT_NS :
							 BABY_TICK_PREEMPT_PROTECT_NS) &&
					   (plain_wake ?
					    plain_wake_cut(tctx, cctx) :
					    (s64)(tctx->deadline -
						  cctx->deadline) < 0) &&
					   p->static_prio <= curr->static_prio &&
					   can_resched(cctx)) {
					scx_bpf_dsq_insert(
						p, SCX_DSQ_LOCAL_ON | prev_cpu,
						task_slice(tctx),
						enq_flags | SCX_ENQ_PREEMPT);
					if (stats_enabled)
						__sync_fetch_and_add(
							&nr_preemptions, 1);
					return;
				}
			}
		}

		/*
		 * Warm seat, gated on oversubscription (see balance.bpf.c).
		 * Plain mode has no seats.
		 */
		if (!plain &&
		    balance_try_warm_seat(p, tctx, enq_flags, bulk_backlog,
					  fl_backlog, now))
			return;
	}

	/*
	 * No idle CPU: join the deadline order. In the full scheduler a
	 * deep backlog grants the fourfold slice, a tick-preempted victim
	 * keeps the base slice, and latency-critical tasks use their own
	 * node queue, which dispatch serves ahead of bulk while the time
	 * budget allows. Plain mode has one queue and one base slice.
	 *
	 * Under the seat guard the fourfold rung is bulk-only. A
	 * non-foreground latency-critical arrival granted four slices
	 * becomes a fast-lane resident that the tick gate, the wake-path
	 * preempt and the guarded seat preemption can all no longer cut,
	 * so the deep queue would hand it the CPU for four slices at the
	 * exact moment the guard is trying to bound how long it may hold
	 * one. Foreground tasks still get the fourfold slice from
	 * task_slice().
	 */
	{
		bool lat = !plain && is_lat_cri(tctx);
		u64 lane_backlog = lat ? fl_backlog : bulk_backlog;
		u64 dsq = lat ? fl_node2dsq(node) : (u64)node;

		/*
		 * Plain mode is the minimal EDF baseline: one shared
		 * deadline queue per node, the base slice, no rescue clock
		 * and no arrival tag. The tag and the rescue clock serve
		 * the lanes and the seats, which plain mode does not have.
		 */
		if (plain) {
			u64 key = plain_vtime ?
				vtime_encode(p, tctx, node) : tctx->deadline;

			scx_bpf_dsq_insert_vtime(p, dsq, task_slice(tctx),
						 key, enq_flags);
			stamp_wait(tctx, now, lane_backlog, true);
		} else {
			/*
			 * Seed the rescue clock when the lane's shared
			 * queue was empty; a queue that is already served
			 * does not need it.
			 */
			if (!lane_backlog)
				node_service_at[lat & 1][node &
							 (BABY_NODE_CLOCK_NR - 1)] = now;

			slice = backlog_deep(lane_backlog) &&
				 !tctx->tick_preempted &&
				 !(seat_guard && lat)
				? 4 * deadline_ns : task_slice(tctx);

			baby_insert_vtime(p, tctx, dsq, slice,
					  tctx->deadline, enq_flags,
					  baby_tag(1, lat, (u32)node));
			stamp_wait(tctx, now, lane_backlog, true);
		}
	}

	/*
	 * The task is placed without the wake side effect of
	 * ops.select_cpu(), so wake the CPU that will pull it if idle. A
	 * CPU the pin is shielding is not woken for ordinary work it will
	 * not be served, but a task that can run nowhere outside the
	 * shield must still wake it: an idle CPU that is never kicked
	 * never calls dispatch(), so it never looks at the seat the
	 * arrival was parked in, and the task waits for the watchdog.
	 */
	if (!is_running && !__COMPAT_is_enq_cpu_selected(enq_flags) &&
	    !(plain && game_pin && READ_ONCE(pin_shield_n) &&
	      !pin_wholly_shielded(p) && is_cpu_shielded(prev_cpu, now)))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * The kernel took the CPU for an RT or deadline task and has given it
 * back. Tasks that dispatch() had moved into the local DSQ waited out
 * the lease where no other CPU could see them; push them back through
 * enqueue, where they land on an idle core or in the deadline order.
 * The lease time belongs to the RT task: it breaks the fast-lane
 * interval, so the budget does not charge it.
 */
void BPF_STRUCT_OPS(baby_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	/*
	 * scx_bpf_reenqueue_local() returns a count on some kernels and
	 * is shimmed to void through the compat layer on others; call it
	 * as void, the re-enqueue happens either way.
	 */
	cpu_fl_running_at[(u32)cpu & (BABY_MAX_CPUS - 1)] = 0;
	cpu_bulk_wait[(u32)cpu & (BABY_MAX_CPUS - 1)] = false;
	scx_bpf_reenqueue_local();
}

/*
 * The task has stopped running, either to sleep or because its time slice
 * expired.
 */
void BPF_STRUCT_OPS(baby_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 last_cpu;
	u64 now;

	/*
	 * The count is a hybrid-compaction input and a stats field; a
	 * single-tier machine with stats off reads neither, so it does
	 * not pay two global read-modify-writes per switch to keep it.
	 */
	if ((nr_little_cpus && nr_big_cpus) || stats_enabled)
		__sync_fetch_and_sub(&nr_running, 1);

	/*
	 * The CPU's running-class residency lapses with the resident;
	 * ops.running() re-stamps it when the next task is served.
	 * ops.stopping() can run after a migration, so the stamp to
	 * clear is the CPU the task ran on, not its current one.
	 */
	last_cpu = (tctx && tctx->last_cpu >= 0) ? tctx->last_cpu :
						  scx_bpf_task_cpu(p);
	now = bpf_ktime_get_ns();
	if (plain && game_pin && READ_ONCE(pin_shield_n))
		pin_stopping_stamp(p, now);
	{
		u32 idx = (u32)last_cpu & (BABY_MAX_CPUS - 1);

		/*
		 * Account the contested fast-lane runtime actually
		 * consumed and refill the elapsed-time credit before the
		 * residency lapses; under contention the two together
		 * leave the bucket one third of the interval lower, the
		 * bulk share the budget promises. A latency-critical stop
		 * keeps its stamp, so the next run on this CPU charges the
		 * stop-to-run gap before it starts, bulk or fast-lane; a
		 * bulk stop clears the stamp.
		 */
		if (cpu_is_lat[idx]) {
			bool contended = bulk_waiting(last_cpu);

			refill_fl_budget(idx, now);
			charge_fl_runtime(idx, now, contended);
			cpu_bulk_wait[idx] = contended;
		} else {
			cpu_fl_running_at[idx] = 0;
			cpu_bulk_wait[idx] = false;
		}
		cpu_is_lat[idx] = false;
		cpu_running[idx] = false;
	}

	if (!tctx)
		return;

	/* The run that just ended, for the plain wake gate. */
	if (now > tctx->run_start_ns)
		tctx->last_run_ns = now - tctx->run_start_ns;

	/*
	 * Whatever enqueues this task next is a re-entry of a task that
	 * has run - slice expiry, preemption, an RT-lease reenqueue -
	 * not the wake that started the burst: drop the wake bit so the
	 * wait instrument files the requeues as rotation. A task going
	 * to sleep re-sets the bit in ops.runnable() on its wake.
	 */
	tctx->arrival_is_wake = 0;

	/*
	 * A task that sleeps with an unconsumed yield mark would fire
	 * the push at its wake; a wake is a fresh arrival and keeps its
	 * sleep-time deadline, so drop the mark with the task.
	 */
	if (!runnable)
		tctx->yield_pending = false;

	update_bursts(tctx, now);

	/*
	 * --plain-vtime: charge this run's runtime to the task's virtual
	 * time, inversely scaled by its weight (cosmos ops.stopping()).
	 */
	if (plain_vtime) {
		u64 used = now > tctx->run_start_ns ?
			   now - tctx->run_start_ns : 0;

		used = MIN(used, BABY_VTIME_CHARGE_MAX_NS);
		tctx->vtime += scale_by_task_weight_inverse(p, used);
	}

	class_boost_on_sleep(p, tctx, runnable, now);

	/*
	 * update_curr(): roll the deadline forward once reached.
	 */
	if (reached_deadline(tctx, now))
		tctx->deadline = calc_deadline(p, tctx, now);

	/*
	 * Update CPU runtime for the performance scaling.
	 */
	cpuperf_on_stopping(last_cpu, now);
}

/*
 * The task has become runnable: track how often it wakes. Frequent
 * wakers with real work to do are foreground tasks.
 */
void BPF_STRUCT_OPS(baby_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now;

	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	class_on_runnable(tctx, enq_flags, now);
}

/*
 * The task has started to run on a CPU.
 */
void BPF_STRUCT_OPS(baby_running, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now = bpf_ktime_get_ns();

	if ((nr_little_cpus && nr_big_cpus) || stats_enabled)
		__sync_fetch_and_add(&nr_running, 1);

	/*
	 * The victim-residency stamp for the tick gate, and the point where
	 * a task that was cut short stops carrying the preempted mark: the
	 * requeue has happened by now. The running class feeds the warm
	 * gate and the relocation filter (see cpu_is_lat).
	 */
	{
		s32 cpu = scx_bpf_task_cpu(p);
		u32 cpu_idx = (u32)cpu & (BABY_MAX_CPUS - 1);

		cpu_running_at[cpu_idx] = now;
		cpu_running[cpu_idx] = true;
		cpu_is_lat[cpu_idx] = !plain && tctx && is_lat_cri(tctx);
		if (!cpu_is_lat[cpu_idx])
			cpu_bulk_at[cpu_idx] = now;
		/*
		 * The fast-lane clock. A non-zero stamp means the CPU's last
		 * run was fast-lane work and no bulk run or idle dispatch
		 * came between; the switch back is overhead the budget was
		 * crediting without charging, so charge it before this run
		 * starts, whether it is bulk or fast-lane work. A bulk run
		 * or an idle dispatch clears the stamp.
		 */
		if (cpu_fl_running_at[cpu_idx]) {
			refill_fl_budget(cpu_idx, now);
			charge_fl_runtime(cpu_idx, now,
					  cpu_bulk_wait[cpu_idx]);
		}
		cpu_fl_running_at[cpu_idx] = cpu_is_lat[cpu_idx] ? now : 0;
		if (tctx) {
			tctx->last_cpu = cpu;
			tctx->run_start_ns = now;
		}
	}

	if (!tctx)
		return;

	/*
	 * The pull that delivered this task has emptied its queue of it:
	 * lower the pending count of the queue the arrival was tagged
	 * with, so a lane that has gone quiet reads zero again.
	 */
	baby_untag(tctx);

	tctx->tick_preempted = false;
	tctx->last_acc_at = now;

	charge_wait(tctx, now);

	/*
	 * Class census at the point of truth: 0 bulk normal, 1 bulk
	 * heavy, 2 fast lane base slice, 3 fast lane fourfold slice.
	 * Class 2 plus class 3 is the fast-lane run count.
	 */
	if (stats_enabled) {
		u32 cls = task_nr_class(tctx);

		__sync_fetch_and_add(&nr_class[cls & (BABY_WCLS_NR - 1)], 1);
		__sync_fetch_and_add(
			&nr_lane[!plain && is_lat_cri(tctx) ? 1 : 0], 1);
	}

	/*
	 * Adjust the target CPU frequency before the task starts to run.
	 * A proven consumer or a foreground task saturates the core for
	 * as long as it runs, so give it the boost clock at once instead
	 * of re-climbing the smoothing after every sleep.
	 */
	cpuperf_on_running(scx_bpf_task_cpu(p), now,
			   is_heavy_proven(tctx) || is_foreground(tctx));

	class_on_running(p, tctx, now);

	/*
	 * --plain-vtime: this node's clock follows the virtual time of
	 * the task it just dispatched, monotonically (cosmos does the
	 * same at the head of its dispatch).
	 */
	if (plain_vtime) {
		s32 node = __COMPAT_scx_bpf_cpu_node(scx_bpf_task_cpu(p));
		u32 nidx = (u32)node & (BABY_NODE_CLOCK_NR - 1);

		if (tctx->vtime > node_vtime_now[nidx])
			node_vtime_now[nidx] = tctx->vtime;
	}
}

/*
 * sched_yield(): give up the CPU for the rest of this round, like the
 * original YIELD_MARK. With nothing this CPU can run there is nothing
 * to yield to: a queued head its affinity excludes is not a successor,
 * and honouring the yield for it would cost the caller its slice and
 * re-pick the caller. The kernel leaves the slice alone when ops.yield
 * is defined, so zero it here; only then does the task re-enter
 * through enqueue, where the mark is consumed.
 */
bool BPF_STRUCT_OPS(baby_yield, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 cpu, node;

	if (!tctx)
		return false;

	cpu = scx_bpf_task_cpu(p);
	node = __COMPAT_scx_bpf_cpu_node(cpu);

	if (!dsq_peek_allowed(cpu2dsq(cpu), cpu) &&
	    !dsq_peek_allowed(fl_cpu2dsq(cpu), cpu) &&
	    !dsq_peek_allowed(node, cpu) &&
	    !dsq_peek_allowed(fl_node2dsq(node), cpu))
		return false;

	tctx->yield_pending = true;
	scx_bpf_task_set_slice(p, 0);

	return true;
}

s32 BPF_STRUCT_OPS(baby_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	u64 now;

	tctx = init_task_ctx(p);
	if (!tctx)
		return -ENOMEM;

	now = bpf_ktime_get_ns();
	class_init_task(tctx, p, now);
	/*
	 * A fresh task is in no tagged queue. Task storage arrives zeroed,
	 * but the untag path must never see a tag that no insert raised,
	 * so the invariant is stated here rather than assumed.
	 */
	tctx->queued_tag = 0;

	return 0;
}

/*
 * A queue that no CPU can serve, behind an RT lease or with affinity
 * moved under it, strands its tasks where the rest of the machine
 * cannot see them. A queue that has held work this long without a
 * successful pull is overdue by far more than a warm wait; re-enqueue
 * it. This does not save a task pinned to a queue no CPU can pull: the
 * re-enqueue lands it in the same queue. Dispatch's bulk backstop
 * keeps such a CPU serving bulk, and this timer only returns work
 * whose queue lost its server.
 */
#define STARVE_RESCUE_NS	1000000000ull

struct rescue_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct rescue_timer);
} rescue_timer SEC(".maps");

/*
 * One queue's rescue: a queue that has held work past the starve
 * window without a successful pull is re-enqueued. The service clock
 * is the queue's own, not the head task's arrival stamp: the seats and
 * node queues are ordered by deadline, so a newly arrived sleeper
 * with an older preserved deadline can sort ahead of a task that has
 * waited longer, and a head-based check would mask the stranded task.
 *
 * The clock is seeded when the queue becomes non-empty and written on
 * every successful pull, so a queue that is being served never looks
 * starved. A zero clock means the queue was never populated through
 * the seeded paths; wait for the first insertion rather than rescue a
 * queue that has merely existed since boot.
 */
static bool rescue_one_dsq(u64 dsq, u64 last_service, u64 now)
{
	if (__COMPAT_has_generic_reenq() && last_service &&
	    now - last_service > STARVE_RESCUE_NS &&
	    scx_bpf_dsq_nr_queued(dsq)) {
		scx_bpf_dsq_reenq___compat(dsq, 0);
		return true;
	}
	return false;
}

static int rescue_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = bpf_ktime_get_ns();
	s32 node, cpu;
	int err;

	if (game_pin) {
		pin_release_stale(now);
		/*
		 * Self-heal a lost rebuild: two racing claims can publish
		 * their snapshots out of order, which leaves the shield
		 * record behind the slots until the next slot change. One
		 * rebuild per rescue tick bounds that window, and it is
		 * also what puts the record back after a stale release.
		 */
		if (pin_slot_live() || READ_ONCE(pin_shield_n))
			pin_mask_rebuild();
	}

	if ((!plain || game_pin) && __COMPAT_has_generic_reenq()) {
		bpf_for(cpu, 0, nr_cpu_ids) {
			u32 idx = (u32)cpu & (BABY_MAX_CPUS - 1);

			if (rescue_one_dsq(cpu2dsq(cpu),
					   seat_service_at[0][idx], now))
				seat_used[0][idx] = 0;
			if (rescue_one_dsq(fl_cpu2dsq(cpu),
					   seat_service_at[1][idx], now))
				seat_used[1][idx] = 0;
		}
		/*
		 * The node queues exist only outside plain mode. A plain
		 * run with a pin rescues just the two seat queues the pin
		 * uses; its node queue is rescued by nothing, as before.
		 */
		if (!plain) {
			bpf_for(node, 0, nr_node_ids) {
				u32 idx = (u32)node & (BABY_NODE_CLOCK_NR - 1);

				rescue_one_dsq(node, node_service_at[0][idx], now);
				rescue_one_dsq(fl_node2dsq(node),
					       node_service_at[1][idx], now);
			}
		}
	}

	err = bpf_timer_start(timer, STARVE_RESCUE_NS, 0);
	if (err)
		scx_bpf_error("failed to re-arm the rescue timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(baby_init)
{
	struct bpf_cpumask *mask;
	struct bpf_timer *timer;
	u32 key = 0;
	s32 node, cpu, err;

	/*
	 * The DSQ ids are laid out from the two topology counts, and the
	 * per-CPU arrays are sized for BABY_MAX_CPUS. Userspace publishes
	 * both as rodata before load; assert them against the kernel's own
	 * counts here so a mismatch can never alias two CPUs or two node
	 * queues onto one id.
	 */
	if (!nr_cpu_ids || nr_cpu_ids > BABY_MAX_CPUS ||
	    nr_cpu_ids != scx_bpf_nr_cpu_ids()) {
		scx_bpf_error("CPU count mismatch: rodata %llu, kernel %u, max %u",
			      nr_cpu_ids, scx_bpf_nr_cpu_ids(), BABY_MAX_CPUS);
		return -EINVAL;
	}
	if (!nr_node_ids || nr_node_ids > BABY_MAX_NODES ||
	    nr_node_ids != __COMPAT_scx_bpf_nr_node_ids()) {
		scx_bpf_error("node count mismatch: rodata %llu, kernel %u, max %u",
			      nr_node_ids, __COMPAT_scx_bpf_nr_node_ids(),
			      BABY_MAX_NODES);
		return -EINVAL;
	}

	/*
	 * Create the per-CPU seats and the per-node deadline queues for
	 * both lanes.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu2dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d",
				      cpu2dsq(cpu), err);
			return err;
		}

		err = scx_bpf_create_dsq(fl_cpu2dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d",
				      fl_cpu2dsq(cpu), err);
			return err;
		}
	}

	bpf_for(node, 0, nr_node_ids) {
		err = scx_bpf_create_dsq(node, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", node, err);
			return err;
		}

		err = scx_bpf_create_dsq(fl_node2dsq(node), node);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d",
				      fl_node2dsq(node), err);
			return err;
		}
	}

	/*
	 * The pin's placement mask starts with every CPU eligible. The
	 * tier syscall clears the LP bits afterwards, so with no pin
	 * claimed the mask ends up as the non-LP set the plain selector
	 * already uses, and shields only ever subtract from it.
	 */
	if (game_pin) {
		err = init_cpumask(&pin_worker_cpumask);
		if (err)
			return err;
		bpf_rcu_read_lock();
		mask = pin_worker_cpumask;
		if (mask) {
			bpf_for(cpu, 0, nr_cpu_ids)
				bpf_cpumask_set_cpu(cpu, mask);
		}
		bpf_rcu_read_unlock();
	}

	timer = bpf_map_lookup_elem(&rescue_timer, &key);
	if (!timer) {
		scx_bpf_error("failed to lookup rescue timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &rescue_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, rescue_timerfn);
	err = bpf_timer_start(timer, STARVE_RESCUE_NS, 0);
	if (err) {
		scx_bpf_error("failed to arm the rescue timer");
		return err;
	}

	/* Initialize the CPU frequency performance level. */
	cpuperf_init();

	return 0;
}

void BPF_STRUCT_OPS(baby_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Publish one CPU's tier. Userspace counts the tiers before load and
 * writes the counts as rodata, so this program only fills the masks;
 * calling it twice for the same CPU is a no-op, and the counts cannot
 * double.
 */
SEC("syscall")
int enable_core_class(struct core_arg *input)
{
	struct bpf_cpumask *mask;
	s32 cpu = input->cpu_id;
	s32 tier = input->tier;
	int err;

	if (cpu < 0 || (u32)cpu >= nr_cpu_ids ||
	    tier < CORE_TIER_BIG || tier > CORE_TIER_LP)
		return -EINVAL;

	err = init_cpumask(&big_cpumask);
	if (err)
		return err;
	err = init_cpumask(&little_cpumask);
	if (err)
		return err;
	err = init_cpumask(&non_lp_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	if (tier != CORE_TIER_LP) {
		mask = non_lp_cpumask;
		if (mask)
			bpf_cpumask_set_cpu(cpu, mask);
	}
	/*
	 * The pin's mask mirrors the non-LP set; a pin only ever clears
	 * its shielded homes and siblings from it.
	 */
	if (game_pin) {
		mask = pin_worker_cpumask;
		if (mask) {
			if (tier == CORE_TIER_LP)
				bpf_cpumask_clear_cpu(cpu, mask);
			else
				bpf_cpumask_set_cpu(cpu, mask);
		}
	}
	if (tier == CORE_TIER_BIG)
		mask = big_cpumask;
	else if (tier == CORE_TIER_LITTLE)
		mask = little_cpumask;
	else
		mask = NULL;
	if (mask)
		bpf_cpumask_set_cpu(cpu, mask);
	bpf_rcu_read_unlock();

	return 0;
}

/*
 * Defined in dispatch.bpf.c and preempt.bpf.c. SCX_OPS_DEFINE() takes
 * the callbacks' addresses, so this unit needs the symbols; BPF_PROG()
 * defines them with exactly these signatures.
 */
void baby_dispatch(unsigned long long *ctx);
void baby_tick(unsigned long long *ctx);
s32 baby_select_cpu(unsigned long long *ctx);

SCX_OPS_DEFINE(baby_ops,
	       .select_cpu		= (void *)baby_select_cpu,
	       .enqueue			= (void *)baby_enqueue,
	       .dispatch		= (void *)baby_dispatch,
	       .tick			= (void *)baby_tick,
	       .running			= (void *)baby_running,
	       .runnable		= (void *)baby_runnable,
		       .stopping		= (void *)baby_stopping,
		       .yield			= (void *)baby_yield,
		       .cpu_release		= (void *)baby_cpu_release,
		       .init_task		= (void *)baby_init_task,
		       .init			= (void *)baby_init,
	       .exit			= (void *)baby_exit,
	       .timeout_ms		= 5000,
	       .name			= "baby");
