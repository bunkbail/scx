/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_baby: sched_ext port of the Baby Scheduler deadline variant (baby-dl)
 *
 * CPU performance scaling. This module owns the per-CPU performance
 * ledger: the utilization window, the smoothing, the hysteresis and
 * the request suppression that keeps the platform's iowait boost
 * latched. cpu_ctx and its map are private to the module; the
 * callbacks only report the lifecycle points of a CPU.
 */
#include "baby.bpf.h"

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored. -1 selects the automatic
 * utilization-driven level; -2 leaves the platform governor entirely
 * alone.
 */
const volatile s64 cpuperf_lvl;

/* True when the platform governor is left alone entirely. */
static bool cpuperf_offline(void)
{
	return cpuperf_lvl < -1;
}

/*
 * Thresholds for applying hysteresis to the CPU performance scaling:
 *  - below the low threshold, reduce performance to half
 *  - above the high threshold, raise performance to maximum
 *
 * Values between the two thresholds retain the smoothed performance level.
 */
#define CPUPERF_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUPERF_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 last_running;
	u64 tot_runtime;
	u64 prev_runtime;
	u64 perf_lvl;

	/*
	 * The performance level last requested from the platform.
	 * Redundant requests are suppressed: on an HWP platform every
	 * cpufreq update is also the hook that expires the intel_pstate
	 * iowait boost (it decays when an update arrives more than its
	 * hold time after the previous one), so a scheduler that writes
	 * the same level over and over keeps tearing down the boost its
	 * workload earned. Requesting a level only when it changed is
	 * what lets the boost latch for the duration of a burst.
	 */
	u64 perf_req;

	/*
	 * When this CPU last went idle. A long idle must not be averaged
	 * into the next window with the runtime charged before it: a
	 * 60-second sleep followed by a microsecond blip is not 100%
	 * utilization. A short idle keeps the pre-idle runtime, which is
	 * recent history and is why the window below is capped.
	 */
	u64 idle_since;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

static struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;

	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Update the CPU load and scale its target performance level accordingly,
 * using the utilization observed in the last window, smoothed and applied
 * with hysteresis. A caller that knows the CPU is about to be saturated
 * (@max_floor) skips the ramp: the utilization ledger reads near zero
 * across a brief sleep, and climbing back through the smoothing would
 * keep the core below its boost clock for the first windows of every
 * work chunk.
 */
static void update_cpuperf(struct cpu_ctx *cctx, s32 cpu, u64 now, bool max_floor)
{
	u64 perf_lvl, delta_runtime, delta_t;

	delta_t = now - cctx->last_running;
	if (delta_t) {
		/*
		 * The utilization window cannot predate the last few
		 * slices: runtime charged before a sleep is recent
		 * history, not a load spike to average away. Without the
		 * cap a wake after a short sleep divides that runtime by
		 * the whole sleep and the floor collapses, so a task
		 * that blocks between chunks never holds its boost clock.
		 */
		if (delta_t > 4 * deadline_ns)
			delta_t = 4 * deadline_ns;

		/*
		 * Evaluate the CPU utilization of the last window,
		 * normalized in the range [0 .. SCX_CPUPERF_ONE].
		 */
		delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
		perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t,
			       SCX_CPUPERF_ONE);
	} else {
		/*
		 * A run that opens a fresh window after a long idle has
		 * no elapsed time yet. Its utilization is zero, but the
		 * floor below must still be applied: the idle path just
		 * dropped the request to zero.
		 */
		perf_lvl = 0;
	}

	/*
	 * Smooth the target performance level, so that short spikes are
	 * absorbed while load variations still react quickly.
	 */
	cctx->perf_lvl = calc_avg(cctx->perf_lvl, perf_lvl);

	if (max_floor)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl >= CPUPERF_HIGH_THRESH)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl <= CPUPERF_LOW_THRESH)
		perf_lvl = SCX_CPUPERF_ONE / 4;
	else
		perf_lvl = cctx->perf_lvl;

	/*
	 * Request the level only when it changed. Beyond saving the
	 * write, the suppression keeps the platform's iowait boost
	 * latched; see the comment on perf_req.
	 */
	if (cctx->perf_req != perf_lvl) {
		scx_bpf_cpuperf_set(cpu, perf_lvl);
		cctx->perf_req = perf_lvl;
	}

	cctx->last_running = now;
	cctx->prev_runtime = cctx->tot_runtime;
}

/*
 * Initialize the CPU frequency performance level on all online CPUs.
 */
static void init_cpuperf_target(void)
{
	const struct cpumask *online_cpumask;
	u64 perf_lvl;
	s32 cpu;

	if (cpuperf_offline())
		return;

	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;

		if (cpuperf_lvl < 0)
			perf_lvl = SCX_CPUPERF_ONE;
		else
			perf_lvl = MIN(cpuperf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}
	scx_bpf_put_cpumask(online_cpumask);
}

__hidden void cpuperf_init(void)
{
	/* Initialize the CPU frequency performance level. */
	init_cpuperf_target();
}

/*
 * Advance the CPU runtime ledger and re-evaluate the performance floor
 * from it. The floor must not depend on ops.running() alone: a
 * never-descheduling task fires it once, the idle drop has set the
 * floor to zero, and nothing ever refreshes it - the core then sits at
 * its base clock for as long as the task runs. The tick advances the
 * ledger every tick, so sustained work boosts within a couple of ticks
 * and the ledger stays consistent with ops.stopping(), which charges
 * the time since the last advance.
 */
__hidden void cpuperf_on_tick(struct task_struct *p, u64 now, bool max_floor)
{
	if (cpuperf_lvl == -1) {
		struct cpu_ctx *cctx;
		s32 cpu = scx_bpf_task_cpu(p);

		cctx = try_lookup_cpu_ctx(cpu);
		if (cctx) {
			cctx->tot_runtime += now - cctx->last_running;
			update_cpuperf(cctx, cpu, now, max_floor);
		}
	}
}

/*
 * Scale the target CPU frequency before the task starts to run. A
 * proven consumer or a foreground task saturates the core for as long
 * as it runs, so give it the boost clock at once instead of
 * re-climbing the smoothing after every sleep (@max_floor).
 */
__hidden void cpuperf_on_running(s32 cpu, u64 now, bool max_floor)
{
	if (cpuperf_lvl == -1) {
		struct cpu_ctx *cctx;

		cctx = try_lookup_cpu_ctx(cpu);
		if (cctx) {
			/*
			 * A long idle ends the previous utilization window.
			 * Drop its runtime instead of charging it to the
			 * window that starts with this run; a short idle
			 * keeps it, and the cap in update_cpuperf() stops a
			 * brief sleep from diluting it.
			 */
			if (cctx->idle_since &&
			    now - cctx->idle_since > 4 * deadline_ns) {
				cctx->last_running = now;
				cctx->prev_runtime = cctx->tot_runtime;
			}
			cctx->idle_since = 0;
			update_cpuperf(cctx, cpu, now, max_floor);
		}
	}
}

/*
 * Charge the runtime the task just accumulated to the CPU ledger, so
 * the next window evaluates it, in every mode the module is active in.
 */
__hidden void cpuperf_on_stopping(s32 cpu, u64 now)
{
	if (cpuperf_lvl == -1) {
		struct cpu_ctx *cctx;

		cctx = try_lookup_cpu_ctx(cpu);
		if (cctx)
			cctx->tot_runtime += now - cctx->last_running;
	}
}

/*
 * The CPU is going idle: drop its performance level. The write happens
 * once, when the level changes; see the comment on perf_req.
 */
__hidden void cpuperf_on_idle(s32 cpu)
{
	if (cpuperf_lvl == -1) {
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);

		if (cctx) {
			cctx->idle_since = bpf_ktime_get_ns();
			if (cctx->perf_req) {
				scx_bpf_cpuperf_set(cpu, 0);
				cctx->perf_req = 0;
			}
		}
	}
}
