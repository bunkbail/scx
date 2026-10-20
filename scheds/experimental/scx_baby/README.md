# scx_baby

A [sched_ext](https://github.com/sched-ext/scx) port of the **Baby CPU
Scheduler, deadline variant** (baby-dl) by Hamad Al Marri. The original
implements the policy as a `fair.c` replacement against Linux 5.14
([Baby-CPU-Scheduler](https://github.com/hamadmarri/Baby-CPU-Scheduler),
`baby-dl-5.14.patch`). This port keeps its scheduling model, an absolute
deadline per task with earliest-deadline-first dispatch, and rebuilds the
placement, classification and preemption machinery around sched_ext.

scx_baby targets desktop and gaming workloads: it protects tasks that wake
often to service a request while keeping CPU-bound work moving. It handles
`SCHED_NORMAL`, `SCHED_BATCH` and `SCHED_IDLE` tasks; real-time and deadline
tasks stay in their own kernel classes.

## Overview

Every runnable task owns a deadline, an absolute timestamp by which it
would like to run, and each CPU runs the task with the earliest deadline it
can reach. A deadline is renewed when it is reached, and a task that sleeps
before consuming it is treated as interactive and earns a nice boost that
pulls its future deadlines earlier.

The scheduler has two lanes. The bulk lane carries every class except
latency-critical work: one deadline-ordered queue per NUMA node, plus a
per-CPU warm seat that parks an arrival on the CPU it last ran on while the
machine is oversubscribed. The fast lane carries tasks classified
latency-critical by wake rate, in a queue pair beside the bulk one, so a
game thread's wake never waits behind a batch slice. Dispatch arbitrates
the lanes with a per-CPU time budget so neither starves.

Task classes are measured, not declared. A task's runtime history and its
wake frequency set its slice length, its wake-preemption eligibility and
its lane.

## Design

### Deadline and time slice

Every task owns a deadline, and a CPU always runs the earliest one it can
reach. A deadline is `now + nice_offset`, with the base offset at 1.18ms.
The original nice table is rescaled to the configured offset, so a nice
-20 deadline sits at about 8.5 percent of the base and a nice +19 one at
about 2.07 times it, and every offset stays in the future at the smallest
accepted `-d`.

A task that sleeps before consuming its deadline and is a `SCHED_NORMAL`
task is treated as interactive: it earns a cumulative one-step boost of
its effective nice level, floored at -20, which pulls its future deadlines
earlier. `SCHED_IDLE` and `SCHED_BATCH` tasks keep their requested lower
share.

The deadline is also the base time slice. A foreground task gets four times
the base slice, and an arrival that faces a deep backlog gets the same
fourfold slice, since it will rotate anyway and every rotation costs a
switch. `-d` changes the base offset.

### Queueing and placement

The bulk lane holds one deadline-ordered DSQ per NUMA node, mirroring the
original's global run list: an idle CPU pulls the earliest-deadline task
from wherever it waits, so queue order is the placement. Each CPU also owns
a small warm queue for tasks continuing on it. The latency-critical class
uses the fast-lane queue pair instead (see below).

On a single-tier machine, a waking task is placed by the kernel's idle-CPU
selection, which is SMT-aware, biased to the previous CPU and spreads
across LLCs. A pick that finds an idle CPU dispatches straight onto it.
`SCX_WAKE_SYNC` is ignored: a waker that keeps running after the wake
would otherwise stack the wakee behind it while other CPUs idle. A task
that stops on a loaded core scans again for an idle CPU on its way back
into a queue.

Once the machine is oversubscribed, meaning the running lanes plus
everything queued, shared or warm, exceed the CPU count, an arrival parks
in the warm seat on the CPU it last ran on, right behind whatever runs
there. Its cache and TLB are still warm, and the CPU serves it at its next
slice end. A waking arrival moves to the shallowest seat, with cache
distance breaking ties; other requeues stay on their own CPU's seat. Below
the threshold the seat stays open and the cold path runs, which keeps the
load distribution flowing at saturation.

The gate matters at full saturation. With every CPU running exactly one
task, an open warm seat would freeze whatever lane skew exists: overloaded
lanes would rotate internally while CPUs whose task blocked would starve.
The machine-wide sum is used rather than `nr_running` alone because the sum
is conserved across the running-to-queued transitions that race the bare
counter. The two lanes are counted separately: each lane's clause uses that
lane's shared backlog and seat depths, so fast-lane work cannot open a bulk
seat and bulk work cannot open a fast-lane one.

### Dispatch and preemption

Dispatch serves the earliest deadline across the warm queue and the node
queue of the lane being served, with the warm side winning ties. A running
task keeps its CPU across a slice boundary only while its deadline still
beats the head that would run next; ties go to the waiter. A task that
yields gives up the rest of its round and requeues behind the tasks
queued in its lane.

Wakeup preemption fires only when the target CPU has no warm backlog and
only for interactive or foreground wakers with an earlier deadline than the
running task. A preemption into a deep queue would only trade places with
work that is about to run anyway. It also needs the running task to pass
the original burst tracker's `can_resched()`, which protects a task only
inside the window between its previous burst minus the 5ms completion slack
and that previous burst; a proven CPU hog is always reschedulable. A
latency-critical victim is shielded outright. The wakee is placed ahead of
the victim on the victim's local queue.

At saturation, a latency-critical waiter would otherwise wait a full slice
behind a batch task. The tick cuts the holding task's slice short under
these gates:

- the waiter is latency-critical and sits at a head this CPU serves, its
  own warm seat or the shared queue;
- the victim is not itself latency-critical, so homogeneous batch workers
  never preempt each other;
- the victim has held the CPU for at least 200us, so a task that just got
  the CPU keeps it;
- for a shared-queue waiter, one CPU at a time claims it, since the
  synchronized per-CPU ticks would otherwise all preempt for the same
  waiter. Warm-seat waiters are per-CPU precise and need no claim.

The victim requeues with its deadline intact, behind the waiter, on the
base slice rather than the deep-backlog rung it did not earn.

### Task classes

Classes are driven by two runtime signals, never by the boost counter: a
task's runtime history over 200ms windows, and a wake-frequency EWMA in
wakes per 100ms sampled in `ops.runnable()` on true sleep-to-wake
transitions. Fork activation and affinity or priority changes are not
wakes and do not sample the average.

The wake-rate signal is a peak hold. The EWMA is blended 50/50 over the
first four samples and 3:1 after that, both rounding up so a rate at the
class bar (5) can actually reach it. The peak is armed only after four
completed samples, so a fork interval or a single startup spike cannot
latch it. Once armed the hold decays only above 64 wakes per 100ms,
while the class bar sits at 5. A task that has once earned a wake rate
keeps its class for its lifetime. A real decay would strip the class
from a frame-paced game thread the moment CPU overcommit throttles its
frame rate, which is the state the credit exists for.

- **Latency-critical**: a smoothed wake rate of at least 5 wakes per
  100ms (50Hz) sustained for four samples, whatever its burst size. A
  60Hz frame thread and a 59Hz request probe wake about every 17ms, and
  the integer rate of that interval is 5. Game render threads,
  compositors and submission workers qualify; under overcommit a game
  thread is heavy too, so no burst bound can gate this. A task that
  never leaves runnable state never re-runs the EWMA, so a preempted batch
  task cannot pass as a waker. The class waits in the fast lane and gates
  saturation preemption on both sides: a latency-critical waiter triggers
  it, and a latency-critical victim is shielded from it.
- **Interactive**: used some CPU in its previous window but less than a
  quarter of one, and has not crossed the same bar in its current window.
  UI blips and event loops. Eligible to preempt on wakeup.
- **Foreground**: clears the same 5-wake bar and does real work, more
  than one twentieth of the window. A browser renderer or an audio
  thread: too much CPU for the interactive class, but latency-bound all
  the same. Eligible to preempt on wakeup and granted the fourfold slice.
  There is no upper burst bound: a heavy waker that also does real work
  stays foreground, so the hybrid compaction still lets foreground beat
  the heavy pin. Every foreground task is also latency-critical;
  foreground adds the runtime floor and the fourfold slice.
- **Heavy**: everything else, including fresh tasks. A task that used more
  than a quarter of the window is a proven consumer. It holds its CPU
  across slice boundaries through the sticky rule and asks for the boost
  clock immediately. On a hybrid platform a proven consumer with no wake
  history also pins a big core.

### Dual lanes

The latency-critical class does not wait in the bulk queues. It gets a
per-node fast-lane queue beside every bulk node queue and a per-CPU
fast-lane seat beside every warm seat, so a game thread's wake never sits
behind a batch slice. This is a two-lane split rather than a deeper
hierarchy: the bulk lane keeps the deadline order, and no bulk class asks
for a different one.

Dispatch arbitrates the lanes with a per-CPU time budget. The bucket
accrues two thirds of wall time as fast-lane credit and holds at most four
base slices; a fast-lane service spends the slice it is granted, so bulk
keeps at least a third of every contended CPU however long the fast-lane
slices are, and the fast lane still empties instantly when bulk is idle.
Wake-path preempts charge the bucket when they hand the CPU over; tick
preempts are charged by the dispatch that follows them. A task that sleeps
early still spends its grant, so the bucket can under-serve the fast lane
but never over-serve it.

The oversubscription gates are per lane, keyed on state the queues cannot
express. A per-CPU `cpu_is_lat[]` array, stamped in `ops.running()` and
cleared in `ops.stopping()`, records whether a CPU's resident is
latency-critical. The bulk clause is the single-lane gate: running lanes,
the bulk lane's shared backlog and bulk warm seats, plus a latency-critical
arrival's own seat depth, against the CPU count plus one. The fast-lane
clause opens warm seats when the fast lane itself is oversubscribed:
latency-critical residents plus the fast lane's shared backlog plus
fast-lane warm seats past the same bound. An arrival is seated when either clause holds. Queue depth alone
cannot say whether a CPU runs a cuttable bulk resident: at full saturation
the CPU-bound workers never queue, so bulk depth reads zero exactly where
bulk residency is total.

The same residency array filters the tick preemption's relocation scan:
below a two-deep seat, a latency-critical wake relocates only onto a CPU
running cuttable bulk, since a relocation onto another latency-critical
resident is a pure migration. Two slice rules stay lane-specific: the
warm-seat depth rung is bulk-only, because a non-foreground
latency-critical arrival granted the fourfold slice becomes a long resident
that no preemption path can cut, and the shared-node rung drops its lane
condition because foreground tasks already earn the fourfold slice in
`task_slice()`.

### Hybrid placement

Below saturation (`nr_running` within two of the little-core count), the
scheduler packs wakeups onto the little tier before the kernel's idle-CPU
selection runs. A wholly idle physical core is preferred, and the previous
CPU when it is in the tier, so the rest of the tier idles at its boost
floor without cold migrations. Foreground, interactive and other light
tasks stack there. A proven consumer with no wake history pins a big core;
a proven consumer that is also foreground starts on the little tier and
falls back to a big core when it is full. The gates are statically false on
a single-tier machine, where the little mask is empty.

The tiers come from the kernel's per-CPU capacity: big is every CPU at or
above 85 percent of the top capacity, little is the rest, and a core below
both half of the little tier's top and a third of the machine's top is an
LP island and joins neither. A core-type fallback corroborated by the
clock spread covers platforms without capacity files.

The kernel's idle-CPU selector is restricted to the non-LP mask while the
tier masks are present: `scx_bpf_select_cpu_and()` clears the chosen CPU's
idle bit and there is no helper that restores it, so an LP core picked and
then abandoned would stay marked busy for good. The LP cores remain
reachable through the full task mask when no non-LP CPU is idle, and that
pick is used.

### Fairness

Waking tasks keep the deadline they had when they went to sleep, so an
interactive task runs before everyone else on wakeup. Migrated and freshly
created tasks are renormalized to a fresh deadline; a task pushed back by a
CPU release keeps its deadline. A running task's deadline is renewed only
when it is reached, and a waiting task's deadline is older the longer it
has waited. There is no cap on continuous runtime: a task that keeps
running renews its deadline every slice and yields the moment a waiter's
deadline is earlier.

### CPU frequency

Frequency is driven with `scx_bpf_cpuperf_set()` from each CPU's
utilization, smoothed and applied with hysteresis, because
utilization-based frequency governors are blind under sched_ext. A proven
consumer or foreground task gets the boost clock immediately when it starts
running. A core that goes idle drops its performance level, so blippery
cores, the housekeeping CPU included, ramp down instead of holding a high
floor. `-p` overrides the level; `-p -2` leaves the platform's cpufreq
setup alone.

### RT and deadline leases

A real-time or deadline task can lease a CPU away from the scheduler for an
unbounded time; some configurations run with `sched_rt_runtime_us`
unthrottled. Tasks already moved to the leased CPU's local queue would wait
out the lease where no other CPU can see them. `ops.cpu_release()` pushes
them back through enqueue when the lease ends, so they land on an idle core
or in the deadline order.

A queue can also outlive its CPU, stranded behind a lease or starved while
affinity moved under it. The rescue timer re-enqueues a queue that has held
work for more than a second without a successful pull, well before the
kernel's five-second watchdog could force-unload the scheduler. It covers
both lanes, every per-CPU seat and every node queue.

### Measurement instruments

The `--stats` report decomposes oversubscription wait. Every arrival is
stamped with the depth it waits at and charged when it runs, split by
arrival type (wake handoff or rotation requeue), by class and by the reason
the wake gate missed. A dispatch census records the seat depth and shared
backlog each lane sees, a class and lane census counts every run start, and
the saturation preemption counters split victims by where the waiter sat.
The BPF maxima are reset after each snapshot, so a reported maximum belongs
to its interval. The counters are diagnostic and do not feed the scheduling
policy.

## Mapping to the original scheduler

| Original (5.14 sched class) | scx_baby |
| --- | --- |
| per-rq linked list, O(n) earliest-deadline scan (`pick_next_entity`) | per-node deadline-ordered DSQs: the bulk node queue, plus the fast-lane pair for the latency-critical class |
| `update_curr()` burst accounting and deadline renewal | `ops.stopping()` / `ops.tick()` |
| `hrtick_start_fair()` micro-preemption | slice-end comparison in `ops.dispatch()`: the running task continues only while its deadline beats the head that would run next |
| `check_preempt_wakeup()` | deadline comparison against the previous CPU's current task, gated on an empty warm queue and an interactive or foreground waker; the wakee is placed ahead of the victim on its local queue |
| `yield_task_fair()` YIELD_MARK | `ops.yield()`: the task is pushed behind the tasks queued in its lane in the current round |
| `select_task_rq_fair()` least-loaded CPU | `ops.select_cpu()`: the kernel's idle-CPU selection with direct dispatch |
| `newidle_balance()` / `trigger_load_balance()` (CPU0 scans all CPUs every tick and migrates one task, by count only) | deleted: idle CPUs pull the queue head; a task that stopped on a loaded core re-scans for an idle CPU; the warm-seat scan evens seat depth under the oversubscription gate, depth first with cache distance breaking ties |
| RT/DL lease stranding | `ops.cpu_release()` requeues local tasks through enqueue; the rescue timer re-enqueues a starved warm queue |
| warm-seat oversubscription queueing (absent in the original) | per-CPU warm queues under the machine-wide sum gate, shallowest-first with cache-distance tie-break, fourfold arrival slice on a deep backlog |
| saturation service for latency-critical wakes (absent in the original) | `ops.tick()` cuts a batch victim's slice short when a latency-critical task waits at a head this CPU serves; the victim requeues on the base slice behind the waiter |
| sleep-before-deadline `p->prio--` | per-task `boost` counter shifting the effective nice level, since sched_ext cannot change a task's static priority |
| wake-frequency interactivity (absent in the original) | wake-rate EWMA from `ops.runnable()` and its peak hold |
| latency-critical wakes queuing behind batch slices (absent in the original) | fast-lane queue pair with a per-CPU time-budget arbitration and per-lane oversubscription gates keyed on `cpu_is_lat[]` residency |
| hybrid light-work compaction (absent in the original) | `ops.select_cpu()`: below saturation, class-ordered packing onto the little tier, with a big-core pin for proven consumers |
| 803 HZ / periodic tick / no dynticks kernel hacks | dropped: sched_ext does not need them |

## Options

- `-d, --deadline-us <US>`: deadline offset and base time slice in
  microseconds, default 1180 (the original `DEADLINE_NS`), accepted range
  100 to 100000. Above 10000 the tick is the only preemption source for a
  full slice; the scheduler warns.
- `-p, --perf <LEVEL>`: CPU frequency performance level, -2 to 1024. Level
  0 is the minimum and 1024 the maximum. The default -1 scales each CPU's
  level from its utilization; -2 leaves the platform's cpufreq setup
  alone.
- `--stats <SECS>`: enable the stats report and run normally.
- `--monitor <SECS>`: run in stats monitoring mode without launching the
  scheduler.
- `-D, --debug`: enable BPF debugging via
  `/sys/kernel/tracing/trace_pipe`.
- `-v, --verbose`: verbose output, including libbpf details.
- `--help-stats`: show descriptions for the statistics.
- `--exit-dump-len <LEN>`: exit debug dump buffer length, 0 for the
  default.
- `-V, --version`: print the scheduler version and exit.

## Requirements

- A kernel with sched_ext support. The [root README](../../../README.md)
  covers the required kernel configuration and build dependencies.
- Linux 7.1 or newer for the warm-queue rescue, which uses
  `scx_bpf_dsq_reenq()`. On older kernels the rescue is probe-gated off,
  and a warm queue stranded behind an RT or deadline lease is recovered
  only when the kernel watchdog unloads the scheduler. The remaining
  helpers have older fallbacks built in.
- At most 128 CPUs. The BPF state is sized for that, and the loader refuses
  larger machines.

## Building

```shell
$ cargo build --release -p scx_baby
```

The binary lands in `target/release/scx_baby`.

## Example

```sh
scx_baby                  # run with defaults
scx_baby -d 500           # 500us deadline and base slice
scx_baby --stats 1        # print scheduling statistics every second
```

## Production Ready?

Yes. Topology detection and the placement paths are generic, so scx_baby
should perform well on most machines. It has mostly been tested on a
Zen 3 desktop and an Arrow Lake laptop, and its policy constants are
tuned for those systems.
