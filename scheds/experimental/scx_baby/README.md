# scx_baby

A [sched_ext](https://github.com/sched-ext/scx) port of the **Baby CPU
Scheduler, deadline variant** (baby-dl) by Hamad Al Marri, originally
written as a fair.c replacement against Linux 5.14
([Baby-CPU-Scheduler](https://github.com/hamadmarri/Baby-CPU-Scheduler),
`baby-dl-5.14.patch`).

## Design

Every runnable task owns a **deadline**, an absolute timestamp by which it
would like to run. The CPU always runs the task with the earliest deadline
it can reach:

- All tasks wait in one deadline-ordered queue per NUMA node (a BPF DSQ
  priority queue keyed by the deadline), mirroring the original global run
  list. The queue order IS the placement: an idle CPU pulls the
  earliest-deadline task from wherever it waits. Each CPU also owns a
  small warm queue for tasks continuing on it (below), bounded so a
  deeper backlog overflows into the node queue.
- Waking tasks are placed by the kernel's own idle-CPU selection
  (SMT-aware, previous-CPU biased, LLC-spread); a hit dispatches straight
  onto the CPU, skipping the queue. A task that stops on a fully loaded
  core scans again on its way back into the queue, which is how work
  spreads onto cores that went idle since.
- Once the machine is oversubscribed - the running lanes plus everything
  queued, shared or warm, exceed the CPU count - an arrival parks in the
  warm seat on the CPU it last ran on, right behind whatever runs there:
  its cache and TLB are still warm, and the CPU serves it at its next
  slice end. The seat balance seats the shallowest queue, with cache
  distance breaking ties, and arrivals queued under the gate grant a
  fourfold slice, since they will rotate anyway and every extra rotation
  costs a full switch. Below the threshold the seat stays open and the
  cold path runs, which is what keeps the wall's load distribution
  flowing.
- Dispatch serves the earliest deadline across the warm queue and the
  node queue, the warm side winning ties: it continues work this CPU has
  already paid the cache for. A running task keeps its CPU across a slice
  boundary only while its deadline still beats both heads; ties go to the
  waiter. Wakeup preemption fires only when the target CPU's warm queue
  is empty, and only for interactive or foreground wakers with an earlier
  deadline - trading places between rotation peers is a swap storm the
  queue order already serves.
- When the machine is saturated anyway - a waiter waits in a queue
  because every lane is busy - the tick cuts the holding task's slice
  short for a waiting latency-critical head. The victim requeues with
  its deadline intact, behind the waiter, in the deadline order it
  already prefers, and requeues on the base slice (it did not exhaust
  its quantum, so the deep-backlog rung is not its due). Gates: the
  victim is not itself latency-critical, so homogeneous batch workers
  never preempt each other; it has held the CPU for at least 200us; and
  one CPU at a time claims a shared-queue waiter, since the per-CPU
  ticks would otherwise all preempt for the same single waiter. This is
  what closed the 2x-overcommit gaming gap: without it, every frame of
  a game thread at full saturation paid a full slice of wake-to-run
  wait.
- A task's deadline is `now + deadline_ns + prio_factor[nice]`, with
  `deadline_ns` at 1.18ms and `prio_factor[]` shifting the deadline between
  -1.08ms (nice -20) and +1.26ms (nice +19), exactly as in the original.
- Tasks that voluntarily **sleep before consuming their deadline** are
  treated as interactive: they earn a permanent one-step boost of their
  effective nice level (down to -20), pulling their future deadlines
  earlier.
- A **burst tracker** accounts the runtime each task accumulates over a
  200ms window. A task whose bursts keep growing behind the previous window
  (a CPU hog) cannot preempt other tasks even when its deadline is earlier
  (`can_resched_curr()` carried over verbatim).

### Task classes

Ordering, slice length and preemption eligibility are driven by two
measured signals - the burst history and, inspired by scx_flash, a
wake-frequency EWMA (wakes per 100ms, tracked in `ops.runnable`) - never
by the boost counter, which on a desktop almost every task earns:

- **Latency-critical**: wakes frequently enough to prove it (at least 10
  wakes per 100ms across at least four samples), whatever its burst
  size - game render threads, compositors, submission workers; under
  CPU overcommit a game thread is heavy too, so no burst bound can gate
  this, and a task that never left runnable state never re-runs the
  EWMA, so a preempted batch task cannot pass as a waker. No placement
  and no slice role: this class gates the saturation tick preemption,
  on both sides - a latency-critical waiter triggers it, a
  latency-critical victim is shielded from it.
- **Interactive**: used less than a quarter of a CPU in its last window.
  UI blips and event loops. Eligible to preempt on wakeup.
- **Foreground**: wakes frequently and does real work. A browser renderer
  or an audio thread: too much CPU usage for the interactive class, but
  latency-bound all the same. Same preemption eligibility as interactive,
  plus a fourfold slice, since their requests are memory-bound and
  interleaving them with hog slices multiplies the wall time of each
  request.
- **Heavy** (everything else, including fresh tasks): a task whose recent
  windows used more than a quarter of the period is a *proven* consumer.
  It holds its CPU across slice boundaries through the sticky rule and
  ramps the CPU frequency to full at once.

The classes do not steer placement: on a single-tier machine the deadline
order places everything. The big/little sets the scheduler still publishes
are for the per-tier queues a hybrid platform needs.

### Fairness

Waking tasks keep the deadline they had when they went to sleep, so an
interactive task that wakes up runs before everyone else; migrated and
freshly created tasks are renormalized to a fresh deadline. A running task
is only replenished while its deadline beats the queue head, so a CPU hog
can never starve a waiting task. There is no cap on continuous runtime:
a task that keeps running renews its deadline every slice, and a waiting
task's deadline is older the longer it has waited, so the hog yields the
moment something waits.

### CPU frequency

Frequency is driven explicitly with `scx_bpf_cpuperf_set()` from the
per-CPU utilization, smoothed and applied with hysteresis, because
utilization-based frequency governors are blind under sched_ext. A core
going idle drops its performance level, so blippery cores (the
housekeeping CPU included) ramp down instead of holding a high floor.

### Real-time leases

A real-time or deadline task can lease a CPU away from the scheduler for
an unbounded time (some shipping configs run with `sched_rt_runtime_us`
unthrottled). Tasks already moved to the leased CPU's local queue would
wait out the lease where no other CPU can see them; `ops.cpu_release()`
pushes them back through enqueue the moment the lease ends, so they land
on an idle core or in the deadline order, where the machine can reach
them. A warm queue that outlived its CPU - stranded behind the lease, or
starved for over a second while affinity moved under it - is handed back
to the shared queue by the rescue timer, well before the kernel's
five-second watchdog could force-unload the scheduler.

### Measurement instruments

The `--stats` report decomposes the oversubscription wait: every arrival
is stamped with the depth it waits at and charged when it runs, split by
arrival type (wake handoff vs rotation requeue) and by class, plus a
census of the seat depth and shared backlog each lane sees at dispatch,
and the saturation-preemption counters (victims cut short at the tick,
split by where the waiter sat).
These counters are the readout the overcommit program reasons over; the
decision records under `docs/adr/` hold the verdicts they
produced.

## Mapping to sched_ext

| Original (5.14 sched class) | scx_baby |
| --- | --- |
| per-rq linked list, O(n) earliest-deadline scan (`pick_next_entity`) | one per-node DSQ priority queue ordered by deadline |
| `update_curr()` burst accounting and deadline renewal | `ops.stopping()` / `ops.tick()` |
| `hrtick_start_fair()` micro-preemption | slice-end comparison in `ops.dispatch()`: the running task continues only while its deadline beats the heads of the warm and node queues |
| `check_preempt_wakeup()` | deadline comparison against the previous CPU's current task, gated to an empty warm queue on that CPU; eligible wakers are placed ahead of the victim on its local queue |
| `yield_task_fair()` YIELD_MARK | `ops.yield()`: task is pushed behind everything queued in the current round |
| `select_task_rq_fair()` least-loaded CPU | `ops.select_cpu()`: the kernel's idle-CPU selection with direct dispatch |
| `newidle_balance()` / `trigger_load_balance()` (CPU0 scans all CPUs every tick and migrates one task, by count only) | deleted: idle CPUs pull the queue head; a task that stopped on a loaded core re-scans for a CPU that went idle; the warm-seat scan evens seat depth under the oversubscription gate, depth first with cache distance breaking ties |
| RT/DL lease stranding | `ops.cpu_release()`: locals requeued through enqueue when the lease ends; the rescue timer hands a starved warm queue back to the shared queue |
| warm-seat oversubscription queueing (absent in the original) | per-CPU warm queues under the oversubscription sum gate, shallowest-first with cache-distance tie-break, fourfold arrival slice |
| saturation service for latency-critical wakes (absent in the original) | `ops.tick()` cuts a batch victim's slice short when a wake-rate-classified latency-critical task waits at a queue head this CPU serves; the victim requeues on the base slice, behind the waiter |
| sleep-before-deadline `p->prio--` | per-task `boost` counter shifting the effective nice level, since sched_ext cannot change a task's static priority |
| wake-frequency interactivity (absent in the original) | wake-frequency EWMA from `ops.runnable`, in the spirit of scx_flash's `wakeup_freq` |
| 803 HZ / periodic tick / no dynticks kernel hacks | dropped: sched_ext does not need them |

## Options

- `-d, --deadline-us` : deadline offset (and time slice) in microseconds,
  default 1180 (the original DEADLINE_NS).
- `-p, --perf` : CPU frequency performance level, 0 (min) to 1024 (max),
  default -1 (automatic, scaled from each CPU's utilization).

## Building a static musl binary

On musl-based hosts (Chimera Linux for example) the scheduler is linked
statically:

```sh
rustup target add x86_64-unknown-linux-musl

# From a glibc build host, musl-gcc needs the kernel UAPI headers and argp
# (musl ships neither; install argp.h + libargp.a from argp-standalone into
# the musl include/lib trees):
sudo cp -r /usr/include/{asm,asm-generic,linux} /usr/lib/musl/include/

CC_x86_64_unknown_linux_musl=musl-gcc \
ac_cv_search_fts_close='none required' \
ac_cv_search_fts_open='none required' \
ac_cv_search__obstack_free='none required' \
ac_cv_search_obstack_free='none required' \
cargo build --release --target x86_64-unknown-linux-musl -p scx_baby \
    --features 'libbpf-sys/vendored-libelf libbpf-sys/vendored-zlib \
                libbpf-sys/static-libelf libbpf-sys/static-zlib'
```

The result is a static-pie binary that runs on any x86_64 Linux host.

## Example

```sh
scx_baby                 # run with defaults
scx_baby --stats 1       # print scheduling statistics every second
```
