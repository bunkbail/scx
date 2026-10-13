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
  earliest-deadline task from wherever it waits, and nothing is ever
  stolen from a busy core or pushed onto one.
- Waking tasks are placed by the kernel's own idle-CPU selection
  (SMT-aware, previous-CPU biased, LLC-spread); a hit dispatches straight
  onto the CPU, skipping the queue. A task that stops on a fully loaded
  core scans again on its way back into the queue, which is how work
  spreads onto cores that went idle since.
- A running task keeps its CPU across a slice boundary only while its
  deadline still beats the head of the queue; ties go to the waiter.
  Once every logical CPU is busy, wakeup preemption backs off - trading
  places between rotation peers is a swap storm the queue order already
  serves.
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
them.

## Mapping to sched_ext

| Original (5.14 sched class) | scx_baby |
| --- | --- |
| per-rq linked list, O(n) earliest-deadline scan (`pick_next_entity`) | one per-node DSQ priority queue ordered by deadline |
| `update_curr()` burst accounting and deadline renewal | `ops.stopping()` / `ops.tick()` |
| `hrtick_start_fair()` micro-preemption | slice-end comparison in `ops.dispatch()`: the running task continues only while its deadline beats the queue head |
| `check_preempt_wakeup()` | deadline comparison against the previous CPU's current task while the machine has idle lanes; eligible wakers are placed ahead of the victim on its local queue |
| `yield_task_fair()` YIELD_MARK | `ops.yield()`: task is pushed behind everything queued in the current round |
| `select_task_rq_fair()` least-loaded CPU | `ops.select_cpu()`: the kernel's idle-CPU selection with direct dispatch |
| `newidle_balance()` / `trigger_load_balance()` | idle CPUs pull the queue head; a task that stopped on a loaded core re-scans for a CPU that went idle |
| RT/DL lease stranding | `ops.cpu_release()`: locals requeued through enqueue when the lease ends |
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
