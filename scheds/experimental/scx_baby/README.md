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

- Each CPU owns a deadline-ordered queue (a BPF DSQ priority queue keyed by
  the deadline), mirroring the original per-CPU run lists. Dispatch takes
  the earliest deadline from the CPU's own queue; an idle CPU pulls from
  the most-loaded queue that can spare a task, like the original
  newidle_balance().
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
- Waking tasks keep the deadline they had when they went to sleep, so an
  interactive task that wakes up runs before everyone else; migrated and
  freshly created tasks are renormalized to a fresh deadline. An eligible
  waker (earlier deadline, no lower priority) is placed directly in front
  of the task running on its target CPU and preempts it, like the original
  check_preempt_wakeup().

## Mapping to sched_ext

| Original (5.14 sched class) | scx_baby |
| --- | --- |
| per-rq linked list, O(n) earliest-deadline scan (`pick_next_entity`) | per-CPU DSQ priority queues ordered by deadline |
| `update_curr()` burst accounting and deadline renewal | `ops.stopping()` / `ops.tick()` |
| `hrtick_start_fair()` micro-preemption | time slice = deadline offset, plus preemption kicks from `ops.tick()` and `ops.enqueue()` |
| `check_preempt_wakeup()` | deadline comparison against the target CPU's current task; eligible wakers are placed ahead of the victim on the CPU's local queue |
| `yield_task_fair()` YIELD_MARK | `ops.yield()`: task is pushed behind everything queued in the current round |
| `select_task_rq_fair()` least-loaded CPU | `ops.select_cpu()` with the built-in idle-CPU selection and direct dispatch |
| `newidle_balance()` / `trigger_load_balance()` | idle CPUs pull from the most-loaded per-CPU queue |
| sleep-before-deadline `p->prio--` | per-task `boost` counter shifting the effective nice level, since sched_ext cannot change a task's static priority |
| 803 HZ / periodic tick / no dynticks kernel hacks | dropped: sched_ext does not need them |

## Options

- `-d, --deadline-us` : deadline offset (and time slice) in microseconds,
  default 1180 (the original DEADLINE_NS).

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
