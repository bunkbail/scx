# scx_baby

The project language for the scx_baby scheduler port and its benchmarking
program on the Arrow Lake laptop and the Ryzen 5600X gaming box. Each term
names the code that realizes it.

## Machine and rigs

**Trio**:
The three memory-bandwidth workloads where baby lost to stock on the 5600X
(stress-ng cpu-cache-mem, argon2, xz); the Phase 2 headline gate, run by
`target/threeway3.sh`.

**Rigs**:
The deterministic light/medium/saturation schbench profiles; every change
must pass them, not just benchmarks. (`target/ab5600.sh`, profiles map to
schbench -m/-t.)

**Saturation wall**:
The state where every logical CPU runs exactly one task - the trio's target
state.

**Lane**:
One logical CPU's slot in the saturation wall ("12-lane wall" on the
5600X).
_Avoid_: core (ambiguous between physical and logical)

**Spinner**:
A never-sleeping stress-ng CPU worker; the spinners ARE the overcommit,
producing only rotation requeues. (`target/oc2way-e11.sh`: 24 at 2x.)

**Probe**:
A schbench latency thread riding the wall; probe rps and request p99.9 are
the 2x scoreboard, and probes arrive as wake handoffs. (4 at 2x; probe
cycle ~= threads / rps.)

**Bistability law**:
On homes plus wake-homing only zero or full home redistribution worked;
every partial rate landed worse than either. The measured finding that
killed the gated-steal program (adr/0001).
_Avoid_: threshold effect

## Queue and placement

**Global pull**:
One shared deadline-ordered queue per NUMA node, drained by consumer CPUs,
so queue order IS placement. (The node DSQ; `scx_bpf_dsq_move_to_local()`
in main.bpf.c.)
_Avoid_: central queue, work stealing (it is not stealing)

**Dual lanes**:
The two queue paths dispatch arbitrates between: the bulk lane and
the fast lane, under one per-CPU dispatch quota. Not the CPU slots
of **Lane** above. (The `fl_*` DSQ helpers; `BABY_FL_QUOTA` in
main.bpf.c.)

**Bulk lane**:
The node queues and warm seats serving every class but
latency-critical; the lane the single-queue deadline design already
had.

**Fast lane**:
The latency-critical class's own queues, one id space over from the
bulk lane: a per-node queue beside every bulk node queue and a
per-CPU seat beside every warm seat, served first while the quota
allows. (`fl_cpu2dsq()`/`fl_node2dsq()` in baby.bpf.h.)
_Avoid_: Q1, mlfq (the queue-level naming of the deeper hierarchy
the design dropped; scx_mlfq is a different scheduler)

**Homing** (_retired_):
Assigning a task a specific CPU whose per-CPU queue it waits in; the
pre-Phase-2 topology adr/0001 replaced.
_Avoid_: pinning, placement

**Warm seat**:
The per-CPU warm queue an oversubscribed arrival parks in on the CPU it
last ran on, gated on machine-wide outstanding work. (`cpu2dsq()` warm
queue; `balance_try_warm_seat()` in balance.bpf.c.)

**Sum gate**:
The oversubscription discriminator: warm seats only when running lanes
plus all queued work (shared + warm) exceeds nr_cpus + 1. The sum is
conserved across running-to-queued transitions that race a bare
nr_running gate (the E5 lesson). (`nr_running + backlog + warm_total`
in balance.bpf.c.)

**Warm depth**:
The number of tasks already waiting in the warm queue an arrival lands
behind. (`target_nr` at stamping; `tctx->wait_depth`.)
_Avoid_: queue length, backlog (that is the shared queue)

**Warm / cold**:
A warm placement keeps cache and TLB state; a cold migration pays the
refill. (`nr_coldspreads` counts the cold spreads.)
_Avoid_: locality (overloaded)

**Distance rank**:
The per-pair ordering of two CPUs: same lane < SMT sibling < same L2 <
same LLC < same node < beyond. Pure order, no threshold. (`cpu_dist()`
over the `topo_*` tables in util.bpf.c.)
_Avoid_: distance metric, R_eff

**Tier ladder**:
The sibling/L2/LLC/node cache-membership structure behind the rank,
published from sysfs at startup - the portable locality structure.
(`Topo`/`topo_node..topo_core` in main.rs, arrays in util.bpf.c.)
_Avoid_: cache tiers, domains

**Compaction** (_retired_):
The old laptop policy of stacking desktop work on little cores while
reserving big cores; the big/little masks (`enable_core_class` syscall)
remain only for a future hybrid tier story.

**Sticky run**:
Continuing the same task across a slice boundary while its deadline still
beats the queue head; ties go to the waiter. (`nr_sticky`, the peek
compare in main.bpf.c's dispatch.)
_Avoid_: cache-warm run

**Strand**:
Runnable work stuck where nothing will run it - behind an RT/DL occupant
or in a queue nobody consumes. (The rescue timer, `rescue_timerfn()` in
main.bpf.c.)
_Avoid_: starvation (broader)

**Reenqueue**:
Pushing local-DSQ tasks back into the scheduler's queues when the CPU
returns from an RT/DL lease. (`ops.cpu_release` ->
`scx_bpf_reenqueue_local()`.)
_Avoid_: requeue (that is the slice-expiry re-entry below)

## Tasks and time

**Class**:
A task's interactive/foreground standing from measured burst history;
feeds slice length, deadline shift and preempt eligibility, not
placement. (`wait_cls` bits; `is_interactive()`/`is_foreground()` in
class.bpf.c.)
_Avoid_: priority, boost

**Proven**:
A task measured as consistently CPU-heavy across its burst history.
(`is_heavy_proven()`.)
_Avoid_: heavy (unqualified)

**Ordering key**:
The value the shared queue sorts by: baby's absolute deadline.
(`tctx->deadline`, `calc_deadline()` in class.bpf.c; renewed at
stopping/tick.)
_Avoid_: vtime (flash's relative clock, a different thing)

**Arrival slice**:
The slice an arrival receives when the sum gate parks it in a warm seat
or the shared queue, as opposed to the class slice on direct paths; 4x
the base at the gated sites since e13c.
_Avoid_: backlog slice, doubled slice (the pre-e13c value)

**Rotation round**:
One full pass of the backlog through the lanes at fixed oversubscription;
its length is depth times slice, and the 4x tail lives inside it.

**Wake handoff**:
An arrival re-entering from sleep - the request-response crossing whose
wait the 2x gap is about. (`SCX_ENQ_WAKEUP` -> `tctx->arrival_is_wake`;
waitwk stats line.)

## Instruments

**Wait-at-depth**:
Stamps each warm-seat or shared-queue arrival with its depth and charges
the realized wait to that bucket when the task runs. (`stamp_wait()`/
`charge_wait()`, `nr_wait_*` arrays in stats.bpf.c; waitot stats line.)
_Avoid_: wake latency (the whole wakeup path, not the seat wait)

**Arrival type**:
The split of every wait charge into wake handoffs vs rotation requeues
(slice expiry, preemption, reenqueue) - the two sides price differently.
(`nr_wait_type_*`, `nr_arr_type`; waitwk/waitrot stats lines; adr/0006.)
_Avoid_: wake bit (the mechanism, not the concept)

**Consumption census**:
Sampled at every dispatch: the seat depth and shared backlog a lane sees
when it picks work. (`census_sample()`, `nr_census_*`; census stats
line.)

**Wait-class split**:
The same charge filed under interactive/foreground class bits - measured
the 2x deep wait at 6.7% foreground, which killed fg-keyed designs.
(`nr_wait_cls_*`; waitfg/waitot lines; adr/0005.)
