# AGENTS.md

Instructions for AI agents working on scx_baby, the experimental sched_ext
port of the baby-dl deadline scheduler. The root /AGENTS.md governs commits,
patch descriptions and the general build; this file covers what is specific
to this crate.

## BPF module map

The BPF program is split across modules linked into one object. Every
module includes only "baby.bpf.h", the shared interface. Project
language and decision records live in target/design/ (GLOSSARY.md,
adr/); read an ADR when touching the module it is attached to below.

- `baby.bpf.h`: the interface hub. task_ctx, the DSQ layout, constants,
  extern declarations of the shared tunables and counters (the topo
  tables, deadline_ns, debug and every nr_* counter), pure inline helpers
  (cpu2dsq, backlog_deep, is_queued, is_pcpu_task, reached_deadline,
  calc_avg) and the cross-module prototypes.
- `main.bpf.c`: the ops callbacks, SCX_OPS_DEFINE, the license, DSQ
  creation, the starve-rescue timer, the big/little cpumasks and the
  enable_core_class syscall. Queue-topology or preemption work reads
  adr/0001 (why homes died) and adr/0003 (the depth-0 gate) first.
- `util.bpf.c`: task_ctx_stor and its lookups (try_lookup_task_ctx,
  init_task_ctx), the topo tables and cpu_dist(), UEI_DEFINE, nr_cpu_ids.
- `stats.bpf.c`: every volatile counter, stamp_wait(), charge_wait() and
  census_sample(). The counters are read by userspace through the
  skeleton, so their names and shapes are part of the interface with
  src/stats.rs. adr/0006 defines the arrival-type instrument and the
  census these counters serve.
- `class.bpf.c`: bursts, the wake-frequency EWMA, the class predicates
  (is_interactive, is_heavy_proven, is_foreground), task_slice(), the
  deadline math (prio_factor, task_nice, calc_deadline) and the
  boost-on-sleep award. adr/0004 and adr/0005 are the measured dead
  ends here - slice length and wake-rate ordering; do not re-try them.
- `idle.bpf.c`: pick_idle_cpu() and try_direct_dispatch().
- `power.bpf.c`: CPU performance scaling. cpu_ctx, its map and
  cpuperf_lvl are private to this module; the ops callbacks only report
  lifecycle points (cpuperf_on_tick/running/stopping/idle/init).
- `balance.bpf.c`: balance_try_warm_seat(), the warm-seat balance under
  oversubscription, including the sum gate and the seat scan. adr/0002
  binds the scan: depth dominates, distance only breaks ties.

## BPF module conventions

- One definition per map and global. A SEC(".maps") definition cannot be
  extern-declared, so a map is reached from another module only through
  functions defined in the module that owns it.
- Cross-module functions are __hidden globals with prototypes in
  baby.bpf.h. The hidden visibility makes clang emit their BTF FUNC
  entries as static, so the verifier inlines them at load. A plain
  global function instead faces the kernel's global-function ABI
  checks, which reject pointer returns and mis-verify trusted
  task_struct arguments (observed on the 5600X's 7.2.9 kernel).
  Defense in depth on top: the BPF calling convention passes arguments
  in R1-R5, so a cross-module call still takes at most 5 arguments;
  pack wider state into a context struct instead.
- The ops callbacks stay in main.bpf.c and delegate to the modules; a
  module never defines a BPF_STRUCT_OPS callback.
- intf.h is the bindgen-facing header (src/bpf_intf.rs is generated from
  it). Keep scheduler logic out of it; it stays limited to types and
  constants shared with src/main.rs, such as core_arg.

## Build constraints

- build.rs must end with .compile_link_gen(), not .build(). The build()
  path compiles only the enable_skel file and silently ignores every
  add_source module.
- Each module .c includes only "baby.bpf.h". Including "intf.h" before
  it breaks the build: intf.h defines the u8-u64 typedefs unless
  __VMLINUX_H__ is set, and common.bpf.h (pulled in by the hub) then
  redefines them from vmlinux.h.

## Verifier cliffs

Three patterns in this tree exist because the verifier needed them.
Preserve them when editing nearby code.

- The warm-seat scan computes cpu_dist(prev, i) once per iteration into
  a variable; a re-evaluation on both arms of the three-way compare
  branches the verifier's exploration and blew the jump-complexity
  limit (observed 8193-jump blowup). The note lives in balance.bpf.c.
- Instrument bucket indices are clamped where they are stamped and
  masked again where they are charged; a reloaded u8 proves nothing to
  the verifier on its own.
- scx_bpf_dsq_nr_queued() fails verification inside an RCU read-side
  section; probe it outside any (see node_backlog() in main.bpf.c).
- ops.stopping() cannot insert into DSQs (EACCES), and SCX_DSQ_LOCAL is
  not iterable.
- SCX_ENQ_LAST is delivered to ops.enqueue on these kernels; an early
  note claimed the opposite and was wrong.
