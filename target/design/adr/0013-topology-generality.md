# ADR 0013: topology generality - the fake-tier guard and the classifier tests

Date: 2026-10-17. Status: adopted. Round: argon arbiter round 10,
preceded by a three-scheduler survey (lavd, flash, cake) and an audit
of baby's own topology surface. Commits c786bbceb (classifier guard,
tests, table fixes) and e79c8e655 (clippy row-index fix).

## The question

Round 9 closed the performance frontier and froze four invariants.
The user then asked whether scx_baby is feature-complete for CPU
topologies beyond its two evidence machines, and whether the
machinery of the feature-complete schedulers (lavd, flash, cake)
should be replicated. Upstream-readiness is the stated goal.

The audit of baby's own surface came first: detection is generic
(sysfs topology tables, kernel-delegated idle picks, capacity-based
tiers whose hybrid gates are statically false on homogeneous
machines), but three things did not generalize. The 128-CPU cap
silently aliased per-CPU state through the &127 masks, the distance
tables were indexed by enumeration position so an offline CPU
shifted every later entry, and the tuned constants are two-machine
evidence. The user accepts the 128 cap for the fleet ("baby will
never be tested on a 128 cpu"); for upstream the aliasing became a
refusal and the indexing became id-based.

## The survey

- lavd carries the heaviest machinery: per-cpdom DSQs (node + LLC +
  core type), a neighbor graph with distance-ordered stealing and
  capacity-share migration margins, energy-model core compaction,
  anti-SMT via SCX_PICK_IDLE_CORE and SMT-primary DSQ collapse. Hard
  limits: 640 CPUs (arena lib), 128 cpdoms, >2-way SMT silently
  breaks, NUMA distances read but then treated uniform.
- flash is the thinnest and structurally the closest to baby:
  per-node DSQs, one primary mask, kernel-delegated picks, and one
  mechanism baby lacked - an is_smt_contended() check on the
  rotation path. Its big/little tier only shapes the initial mask,
  and it acknowledges the fake-tier risk of the shared ladder.
- cake is the discipline exemplar: everything measured at attach
  into rodata so the verifier prunes inapplicable arms, explicit
  degradation tiers past 64 CPUs, and a regression suite that loads
  ten synthetic topologies (up to 1024 CPUs) through the verifier.
- Shared substrate: all of them read scx_utils's capacity ladder
  (amd_pstate_prefcore_ranking > amd_pstate_highest_perf >
  acpi_cppc/highest_perf > cpu_capacity > cpuinfo_max_freq,
  normalized to 1024, has_biglittle = max >= 1.3*min). KEY NUMBER:
  the laptop's E/P raw capacity ratio is 0.771 (spread 1.297), which
  sits UNDER the 1.3x bar - the shared heuristic would misclassify
  this exact machine as homogeneous. Baby's 85 percent raw bar
  catches the split; the ladder must never replace it.

## The argon round 10 verdict

Baby's BPF hot path is topology-feature-complete for its realistic
envelope (consumer parts, <=128 CPUs); do not touch .bpf.c. Grades:

- (a) classification robustness: PROBE. The CoreType fallback is a
  LIVE fake-tier bug on homogeneous Zen4/5/X3D desktops: prefcore
  ranking spreads >=1.3x across identical cores pass has_biglittle,
  and the hybrid gates engage inversely - light wakes stack onto
  lower-ranked same-speed cores, preferred cores gated behind
  big_pin. The 5600X escapes only because its ranking spread lands
  under the bar.
- (b) flash-style anti-SMT-stacking on the seat path: REJECT. At 2x
  on 12 SMT CPUs the idle mask is empty, so the predicate is
  identically false exactly where a loss was hypothesized, and the
  checks would live on the E2BIG-frozen enqueue path.
- (c) cake-style degradation tests: PROBE, repo-only.
- (d) lavd-style per-cpdom queues and migration margins: REJECT.
  Violates the frozen invariants (node queue, warm seats,
  lowest-ID scan, enqueue freeze); no observed cross-CCD loss (the
  kernel wake pick preserves LLC locality, the warm-seat ladder and
  depth-1 node pulls cover the rest).
- (e) deep-idle/IRQ avoidance: REJECT. Deep-idle avoidance directly
  contradicts the compaction, whose lowest-ID little-stack packing
  exists to leave higher cores in package C-states.

## The fix (userspace only, zero .bpf.c edits)

- tiers.rs: classification is a pure function over (capacity,
  core type, max frequency) inputs. The capacity branch is
  byte-equivalent to the old code. The core-type fallback keeps a
  claimed split only when the per-CPU cpuinfo_max_freq spread also
  clears the 85 percent bar (homogeneous AMD prefcore parts sit
  under 8 percent; real hybrids separate P from E clocks by 20
  percent or more); an uncorroborated split collapses to one tier
  and the hybrid gates stay statically false.
- The distance tables are indexed by CPU id, and hosts wider than
  the tables are refused at init with a clear error instead of
  aliasing per-CPU residency and skip-pid state.
- Tests: nine fixture shapes (laptop hybrid, 5600X homogeneous, the
  fake Zen4/5 shape, the corroborated old-kernel hybrid, the strict
  boundaries of both bars, partial capacity, only-little), a
  live-host consistency test that partitions the real CPUs and
  checks the branch invariants, and an ignore-gated verifier load
  test over synthetic rodata (1/14/128 CPU shapes) for privileged
  runners.

## The gates

- cargo test -p scx_baby: 10 passed (the verifier test ignored),
  clippy clean, fmt clean, full workspace build green.
- The verifier load test cannot run in the dev container (BPF
  blocked, -EPERM) by design; it is for a privileged runner.
- Smoke attach on the laptop (the only machine whose branch the fix
  can change): the banner reads "core classes (Capacity):
  big=[0, 1, 2, 3] little=[4, 5, 6, 7, 8, 9, 10, 11] lp=[12, 13]" -
  identical to the deployed behavior, now with the deciding branch
  named. The 5600X is covered by construction: its all-big fallback
  path is untouched (ADR 0012's banner big=[0-11] little=[] remains
  the behavior), so no benchmark rounds were run and argon's STOP
  fired as specified.

## Consequences

1. The classifier is pinned by tests; any future tier change must
   update the fixtures and re-justify both bars (85 percent
   capacity/frequency, 2x LP).
2. The open upstream item is a privileged, wide verifier-load CI
   runner (cake's pattern); baby's loops are bounded by the host
   CPU count, so loop-width coverage needs a real wide machine.
3. Hygiene for the upstream series: agent-tooling state (.zcode/,
   .zcodeignore, skills-lock.json) is locally excluded via
   .git/info/exclude and never enters commits; the stray
   .zcode/workflow-runs journal that landed in the crate's bpf/
   directory was removed.
