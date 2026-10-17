# Adopt flash-style global pull queues for scx_baby (Phase 2)

The age-gated-steal program ended in a measured bistability law: on baby's
per-CPU DSQ plus lowest-idle wake-homing architecture, only zero or full
home redistribution works (6 builds; every partial gate landed between the
two regimes and worse), so no gate can serve the trio and the med rig at
once. We therefore replace homes with a flash-style global pull queue
(per-capacity-tier on the laptop later; a single degenerate queue on the
5600X), keep baby's absolute-deadline ordering and class machinery as
ordering/slice inputs, and validate 5600X-first with laptop regression
gates deferred until that machine is available.

## Considered options

- Pandemonium-direction (keep homes, price every move with R_eff):
  rejected - warm-stay freezes placement further, and the Phase 0 xz
  mechanism was exactly a frozen homing imbalance; the full R_eff
  machinery only pays on multi-domain parts.
- Regime switch (homing normally, pull under detected saturation):
  rejected - it is just another gate, and every gate tried landed in the
  disorganized middle.
- Profile-gated v2 (enable the age-steal tier only for memory-bound
  loads): rejected - violates the standing never-benchmark-only-tuning
  directive, and the bistability result says the gate cannot be found.

## Consequences

- The steal machinery (idle-steal, big-core steal/claim, saturation
  rebalance) and the 1s RT sweep die with the per-CPU queues; the local
  RT-strand case is covered by the cpu_release reenqueue commit landed
  beforehand.
- Classes stop being placement decisions and become ordering and
  slice-length inputs.
- The laptop's compaction/big-little story must be re-derived (tier
  queues or dispatch-side gating); nothing is built for it now.
- Light-load latency and the SC metronome must be re-proven after the
  change, since wake-homing is replaced by kernel select_cpu plus direct
  local insert.
