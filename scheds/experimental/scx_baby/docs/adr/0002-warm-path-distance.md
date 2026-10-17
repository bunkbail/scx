# Measure warm-path distance before pricing it; break ties with it,
# never gate on it

The warm-path distance round (2026-10-14) set out to close the 2x
overcommit loss to lavd (E7 191 rps / p99.9 43ms vs lavd 248 / 21ms)
by reducing cold migrations in the warm paths. The distance
instrument first, the mechanism second, per the E6 lesson.

## Findings

- The distance histograms falsified the round's premise: at 2x, the
  kernel wake path lands 95% of picks on the previous CPU, the
  direct-dispatch scan 83%, the warm seats themselves are 99.2%
  same-lane, and the shared-queue pull is head-forced (the pulled task
  is the deadline winner, not a placement choice). Only the warm-seat
  rebalance has distance freedom, and it fires on 0.8% of warm seats.
  The 2x loss is not a locality loss; it belongs to the preemption
  machinery (the standing depth-1-2 lead).
- The rebalance's distance-blind shallowest-queue rule did send 93%
  of its rare moves across a physical core. On the single-CCD 5600X
  that is the SMT-sibling-or-farther split; on multi-LLC parts it
  would be unpriced cross-LLC traffic.

## Decision

- Distance enters placement as an ordering only, never a gate: the
  warm-seat balance is depth-first, distance tie-break (E9). Depth
  strictly dominates, so the balance's saturation behavior is
  unchanged; only equal-depth candidate picks get a nearest-first
  order. This keeps the bistability law intact - no new thresholds.
- The tier ladder (sibling, L2, LLC, node) is built from sysfs cache
  ids at startup, replacing capacity heuristics as the portable
  locality structure. This retires the LP-exclusion portability scar
  for any future hybrid work (LLC membership, not capacity ratios).

## Consequences

- The 2x-overcommit rps frontier is handed to the preemption round
  (deadline-aware preempt at depth 1-2) with the locality hypothesis
  measured and closed.
- E9 is parity-everywhere on the 5600X (sat/med/light rigs, 1x/2x
  overcommit, trio all within noise of b92e0152c), so it lands as
  robustness for multi-LLC parts, not a measured win anywhere.
- Verifier cost: the rank computation must stay flat in the BPF
  verifier's state space. cpu_dist returns u32 and the rebalance
  calls it once per queue into a variable; two inlined calls inside
  the three-way comparison exceed the jump-complexity limit (8193
  jumps, E2BIG at load).
