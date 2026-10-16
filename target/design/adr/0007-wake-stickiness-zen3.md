# Keep wake stickiness on idle: it is Zen 3 economics, not a bug

The user observed that under scx_baby desktop tasks concentrate on one
or two cores while the rest idle, unlike scx_lavd which spreads them.
Asked whether this is intentional and whether to explore spreading.

## Findings

- The concentration is real and measurable: on an idle box,
  nr_wake_land self = 95.5-100% - nearly every wake pick lands on the
  task's previous CPU. It comes from delegating wake placement to the
  kernel's default selector (scx_bpf_select_cpu_and, called with the
  sync hint stripped), which is prev-CPU biased for cache warmth.
- The counterpoint is real too: six fresh identical wake-blips spread
  across 5-6 cores under baby (the selector's idle-core picking
  overrides the bias when prev is busy), and concentrate under lavd.
  The user's one-or-two-core pattern is not a global behavior; it is
  the steady state of long-lived tasks that wake sequentially.
- Upstream semantics make self-picks contention-free by construction:
  scx_select_cpu_dfl / select_cpu_and returns prev_cpu only when the
  ENTIRE physical core is idle (idle_masks.smt test-and-clear on prev),
  and on a collision falls through to another full-idle physical core
  in the LLC before ever considering a busy core's sibling. The
  measured 0-4.5% non-self wakes are exactly those spills.
- Zen 3 economics reward the pattern. Two tasks that wake sequentially
  (client/compositor IPC) reuse a core whose L1/L2 stay hot, avoiding a
  32MB L3 snoop; waking a deep-CC6 core costs 15-30us of hardware exit
  plus cache refill; and the SMU grants its single/dual-core boost
  (4.65GHz class) only while the remaining cores stay parked, so
  spreading lat-critical wakes onto the longest-idle (deepest-CC6)
  core injects exit latency into every critical wakeup and drops the
  package to the all-core boost ceiling. Longest-idle is the worst
  possible target for a latency-critical wake.
- The one real hazard - a task warm-seating on a busy previous CPU
  while another core went idle - is already structurally excluded: the
  warm seat opens only under the oversubscription sum gate, and
  ops.enqueue's direct-dispatch scan claims a confirmed idle CPU
  otherwise.

## Topology scoping

The selector's semantics are topology-universal: prev CPU iff the full
physical core is idle, spill to another full-idle core on collision,
SMT/LLC aware everywhere. The cache-warmth and C-state-exit arguments
hold on any silicon. The boost economics do not, and the policy must
be read per platform:

- Zen 3 (this ADR's evidence): concentration is rewarded - the SMU's
  peak per-core boost holds while sibling cores stay parked in CC6.
- Intel HWP hybrids (the laptop, P/E/LP): the boost-window evidence
  recorded in the GB round runs the other way - lavd's boost state was
  sustained by wake transitions spread across the package, and baby's
  single-core residency was what that platform did not reward. Baby's
  answer there is not pure stickiness either: the shipped heavy_proven
  big-core pin (lowest idle big core, previous first) is an explicit
  placement override that bends stickiness where the hybrid topology
  needs it, and the big/little classification keeps fresh and light
  tasks off the performance cores. Stickiness is the default, not the
  whole policy; overrides are added per topology on measured evidence,
  never on principle.

## Consequences

- No code change. Keep ops.select_cpu's delegation to
  scx_bpf_select_cpu_and with wake_flags stripped of the sync hint and
  flags = 0, preserving the selector's priority order (prev CPU if the
  full core is idle, any other full-idle core in the LLC, prev CPU if
  logically idle, any idle logical CPU in the LLC).
- The observed concentration is documented as intentional: two cores
  hot and boosted, four in CC6, is the cheapest correct state for a
  desktop on this silicon.
- Guard for any future change here: game2 clean/bg50/mem and the mem
  cell's cache-warmth wins must not regress; any spread policy would
  have to beat the CC6-exit + boost-ceiling cost first.
- Arbitration: argon round 2 (2026-10-16), policy (iii) over (i)
  least-recently-idle spread (anti-pattern, per the CC6/boost
  analysis) and (ii) full-idle-core-first (already implemented inside
  the kernel selector).