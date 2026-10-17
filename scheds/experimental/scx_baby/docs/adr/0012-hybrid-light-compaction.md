# ADR 0012: the hybrid light compaction and the round that closed ADR 0011

Date: 2026-10-17 (early morning). Status: adopted; the ADR 0011 fix
round executed the same night. Round: argon arbiter round 8, executed
with two evidence-driven deviations. Commits c1c7cc6c8 (code). Deploy
/usr/bin/scx_baby-comp on the laptop.

## The round, as arbitrated and as run

Argon round 8 ordered Step 0 (price the old build's GB SC on this
kernel), Step 1 (fix the E13 rung gate), Step 2 (state-scoped
compaction in select_cpu). Two deviations, both forced by counters:

- Step 0 ran and settled argon's capacity question: the old build's
  SC wall is 225.1s on this kernel (gbsc instrument), consistent
  with the historical 1310-1450 score band and with argon's ratio
  reading (E/P capacity 0.771 vs old-SC/tip-SC 0.756) - the old
  build trapped single-thread work on E cores, and the compute
  exemption is mandatory in Step 2.
- Step 1 was SKIPPED. The e13c binary probed at light with --stats:
  wakeups land on the previous CPU 98-99 percent of the time (the
  kernel selector's prev-bias is the lock-in), the warm seat never
  fires (the sum gate is inert at light), and the shared queue
  carries only ~17 arrivals per 5s at ~99 percent depth 0 - so the
  4x rung the step would fix rarely fires and its ladder leg was
  probe noise plus second-order effects. The lever is the selector,
  not the slice.

## The design (commit c1c7cc6c8)

select_cpu gains a state-gated compaction pick ahead of the kernel
selector: below nr_little + 2 running tasks on a platform with both
tiers published, wake-driven tasks take the lowest-numbered idle CPU
of the little tier (atomic claim; a lost race retries the next idle
bit of the tier), a heavy consumer with no wake history pins a big
core first, and everything else falls back big. The order is the old
select_cpu's, and foreground beats heavy there on purpose: the light
workers cross the heavy bar with their mutex spins and must keep
stacking. A kernel pick that lands on an LP core is re-picked inside
the tiers while either has an idle CPU - the prev-bias would
otherwise lock the task onto a 0.7GHz no-L3 core. Heavy tasks keep
the kernel path elsewhere: their prev-stickiness is what holds a
compute thread on its boosted core, which is the SC win.

The gates read only lockless counters and the published tier sizes:
on a machine without a capacity split the little set is empty and
every new branch is statically false. The 5600X confirms it with the
new binary attached: the banner reads big=[0-11] little=[] lp=[],
the BPF loads clean on the box's 7.2.9 kernel, and the ab5600 trio
(com vs oc2p7, 2 interleaved rounds each) ties - light -0.5, med
+0.0, sat +0.8 percent, the same spread as the oc2p7-vs-oc2p6 trio
before it.

## The v1 lesson (recorded because it cost one probe)

The first cut gated compaction on !is_heavy_proven. The light
workers ARE heavy (90 percent duty mutex spins) and are foreground;
exempting them handed them to the kernel selector, which spread them
onto P cores, where the slower clock lengthens the spins and
reinforces heavy - the probe read 1379 rps with an LP at 22 percent
busy. The class order, not the exemption, is the mechanism.

## The gates (same fresh-boot laptop, same instruments as ADR 0011)

- Light profile, interleaved 3 pairs vs the incumbent: comp
  2018.0/2025.5/2021.7 vs old 2018.0/2026.6/2020.7 - a tie at the
  incumbent's band, per-round deltas within 0.05 percent. The single
  probe reads 2021.5 with the compaction shape restored: E4-E7 at
  91-93 percent busy and 4.25-4.28GHz, P cores 0-0.5 percent at
  400MHz, LPs at 0.0.
- GB SC: comp wall 199.3s vs tip 200.0s on the identical instrument
  - parity - and comp beats the old build's 225.1s by 11.5 percent.
  The tip's score anchor (1724/1743, +15 percent over lavd, measured
  earlier the same night) carries over; the wall parity is the gate
  instrument pending a full score run.
- 5600X: inert and verified - clean load on 7.2.9, banner little
  set empty, ab5600 trio ties.

Argon's STOP condition fires in the full-win branch: light recovered
+314 rps over tip (1707 to 2021) with SC intact. The old build stays
installed until the user switches the daily driver; the target state
is one build for both machines.

## Consequences

1. scx_baby-comp is the laptop's preferred build; the laptop gate
   suite (lGB + light A/B vs the incumbent) stays mandatory for
   every future baseline claim (adr/0011).
2. The box gates closed the same night: the trio verified behavior
   and the attach verified the 7.2.9 load. oc2way and game2 remain
   covered by the structural argument (the box's little set is
   empty, so every new branch is unreachable there); run them on
   the next box session if the belt-and-suspenders version is
   wanted.
3. The probe instruments: light_spread.sh (per-cpu busy/freq/psr
   through a light round) proved the mechanism and the fix; the
   e13c --stats probe (path frequencies per 5s) is the pattern for
   pre-verifying any future gate-fix lever before writing it.
