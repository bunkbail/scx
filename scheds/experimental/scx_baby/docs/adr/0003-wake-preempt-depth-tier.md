# Reject the depth-1-2 wake-preempt tier; keep the depth-0 gate

The preemption round (2026-10-15) set out to close the 2x overcommit
loss to lavd (E9 191 rps / p99.9 43ms vs lavd 248 / 21ms) with the
standing lead: deadline-aware wakes preempting through a warm backlog
of one or two waiters, instead of the empty-queue wall the depth-0
gate imposes.

## Findings

- The wait-at-depth instrument (a3f9d6486) localized the tail: at 2x,
  depth-0 wakes average 2.2ms (one full remaining slice, doubled by
  the deep-backlog slice) and depth-1 wakes 3.7ms with 15% over 5ms;
  the schbench request pays the wait twice per cycle, which is the
  4.8ms per-request gap to lavd. At 4x every wait is a full rotation
  round (d2/d3+ means 9.0-9.2ms, 99% over 5ms) - the 4x tail lives in
  the rotation depth, outside any wake-path lever.
- The lead is falsified. Every variant of the tier lost to the plain
  depth-0 gate: depth<=2 with the full foreground slice -13% rps at
  1x and -6% at 2x (E10); capping the preempt slice at one deadline
  -13% and -12% (E10b); depth<=1 -13% and -8% (E10c). The shape of
  the loss is invariant: the waker's saving (skipping the current
  task's remaining slice) is smaller than the victim's eviction cost
  re-seated behind the queue, which cascades onto every later wake.
- At 1x the harm is the depth-1 preempt alone (identical -13% in all
  variants; the slice cap is irrelevant there). At 2x the capped
  slice additionally hurts: the waker cannot finish its request in
  one deadline and re-queues behind the rotation it just tried to
  escape.
- lavd's 2x advantage is not reachable by one-shot preemption. Its
  design gives latency-critical tasks shorter slices and standing
  priority; baby's absolute-deadline EDF with warm seats pays the
  full-slice wait by construction. Chasing the wait through slice
  policy under oversubscription is the next round's candidate, not
  this one's.

## Consequences

- The depth-0 gate stays. It earned its place at the saturation wall
  (04e1ebcd1) and again here: every relaxation measured worse.
- The wake-preempt logic returns to ops.enqueue's depth-0 form; the
  select_cpu relocation (needed because enqueue has no verifier
  headroom) is shelved with the mechanism.
- The wait-at-depth instrument is the round's keeper: it decomposes
  the overcommit tail per depth and turned a standing attribution
  into a measured falsification.
- Verifier note: enqueue sits at the jump-complexity ceiling. Even a
  three-instruction addition (a MIN on the slice) re-breaks the load
  (E2BIG, 8193-jump blowup). The preempt gate had to move out of
  enqueue entirely to fit - and that headroom fact survives the
  mechanism's rejection.

## Decision

Close the round with the negative verdict. The 2x frontier passes to
a slice-policy round (deep-backlog slice doubling vs wake wait) or to
a classification-shaped design review, with the instrument already in
place to measure whichever is chosen.
