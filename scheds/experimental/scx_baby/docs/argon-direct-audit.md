# Argon Direct Repo Audit & Bug-Fix / Tuning Plan (2026-10-17)

Author: Gemini 4 Argon (direct repository audit on `scx-baby` @ `6b6c4c81c`).
Audience: `glm-5.3-flash` execution session, guided by `argon-arbiter`.

This document records the findings from Argon's first direct source and log
audit of `scheds/experimental/scx_baby/` and `target/design/wg-readout/`.
It supersedes the premature STOP conclusions in ADR 0010 (Round 7) and the
units error in the Round 11 MLFQ falsifier, and defines the two-phase
execution plan for the next session.

---

## 1. Instrument & Units Corrections (Why ADR 0010 / Round 11 Misread `d1`)

1. **`stamp_wait()` stamps pre-insert queue length, not `vtime` position**
   (`balance.bpf.c:49, 117-119`):
   `target_nr = scx_bpf_dsq_nr_queued(cpu2dsq(target))` is read *before*
   `scx_bpf_dsq_insert_vtime()`. Whenever a wakeup misses `baby_select_cpu()`'s
   depth-0 wake-preempt gate with `BABY_WG_M3_SEAT_BUSY` (`seat_nr >= 1` at
   `main.bpf.c:360`), `target_nr` at `baby_enqueue()` time (~100ns later) is
   still `>= 1` unless `balance_try_warm_seat()` rebalanced the task to a
   different CPU with an empty seat. Thus:
   - **88% of `BABY_WG_M3_SEAT_BUSY` misses are filed in `wg d1`, not `wg d0`**,
     even when the waking task's sleeping deadline sorts it to the **head**
     (position 0) of that 1-deep warm seat.
   - In `target/design/wg-readout/A_r1_sched.log` (`wg_analyze.py` output):
     - `d0`: `n = 3,069`, `mean = 904 us` (`2.77 s` total `lat_cri` wait):
       `rot = 57% ns (n=1,488) | seat = 35% ns (n=1,408)`
     - `d1`: `n = 12,437`, `mean = 1,412 us` (**`17.56 s` total `lat_cri` wait,
       6.3x larger than `d0`**):
       `rot = 20% ns (n=1,798) | seat = 79% ns, 1,324 us (n=10,534)`
   - ADR 0010 only inspected row `d0` and missed `10,534` `BABY_WG_M3_SEAT_BUSY`
     waits (`13.95 s` per 50s round = **69% of all `lat_cri` wait across all
     depths combined**) sitting in row `d1`.

2. **Units error in the Round 11 falsifier (`mlfq-fork-verdict.md`)**:
   In `stats.rs:834`, `vmean` prints `ns / n / 1000` (microseconds). Summing
   `n * mean` across the `wg-readout` logs yields `~121,000,000 us` =
   **121 seconds** of `lat_cri` `d1+` wait across the 8 runs (~15s per 50s
   run), not `121 ms`. And `231` is `schbench` requests/sec (`rps`), not
   wall-clock seconds. (The fork rejection itself still stands: the fix is
   consumption/preemption parity at `d1`, not a 5-level MLFQ fork.)

---

## 2. Phase 1: Correctness Bugs & Hot-Path Overhead Cleanup

Execute Phase 1 first as a clean, self-contained correctness and overhead
pass before touching 2x overcommit preemption behavior.

### Bug 1A: `power.bpf.c:191-193` Premature `cctx->last_running = now` Overwrite
- **Location**: `scheds/experimental/scx_baby/src/bpf/power.bpf.c:84-91, 137, 190-194`
- **Problem**: `cpuperf_on_tick()` sets `cctx->last_running = now` on line 192
  *immediately before* calling `update_cpuperf(cctx, cpu, max_floor)`. Inside
  `update_cpuperf()`, line 86 reads a fresh `now = bpf_ktime_get_ns()` and
  computes `delta_t = now - cctx->last_running` (line 89), which measures only
  the 0–30ns between the two `bpf_ktime_get_ns()` calls instead of the ~1ms
  tick window. Either `delta_t == 0` (early return on line 90, skipping the
  tick cpufreq update and leaving `prev_runtime` un-advanced) or `delta_t` is
  ~20ns (dividing 1ms of `delta_runtime` by 20ns and pegging `perf_lvl` at
  100%).
- **Fix**:
  1. Remove `cctx->last_running = now;` from `cpuperf_on_tick()` (`update_cpuperf`
     already sets `cctx->last_running = now` at line 137 after computing
     `delta_t`).
  2. Pass `u64 now` into `update_cpuperf(struct cpu_ctx *cctx, s32 cpu, u64 now, bool max_floor)`
     from both `cpuperf_on_tick(p, now, ...)` and `cpuperf_on_running(cpu, now, ...)`
     so `update_cpuperf()` does not make a redundant `bpf_ktime_get_ns()` call
     and `delta_t` in `cpuperf_on_tick()` is the true elapsed window since the
     previous `last_running` stamp.

### Bug 1B: `SCX_ENQ_REENQ` Watchdog-Stall Trap & `baby_enqueue()` Ordering Inversion
- **Location**: `scheds/experimental/scx_baby/src/bpf/main.bpf.c:618-629`,
  `balance.bpf.c:42-136`, `idle.bpf.c:49-88`
- **Problem**:
  1. In `baby_enqueue()`, `balance_try_warm_seat()` is called *before*
     `try_direct_dispatch()`, and `balance_try_warm_seat()` does not reject
     `SCX_ENQ_REENQ`. When `baby_cpu_release()` (`scx_bpf_reenqueue_local()`)
     or `rescue_timerfn()` (`scx_bpf_dsq_reenq___compat()`) re-enqueues tasks
     with `SCX_ENQ_REENQ` while the machine is oversubscribed,
     `balance_try_warm_seat()` intercepts them, skips the wakeup-only rebalance
     scan (`balance.bpf.c:80`), and inserts them **right back into the stranded
     CPU's warm seat** while `baby_enqueue()` resets `tctx->last_acc_at = now`.
  2. On slice expiry (`SCX_ENQ_LAST`, where `is_running == true` and
     `ops.select_cpu()` did not run), running `balance_try_warm_seat()` before
     `try_direct_dispatch()` traps expiring tasks on a busy `prev_cpu` even
     when another CPU just went completely idle while `warm_total` keeps the
     sum gate open.
  3. On wakeups (`__COMPAT_is_enq_cpu_selected(enq_flags)` is true and
     `!is_running`), `try_direct_dispatch()` immediately returns `false` in two
     instructions (`idle.bpf.c:62-64`), so placing `try_direct_dispatch()`
     ahead of `balance_try_warm_seat()` is a zero-cost no-op for wakeups.
- **Fix**:
  1. In `baby_enqueue()` (`main.bpf.c:618-628`), call `try_direct_dispatch()`
     **before** `balance_try_warm_seat()`.
  2. In `balance_try_warm_seat()` (`balance.bpf.c:47`), immediately return
     `false` if `(enq_flags & SCX_ENQ_REENQ)` so rescued/released tasks that
     find no idle CPU in `try_direct_dispatch()` go to the shared node queue
     where any CPU can pull them.
  3. In `rescue_timerfn()` (`main.bpf.c:1061`), check
     `hctx->wait_stamp && now - hctx->wait_stamp > STARVE_RESCUE_NS` (or keep
     `last_acc_at` once `SCX_ENQ_REENQ` bypasses `balance_try_warm_seat()`).

### Bug 1C: Missing Hybrid LP-Island Guard in `try_direct_dispatch()`
- **Location**: `scheds/experimental/scx_baby/src/bpf/idle.bpf.c:71-74`,
  `main.bpf.c:155-201, 272-300`
- **Problem**: `try_direct_dispatch()` calls `pick_idle_cpu(p, prev_cpu, 0, &is_idle)`
  without the hybrid LP-island guard that `baby_select_cpu()` has. When a
  stopping or reenqueued task spreads via `try_direct_dispatch()` on a hybrid
  part (Arrow Lake CPUs 12–13), `scx_bpf_select_cpu_and` can place it on an
  LP-E island core, after which `prev_cpu` bias locks it there.
- **Fix**: Apply the same `!on_tier -> pick_idle_tier(p, big_first)` LP guard
  when `is_idle && nr_little_cpus && nr_big_cpus` in `try_direct_dispatch()`
  (or fold the LP guard into a shared helper in `idle.bpf.c`).

### Bug 1D: Hot-Path Redundancies in `baby_dispatch()` and `balance_try_warm_seat()`
- **Locations**:
  - `main.bpf.c:678-679` and `703-704` (`baby_dispatch()`)
  - `balance.bpf.c:54-91, 106` (`balance_try_warm_seat()`)
- **Problems & Fixes**:
  1. **Duplicate DSQ peeks in `baby_dispatch()`**: When `need_running && tctx`
     is true and `prev` loses the deadline check, `baby_dispatch()` peeks
     `cpu2dsq(cpu)` and `node` at lines 678–679 and then peeks both DSQs a
     second time at lines 703–704. Peek `wq` and `q` (and compute `wq_dl`,
     `g_dl`) **once** before `if (need_running && tctx)` and reuse them in both
     blocks.
  2. **Useless `cpu_dist` / `bpf_cpumask_test_cpu` scan when `target_nr < 2`**:
     In `balance_try_warm_seat()`, line 106 only rebalances when
     `best_nr + 2 <= target_nr`, which is mathematically impossible when
     `target_nr < 2`. Gate the per-CPU rebalance body inside the `bpf_for`
     loop on `target_nr >= 2`:
     ```c
     if (target_nr < 2 || !(enq_flags & SCX_ENQ_WAKEUP) ||
         !bpf_cpumask_test_cpu((s32)i, p->cpus_ptr))
         continue;
     ```
     (Check verifier jump count on load; because `target_nr < 2` is loop-invariant,
     it prunes the inner branch cleanly.)

### Bug 1E: False Sharing on `nr_running` & Always-On Heavy Telemetry
- **Location**: `scheds/experimental/scx_baby/src/bpf/stats.bpf.c:17-19, 143-241`,
  `main.bpf.c:662, 961`
- **Problem**:
  1. `nr_running` is an active control-plane input read by `baby_select_cpu()`
     and `balance_try_warm_seat()`, but is declared in the same 64-byte BSS
     cache line as `nr_direct_dispatches`, `nr_shared_dispatches`,
     `nr_preemptions`, `nr_boosts`, `nr_sticky`, `nr_warmseats`, and
     `nr_coldspreads`.
  2. `census_sample()` runs unconditionally on every `baby_dispatch()` (2 kfuncs
     + 2 global `lock xadd`s), and `charge_wait()` runs 10–15 global `lock xadd`s
     on every queued `baby_running()`, even when neither `--stats` nor
     `--monitor` is active.
  3. In `src/stats.rs:900-905` (and `WaitCls::sub`, `WaitType::sub`,
     `WaitLCRI::sub`, `WaitGateMiss::sub`), `delta()` computes
     `self.max.max(rhs.max)` on monotonic BPF high-water marks, printing the
     all-time max since attach even when `n == 0` in the interval.
- **Fix**:
  1. Give `nr_running` its own cache line (`__attribute__((aligned(64)))` or
     move it to `util.bpf.c` aligned to 64 bytes, with the next variable in
     `stats.bpf.c` also `__attribute__((aligned(64)))`).
  2. Gate the heavy diagnostic instrumentation (`stamp_wait`, `charge_wait`,
     `census_sample`, and the `nr_land` / `nr_wake_land` / `nr_seat_move` /
     `nr_pull_land` distance histograms) on a `.rodata` flag
     `const volatile bool stats_enabled` (Wait: note that `scx_baby --monitor`
     connects to an already-running `scx_baby` instance via `StatsServer`! If
     `--monitor` is used against a daemon started without `--stats`, check
     whether benchmark scripts use `scx_baby --stats 5` directly—`oc2way` uses
     `--stats 5`. If `--monitor` support on a default launch is required, keep
     either a `--no-stats` / `--stats` flag or at minimum isolate `nr_running`
     and only gate `census_sample` / `charge_wait` when `stats` is enabled).

---

## 3. Phase 2: Closing the 2x Overcommit `d1` Warm-Seat Gap (`BABY_WG_M3_SEAT_BUSY`)

Once Phase 1 is verified neutral/positive on the laptop and 5600X gates,
open the Phase 2 round on the 5600X `oc2way` rig.

### The Mechanism Gap Found in the Code
In `A_r1_sched.log`, `wlcri lat d1` has `12,437` waits (`17.56 s` total wait),
of which **`10,534` (`13.95 s`, `mean = 1,324 us`) are `BABY_WG_M3_SEAT_BUSY`**.
Those `10,534` waits split into two sub-populations inside `cpu2dsq(prev_cpu)`
(where `target_nr == 1` before insert):

1. **Sub-population A (~38% of `d1 seat`, ~533/5s = `nr_depth1_pulls_seat`):
   The waking `lat_cri` task `w` sorts 2nd (`depth 1`) behind a non-`lat_cri`
   batch head `h` with an older/overdue deadline.**
   - `baby_dispatch()` knows how to pull `w` ahead of `h` via
     `depth1_pull_seat()` (`main.bpf.c:755`, landed in ADR 0008).
   - **However, `baby_tick()` (`main.bpf.c:844-849`) only peeks the 1st entry
     (`head`, depth 0) of `cpu2dsq(cpu)`!**
   - Because `head` (`h`) is *not* `is_lat_cri`, `baby_tick()` sees
     `!is_lat_cri(hctx)` and **never cuts the running batch task's `4.72ms`
     (`4 * deadline_ns`) slice**!
   - Therefore, `w` is forced to wait out the running batch task's entire
     remaining `4.72ms` slice (~2,360 us mean, up to 5–10ms `slow5ms` spikes)
     before `baby_dispatch()` is even called to run `depth1_pull_seat()`.

2. **Sub-population B (~62% of `d1 seat`, ~880/5s):
   The waking `lat_cri` task `w` has a sleeping deadline earlier than `h` and
   sorts to the HEAD (`depth 0`) of `cpu2dsq(prev_cpu)`.**
   - At wakeup time, `baby_select_cpu()` (`main.bpf.c:360`) saw
     `scx_bpf_dsq_nr_queued(cpu2dsq(prev_cpu)) == 1` (`BABY_WG_M3_SEAT_BUSY`)
     and refused `SCX_ENQ_PREEMPT`.
   - `w` was inserted at the head of `cpu2dsq(prev_cpu)` and waited ~750 us
     for the next 1000Hz `baby_tick()` (`nr_tick_preempts_warm = 1269`/5s) to
     zero `curr->scx.slice` and force `curr` through `ops.enqueue()`.
   - Weighted check: `(876 * 750 us + 533 * 2,360 us) / 1,409 = 1,359 us`,
     matching the measured `1,362 us` in `A_r1_sched.log` line 45 to within 3 us.

### Pre-Registered Probes for Phase 2 (Consult `argon-arbiter` With Counter Readouts)

- **Arm 2A (Tick gate depth-1 parity with `depth1_pull_seat`)**:
  In `baby_tick()` (`main.bpf.c:844-850`), when `cpu2dsq(cpu)` has a non-`lat_cri`
  head `h` whose `h->pid != seat_skip_pid[cpu]`, step a 2-entry DSQ iterator
  to inspect the second entry `w` (same straight-line 2-step DAG pattern as
  `depth1_pull()`): if `w` is `is_lat_cri(wctx)`, set `cri = true; warm = true;`.
  When `baby_tick()` zeroes `p->scx.slice`, `baby_dispatch()` immediately runs
  `depth1_pull_seat()` and dispatches `w` past `h`, respecting the existing
  `seat_skip_pid[cpu]` 1-bypass-per-head starvation bound.
  - *Expected readout*: `wlcri lat d1` `slow5ms` drops sharply (eliminating the
    4.72ms batch-slice wait ahead of `depth1_pull_seat`), `d1` mean drops from
    ~1,350 us toward ~750 us.

- **Arm 2B (Wake-path depth-1 preempt in `baby_select_cpu` under a 1-skip bound)**:
  If Arm 2A passes and `d1 seat` (~750 us tick-quantization wait on ~1,400
  wakes/5s) remains the dominant pool: in `baby_select_cpu()` (`main.bpf.c:360`),
  relax `scx_bpf_dsq_nr_queued(cpu2dsq(prev_cpu)) == 0` to allow `seat_nr == 1`
  when the single seated task `h` is non-`lat_cri` and has not already been
  preempted-over (1-skip bound per seated head PID). Remember that in 6.12+
  `ext.c`, `SCX_ENQ_PREEMPT` on `SCX_DSQ_LOCAL_ON | prev_cpu` keeps `curr` at
  the head of `SCX_DSQ_LOCAL` without calling `ops.enqueue()`, so `curr`
  resumes its remaining slice right after the wakee finishes its short burst,
  without churning `cpu2dsq(prev_cpu)`.
  - *Gates*: 5600X `oc2way` (1x/2x/4x), `game2` (`oc2`, `clean`, `bg50`, `mem`),
    and `ab5600` (`light`, `med`, `sat`).
