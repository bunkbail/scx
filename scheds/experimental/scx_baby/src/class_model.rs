// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Test-only mirrors of the class model in src/bpf/class.bpf.c.
//!
//! The BPF side cannot be unit tested from userspace, so these pin the
//! arithmetic the class bars depend on. The window, the bars and the
//! demotion point are read from bpf_intf, so the mirror cannot agree with
//! itself while disagreeing with the constants the BPF object was built
//! with.

use crate::Mode;
use crate::Opts;
use crate::consts_FOREGROUND_WAKE_FREQ;
use crate::consts_LAT_CRI_WAKE_FREQ;
use crate::consts_TIME_PERIOD;
use crate::consts_WAKE_SANE_MIN;
use crate::consts_WAKELESS_DEMOTE_NS;
use clap::Parser;

/// One millisecond of runtime, the step the demotion test walks in.
const RUN_NS: u64 = 1_000_000;

/// Test-only mirror of the wake-rate blend in class_on_runnable(): the
/// 50/50 warmup over the first WAKE_SANE_MIN samples, then the documented
/// 3:1, both rounded up so a rate at the bar does not settle just below
/// it.
fn wake_rate_blend(avg: u64, raw: u64, samples: u32) -> u64 {
    if samples < consts_WAKE_SANE_MIN {
        (avg + raw + 1) >> 1
    } else {
        (3 * avg + raw + 3) >> 2
    }
}

/// Mirror of the peak gate's decay and arm sequence: the peak decays by
/// one part in 64 on every sample and may rise only once the warmup is
/// done, so one startup spike cannot latch the class.
fn class_peak_after(seq: &[u64]) -> u32 {
    let mut avg = 0u64;
    let mut samples = 0u32;
    let mut peak = 0u32;

    for &raw in seq {
        avg = wake_rate_blend(avg, raw, samples);
        if samples < consts_WAKE_SANE_MIN {
            samples += 1;
        }
        peak -= peak >> 6;
        if samples >= consts_WAKE_SANE_MIN {
            let cand = avg as u32;

            if cand > peak {
                peak = cand;
            }
        }
    }
    peak
}

/// Mirror of the seat-guard arm of update_bursts(): the peak is zeroed
/// once the runtime since the last wake passes the demotion bar. Wakes
/// alone cannot demote a task that stopped waking, so this is the only
/// path that unlatches the class.
fn wakeless_peak(guard: bool, peak: u32, runs: &[u64]) -> u32 {
    let total: u64 = runs.iter().sum();

    if guard && total > consts_WAKELESS_DEMOTE_NS as u64 {
        0
    } else {
        peak
    }
}

#[test]
fn rounded_blend_reaches_the_wake_bar() {
    // 100Hz reaches 10; a 50Hz sample of 5 reaches the class bar of 5. A
    // truncating 3:1 blend has a fixed point at 9 for the 100Hz input, so
    // the round-up matters.
    assert_eq!(
        wake_rate_blend(9, consts_FOREGROUND_WAKE_FREQ as u64, consts_WAKE_SANE_MIN),
        consts_FOREGROUND_WAKE_FREQ as u64
    );
    assert!(class_peak_after(&[10; 8]) >= consts_FOREGROUND_WAKE_FREQ);
    assert!(class_peak_after(&[5; 8]) >= consts_LAT_CRI_WAKE_FREQ);
}

#[test]
fn the_two_bars_stay_distinct() {
    // The bug this pins: the two bars were both 5, so is_foreground()
    // collapsed into "latency critical with real work" and every
    // 60Hz-class poller earned the fourfold slice. The bars live in
    // intf.h and baby.bpf.h carries static assertions for the
    // relationship; this test pins the consequence: a 60Hz cadence (six
    // wakes per 100ms) clears the latency bar and stays below the
    // foreground bar, a 100Hz cadence clears both.
    let sixty = class_peak_after(&[6; 16]);
    assert!(
        sixty >= consts_LAT_CRI_WAKE_FREQ,
        "60Hz must clear the latency bar, got {sixty}"
    );
    assert!(
        sixty < consts_FOREGROUND_WAKE_FREQ,
        "60Hz must not reach the foreground bar, got {sixty}"
    );

    let hundred = class_peak_after(&[10; 16]);
    assert!(
        hundred >= consts_FOREGROUND_WAKE_FREQ,
        "100Hz must reach the foreground bar, got {hundred}"
    );
}

#[test]
fn sixty_hz_clears_the_wake_bar() {
    // 60Hz is six wakes per 100ms: above the class bar of 5. The
    // foreground test adds the runtime floor on top of the bar, which
    // this mirror does not model.
    let peak = class_peak_after(&[6; 16]);
    assert!(peak >= consts_LAT_CRI_WAKE_FREQ);
}

#[test]
fn one_startup_spike_is_smoothed_out() {
    // One very short interval followed by three slow wakes blends down to
    // 7 by the time the peak can arm; it does not latch the spike.
    assert_eq!(class_peak_after(&[100, 0, 0, 0]), 7);
}

#[test]
fn fast_wakers_keep_the_class() {
    assert!(class_peak_after(&[12; 8]) >= consts_LAT_CRI_WAKE_FREQ);
    // After a slowdown the hold stays above the bar even though the
    // current average is no longer there.
    let peak = class_peak_after(&[12, 12, 12, 12, 6, 6, 6, 6]);
    assert!(peak >= consts_LAT_CRI_WAKE_FREQ);
}

#[test]
fn a_burst_then_hog_loses_the_peak() {
    // One 120Hz burst earns the foreground hold, then the task runs
    // continuously and never wakes again. A run exactly at the demotion
    // bar keeps the credit, the next accounting tick past it drops the
    // peak.
    let peak = class_peak_after(&[12; 48]);
    let at_bar = (consts_WAKELESS_DEMOTE_NS as u64 / RUN_NS) as usize;

    assert!(peak >= consts_FOREGROUND_WAKE_FREQ);
    assert_eq!(wakeless_peak(true, peak, &vec![RUN_NS; at_bar]), peak);
    assert_eq!(wakeless_peak(true, peak, &vec![RUN_NS; at_bar + 1]), 0);
}

#[test]
fn wakeless_demotion_is_off_outside_the_guard() {
    // --game and every plain variant read the seat guard as !plain, which
    // is false there, so the verifier prunes the demotion branch and their
    // behaviour is unchanged no matter how long a task runs without waking.
    for args in [&["--game"][..], &["--plain"][..], &["--plain-1x"][..]] {
        let mut argv = vec!["scx_baby"];
        argv.extend_from_slice(args);

        let mode = Mode::from_opts(&Opts::try_parse_from(&argv).unwrap());

        assert_eq!(
            wakeless_peak(!mode.plain, 12, &[3_000_000_000]),
            12,
            "{args:?}"
        );
    }
}

#[test]
fn the_latency_bar_interval_stays_under_the_demotion_bar() {
    // A task exactly at the latency bar wakes every 20ms, well under the
    // 50ms demotion bar, so a waker that still meets the bar is never
    // demoted between two of its wakes.
    let interval = (consts_TIME_PERIOD / 2) / consts_LAT_CRI_WAKE_FREQ;

    assert_eq!(
        wakeless_peak(true, consts_LAT_CRI_WAKE_FREQ, &[interval as u64]),
        consts_LAT_CRI_WAKE_FREQ
    );
}

#[test]
fn a_hitch_re_earns_the_class_from_the_kept_average() {
    // The peak is zeroed but wake_samples and wakeup_freq are kept, so a
    // throttled 60Hz thread re-earns the class on its next wakes instead
    // of replaying the four-sample warmup.
    let avg = wake_rate_blend(6, 1, consts_WAKE_SANE_MIN);

    assert_eq!(avg, consts_LAT_CRI_WAKE_FREQ as u64);
    assert!(wake_rate_blend(avg, 6, consts_WAKE_SANE_MIN) >= consts_LAT_CRI_WAKE_FREQ as u64);
}

#[test]
fn woke_task_keeps_interactive_through_a_zero_window() {
    // Mirror of is_interactive: runtime in either window, or
    // WAKE_SANE_MIN wake samples, keeps a task interactive; a fresh hog is
    // rejected by the burst bound.
    let burst_bar = consts_TIME_PERIOD as u64 / 4;

    fn interactive(prev: u64, curr: u64, samples: u32, burst_bar: u64) -> bool {
        (prev > 0 || curr > 0 || samples >= consts_WAKE_SANE_MIN)
            && prev < burst_bar
            && curr < burst_bar
    }

    assert!(interactive(0, 10_000_000, consts_WAKE_SANE_MIN, burst_bar));
    assert!(interactive(0, 10_000_000, 0, burst_bar));
    assert!(!interactive(0, 60_000_000, 0, burst_bar));
    assert!(!interactive(
        60_000_000,
        10_000_000,
        consts_WAKE_SANE_MIN,
        burst_bar
    ));
}
