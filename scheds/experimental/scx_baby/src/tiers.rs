// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2026 bunkbail <nabildanial.93@gmail.com>
//
// Core-tier classification. Decides which CPUs are big cores, which are
// little ones and which low-power islands stay out of both tiers. The
// decision is pure over its inputs so the tests can pin every branch;
// init() gathers the inputs from sysfs and applies the result.

/// The classification result for one machine.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CoreClasses {
    pub big: Vec<usize>,
    pub little: Vec<usize>,
    pub lp: Vec<usize>,
}

/// Which input decided the classification, for the init log.
#[derive(Debug, PartialEq, Eq)]
pub enum TierSource {
    /// Exact kernel-provided capacities (cpu_capacity) split the tiers.
    Capacity,
    /// Topology core types, corroborated by a real frequency spread.
    CoreType,
    /// No usable split: one tier came out empty and every hybrid gate
    /// is statically false.
    NoSplit,
}

/// Classify the CPUs of a machine.
///
/// The capacity branch needs the kernel's own per-CPU capacity
/// (cpu_capacity): the tiers split when the weakest CPU falls below 85
/// percent of the strongest, and the big set is exactly the CPUs at the
/// top capacity.
///
/// The core-type fallback exists for platforms whose sysfs does not
/// expose capacities. It keeps a split the topology claims only when
/// the per-CPU hardware maximum frequencies corroborate it under the
/// same 85 percent bar. The corroboration is the fake-tier guard:
/// amd_pstate preferred-core rankings spread more than 30 percent
/// across architecturally identical Zen cores, which passes scx_utils's
/// 1.3x big/little heuristic and would otherwise engage the hybrid
/// gates with fake tiers - stacking light wakes on lower-ranked
/// same-speed cores and hiding the preferred cores behind the heavy
/// pin. Frequency spread on those parts is under 8 percent, so the
/// guard rejects them; real hybrids separate P from E clocks by 20
/// percent or more and pass.
///
/// On a machine without a usable split every CPU is published as a big
/// core (or, when the topology claims nothing but little cores, as
/// little ones): either way one tier is empty and the hybrid gates are
/// statically false.
pub fn classify(
    ids: &[usize],
    capacity: &impl Fn(usize) -> Option<u32>,
    is_big_core_type: &impl Fn(usize) -> Option<bool>,
    max_freq: &impl Fn(usize) -> Option<u32>,
) -> (CoreClasses, TierSource) {
    let capacities: Vec<Option<u32>> = ids.iter().map(|id| capacity(*id)).collect();
    let caps: Vec<u32> = capacities.iter().flatten().copied().collect();
    if let (Some(lo), Some(hi)) = (caps.iter().min(), caps.iter().max())
        && lo * 100 < hi * 85
    {
        let max_cap = *hi;
        let big: Vec<usize> = ids
            .iter()
            .zip(&capacities)
            .filter(|(_, cap)| **cap == Some(max_cap))
            .map(|(id, _)| *id)
            .collect();
        let rest: Vec<usize> = ids.iter().filter(|id| !big.contains(id)).copied().collect();
        let (little, lp) = split_lps(&rest, capacity);
        return (CoreClasses { big, little, lp }, TierSource::Capacity);
    }

    let big: Vec<usize> = ids
        .iter()
        .filter(|id| is_big_core_type(**id) == Some(true))
        .copied()
        .collect();
    let rest: Vec<usize> = ids
        .iter()
        .filter(|id| is_big_core_type(**id) != Some(true))
        .copied()
        .collect();
    let (little, lp) = split_lps(&rest, capacity);

    if big.is_empty() || little.is_empty() {
        return (CoreClasses { big, little, lp }, TierSource::NoSplit);
    }

    let freqs: Vec<u32> = ids.iter().filter_map(|id| max_freq(*id)).collect();
    let corroborated = matches!(
        (freqs.iter().min(), freqs.iter().max()),
        (Some(lo), Some(hi)) if u64::from(*lo) * 100 < u64::from(*hi) * 85
    );
    if !corroborated {
        // A core-type split the clocks do not show is a ranking
        // artifact, not a hardware tier: refuse it and run homogeneous.
        return (
            CoreClasses {
                big: ids.to_vec(),
                little: Vec::new(),
                lp: Vec::new(),
            },
            TierSource::NoSplit,
        );
    }

    (CoreClasses { big, little, lp }, TierSource::CoreType)
}

/// Cores far below the little tier - the L3-less low-power islands on
/// hybrid parts - stay out of the little set: that set is the tier the
/// queue work waits in, and a worker pulled onto an LP core runs at a
/// fraction of the little cores' speed with no last-level cache, which
/// stretches every batch of a batch-parallel workload to its slowest
/// worker. They are not lost to scheduling: the kernel's placement and
/// the direct-dispatch scan still run work there when nothing else
/// fits. Only the tier assignment skips them.
fn split_lps(rest: &[usize], capacity: &impl Fn(usize) -> Option<u32>) -> (Vec<usize>, Vec<usize>) {
    let little_cap = rest.iter().filter_map(|id| capacity(*id)).max();
    let mut little = Vec::new();
    let mut lp = Vec::new();
    for id in rest {
        match (capacity(*id), little_cap) {
            (Some(cap), Some(max)) if cap * 2 < max => lp.push(*id),
            _ => little.push(*id),
        }
    }
    (little, lp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CPU id list 0..n and closures reading the fixture
    /// tables by id.
    fn fixture(
        caps: Vec<Option<u32>>,
        bigs: Vec<Option<bool>>,
        freqs: Vec<Option<u32>>,
    ) -> (
        Vec<usize>,
        impl Fn(usize) -> Option<u32>,
        impl Fn(usize) -> Option<bool>,
        impl Fn(usize) -> Option<u32>,
    ) {
        (
            (0..caps.len()).collect(),
            move |id| caps[id],
            move |id| bigs[id],
            move |id| freqs[id],
        )
    }

    #[test]
    fn capacity_split_matches_the_hybrid_shape() {
        // Four big cores at the top capacity, eight little ones at
        // 0.771, and two LP islands below half of the little tier.
        let mut caps = vec![Some(1024u32); 4];
        caps.extend(vec![Some(790); 8]);
        caps.extend(vec![Some(256); 2]);
        let (ids, capacity, is_big, max_freq) = fixture(caps, vec![], vec![]);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::Capacity);
        assert_eq!(classes.big, vec![0, 1, 2, 3]);
        assert_eq!(classes.little, (4..12).collect::<Vec<usize>>());
        assert_eq!(classes.lp, vec![12, 13]);
    }

    #[test]
    fn homogeneous_core_types_publish_no_split() {
        // A homogeneous desktop: no capacity files, every core type big.
        let n = 12;
        let (ids, capacity, is_big, max_freq) =
            fixture(vec![None; n], vec![Some(true); n], vec![Some(5700000); n]);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::NoSplit);
        assert_eq!(classes.big, (0..n).collect::<Vec<usize>>());
        assert!(classes.little.is_empty() && classes.lp.is_empty());
    }

    #[test]
    fn uncorroborated_core_type_split_is_refused() {
        // A homogeneous desktop whose amd_pstate preferred-core ranking
        // presents a 1.45x spread across identical cores: it trips the
        // ladder's big/little bar, but the clocks differ by 5 percent,
        // so the fake-tier guard must collapse to one tier.
        let n = 16;
        let mut bigs = vec![Some(true); n];
        bigs[12..16].fill(Some(false));
        let (ids, capacity, is_big, max_freq) =
            fixture(vec![None; n], bigs, vec![Some(5700000); n]);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::NoSplit);
        assert_eq!(classes.big, (0..n).collect::<Vec<usize>>());
        assert!(classes.little.is_empty() && classes.lp.is_empty());
    }

    #[test]
    fn corroborated_core_type_split_is_kept() {
        // An older-kernel hybrid without cpu_capacity: the core types
        // split and the clocks back them up (P 5.0GHz, E 3.7GHz).
        let n = 10;
        let mut bigs = vec![Some(true); 4];
        bigs.extend(vec![Some(false); 6]);
        let mut freqs = vec![Some(5000000u32); 4];
        freqs.extend(vec![Some(3700000); 6]);
        let (ids, capacity, is_big, max_freq) = fixture(vec![None; n], bigs, freqs);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::CoreType);
        assert_eq!(classes.big, (0..4).collect::<Vec<usize>>());
        assert_eq!(classes.little, (4..10).collect::<Vec<usize>>());
    }

    #[test]
    fn frequency_corroboration_uses_the_same_85_percent_bar() {
        // Exactly 0.85 is no split (the comparison is strict); below
        // the bar by one step is one.
        let n = 4;
        let mut bigs = vec![Some(true); 2];
        bigs.extend(vec![Some(false); 2]);
        let at_bar = vec![
            Some(5000000u32),
            Some(5000000u32),
            Some(4250000),
            Some(4250000),
        ];
        let below = vec![
            Some(5000000u32),
            Some(5000000u32),
            Some(4240000),
            Some(4240000),
        ];
        let (ids, capacity, is_big, max_freq) = fixture(vec![None; n], bigs.clone(), at_bar);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::NoSplit);
        assert!(classes.little.is_empty());
        let (ids, capacity, is_big, max_freq) = fixture(vec![None; n], bigs.clone(), below);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::CoreType);
        assert_eq!(classes.little, vec![2, 3]);
    }

    #[test]
    fn capacity_bar_is_strict_at_85_percent() {
        // 0.85 of the top capacity exactly: no split, the fallback
        // decides. Just under it: the capacity branch splits.
        let uniform = vec![Some(1000u32), Some(1000), Some(850), Some(850)];
        let (ids, capacity, is_big, max_freq) =
            fixture(uniform, vec![Some(true); 4], vec![Some(5000000); 4]);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::NoSplit);
        assert_eq!(classes.big, (0..4).collect::<Vec<usize>>());

        let split = vec![Some(1000u32), Some(1000), Some(849), Some(849)];
        let (ids, capacity, is_big, max_freq) =
            fixture(split, vec![Some(true); 4], vec![Some(5000000); 4]);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::Capacity);
        assert_eq!(classes.big, vec![0, 1]);
        assert_eq!(classes.little, vec![2, 3]);
    }

    #[test]
    fn lp_boundary_is_strict_at_half_the_little_capacity() {
        // A rest CPU at exactly half the little tier's top capacity is
        // a little core; one step below it is an LP island.
        let at = vec![Some(1024u32), Some(800), Some(400), Some(400)];
        let (ids, capacity, is_big, max_freq) =
            fixture(at, vec![Some(true); 4], vec![Some(5000000); 4]);
        let (classes, _) = classify(&ids, &capacity, &is_big, &max_freq);
        assert!(classes.lp.is_empty());
        assert_eq!(classes.little, vec![1, 2, 3]);

        let below = vec![Some(1024u32), Some(800), Some(399), Some(399)];
        let (ids, capacity, is_big, max_freq) =
            fixture(below, vec![Some(true); 4], vec![Some(5000000); 4]);
        let (classes, _) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(classes.lp, vec![2, 3]);
        assert_eq!(classes.little, vec![1]);
    }

    #[test]
    fn unknown_capacity_cpus_fall_to_the_little_set() {
        // Partial capacity files: the split reads the CPUs that
        // reported, CPUs without a value are not big and land in the
        // little set (the pre-classification behavior, pinned).
        let caps = vec![Some(1024u32), Some(500), None, None];
        let (ids, capacity, is_big, max_freq) =
            fixture(caps, vec![Some(true); 4], vec![Some(5000000); 4]);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::Capacity);
        assert_eq!(classes.big, vec![0]);
        assert_eq!(classes.little, vec![1, 2, 3]);
    }

    #[test]
    fn only_little_core_types_publish_no_big_tier() {
        // Whatever the topology claims, one empty tier disables the
        // hybrid gates; here the little set carries everything.
        let n = 4;
        let (ids, capacity, is_big, max_freq) =
            fixture(vec![None; n], vec![Some(false); n], vec![Some(5000000); n]);
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);
        assert_eq!(source, TierSource::NoSplit);
        assert!(classes.big.is_empty());
        assert_eq!(classes.little, (0..n).collect::<Vec<usize>>());
    }

    #[test]
    fn real_host_classification_is_consistent() {
        // The live machine, whatever it is: the sets must partition the
        // CPUs, and when the capacity branch decided, the big set is
        // exactly the top-capacity CPUs and the LP islands sit below
        // half of the little tier.
        let capacity = |id: usize| {
            std::fs::read_to_string(format!("/sys/devices/system/cpu/cpu{id}/cpu_capacity"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
        };
        let topo = scx_utils::Topology::new().expect("topology");
        let ids: Vec<usize> = topo.all_cpus.keys().copied().collect();
        let is_big = |id: usize| {
            topo.all_cpus
                .get(&id)
                .map(|cpu| matches!(cpu.core_type, scx_utils::CoreType::Big { .. }))
        };
        let max_freq = |id: usize| {
            std::fs::read_to_string(format!(
                "/sys/devices/system/cpu/cpu{id}/cpufreq/cpuinfo_max_freq"
            ))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        };
        let (classes, source) = classify(&ids, &capacity, &is_big, &max_freq);

        let mut seen: Vec<usize> = classes.big.clone();
        seen.extend(&classes.little);
        seen.extend(&classes.lp);
        seen.sort_unstable();
        assert_eq!(seen, ids, "the classes must partition the CPUs");

        let caps_of =
            |set: &[usize]| -> Vec<Option<u32>> { set.iter().map(|id| capacity(*id)).collect() };
        if let Some(max_cap) = caps_of(&classes.big).into_iter().flatten().max() {
            for cap in caps_of(&classes.big) {
                assert_eq!(cap, Some(max_cap), "big cores share the top capacity");
            }
        }
        if source == TierSource::Capacity {
            let little_cap = caps_of(&classes.little)
                .into_iter()
                .flatten()
                .max()
                .expect("capacity split with an empty little set");
            for cap in caps_of(&classes.lp) {
                assert!(cap.is_some_and(|c| c * 2 < little_cap));
            }
        }
    }
}
