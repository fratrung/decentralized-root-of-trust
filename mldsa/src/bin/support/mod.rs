//! Shared, dependency-light helpers for the ML-DSA measurement binaries.

// Each binary uses a different subset of these helpers.
#![allow(dead_code)]

use sha3::{Digest, Sha3_256};

pub const MAX_UPDATES: usize = 64;

pub fn milliseconds(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// CPU time this process has consumed since it started: user plus system,
/// summed over every thread (`CLOCK_PROCESS_CPUTIME_ID`). The same clock as
/// the XMSS crate's `bench::timing::process_cpu_time`: each timed phase is
/// bracketed by it outside the elapsed timer, so every target reports both how
/// long a caller waits and how much CPU the work used.
pub fn process_cpu_time() -> std::time::Duration {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable `timespec` for the duration of the
    // call, and `clock_gettime` writes nothing else.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut now) };
    // A failure here would be reported as zero CPU; refuse instead.
    assert_eq!(status, 0, "clock_gettime(CLOCK_PROCESS_CPUTIME_ID) failed");
    std::time::Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

pub fn fingerprint(index: u32) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"decentralized-root-of-trust/ml-dsa-benchmark-entry/v1\0");
    hasher.update(index.to_le_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    bytes
}

/// The environment variable that fixes the list size, as in the XMSS crate's
/// `bench::workload`: unset keeps the default list growing by one entry per
/// version, `L` makes every version carry exactly `L` entries with one of them
/// replaced per version.
pub const LIST_ENTRIES_ENV: &str = "BENCH_LIST_ENTRIES";
pub const MAX_LIST_ENTRIES: usize = 1 << 20;

pub fn list_entries_from_env() -> Option<usize> {
    let raw = std::env::var(LIST_ENTRIES_ENV).ok()?;
    if raw.is_empty() {
        return None;
    }
    match raw.parse::<usize>() {
        Ok(entries) if (1..=MAX_LIST_ENTRIES).contains(&entries) => Some(entries),
        _ => panic!("{LIST_ENTRIES_ENV} must be an integer in 1..={MAX_LIST_ENTRIES}, got '{raw}'"),
    }
}

/// Turn the list of version `version - 1` into the list of `version`. Fresh
/// entries are numbered from `next_entry`, which is advanced.
pub fn advance_list(
    list: &mut Vec<[u8; 32]>,
    version: usize,
    fixed: Option<usize>,
    next_entry: &mut u32,
) {
    let mut fresh = || {
        let entry = fingerprint(*next_entry);
        *next_entry += 1;
        entry
    };
    match fixed {
        None => list.push(fresh()),
        Some(len) if list.len() != len => {
            list.clear();
            list.extend((0..len).map(|_| fresh()));
        }
        Some(len) => list[version.wrapping_sub(1) % len] = fresh(),
    }
}

/// How the fixtures choose each version's quorum; written to `workload.txt`.
pub const QUORUM_SELECTION: &str = "spread-splitmix64-v1";

/// What a fixture declares about its workload, as `workload.txt`: the list
/// size (`growing` for the default 1..=updates list) and how quorums were
/// chosen. `benchmark.sh` compares it with the workload it was asked for.
pub fn workload_manifest(list_entries: Option<usize>) -> String {
    let entries = list_entries.map_or("growing".to_string(), |len| len.to_string());
    format!("list_entries={entries}\nquorum={QUORUM_SELECTION}\n")
}

/// The smallest and largest list a measured process actually handled. Every
/// target prints it in its summary line as `list_min=.. list_max=..`, and
/// `benchmark.sh` refuses a run whose lists are not the declared workload: the
/// list size is then evidence from the measured process, not a label.
#[derive(Default)]
pub struct ListSizes(Option<(usize, usize)>);

impl ListSizes {
    pub fn record(&mut self, entries: usize) {
        self.0 = Some(match self.0 {
            None => (entries, entries),
            Some((min, max)) => (min.min(entries), max.max(entries)),
        });
    }
}

impl std::fmt::Display for ListSizes {
    /// `NA` when no list was seen: a missing reading is not a list of size 0.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some((min, max)) => write!(f, "list_min={min} list_max={max}"),
            None => write!(f, "list_min=NA list_max=NA"),
        }
    }
}

/// `t` distinct member indices out of `n`, spread over the whole committee and
/// determined by `version` alone: the same partial Fisher-Yates shuffle over
/// SplitMix64 as the XMSS fixture, so both corpora draw their quorums alike
/// and a small quorum is not confined to the start of a large anchor.
pub fn quorum_indices(n: usize, t: usize, version: u32) -> Vec<usize> {
    assert!(t <= n, "quorum {t} exceeds committee {n}");
    let mut state =
        0x9E37_79B9_7F4A_7C15_u64 ^ u64::from(version).wrapping_mul(0xD6E8_FEB8_6659_FD93);
    let mut next = move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut members: Vec<usize> = (0..n).collect();
    for position in 0..t {
        let pick = position + (next() % (n - position) as u64) as usize;
        members.swap(position, pick);
    }
    members.truncate(t);
    members
}

pub fn parse_count(text: &str, name: &str, max: usize) -> usize {
    let value = text
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{name} must be a positive decimal integer"));
    assert!((1..=max).contains(&value), "{name} must lie in 1..={max}");
    value
}

pub fn rss_mb(field: &str) -> usize {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("benchmark requires Linux /proc/self/status");
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .unwrap_or_else(|| panic!("missing {field} in /proc/self/status"));
    let kb: usize = line
        .split_whitespace()
        .nth(1)
        .expect("missing RSS value")
        .parse()
        .expect("invalid RSS value");
    kb / 1024
}

pub struct Summary {
    pub count: usize,
    pub min: f64,
    pub median: f64,
    pub max: f64,
    pub mean: f64,
    pub sd: f64,
    pub total: f64,
}

pub fn summary(values: &[f64]) -> Summary {
    assert!(
        !values.is_empty(),
        "cannot summarize an empty measurement series"
    );
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let count = sorted.len();
    let middle = count / 2;
    let median = if count.is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    };
    let total: f64 = sorted.iter().sum();
    let mean = total / count as f64;
    let sd = if count < 2 {
        0.0
    } else {
        (sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (count - 1) as f64).sqrt()
    };
    Summary {
        count,
        min: sorted[0],
        median,
        max: sorted[count - 1],
        mean,
        sd,
        total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_sizes_report_the_range_seen_and_never_a_zero_for_nothing() {
        let mut sizes = ListSizes::default();
        assert_eq!(sizes.to_string(), "list_min=NA list_max=NA");
        for entries in [3, 1, 20] {
            sizes.record(entries);
        }
        assert_eq!(sizes.to_string(), "list_min=1 list_max=20");
        assert_eq!(
            workload_manifest(Some(1000)),
            "list_entries=1000\nquorum=spread-splitmix64-v1\n"
        );
    }

    /// Only the lower bound: the clock covers the whole process, and the other
    /// tests of this binary run in parallel, so "waiting costs no CPU" cannot
    /// be asserted here. The XMSS crate's `tests/cpu_clock.rs` checks that, for
    /// the same system call, in a process of its own.
    #[test]
    fn the_cpu_clock_counts_work() {
        let window = std::time::Duration::from_millis(60);
        let before = process_cpu_time();
        let start = std::time::Instant::now();
        let mut x = 0u64;
        while start.elapsed() < window {
            x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
        let busy = process_cpu_time() - before;
        assert!(busy > window / 2, "a busy {window:?} cost only {busy:?}");
    }

    #[test]
    fn even_median_and_sample_deviation() {
        let result = summary(&[4.0, 1.0, 3.0, 2.0]);
        assert_eq!(result.median, 2.5);
        assert_eq!(result.mean, 2.5);
        assert!((result.sd - (5.0_f64 / 3.0).sqrt()).abs() < 1e-12);
    }

    #[test]
    fn quorum_matches_the_independent_vectors_shared_with_the_xmss_fixture() {
        assert_eq!(quorum_indices(10, 4, 3), [3, 5, 4, 0]);
        assert_eq!(quorum_indices(100, 5, 0), [0, 2, 20, 51, 46]);
    }

    #[test]
    fn a_fixed_list_keeps_its_size_and_changes_one_entry_per_version() {
        let mut list = Vec::new();
        let mut next_entry = 0;
        advance_list(&mut list, 0, Some(4), &mut next_entry);
        assert_eq!(list.len(), 4);
        for version in 1..10 {
            let before = list.clone();
            advance_list(&mut list, version, Some(4), &mut next_entry);
            assert_eq!((0..4).filter(|&i| list[i] != before[i]).count(), 1);
        }
        let mut growing = Vec::new();
        for version in 0..3 {
            advance_list(&mut growing, version, None, &mut next_entry);
            assert_eq!(growing.len(), version + 1);
        }
    }
}
