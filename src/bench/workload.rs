//! The benchmark workload: how large the status list is and who signs it.
//!
//! Both are parameters of every figure the harness reports, so they are
//! declared rather than left to how a fixture happened to be written.
//!
//! **List size.** A record carries the whole list (32 bytes per credential) and
//! every scheme must read it to authenticate it, so list size enters record
//! size and verification time. The default workload grows the list by one
//! entry per version (1..=`N_UPDATES` entries): cheap, but it says nothing
//! about a list of realistic size. `BENCH_LIST_ENTRIES=L` makes every
//! version carry exactly `L` entries, one of them replaced per version — a
//! credential issued and one revoked, with the snapshot size held constant.
//!
//! **Quorum.** A contiguous window of signers starting at the version number
//! would, in a large committee, only ever use members near the start of the
//! anchor, and a verifier that looks signers up by scanning the member list
//! would see shorter scans than a deployment does. `quorum_indices` therefore
//! picks `t` distinct members spread over the whole committee, reproducibly
//! from the version alone.

/// The environment variable that fixes the list size.
pub const LIST_ENTRIES_ENV: &str = "BENCH_LIST_ENTRIES";
/// Largest accepted list size: 32 MiB of entries.
pub const MAX_LIST_ENTRIES: usize = 1 << 20;

/// `Some(L)` when `BENCH_LIST_ENTRIES` asks for fixed-size lists, `None` for
/// the default growing list. Anything that is not an integer in
/// `1..=MAX_LIST_ENTRIES` stops the process: a misspelt size must not silently
/// fall back to another workload.
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

/// Turn the list of version `version - 1` into the list of `version`.
///
/// With `fixed = None` one entry is appended. With `fixed = Some(len)` the
/// list is filled to `len` entries at version 0 and afterwards has one entry
/// replaced per version, cycling through the positions.
pub fn advance_list(
    list: &mut Vec<[u8; 32]>,
    version: usize,
    fixed: Option<usize>,
    mut fresh: impl FnMut() -> [u8; 32],
) {
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
/// determined by `version` alone (a partial Fisher–Yates shuffle driven by
/// SplitMix64). Not a security mechanism: fixtures only.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn counter() -> impl FnMut() -> [u8; 32] {
        let mut next = 0u32;
        move || {
            next += 1;
            let mut entry = [0u8; 32];
            entry[..4].copy_from_slice(&next.to_le_bytes());
            entry
        }
    }

    #[test]
    fn list_sizes_report_the_range_seen_and_never_a_zero_for_nothing() {
        let mut sizes = ListSizes::default();
        assert_eq!(sizes.to_string(), "list_min=NA list_max=NA");
        for entries in [3, 1, 20] {
            sizes.record(entries);
        }
        assert_eq!(sizes.to_string(), "list_min=1 list_max=20");
        assert_eq!(
            workload_manifest(None),
            "list_entries=growing\nquorum=spread-splitmix64-v1\n"
        );
        assert_eq!(
            workload_manifest(Some(1000)),
            "list_entries=1000\nquorum=spread-splitmix64-v1\n"
        );
    }

    #[test]
    fn the_default_list_grows_by_one_entry_per_version() {
        let mut list = Vec::new();
        let mut fresh = counter();
        for version in 0..5 {
            advance_list(&mut list, version, None, &mut fresh);
            assert_eq!(list.len(), version + 1);
        }
    }

    #[test]
    fn a_fixed_list_keeps_its_size_and_changes_one_entry_per_version() {
        let mut list = Vec::new();
        let mut fresh = counter();
        advance_list(&mut list, 0, Some(4), &mut fresh);
        assert_eq!(list.len(), 4);
        for version in 1..10 {
            let before = list.clone();
            advance_list(&mut list, version, Some(4), &mut fresh);
            assert_eq!(list.len(), 4);
            let changed = (0..4).filter(|&i| list[i] != before[i]).count();
            assert_eq!(changed, 1, "version {version} changed {changed} entries");
        }
    }

    #[test]
    fn a_quorum_is_distinct_in_range_reproducible_and_spread() {
        for (n, t) in [(1, 1), (5, 4), (100, 67), (1500, 1001)] {
            let quorum = quorum_indices(n, t, 3);
            assert_eq!(quorum.len(), t);
            let mut sorted = quorum.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), t, "repeated signer for N={n}");
            assert!(sorted.iter().all(|&index| index < n));
            assert_eq!(quorum, quorum_indices(n, t, 3));
        }
        // Values from an independent Python implementation of the same shuffle;
        // the ML-DSA fixture pins the identical vectors, so both crates spread
        // their quorums the same way.
        assert_eq!(quorum_indices(10, 4, 3), [3, 5, 4, 0]);
        assert_eq!(quorum_indices(100, 5, 0), [0, 2, 20, 51, 46]);
        // Different versions use different quorums, and a small quorum of a
        // large committee is not confined to the start of the anchor.
        assert_ne!(quorum_indices(100, 67, 0), quorum_indices(100, 67, 1));
        let late = (0..20)
            .flat_map(|version| quorum_indices(1500, 10, version))
            .filter(|&index| index >= 750)
            .count();
        assert!(
            (60..=140).contains(&late),
            "{late} of 200 picks in the upper half"
        );
    }
}
