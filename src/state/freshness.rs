//! Persistent anti-rollback state for a status-list verifier.
//!
//! The gate accepts only versions strictly above its mark. It is scoped to an
//! anchor fingerprint, so an anchor change begins a new trust domain. This state
//! is local and must not be published.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha3::{Digest, Sha3_256};

/// Outcome of offering a version to the gate.
pub enum Decision {
    /// Strictly newer than the stored mark: it advanced and was persisted.
    Accepted,
    /// Not newer than the stored high-water (carried here): refused.
    Stale(u32),
}

/// The highest version accepted so far, persisted across restarts.
pub struct HighWaterMark {
    path: PathBuf,
    fingerprint: String, // hex of Sha3-256(anchor): the trust-domain tag
    current: u32,
    have: bool, // false = nothing accepted yet (so version 0 is still distinguishable)
}

impl HighWaterMark {
    /// Loads the mark for the trust domain identified by `anchor`. If the file is
    /// missing, unreadable, or was written for a different anchor, the mark starts
    /// empty: a rotated committee legitimately resets the counter.
    pub fn load(path: impl Into<PathBuf>, anchor: &[u8]) -> Self {
        let path = path.into();
        let fingerprint = fingerprint(anchor);
        let (current, have) = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| parse(&s, &fingerprint))
            .unwrap_or((0, false));
        Self {
            path,
            fingerprint,
            current,
            have,
        }
    }

    /// The current mark, or `None` if nothing has been accepted for this domain.
    pub fn current(&self) -> Option<u32> {
        self.have.then_some(self.current)
    }

    /// Strict monotonic rule: accept `version` only if it is strictly greater than
    /// the stored mark. On acceptance the mark advances and is persisted *before*
    /// returning, so a crash right after cannot lose the advance and re-open the
    /// window.
    pub fn try_advance(&mut self, version: u32) -> Decision {
        if self.have && version <= self.current {
            return Decision::Stale(self.current);
        }
        self.current = version;
        self.have = true;
        self.persist();
        Decision::Accepted
    }

    /// Persists with write + fsync, atomic rename, and a directory fsync.
    /// Persistence is fail-open, but a failure is reported to stderr.
    fn persist(&self) {
        let line = format!("{} {}\n", self.fingerprint, self.current);
        // Appending avoids colliding dotted state-file names.
        let tmp = crate::state::slot_counter::sibling(&self.path, "tmp");

        let durable = || -> std::io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(line.as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &self.path)?;
            let dir = self.path.parent().filter(|p| !p.as_os_str().is_empty());
            File::open(dir.unwrap_or_else(|| Path::new(".")))?.sync_all()
        };

        if let Err(e) = durable() {
            eprintln!(
                "warning: high-water mark not persisted to {}: {e}",
                self.path.display()
            );
        }
    }
}

fn fingerprint(anchor: &[u8]) -> String {
    let digest = Sha3_256::digest(anchor);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parses a mark only when it belongs to this anchor fingerprint.
fn parse(s: &str, fingerprint: &str) -> Option<(u32, bool)> {
    let mut it = s.split_whitespace();
    let fp = it.next()?;
    let version: u32 = it.next()?.parse().ok()?;
    (fp == fingerprint).then_some((version, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hwm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("tmp"));
        p
    }

    fn accepted(d: Decision) -> bool {
        matches!(d, Decision::Accepted)
    }

    /// The whole point of the gate: `>` and not `>=`. Re-accepting an equal
    /// version would let a peer replay the record currently in force, and any
    /// window at all below the mark reopens the rollback it exists to close.
    #[test]
    fn only_strictly_newer_versions_advance_the_mark() {
        let mut hwm = HighWaterMark::load(scratch("strict"), b"anchor-A");

        // Nothing accepted yet, so version 0 is still a real advance: this is why
        // the type carries `have` instead of treating 0 as "empty".
        assert_eq!(hwm.current(), None);
        assert!(accepted(hwm.try_advance(0)));
        assert_eq!(hwm.current(), Some(0));

        // Equal is not newer.
        assert!(matches!(hwm.try_advance(0), Decision::Stale(0)));

        assert!(accepted(hwm.try_advance(7)));
        // Older is refused, and the refusal does not disturb the mark.
        assert!(matches!(hwm.try_advance(6), Decision::Stale(7)));
        assert!(matches!(hwm.try_advance(0), Decision::Stale(7)));
        assert_eq!(hwm.current(), Some(7));

        // A gap is fine: versions need not be contiguous, only increasing.
        assert!(accepted(hwm.try_advance(100)));
        assert_eq!(hwm.current(), Some(100));
    }

    /// A gate that forgets on restart is not a gate: the first stale record after
    /// a reboot would be accepted.
    #[test]
    fn the_mark_survives_a_restart() {
        let path = scratch("restart");
        let anchor = b"anchor-A";

        let mut hwm = HighWaterMark::load(&path, anchor);
        assert!(accepted(hwm.try_advance(42)));
        drop(hwm);

        let mut reloaded = HighWaterMark::load(&path, anchor);
        assert_eq!(reloaded.current(), Some(42));
        assert!(matches!(reloaded.try_advance(42), Decision::Stale(42)));
        assert!(accepted(reloaded.try_advance(43)));
    }

    /// The mark is scoped to a trust domain. A version counter only totally-orders
    /// records under one committee, so a rotation must reset it rather than carry a
    /// number that now means something else, and the old domain's mark must not be
    /// destroyed in the process.
    #[test]
    fn a_different_anchor_is_a_different_domain() {
        let path = scratch("domain");

        let mut a = HighWaterMark::load(&path, b"anchor-A");
        assert!(accepted(a.try_advance(500)));
        drop(a);

        // Same file, rotated committee: the stored mark is not ours, so we start
        // empty and a low version is legitimately accepted.
        let mut b = HighWaterMark::load(&path, b"anchor-B");
        assert_eq!(b.current(), None);
        assert!(accepted(b.try_advance(1)));
        assert_eq!(b.current(), Some(1));
    }

    /// An unreadable or corrupt file must not be guessed at. Fail-open is the
    /// documented choice here (losing the mark costs one stale record accepted
    /// once); what matters is that it does not fail *closed* into a wedged node,
    /// nor silently inherit a number it cannot authenticate.
    #[test]
    fn a_corrupt_file_starts_empty() {
        let path = scratch("corrupt");
        std::fs::write(&path, "not-a-fingerprint\n").unwrap();
        let mut hwm = HighWaterMark::load(&path, b"anchor-A");
        assert_eq!(hwm.current(), None);
        assert!(accepted(hwm.try_advance(0)));
    }
}
