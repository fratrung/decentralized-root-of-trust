//! Persistent anti-rollback for the DHT layer.
//!
//! `verify_proof` is stateless: an old but validly signed `(list, version)` pair
//! verifies forever, so the cryptographic checks alone cannot stop a peer from
//! replaying a stale record. For an authorization list that is a real attack — an
//! old status list re-grants access to a node that has since been revoked. This
//! gate is the missing memory: it records the highest version accepted so far and
//! refuses anything that is not strictly newer.
//!
//! The rule is strict (`version > mark`), not a window: accepting an older version
//! would reopen exactly the rollback it is meant to close.
//!
//! The mark is scoped to a trust domain. It stores a fingerprint of the anchor it
//! was built against and resets when that anchor changes (a committee rotation),
//! because a version counter only totally-orders records under one committee. This
//! is *local verifier state* and must never be published.

use std::path::PathBuf;

use sha3::{Digest, Sha3_256};

/// Outcome of offering a version to the gate.
pub enum Decision {
    /// Strictly newer than the stored mark: it advanced and was persisted.
    Accepted,
    /// Not newer than the stored high-water (carried here) — refused.
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
    /// empty — a rotated committee legitimately resets the counter.
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

    fn persist(&self) {
        let line = format!("{} {}\n", self.fingerprint, self.current);
        // Write-then-rename so a concurrent reader never sees a half-written mark.
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, line).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
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

/// Parses `"<fingerprint> <version>"`, returning the version only if the
/// fingerprint matches this domain — a different anchor means an unrelated
/// counter, so we treat it as no mark at all.
fn parse(s: &str, fingerprint: &str) -> Option<(u32, bool)> {
    let mut it = s.split_whitespace();
    let fp = it.next()?;
    let version: u32 = it.next()?.parse().ok()?;
    (fp == fingerprint).then_some((version, true))
}
