//! Persistent anti-rollback state for a status-list verifier.
//!
//! The gate accepts only versions strictly above its mark. It is scoped to an
//! anchor fingerprint, so a state file can never be reused silently under a
//! different anchor. This state is local and must not be published.

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

/// Why the freshness gate could not be used safely.
#[derive(Debug)]
pub enum HighWaterMarkError {
    /// The state is missing, malformed, foreign, or would be overwritten.
    State(String),
    /// Another process already holds the mark for this status list.
    Busy,
    /// The mark could not be locked or durably written.
    Io(std::io::Error),
}

impl std::fmt::Display for HighWaterMarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(m) => write!(f, "unusable high-water mark: {m}"),
            Self::Busy => write!(f, "another process holds this high-water mark"),
            Self::Io(e) => write!(f, "high-water mark I/O failed: {e}"),
        }
    }
}

impl std::error::Error for HighWaterMarkError {}

impl From<std::io::Error> for HighWaterMarkError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The highest version accepted so far, persisted across restarts.
pub struct HighWaterMark {
    path: PathBuf,
    fingerprint: String, // hex of Sha3-256(anchor): the trust-domain tag
    current: u32,
    have: bool, // false = nothing accepted yet (so version 0 is still distinguishable)
    /// Held for the lifetime of the mark. The lock lives in a sibling file so the
    /// atomic rename of the state file cannot discard it.
    _lock: File,
}

impl HighWaterMark {
    /// Initialises a mark for a verifier that has never accepted a record.
    ///
    /// The empty state is persisted before this returns. Any existing filesystem
    /// entry is refused, including malformed or foreign state: initialization is
    /// not recovery, and overwriting here would silently discard rollback
    /// protection.
    pub fn create(path: impl Into<PathBuf>, anchor: &[u8]) -> Result<Self, HighWaterMarkError> {
        let path = path.into();
        let lock = acquire_lock(&path)?;
        let fingerprint = fingerprint(anchor);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(HighWaterMarkError::State(format!(
                    "{} already exists; refusing to reset freshness state",
                    path.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(HighWaterMarkError::Io(e)),
        }
        let mark = Self {
            path,
            fingerprint,
            current: 0,
            have: false,
            _lock: lock,
        };
        mark.persist(None)?;
        Ok(mark)
    }

    /// Opens existing state for the trust domain identified by `anchor`.
    ///
    /// Missing, unreadable, malformed, and foreign-anchor state are all errors.
    /// None can be distinguished safely from loss of an established mark, so
    /// callers must either repair it or use [`Self::load_from_trusted_source`]
    /// after authenticating the VDR's canonical-latest record.
    pub fn open(path: impl Into<PathBuf>, anchor: &[u8]) -> Result<Self, HighWaterMarkError> {
        let path = path.into();
        let lock = acquire_lock(&path)?;
        let fingerprint = fingerprint(anchor);
        let bytes = std::fs::read(&path).map_err(|e| {
            HighWaterMarkError::State(format!("cannot read {}: {e}", path.display()))
        })?;
        let raw = std::str::from_utf8(&bytes).map_err(|e| {
            HighWaterMarkError::State(format!("{} is not UTF-8: {e}", path.display()))
        })?;
        let (current, have) = parse(raw, &fingerprint).map_err(HighWaterMarkError::State)?;
        Ok(Self {
            path,
            fingerprint,
            current,
            have,
            _lock: lock,
        })
    }

    /// Reconstructs missing or invalid local state from a trusted freshness
    /// source, such as the deployment's Verifiable Data Registry.
    ///
    /// `authenticated_latest_version` must come from the registry's
    /// canonical-latest record *after* that raw or SNARK record has verified
    /// under exactly `anchor`. Cryptographic validity alone is insufficient: an
    /// old signed record is valid but is not a safe recovery checkpoint.
    ///
    /// This is an explicit recovery operation, not an alternate open path. It
    /// writes the recovered version directly, with no durable empty-state window,
    /// and refuses to overwrite any valid state for this anchor. A caller that
    /// can open a valid mark must use normal monotonic advancement instead.
    pub fn load_from_trusted_source(
        path: impl Into<PathBuf>,
        anchor: &[u8],
        authenticated_latest_version: u32,
    ) -> Result<Self, HighWaterMarkError> {
        let path = path.into();
        let lock = acquire_lock(&path)?;
        let fingerprint = fingerprint(anchor);

        match std::fs::read(&path) {
            Ok(bytes)
                if std::str::from_utf8(&bytes)
                    .is_ok_and(|raw| parse(raw, &fingerprint).is_ok()) =>
            {
                return Err(HighWaterMarkError::State(format!(
                    "{} contains valid state; refusing trusted-source recovery",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(HighWaterMarkError::Io(e)),
        }

        let mark = Self {
            path,
            fingerprint,
            current: authenticated_latest_version,
            have: true,
            _lock: lock,
        };
        mark.persist(Some(authenticated_latest_version))?;
        Ok(mark)
    }

    /// The current mark, or `None` if nothing has been accepted for this domain.
    pub fn current(&self) -> Option<u32> {
        self.have.then_some(self.current)
    }

    /// Strict monotonic rule: accept `version` only if it is strictly greater than
    /// the stored mark. On acceptance the mark is persisted before memory moves,
    /// so a failed write cannot make callers act on a version that will be
    /// forgotten after restart.
    pub fn try_advance(&mut self, version: u32) -> Result<Decision, HighWaterMarkError> {
        if self.have && version <= self.current {
            return Ok(Decision::Stale(self.current));
        }
        self.persist(Some(version))?;
        self.current = version;
        self.have = true;
        Ok(Decision::Accepted)
    }

    /// Persists with write + fsync, atomic rename, and a directory fsync.
    fn persist(&self, version: Option<u32>) -> Result<(), HighWaterMarkError> {
        let value = version.map_or_else(|| "none".to_owned(), |v| v.to_string());
        let line = format!("{} {value}\n", self.fingerprint);
        // Appending avoids colliding dotted state-file names.
        let tmp = crate::state::slot_counter::sibling(&self.path, "tmp");

        let mut f = File::create(&tmp)?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
        drop(f);

        std::fs::rename(&tmp, &self.path)?;
        let dir = self.path.parent().filter(|p| !p.as_os_str().is_empty());
        File::open(dir.unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(())
    }
}

fn acquire_lock(path: &Path) -> Result<File, HighWaterMarkError> {
    let lock_path = crate::state::slot_counter::sibling(path, "lock");
    let file = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    file.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => HighWaterMarkError::Busy,
        std::fs::TryLockError::Error(e) => HighWaterMarkError::Io(e),
    })?;
    Ok(file)
}

fn fingerprint(anchor: &[u8]) -> String {
    let digest = Sha3_256::digest(anchor);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parses exactly one canonical mark for this anchor fingerprint.
fn parse(s: &str, fingerprint: &str) -> Result<(u32, bool), String> {
    let mut it = s.split_whitespace();
    let fp = it.next().ok_or_else(|| "empty state file".to_owned())?;
    let value = it
        .next()
        .ok_or_else(|| "missing freshness value".to_owned())?;
    if it.next().is_some() {
        return Err("trailing data in state file".to_owned());
    }
    if fp != fingerprint {
        return Err("state file belongs to a different anchor".to_owned());
    }
    if value == "none" {
        return Ok((0, false));
    }
    let version = value
        .parse::<u32>()
        .map_err(|e| format!("unparseable freshness value: {e}"))?;
    Ok((version, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hwm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::remove_file(crate::state::slot_counter::sibling(&p, "tmp"));
        let _ = std::fs::remove_dir_all(crate::state::slot_counter::sibling(&p, "tmp"));
        let _ = std::fs::remove_file(crate::state::slot_counter::sibling(&p, "lock"));
        p
    }

    fn accepted(d: Result<Decision, HighWaterMarkError>) -> bool {
        matches!(d, Ok(Decision::Accepted))
    }

    /// The whole point of the gate: `>` and not `>=`. Re-accepting an equal
    /// version would let a peer replay the record currently in force, and any
    /// window at all below the mark reopens the rollback it exists to close.
    #[test]
    fn only_strictly_newer_versions_advance_the_mark() {
        let mut hwm = HighWaterMark::create(scratch("strict"), b"anchor-A").unwrap();

        // Nothing accepted yet, so version 0 is still a real advance: this is why
        // the type carries `have` instead of treating 0 as "empty".
        assert_eq!(hwm.current(), None);
        assert!(accepted(hwm.try_advance(0)));
        assert_eq!(hwm.current(), Some(0));

        // Equal is not newer.
        assert!(matches!(hwm.try_advance(0), Ok(Decision::Stale(0))));

        assert!(accepted(hwm.try_advance(7)));
        // Older is refused, and the refusal does not disturb the mark.
        assert!(matches!(hwm.try_advance(6), Ok(Decision::Stale(7))));
        assert!(matches!(hwm.try_advance(0), Ok(Decision::Stale(7))));
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

        let mut hwm = HighWaterMark::create(&path, anchor).unwrap();
        assert!(accepted(hwm.try_advance(42)));
        drop(hwm);

        let mut reloaded = HighWaterMark::open(&path, anchor).unwrap();
        assert_eq!(reloaded.current(), Some(42));
        assert!(matches!(reloaded.try_advance(42), Ok(Decision::Stale(42))));
        assert!(accepted(reloaded.try_advance(43)));
    }

    /// Reusing one state path under another anchor is ambiguous: it could be a
    /// legitimate rotation, a configuration error, or an attack. Opening it must
    /// therefore fail rather than silently reset rollback protection.
    #[test]
    fn a_different_anchor_is_refused() {
        let path = scratch("domain");

        let mut a = HighWaterMark::create(&path, b"anchor-A").unwrap();
        assert!(accepted(a.try_advance(500)));
        drop(a);

        assert!(matches!(
            HighWaterMark::open(&path, b"anchor-B"),
            Err(HighWaterMarkError::State(_))
        ));

        let reopened = HighWaterMark::open(&path, b"anchor-A").unwrap();
        assert_eq!(reopened.current(), Some(500));
    }

    /// A corrupt mark is indistinguishable from lost anti-rollback state. It must
    /// stop normal startup rather than turn an old authentic record into a first
    /// acceptance again.
    #[test]
    fn a_corrupt_file_is_refused() {
        let path = scratch("corrupt");
        std::fs::write(&path, "not-a-fingerprint\n").unwrap();
        assert!(matches!(
            HighWaterMark::open(&path, b"anchor-A"),
            Err(HighWaterMarkError::State(_))
        ));
    }

    #[test]
    fn a_live_mark_locks_its_state_file() {
        let path = scratch("lock");

        let held = HighWaterMark::create(&path, b"anchor-A").expect("first mark");
        assert!(matches!(
            HighWaterMark::open(&path, b"anchor-A"),
            Err(HighWaterMarkError::Busy)
        ));
        drop(held);
        assert!(HighWaterMark::open(&path, b"anchor-A").is_ok());
    }

    #[test]
    fn a_persistence_failure_does_not_advance_memory() {
        let path = scratch("persist-failure");
        let mut hwm = HighWaterMark::create(&path, b"anchor-A").unwrap();
        let tmp = crate::state::slot_counter::sibling(&path, "tmp");
        std::fs::create_dir(&tmp).unwrap();

        assert!(matches!(hwm.try_advance(1), Err(HighWaterMarkError::Io(_))));
        assert_eq!(hwm.current(), None);

        drop(hwm);
        std::fs::remove_dir_all(&tmp).unwrap();
        assert_eq!(
            HighWaterMark::open(&path, b"anchor-A").unwrap().current(),
            None
        );
    }

    #[test]
    fn create_is_explicit_and_never_overwrites_state() {
        let path = scratch("create");
        let created = HighWaterMark::create(&path, b"anchor-A").unwrap();
        assert_eq!(created.current(), None);
        drop(created);

        assert_eq!(
            HighWaterMark::open(&path, b"anchor-A").unwrap().current(),
            None
        );
        assert!(matches!(
            HighWaterMark::create(&path, b"anchor-A"),
            Err(HighWaterMarkError::State(_))
        ));
        assert!(matches!(
            HighWaterMark::open(scratch("missing"), b"anchor-A"),
            Err(HighWaterMarkError::State(_))
        ));
    }

    #[test]
    fn legacy_numeric_state_remains_compatible_but_trailing_data_is_rejected() {
        let path = scratch("legacy");
        std::fs::write(&path, format!("{} 17\n", fingerprint(b"anchor-A"))).unwrap();
        assert_eq!(
            HighWaterMark::open(&path, b"anchor-A").unwrap().current(),
            Some(17)
        );

        std::fs::write(
            &path,
            format!("{} 17 unexpected\n", fingerprint(b"anchor-A")),
        )
        .unwrap();
        assert!(matches!(
            HighWaterMark::open(&path, b"anchor-A"),
            Err(HighWaterMarkError::State(_))
        ));
    }

    #[test]
    fn trusted_source_recovery_persists_the_authenticated_latest_version() {
        let path = scratch("trusted-source");
        let mut recovered =
            HighWaterMark::load_from_trusted_source(&path, b"anchor-A", 42).unwrap();
        assert_eq!(recovered.current(), Some(42));
        assert!(matches!(recovered.try_advance(42), Ok(Decision::Stale(42))));
        drop(recovered);

        let mut reopened = HighWaterMark::open(&path, b"anchor-A").unwrap();
        assert_eq!(reopened.current(), Some(42));
        assert!(matches!(reopened.try_advance(7), Ok(Decision::Stale(42))));
        assert!(accepted(reopened.try_advance(43)));
    }

    #[test]
    fn trusted_source_recovery_replaces_invalid_but_never_valid_state() {
        let corrupt = scratch("recover-corrupt");
        std::fs::write(&corrupt, [0xff, 0xfe]).unwrap();
        assert_eq!(
            HighWaterMark::load_from_trusted_source(&corrupt, b"anchor-A", 9)
                .unwrap()
                .current(),
            Some(9)
        );

        let foreign = scratch("recover-foreign");
        drop(HighWaterMark::create(&foreign, b"anchor-B").unwrap());
        assert_eq!(
            HighWaterMark::load_from_trusted_source(&foreign, b"anchor-A", 10)
                .unwrap()
                .current(),
            Some(10)
        );

        let valid = scratch("recover-valid");
        drop(HighWaterMark::create(&valid, b"anchor-A").unwrap());
        assert!(matches!(
            HighWaterMark::load_from_trusted_source(&valid, b"anchor-A", 11),
            Err(HighWaterMarkError::State(_))
        ));
    }
}
