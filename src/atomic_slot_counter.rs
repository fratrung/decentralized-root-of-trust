//! Durable, monotonic slot allocator for one XMSS key.
//!
//! XMSS is a **stateful** signature scheme. Each `(key, slot)` pair may sign
//! exactly once; signing two different messages under one slot reveals enough of
//! the WOTS hash chains to forge signatures for that slot, and the key is gone.
//! Unlike a rollback on the verifier side this is not recoverable, so every
//! choice in this module is made in the pessimistic direction.
//!
//! Everything rests on one ordering rule:
//!
//! > **The slot is burned on disk, durably, *before* it is handed to the signer.**
//!
//! Persisting after signing is the natural-looking order and it is wrong: a crash
//! between the signature and the write leaves the slot looking free, so the next
//! boot signs a *different* message under it. Burning first means a crash can only
//! ever waste slots, never reuse them — and wasting is free, since a key covers
//! `2^32` of them.
//!
//! The caller's policy then follows for nothing: a slot is consumed at reservation
//! time, so whatever happens downstream — aggregation fails, the proof does not
//! verify, the publish is refused — the slot is *not* reused. There is no
//! `release`, by design. The counter only ever moves forward.
//!
//! Contrast with [`crate::freshness`]: that gate is deliberately fail-**open** (a
//! missing mark just means "nothing accepted yet"; worst case one stale record is
//! accepted once). This counter is fail-**closed**: a missing or unreadable state
//! file aborts signing, because the alternative is to restart from the first slot
//! and silently reuse every slot the key has already spent. That is also why
//! [`AtomicSlotCounter::create`] and [`AtomicSlotCounter::open`] are separate —
//! initialising state is an explicit first-install act, never a fallback.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use lean_multisig::XmssPublicKey;
use sha3::{Digest, Sha3_256};


/// Writes `next_free` so that it survives a power cut, then returns.
///
/// The four steps are all load-bearing:
///   1. write the replacement to a temporary file;
///   2. `fsync` it, so its *contents* reach the medium;
///   3. `rename` over the target — atomic on POSIX, so a reader or a crash sees
///      either the whole old record or the whole new one, never a mix;
///   4. `fsync` the *directory*, so the rename itself is durable.
///
/// Step 4 is the one usually missing. Without it the contents are safe but the
/// directory entry may still point at the old inode after a crash, which for this
/// counter means resurrecting spent slots.
fn persist(path: &Path, key_tag: &str, next_free: u32) -> Result<(), AtomicSlotCounterError> {
    let tmp = path.with_extension("tmp");

    let mut f = File::create(&tmp)?;
    f.write_all(format!("{key_tag} {next_free}\n").as_bytes())?;
    f.sync_all()?;
    drop(f);

    fs::rename(&tmp, path)?;

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}

/// Advisory lock guarding one key's counter, so two processes cannot hand out the
/// same slot. It lives on a *separate* file: locking the state file we replace by
/// rename would leave the lock attached to the old, now orphaned inode, and two
/// processes would each believe they hold it.
fn acquire_lock(state_path: &Path) -> Result<File, AtomicSlotCounterError> {
    let lock_path = state_path.with_extension("lock");
    let file = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    file.try_lock()
        .map_err(|_| AtomicSlotCounterError::Busy)?;
    Ok(file)
}

fn key_fingerprint(pk: &XmssPublicKey) -> String {
    let bytes = postcard::to_allocvec(pk).expect("public key serialization failed");
    Sha3_256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Parses `"<fingerprint> <next_free>"`. Every failure mode is an error, never a
/// default: a counter we cannot read is a counter we must not guess.
fn parse(s: &str, key_tag: &str) -> Result<u32, AtomicSlotCounterError> {
    let mut it = s.split_whitespace();
    let fp = it
        .next()
        .ok_or_else(|| AtomicSlotCounterError::State("empty state file".into()))?;
    let next = it
        .next()
        .ok_or_else(|| AtomicSlotCounterError::State("missing slot counter".into()))?;
    if fp != key_tag {
        return Err(AtomicSlotCounterError::State(
            "state file belongs to a different key".into(),
        ));
    }
    next.parse::<u32>()
        .map_err(|e| AtomicSlotCounterError::State(format!("unparseable slot counter: {e}")))
}

/// Everything that can stop the counter from issuing a slot.
///
/// Every variant is a refusal. There is deliberately no variant meaning
/// "carry on with a guessed slot".
#[derive(Debug)]
pub enum AtomicSlotCounterError {
    /// The key's slot window is used up. Only a re-key fixes this.
    Exhausted { next: u32, end: u32 },
    /// The state file is missing, malformed, or belongs to a different key.
    /// Refusing here is the whole point: see the module docs.
    State(String),
    /// Another process already holds the lock on this key's state.
    Busy,
    /// The state could not be read or durably written.
    Io(std::io::Error),
}

impl std::fmt::Display for AtomicSlotCounterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted { next, end } => write!(
                f,
                "slot window exhausted (next {next} > end {end}); re-key required"
            ),
            Self::State(m) => write!(f, "unusable slot state: {m}"),
            Self::Busy => write!(f, "another process holds this key"),
            Self::Io(e) => write!(f, "slot state I/O failed: {e}"),
        }
    }
}

impl std::error::Error for AtomicSlotCounterError {}

impl From<std::io::Error> for AtomicSlotCounterError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The on-disk record is a single line, `"<key fingerprint> <next_free>"`, where
/// every slot below `next_free` is considered spent. The fingerprint ties the
/// counter to one key: a state file written for a different key is rejected
/// outright rather than reset, because it says nothing about *this* key's history.
pub struct AtomicSlotCounter {
    path: PathBuf,
    key_tag: String,
    /// Next slot to hand out (in memory). Invariant: `next <= durable`.
    next: u32,
    /// Highest `next_free` written to disk. Slots in `next..durable` are already
    /// burned on disk and can be handed out without another fsync.
    durable: u32,
    /// Last usable slot, inclusive (as passed to `xmss_key_gen`).
    end: u32,
    /// How many slots to burn per fsync. See [`AtomicSlotCounter::with_batch`].
    batch: u32,
    /// Held for the counter's whole lifetime: cross-process mutual exclusion.
    _lock: File,
}

impl AtomicSlotCounter {
    /// Initialises the counter for a brand-new key. Fails if the state file
    /// already exists — overwriting it would reset a counter that is very likely
    /// still live, which is precisely the accident this module exists to prevent.
    pub fn create(
        path: impl Into<PathBuf>,
        pk: &XmssPublicKey,
        slot_start: u32,
        slot_end: u32,
    ) -> Result<Self, AtomicSlotCounterError> {
        let path = path.into();
        if path.exists() {
            return Err(AtomicSlotCounterError::State(format!(
                "{} already exists; refusing to reset a live counter",
                path.display()
            )));
        }
        let key_tag = key_fingerprint(pk);
        let lock = acquire_lock(&path)?;
        persist(&path, &key_tag, slot_start)?;
        Ok(Self {
            path,
            key_tag,
            next: slot_start,
            durable: slot_start,
            end: slot_end,
            batch: 1,
            _lock: lock,
        })
    }

    /// Resumes an existing counter. `slot_end` must be the same bound the key was
    /// generated for; it is passed here because leanVM keeps the secret key's
    /// `slot_start` / `slot_end` `pub(crate)`, so this crate cannot read them back.
    ///
    /// A missing, truncated, or foreign state file is an error, never a fresh
    /// start. If you genuinely have a new key, call [`AtomicSlotCounter::create`].
    pub fn open(
        path: impl Into<PathBuf>,
        pk: &XmssPublicKey,
        slot_end: u32,
    ) -> Result<Self, AtomicSlotCounterError> {
        let path = path.into();
        let key_tag = key_fingerprint(pk);
        let lock = acquire_lock(&path)?;
        let raw = fs::read_to_string(&path).map_err(|e| {
            AtomicSlotCounterError::State(format!("cannot read {}: {e}", path.display()))
        })?;
        let next = parse(&raw, &key_tag)?;
        // Everything below the persisted `next_free` is treated as spent. This is
        // what makes a crash mid-window safe: the unused tail of the previous
        // reservation is skipped, never replayed.
        Ok(Self {
            path,
            key_tag,
            next,
            durable: next,
            end: slot_end,
            batch: 1,
            _lock: lock,
        })
    }

    /// Burns `batch` slots per fsync instead of one.
    ///
    /// An fsync costs milliseconds on an SSD and considerably more on the SD card
    /// of an embedded controller, so paying one per signature can dominate
    /// signing. Reserving a window amortises it; the cost is that an unclean
    /// shutdown discards the unused remainder of that window. That is the harmless
    /// direction — slots are skipped, never reused — so the only real budget is
    /// how much of the `2^32` window you are willing to waste per crash.
    ///
    /// `batch = 1` (the default) wastes nothing and fsyncs every signature.
    pub fn with_batch(mut self, batch: u32) -> Self {
        self.batch = batch.max(1);
        self
    }

    /// The next slot that would be handed out.
    pub fn next_slot(&self) -> u32 {
        self.next
    }

    /// Slots left in the window.
    pub fn remaining(&self) -> u64 {
        (u64::from(self.end) + 1).saturating_sub(u64::from(self.next))
    }

    /// Reserves the next slot, making it durably spent **before** returning it.
    ///
    /// Once this returns `Ok(slot)`, that slot must be considered consumed
    /// whatever the caller does with it — including doing nothing at all.
    pub fn reserve(&mut self) -> Result<u32, AtomicSlotCounterError> {
        if self.next > self.end {
            return Err(AtomicSlotCounterError::Exhausted {
                next: self.next,
                end: self.end,
            });
        }
        if self.next >= self.durable {
            // Extend the durable window. Saturating at `end + 1` keeps the record
            // inside the key's range even with a large batch.
            let target = self
                .next
                .saturating_add(self.batch)
                .min(self.end.saturating_add(1));
            persist(&self.path, &self.key_tag, target)?;
            self.durable = target;
        }
        let slot = self.next;
        self.next += 1;
        Ok(slot)
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use lean_multisig::{XmssSecretKey, xmss_key_gen};

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("slotctr-{name}-{}", std::process::id()));
        for ext in ["", "lock", "tmp"] {
            let _ = fs::remove_file(if ext.is_empty() {
                p.clone()
            } else {
                p.with_extension(ext)
            });
        }
        p
    }

    fn key(seed: u8) -> (XmssSecretKey, XmssPublicKey) {
        xmss_key_gen([seed; 32], 100, 140, false).expect("keygen")
    }

    #[test]
    fn reserves_monotonically_and_survives_reopen() {
        let path = scratch("reopen");
        let (_, pk) = key(7);

        let mut c = AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap();
        assert_eq!(c.reserve().unwrap(), 100);
        assert_eq!(c.reserve().unwrap(), 101);
        drop(c); // releases the lock

        // A restart must never hand out a slot it already gave away.
        let mut c = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert_eq!(c.reserve().unwrap(), 102);
    }

    #[test]
    fn unused_batch_window_is_skipped_never_replayed() {
        let path = scratch("batch");
        let (_, pk) = key(7);

        let mut c = AtomicSlotCounter::create(&path, &pk, 100, 140)
            .unwrap()
            .with_batch(16);
        assert_eq!(c.reserve().unwrap(), 100); // burns 100..116 on disk at once
        drop(c);

        // 101..115 were reserved but never used: they are lost, not reissued.
        let mut c = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert_eq!(c.reserve().unwrap(), 116);
    }

    #[test]
    fn refuses_missing_foreign_and_exhausted_state() {
        let path = scratch("closed");
        let (_, pk) = key(7);

        // Missing state must not silently restart at the first slot.
        assert!(matches!(
            AtomicSlotCounter::open(&path, &pk, 140),
            Err(AtomicSlotCounterError::State(_))
        ));

        drop(AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap());

        // A counter written for another key is rejected, not reset.
        let (_, other) = key(9);
        assert!(matches!(
            AtomicSlotCounter::open(&path, &other, 140),
            Err(AtomicSlotCounterError::State(_))
        ));

        // Creating over live state is refused too.
        assert!(matches!(
            AtomicSlotCounter::create(&path, &pk, 100, 140),
            Err(AtomicSlotCounterError::State(_))
        ));

        // And the window has a hard end.
        let mut c = AtomicSlotCounter::open(&path, &pk, 101).unwrap();
        assert_eq!(c.reserve().unwrap(), 100);
        assert_eq!(c.reserve().unwrap(), 101);
        assert!(matches!(
            c.reserve(),
            Err(AtomicSlotCounterError::Exhausted { .. })
        ));
    }

    #[test]
    fn second_process_style_lock_is_refused_while_held() {
        let path = scratch("lock");
        let (_, pk) = key(7);

        let held = AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap();
        // A second counter on the same state, while the first is alive.
        assert!(matches!(
            AtomicSlotCounter::open(&path, &pk, 140),
            Err(AtomicSlotCounterError::Busy)
        ));
        drop(held);
        assert!(AtomicSlotCounter::open(&path, &pk, 140).is_ok());
    }
}
