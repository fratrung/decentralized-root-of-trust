//! Durable, monotonic slot allocation for one XMSS key.
//!
//! A slot is fsync'd as spent before it is returned. A crash may waste slots but
//! cannot reuse one, which would compromise stateful XMSS. Missing or invalid state
//! therefore refuses signing; initialization is explicit through [`AtomicSlotCounter::create`].

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use lean_multisig::XmssPublicKey;
use sha3::{Digest, Sha3_256};
use ssz::Encode as _;

/// Returns `<path>.<suffix>` without replacing an existing extension.
///
/// Separate dotted key names must not share a lock or temporary state file.
pub(crate) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Persists `next_free` through power loss: write + fsync, rename, then fsync the
/// parent directory. Skipping the final sync could resurrect spent slots.
fn persist(path: &Path, key_tag: &str, next_free: u64) -> Result<(), AtomicSlotCounterError> {
    let tmp = sibling(path, "tmp");

    let mut f = File::create(&tmp)?;
    f.write_all(format!("v2 {key_tag} {next_free}\n").as_bytes())?;
    f.sync_all()?;
    drop(f);

    fs::rename(&tmp, path)?;

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}

/// Locks a separate sibling file so replacing the state file cannot discard the
/// cross-process lock.
fn acquire_lock(state_path: &Path) -> Result<File, AtomicSlotCounterError> {
    let lock_path = sibling(state_path, "lock");
    let file = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    file.try_lock().map_err(|_| AtomicSlotCounterError::Busy)?;
    Ok(file)
}

/// Binds state to the public key's canonical SSZ representation.
fn key_fingerprint(pk: &XmssPublicKey) -> String {
    let bytes = pk.as_ssz_bytes();
    Sha3_256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Parses the versioned state record, while recognizing ordinary legacy files.
fn parse(s: &str, key_tag: &str) -> Result<(u64, bool), AtomicSlotCounterError> {
    let (s, legacy) = match s.strip_prefix("v2 ") {
        Some(versioned) => (versioned, false),
        None => (s, true),
    };
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
    let next = next
        .parse::<u64>()
        .map_err(|e| AtomicSlotCounterError::State(format!("unparseable slot counter: {e}")))?;
    Ok((next, legacy))
}

/// Refusals from slot allocation. None permit guessing a slot.
#[derive(Debug)]
pub enum AtomicSlotCounterError {
    /// The key's slot window is used up. Only a re-key fixes this.
    Exhausted { next: u64, end: u32 },
    /// A protocol-chosen slot lies in this member's past. Returned only by
    /// [`AtomicSlotCounter::reserve_at`], and the one variant here that is not a
    /// malfunction: the member simply sits this round out.
    AlreadySpent { requested: u32, next: u64 },
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
            Self::AlreadySpent { requested, next } => write!(
                f,
                "slot {requested} already spent (next free {next}); abstaining from this round"
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

/// On-disk state is `"v2 <key fingerprint> <next_free-u64>"`; every lower slot is spent.
/// A foreign state file is refused rather than reset.
pub struct AtomicSlotCounter {
    path: PathBuf,
    key_tag: String,
    /// Next slot to hand out (in memory). Invariant: `next <= durable`.
    next: u64,
    /// Highest `next_free` written to disk. Slots in `next..durable` are already
    /// burned on disk and can be handed out without another fsync.
    durable: u64,
    /// Last usable slot, inclusive (as passed to `xmss_key_gen`).
    end: u32,
    /// How many slots to burn per fsync. See [`AtomicSlotCounter::with_batch`].
    batch: u64,
    /// Held for the counter's whole lifetime: cross-process mutual exclusion.
    _lock: File,
}

impl AtomicSlotCounter {
    /// Initialises the counter for a brand-new key. Fails if the state file
    /// already exists: overwriting it would reset a counter that is very likely
    /// still live, which is precisely the accident this module exists to prevent.
    ///
    /// The existence check runs **while holding the lock**, and the order matters.
    /// Checking first and locking second leaves a window in which the refusal is
    /// decided against stale information: two processes both observe "no state
    /// file", the first wins the lock, creates the counter, spends slots and exits
    /// releasing the lock, at which point the second acquires it and, still acting
    /// on its pre-lock observation, rewrites `next_free` back to `slot_start`. The
    /// key's own fingerprint check cannot catch that, because it is the same key.
    /// Every slot the first process spent is handed out a second time.
    pub fn create(
        path: impl Into<PathBuf>,
        pk: &XmssPublicKey,
        slot_start: u32,
        slot_end: u32,
    ) -> Result<Self, AtomicSlotCounterError> {
        let path = path.into();
        let key_tag = key_fingerprint(pk);
        let lock = acquire_lock(&path)?;
        if path.exists() {
            return Err(AtomicSlotCounterError::State(format!(
                "{} already exists; refusing to reset a live counter",
                path.display()
            )));
        }
        persist(&path, &key_tag, u64::from(slot_start))?;
        Ok(Self {
            path,
            key_tag,
            next: u64::from(slot_start),
            durable: u64::from(slot_start),
            end: slot_end,
            batch: 1,
            _lock: lock,
        })
    }

    /// Resumes an existing counter. `slot_end` must be the same bound the key was
    /// generated for. It is passed rather than read back because a counter is
    /// keyed to the *public* key (that is what the anchor names a member by), and
    /// a public key carries no slot window: it is a Merkle root, identical in
    /// shape whatever range it covers. (The secret key does know, via
    /// `XmssSecretKey::activation_slots()`, but the holder of a secret key is the
    /// signer, not whoever opens the counter file.)
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
        let (next, legacy) = parse(&raw, &key_tag)?;
        let one_past_end = u64::from(slot_end) + 1;
        if next > one_past_end {
            return Err(AtomicSlotCounterError::State(format!(
                "persisted next slot {next} is outside this key's window ending at {slot_end}"
            )));
        }
        if legacy && slot_end == u32::MAX && next == u64::from(u32::MAX) {
            return Err(AtomicSlotCounterError::State(
                "legacy state at u32::MAX is ambiguous; refusing to risk slot reuse".into(),
            ));
        }
        if legacy {
            persist(&path, &key_tag, next)?;
        }
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
    /// direction (slots are skipped, never reused), so the only real budget is
    /// how much of the `2^32` window you are willing to waste per crash.
    ///
    /// `batch = 1` (the default) wastes nothing and fsyncs every signature.
    pub fn with_batch(mut self, batch: u32) -> Self {
        self.batch = u64::from(batch.max(1));
        self
    }

    /// The next slot that would be handed out.
    pub fn next_slot(&self) -> u64 {
        self.next
    }

    /// Slots left in the window.
    pub fn remaining(&self) -> u64 {
        (u64::from(self.end) + 1).saturating_sub(self.next)
    }

    /// Reserves the next slot, making it durably spent **before** returning it.
    ///
    /// Once this returns `Ok(slot)`, that slot must be considered consumed
    /// whatever the caller does with it, including doing nothing at all.
    pub fn reserve(&mut self) -> Result<u32, AtomicSlotCounterError> {
        if self.next > u64::from(self.end) {
            return Err(AtomicSlotCounterError::Exhausted {
                next: self.next,
                end: self.end,
            });
        }
        if self.next >= self.durable {
            // Extend the durable window. Saturating at `end + 1` keeps the record
            // inside the key's range even with a large batch.
            let target = (self.next + self.batch).min(u64::from(self.end) + 1);
            persist(&self.path, &self.key_tag, target)?;
            self.durable = target;
        }
        let slot = u32::try_from(self.next).expect("next is within the u32 slot window");
        self.next += 1;
        Ok(slot)
    }

    /// Reserves the slot the *protocol* chose, rather than the next local one.
    ///
    /// Per-member counters stop working once `t < N`: the members that sit out a
    /// round do not advance, so by the next one they disagree about the slot, and
    /// an aggregate over one shared slot becomes impossible. Deriving the slot
    /// from shared state (`slot = genesis + version`) removes the disagreement
    /// instead of reconciling it.
    ///
    /// Above `next`, every slot up to `requested` is burned in one durable write:
    /// a member that missed six rounds skips six slots rather than reclaiming
    /// them. Skipping is free (the window is `2^32` wide), reuse costs the key.
    ///
    /// Below `next` the answer is [`AtomicSlotCounterError::AlreadySpent`], which
    /// doubles as the anti-double-sign guard: a version this member already signed
    /// maps to a spent slot and is unreachable, with no extra state to keep. Being
    /// refused is a normal outcome: the member abstains and the quorum proceeds
    /// without it, which is what `t < N` is for.
    pub fn reserve_at(&mut self, requested: u32) -> Result<u32, AtomicSlotCounterError> {
        let requested_u64 = u64::from(requested);
        if self.next > u64::from(self.end) || requested > self.end {
            return Err(AtomicSlotCounterError::Exhausted {
                next: self.next.max(requested_u64),
                end: self.end,
            });
        }
        if requested_u64 < self.next {
            return Err(AtomicSlotCounterError::AlreadySpent {
                requested,
                next: self.next,
            });
        }
        if requested_u64 >= self.durable {
            // Same batching rule as `reserve`, clamped so the record never claims
            // slots outside the key's window.
            let target = (requested_u64 + self.batch).min(u64::from(self.end) + 1);
            persist(&self.path, &self.key_tag, target)?;
            self.durable = target;
        }
        self.next = requested_u64 + 1;
        Ok(requested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lean_multisig::{XmssSecretKey, xmss_key_gen_from_seed};

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

    /// Slots 100..=140, 41 of them. leanVM v0.9 takes an activation slot and a
    /// count where the old API took an inclusive pair, so the `+ 1` is explicit
    /// here rather than hidden in the callee.
    fn key(seed: u8) -> (XmssSecretKey, XmssPublicKey) {
        let (pk, sk) = xmss_key_gen_from_seed([seed; 32], 100, 41).expect("keygen");
        (sk, pk)
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

    /// `create` must decide whether to refuse *while holding the lock*. Deciding
    /// first and locking second lets a second process act on an observation taken
    /// before the counter existed: it waits for the lock, gets it once the first
    /// process exits, and rewinds `next_free` to `slot_start`, reissuing every
    /// slot already spent, with the key fingerprint matching because it is the
    /// same key.
    ///
    /// `Busy` rather than `State` while the counter is live is the observable
    /// evidence of the ordering: the lock is what answers first.
    #[test]
    fn create_decides_under_the_lock() {
        let path = scratch("toctou");
        let (_, pk) = key(7);

        let mut live = AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap();
        assert_eq!(live.reserve().unwrap(), 100);
        assert_eq!(live.reserve().unwrap(), 101);

        assert!(matches!(
            AtomicSlotCounter::create(&path, &pk, 100, 140),
            Err(AtomicSlotCounterError::Busy)
        ));

        drop(live); // lock released; the state file still stands in the way
        assert!(matches!(
            AtomicSlotCounter::create(&path, &pk, 100, 140),
            Err(AtomicSlotCounterError::State(_))
        ));

        // Neither refusal may have touched the counter.
        let mut reopened = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert_eq!(reopened.reserve().unwrap(), 102);
    }

    /// The persisted `u64` value must retain "one past `u32::MAX`" across a
    /// restart. Otherwise the last slot remains recorded as the next free slot
    /// and is issued again when the process comes back.
    ///
    /// The key is irrelevant here; only the counter's arithmetic is under test.
    #[test]
    fn the_top_of_the_u32_window_is_not_wrapped_around() {
        let path = scratch("wrap");
        let (_, pk) = key(7);

        let mut c = AtomicSlotCounter::create(&path, &pk, u32::MAX, u32::MAX).unwrap();
        assert_eq!(c.reserve().unwrap(), u32::MAX);
        assert_eq!(c.remaining(), 0);

        assert!(matches!(
            c.reserve(),
            Err(AtomicSlotCounterError::Exhausted { .. })
        ));
        assert!(matches!(
            c.reserve_at(u32::MAX),
            Err(AtomicSlotCounterError::Exhausted { .. })
        ));
        drop(c);

        let mut reopened = AtomicSlotCounter::open(&path, &pk, u32::MAX).unwrap();
        assert_eq!(reopened.next_slot(), u64::from(u32::MAX) + 1);
        assert!(matches!(
            reopened.reserve(),
            Err(AtomicSlotCounterError::Exhausted { .. })
        ));
        assert!(matches!(
            reopened.reserve_at(u32::MAX),
            Err(AtomicSlotCounterError::Exhausted { .. })
        ));
    }

    #[test]
    fn ambiguous_legacy_state_at_u32_max_is_refused() {
        let path = scratch("legacy-max");
        let (_, pk) = key(7);
        fs::write(&path, format!("{} {}\n", key_fingerprint(&pk), u32::MAX)).unwrap();

        assert!(matches!(
            AtomicSlotCounter::open(&path, &pk, u32::MAX),
            Err(AtomicSlotCounterError::State(message))
                if message.contains("ambiguous")
        ));
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

    /// The protocol-driven path: a member follows the round number, skipping the
    /// slots of the rounds it missed instead of replaying them.
    #[test]
    fn protocol_slots_jump_forward_and_never_back() {
        let path = scratch("at");
        let (_, pk) = key(7);
        let mut c = AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap();

        assert_eq!(c.reserve_at(100).unwrap(), 100);
        // Missed rounds 101..104: those slots are burned, not banked.
        assert_eq!(c.reserve_at(105).unwrap(), 105);
        assert_eq!(c.next_slot(), 106);

        // A round already behind us is refused, including the one just signed,
        // which is the anti-double-sign guard.
        assert!(matches!(
            c.reserve_at(103),
            Err(AtomicSlotCounterError::AlreadySpent { .. })
        ));
        assert!(matches!(
            c.reserve_at(105),
            Err(AtomicSlotCounterError::AlreadySpent { .. })
        ));
        // A refusal must not move the counter: the member abstained, nothing more.
        assert_eq!(c.next_slot(), 106);

        // Past the key's window is exhaustion, a different failure entirely.
        assert!(matches!(
            c.reserve_at(141),
            Err(AtomicSlotCounterError::Exhausted { .. })
        ));

        // The refusal survives a restart, which is the only thing that matters.
        drop(c);
        let mut c = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert!(matches!(
            c.reserve_at(105),
            Err(AtomicSlotCounterError::AlreadySpent { .. })
        ));
        assert_eq!(c.reserve_at(106).unwrap(), 106);
    }

    /// `reserve` and `reserve_at` share one counter, so mixing them is safe:
    /// whichever ran last, the next slot is still strictly ahead of every slot
    /// already handed out.
    #[test]
    fn protocol_and_local_reservations_share_one_counter() {
        let path = scratch("mixed");
        let (_, pk) = key(7);
        let mut c = AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap();

        assert_eq!(c.reserve().unwrap(), 100);
        assert_eq!(c.reserve_at(110).unwrap(), 110);
        assert_eq!(c.reserve().unwrap(), 111);
        assert!(matches!(
            c.reserve_at(111),
            Err(AtomicSlotCounterError::AlreadySpent { .. })
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
