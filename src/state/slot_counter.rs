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
//! ever waste slots, never reuse them, and wasting is free, since a key covers
//! `2^32` of them.
//!
//! The caller's policy then follows for nothing: a slot is consumed at reservation
//! time, so whatever happens downstream (aggregation fails, the proof does not
//! verify, the publish is refused), the slot is *not* reused. There is no
//! `release`, by design. The counter only ever moves forward.
//!
//! Contrast with [`crate::state::freshness`]: that gate is deliberately fail-**open** (a
//! missing mark just means "nothing accepted yet"; worst case one stale record is
//! accepted once). This counter is fail-**closed**: a missing or unreadable state
//! file aborts signing, because the alternative is to restart from the first slot
//! and silently reuse every slot the key has already spent. That is also why
//! [`AtomicSlotCounter::create`] and [`AtomicSlotCounter::open`] are separate:
//! initialising state is an explicit first-install act, never a fallback.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use lean_multisig::XmssPublicKey;
use sha3::{Digest, Sha3_256};
use ssz::Encode as _;

/// `<path>.<suffix>`, **appending** to the file name rather than replacing its
/// extension.
///
/// `Path::with_extension` replaces the last dotted component, silently mapping
/// distinct keys onto one sibling file: `node-1.2` and `node-1.3` both yield
/// `node-1.lock` and `node-1.tmp`. Two keys would then contend on one lock (one
/// refused as `Busy` for no reason) and share the temporary file that `persist`
/// renames over the state, so one key's counter can land on the other's path. The
/// fingerprint check catches that only after the state on disk is already wrong.
///
/// Key names are caller-supplied, so dots are not hypothetical.
pub(crate) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Writes `next_free` so that it survives a power cut.
///
/// All four steps are load-bearing: write to a temporary file, `fsync` it so its
/// *contents* reach the medium, `rename` over the target (atomic on POSIX, so a
/// crash sees the whole old record or the whole new one), then `fsync` the
/// *directory* so the rename itself is durable.
///
/// The last is the one usually missing. Without it the contents are safe but the
/// directory entry may still point at the old inode after a crash, which for
/// this counter means resurrecting spent slots.
fn persist(path: &Path, key_tag: &str, next_free: u32) -> Result<(), AtomicSlotCounterError> {
    let tmp = sibling(path, "tmp");

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
    let lock_path = sibling(state_path, "lock");
    let file = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    file.try_lock().map_err(|_| AtomicSlotCounterError::Busy)?;
    Ok(file)
}

/// Ties a state file to one key. Over the public key's canonical SSZ bytes (32,
/// fixed) rather than a self-describing encoding: the tag must be stable for a
/// given key and distinct for every other, and a format with alternative
/// spellings of the same value cannot promise the first half of that.
fn key_fingerprint(pk: &XmssPublicKey) -> String {
    let bytes = pk.as_ssz_bytes();
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
    /// A protocol-chosen slot lies in this member's past. Returned only by
    /// [`AtomicSlotCounter::reserve_at`], and the one variant here that is not a
    /// malfunction: the member simply sits this round out.
    AlreadySpent { requested: u32, next: u32 },
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
    /// Set once the window's last slot has been handed out.
    ///
    /// `next` cannot represent "one past `u32::MAX`", so with `end == u32::MAX`
    /// (legal, since `xmss_key_gen` only rejects `slot_end >= 2^LOG_LIFETIME` and
    /// `LOG_LIFETIME` is 32), incrementing it wraps to 0. The guard is `next >
    /// end`, which `0` sails straight through, so the counter would quietly start
    /// the window over and reissue slots it had already spent. This flag is the
    /// bit that `next` has no room for.
    exhausted: bool,
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
        persist(&path, &key_tag, slot_start)?;
        Ok(Self {
            path,
            key_tag,
            next: slot_start,
            durable: slot_start,
            end: slot_end,
            batch: 1,
            exhausted: false,
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
            exhausted: false,
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
        self.batch = batch.max(1);
        self
    }

    /// The next slot that would be handed out.
    pub fn next_slot(&self) -> u32 {
        self.next
    }

    /// Slots left in the window.
    pub fn remaining(&self) -> u64 {
        if self.exhausted {
            return 0;
        }
        (u64::from(self.end) + 1).saturating_sub(u64::from(self.next))
    }

    /// Reserves the next slot, making it durably spent **before** returning it.
    ///
    /// Once this returns `Ok(slot)`, that slot must be considered consumed
    /// whatever the caller does with it, including doing nothing at all.
    pub fn reserve(&mut self) -> Result<u32, AtomicSlotCounterError> {
        if self.exhausted || self.next > self.end {
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
        match self.next.checked_add(1) {
            Some(n) => self.next = n,
            // `slot` was `u32::MAX`, the last slot the type can name. Leave `next`
            // pointing at it and record the exhaustion out of band rather than
            // wrapping to 0.
            None => self.exhausted = true,
        }
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
        if self.exhausted || requested > self.end {
            return Err(AtomicSlotCounterError::Exhausted {
                next: requested,
                end: self.end,
            });
        }
        if requested < self.next {
            return Err(AtomicSlotCounterError::AlreadySpent {
                requested,
                next: self.next,
            });
        }
        if requested >= self.durable {
            // Same batching rule as `reserve`, clamped so the record never claims
            // slots outside the key's window.
            let target = requested
                .saturating_add(self.batch)
                .min(self.end.saturating_add(1));
            persist(&self.path, &self.key_tag, target)?;
            self.durable = target;
        }
        // Same wraparound reasoning as `reserve`.
        match requested.checked_add(1) {
            Some(n) => self.next = n,
            None => self.exhausted = true,
        }
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

    /// `next` cannot hold "one past `u32::MAX`", and the guard is `next > end`,
    /// which `0` passes. Without the exhaustion flag the counter wraps and hands
    /// out the bottom of the window a second time, silently, and without even an
    /// fsync, since `durable` is still at the top.
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
