//! Durable, monotonic slot allocation for one XMSS key.
//!
//! A slot is recorded as spent and `sync_data` completes before it is returned.
//! A crash may waste slots but cannot reuse one, which would compromise stateful
//! XMSS. Missing or invalid state therefore refuses signing; initialization is
//! explicit through [`AtomicSlotCounter::create`].

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use leanvm::xmss::XmssPublicKey;
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

const RECORD_SIZE: usize = 128;
// Keep the two records in separate 4 KiB regions so an interrupted block write
// does not normally damage both generations. The durability guarantee still
// depends on the filesystem and device honoring sync_data().
const JOURNAL_SLOT_SIZE: usize = 4096;
const JOURNAL_SIZE: usize = JOURNAL_SLOT_SIZE * 2;
const CHECKSUM_OFFSET: usize = 96;
const JOURNAL_MAGIC: &[u8; 8] = b"DROTSL03";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalRecord {
    generation: u64,
    next_free: u64,
    key_tag: [u8; 32],
}

fn encode_record(record: JournalRecord) -> [u8; RECORD_SIZE] {
    let mut bytes = [0u8; RECORD_SIZE];
    bytes[..8].copy_from_slice(JOURNAL_MAGIC);
    bytes[8..16].copy_from_slice(&record.generation.to_le_bytes());
    bytes[16..24].copy_from_slice(&record.next_free.to_le_bytes());
    bytes[24..56].copy_from_slice(&record.key_tag);
    let checksum = Sha3_256::digest(&bytes[..CHECKSUM_OFFSET]);
    bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    bytes
}

fn decode_record(bytes: &[u8], slot: usize) -> Result<Option<JournalRecord>, String> {
    if bytes.len() != RECORD_SIZE {
        return Err("wrong record length".into());
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if &bytes[..8] != JOURNAL_MAGIC {
        return Err("wrong journal magic".into());
    }
    if bytes[56..CHECKSUM_OFFSET].iter().any(|byte| *byte != 0) {
        return Err("non-zero reserved bytes".into());
    }
    let expected = Sha3_256::digest(&bytes[..CHECKSUM_OFFSET]);
    if bytes[CHECKSUM_OFFSET..] != expected[..] {
        return Err("checksum mismatch".into());
    }

    let generation = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed slice"));
    if generation % 2 != slot as u64 {
        return Err("generation is stored in the wrong journal slot".into());
    }
    let next_free = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed slice"));
    let key_tag = bytes[24..56].try_into().expect("fixed slice");
    Ok(Some(JournalRecord {
        generation,
        next_free,
        key_tag,
    }))
}

/// Creates a complete journal image and installs it atomically. This metadata-
/// heavy path runs only at first provisioning or while migrating legacy state;
/// ordinary reservations overwrite one already-allocated record in place.
fn install_journal(
    path: &Path,
    key_tag: [u8; 32],
    next_free: u64,
) -> Result<File, AtomicSlotCounterError> {
    let tmp = sibling(path, "tmp");
    let mut image = [0u8; JOURNAL_SIZE];
    image[..RECORD_SIZE].copy_from_slice(&encode_record(JournalRecord {
        generation: 0,
        next_free,
        key_tag,
    }));

    let mut f = File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&tmp)?;
    // Writing the whole image allocates both fixed record slots up front. Later
    // updates neither resize the file nor change its directory entry.
    f.write_all(&image)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(f)
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
fn key_fingerprint(pk: &XmssPublicKey) -> [u8; 32] {
    let bytes = pk.as_ssz_bytes();
    Sha3_256::digest(&bytes).into()
}

fn key_fingerprint_hex(key_tag: &[u8; 32]) -> String {
    key_tag.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses either textual predecessor of the journal. The boolean reports the
/// unversioned format whose top-of-window value was historically ambiguous.
fn parse_legacy(s: &str, key_tag: &[u8; 32]) -> Result<(u64, bool), AtomicSlotCounterError> {
    let (s, unversioned) = match s.strip_prefix("v2 ") {
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
    if fp != key_fingerprint_hex(key_tag) {
        return Err(AtomicSlotCounterError::State(
            "state file belongs to a different key".into(),
        ));
    }
    let next = next
        .parse::<u64>()
        .map_err(|e| AtomicSlotCounterError::State(format!("unparseable slot counter: {e}")))?;
    if it.next().is_some() {
        return Err(AtomicSlotCounterError::State(
            "unexpected trailing data in state file".into(),
        ));
    }
    Ok((next, unversioned))
}

fn recover_journal(
    bytes: &[u8],
    key_tag: &[u8; 32],
    slot_end: u32,
) -> Result<JournalRecord, AtomicSlotCounterError> {
    if bytes.len() != JOURNAL_SIZE {
        return Err(AtomicSlotCounterError::State(format!(
            "journal has length {}, expected {JOURNAL_SIZE}",
            bytes.len()
        )));
    }

    let mut records = Vec::with_capacity(2);
    let mut invalid = Vec::new();
    for slot in 0..2 {
        let start = slot * JOURNAL_SLOT_SIZE;
        let range = start..start + RECORD_SIZE;
        match decode_record(&bytes[range], slot) {
            Ok(Some(record)) => records.push(record),
            Ok(None) => {}
            Err(reason) => invalid.push(format!("record {slot}: {reason}")),
        }
    }
    if records.is_empty() {
        let detail = if invalid.is_empty() {
            "both records are empty".into()
        } else {
            invalid.join("; ")
        };
        return Err(AtomicSlotCounterError::State(format!(
            "journal contains no valid record ({detail})"
        )));
    }
    if records.iter().any(|record| &record.key_tag != key_tag) {
        return Err(AtomicSlotCounterError::State(
            "journal belongs to a different key or mixes keys".into(),
        ));
    }
    records.sort_unstable_by_key(|record| record.generation);
    if records.len() == 2 {
        let older = records[0];
        let newer = records[1];
        if newer.generation != older.generation + 1 || newer.next_free <= older.next_free {
            return Err(AtomicSlotCounterError::State(
                "journal records are not one monotonic generation apart".into(),
            ));
        }
    }
    let current = *records.last().expect("at least one record");
    let one_past_end = u64::from(slot_end) + 1;
    if current.next_free > one_past_end {
        return Err(AtomicSlotCounterError::State(format!(
            "persisted next slot {} is outside this key's window ending at {slot_end}",
            current.next_free
        )));
    }
    Ok(current)
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

/// On-disk state is a fixed-size, two-record journal; every slot below its latest
/// valid `next_free` is spent. A foreign state file is refused rather than reset.
pub struct AtomicSlotCounter {
    state_file: File,
    key_tag: [u8; 32],
    generation: u64,
    /// Next slot to hand out. The same value is already durable on disk whenever
    /// no reservation is in progress.
    next: u64,
    /// Last usable slot, inclusive (as passed to `leanvm::xmss::key_gen`).
    end: u32,
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
        let state_file = install_journal(&path, key_tag, u64::from(slot_start))?;
        Ok(Self {
            state_file,
            key_tag,
            generation: 0,
            next: u64::from(slot_start),
            end: slot_end,
            _lock: lock,
        })
    }

    /// Resumes an existing counter. `slot_end` must be the same bound the key was
    /// generated for. It is passed rather than read back because a counter is
    /// keyed to the *public* key (that is what the anchor names a member by), and
    /// a public key carries no slot window: it is a Merkle root, identical in
    /// shape whatever range it covers. (The secret key does know, via
    /// `XmssSecretKey::epoch_range()`, but the holder of a secret key is the
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
        let mut state_file = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                AtomicSlotCounterError::State(format!("cannot read {}: {e}", path.display()))
            })?;
        let mut raw = Vec::new();
        state_file.read_to_end(&mut raw).map_err(|e| {
            AtomicSlotCounterError::State(format!("cannot read {}: {e}", path.display()))
        })?;

        if raw.len() == JOURNAL_SIZE {
            let current = recover_journal(&raw, &key_tag, slot_end)?;
            return Ok(Self {
                state_file,
                key_tag,
                generation: current.generation,
                next: current.next_free,
                end: slot_end,
                _lock: lock,
            });
        }

        let raw = std::str::from_utf8(&raw).map_err(|e| {
            AtomicSlotCounterError::State(format!("state is neither a journal nor UTF-8: {e}"))
        })?;
        let (next, unversioned) = parse_legacy(raw, &key_tag)?;
        let one_past_end = u64::from(slot_end) + 1;
        if next > one_past_end {
            return Err(AtomicSlotCounterError::State(format!(
                "persisted next slot {next} is outside this key's window ending at {slot_end}"
            )));
        }
        if unversioned && slot_end == u32::MAX && next == u64::from(u32::MAX) {
            return Err(AtomicSlotCounterError::State(
                "legacy state at u32::MAX is ambiguous; refusing to risk slot reuse".into(),
            ));
        }

        // Migration retains the exact durable frontier. Its one-time rename is
        // crash-safe: before the directory sync, recovery sees either the old
        // text record or the new journal, both naming the same `next_free`.
        drop(state_file);
        let state_file = install_journal(&path, key_tag, next)?;
        Ok(Self {
            state_file,
            key_tag,
            generation: 0,
            next,
            end: slot_end,
            _lock: lock,
        })
    }

    fn persist_next(&mut self, next_free: u64) -> Result<(), AtomicSlotCounterError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| AtomicSlotCounterError::State("journal generation exhausted".into()))?;
        let slot = (generation % 2) as usize;
        let bytes = encode_record(JournalRecord {
            generation,
            next_free,
            key_tag: self.key_tag,
        });
        self.state_file
            .seek(SeekFrom::Start((slot * JOURNAL_SLOT_SIZE) as u64))?;
        self.state_file.write_all(&bytes)?;
        // The file was fully allocated and its directory entry synced at create
        // or migration time. Only record data changes here, so sync_data is the
        // durability barrier that must complete before XMSS can touch the slot.
        self.state_file.sync_data()?;
        self.generation = generation;
        Ok(())
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
        let slot = u32::try_from(self.next).expect("next is within the u32 slot window");
        let target = self.next + 1;
        self.persist_next(target)?;
        self.next = target;
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
        let target = requested_u64 + 1;
        self.persist_next(target)?;
        self.next = target;
        Ok(requested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm::xmss::{XmssSecretKey, key_gen_from_seed};

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

    /// Slots 100..=140, passed directly as leanVM's inclusive interval.
    fn key(seed: u8) -> (XmssSecretKey, XmssPublicKey) {
        key_gen_from_seed([seed; 32], 100, 140).expect("keygen")
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
        fs::write(
            &path,
            format!(
                "{} {}\n",
                key_fingerprint_hex(&key_fingerprint(&pk)),
                u32::MAX
            ),
        )
        .unwrap();

        assert!(matches!(
            AtomicSlotCounter::open(&path, &pk, u32::MAX),
            Err(AtomicSlotCounterError::State(message))
                if message.contains("ambiguous")
        ));
    }

    #[test]
    fn v2_state_migrates_without_moving_the_frontier() {
        let path = scratch("v2-migration");
        let (_, pk) = key(7);
        fs::write(
            &path,
            format!("v2 {} 103\n", key_fingerprint_hex(&key_fingerprint(&pk))),
        )
        .unwrap();

        let mut c = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert_eq!(c.next_slot(), 103);
        assert_eq!(fs::metadata(&path).unwrap().len(), JOURNAL_SIZE as u64);
        assert_eq!(c.reserve().unwrap(), 103);
        drop(c);

        assert_eq!(
            AtomicSlotCounter::open(&path, &pk, 140)
                .unwrap()
                .next_slot(),
            104
        );
    }

    #[test]
    fn journal_alternates_records_without_resizing_or_batching() {
        let path = scratch("journal");
        let (_, pk) = key(7);
        let mut c = AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), JOURNAL_SIZE as u64);

        assert_eq!(c.reserve().unwrap(), 100);
        assert_eq!(c.reserve().unwrap(), 101);
        assert_eq!(fs::metadata(&path).unwrap().len(), JOURNAL_SIZE as u64);
        drop(c);

        let raw = fs::read(&path).unwrap();
        let first = decode_record(&raw[..RECORD_SIZE], 0).unwrap().unwrap();
        let second = decode_record(&raw[JOURNAL_SLOT_SIZE..JOURNAL_SLOT_SIZE + RECORD_SIZE], 1)
            .unwrap()
            .unwrap();
        assert_eq!((first.generation, first.next_free), (2, 102));
        assert_eq!((second.generation, second.next_free), (1, 101));

        let mut reopened = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert_eq!(reopened.reserve().unwrap(), 102);
    }

    #[test]
    fn incomplete_inactive_record_does_not_advance_the_frontier() {
        let path = scratch("torn-inactive");
        let (_, pk) = key(7);
        drop(AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap());

        // Model a crash during the next in-place write. Because persistence did
        // not complete, SignerNode could not yet have touched slot 100.
        let mut incomplete = encode_record(JournalRecord {
            generation: 1,
            next_free: 101,
            key_tag: key_fingerprint(&pk),
        });
        incomplete[CHECKSUM_OFFSET] ^= 1;
        let mut file = File::options().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(JOURNAL_SLOT_SIZE as u64))
            .unwrap();
        file.write_all(&incomplete).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut reopened = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert_eq!(reopened.reserve().unwrap(), 100);
    }

    #[test]
    fn valid_latest_record_survives_a_damaged_older_record() {
        let path = scratch("damaged-old");
        let (_, pk) = key(7);
        let mut c = AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap();
        assert_eq!(c.reserve().unwrap(), 100);
        drop(c);

        let mut file = File::options().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(CHECKSUM_OFFSET as u64)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut reopened = AtomicSlotCounter::open(&path, &pk, 140).unwrap();
        assert_eq!(reopened.reserve().unwrap(), 101);
    }

    #[test]
    fn journal_with_no_valid_record_is_refused() {
        let path = scratch("both-invalid");
        let (_, pk) = key(7);
        drop(AtomicSlotCounter::create(&path, &pk, 100, 140).unwrap());

        let mut file = File::options().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(CHECKSUM_OFFSET as u64)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            AtomicSlotCounter::open(&path, &pk, 140),
            Err(AtomicSlotCounterError::State(_))
        ));
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
