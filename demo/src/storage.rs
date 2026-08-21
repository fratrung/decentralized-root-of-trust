//! The two shared volumes, and the per-node one.
//!
//! * **committee/** is the bootstrap channel: the run identifier, one file per
//!   member public key, and the anchor assembled from them. Written once at
//!   network start, then read-only.
//! * **storage/** stands in for the DHT the records are published to. Anyone can
//!   read it, and in the demo anyone could write to it; that is deliberate,
//!   because a record's authority comes from the committee signatures inside it
//!   and never from where it was found.
//! * **state/** is private to one node: its slot counter, or the holder's
//!   anti-rollback mark. It is a separate volume per container precisely because
//!   sharing it would break the property it exists to provide.
//!
//! Publication is atomic. A reader that catches a half-written record would
//! report a decode failure, which reads as a security event rather than as the
//! race it is.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use decentralized_root_of_trust::protocol::committee::Committee;
use sha3::{Digest, Sha3_256};

/// Marks the network as initialised, and identifies *this* run.
///
/// Member keys are derived from it, so a fresh run identifier means a fresh
/// committee. That is what keeps a re-run from signing new content at slots the
/// previous run already spent, which is the one XMSS mistake this project exists
/// to prevent. A container restart, by contrast, finds the same identifier and
/// so resumes the same key and the same counter.
pub const RUN_ID: &str = "run-id";

/// The assembled trust anchor, and the only file a verifier needs a priori.
pub const ANCHOR: &str = "anchor.bin";

pub fn committee_dir() -> PathBuf {
    dir_from_env("COMMITTEE_DIR", "/shared/committee")
}

pub fn storage_dir() -> PathBuf {
    dir_from_env("STORAGE_DIR", "/shared/storage")
}

pub fn state_dir() -> PathBuf {
    dir_from_env("STATE_DIR", "/state")
}

fn dir_from_env(name: &str, default: &str) -> PathBuf {
    let dir = PathBuf::from(std::env::var(name).unwrap_or_else(|_| default.into()));
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
    dir
}

/// Where member `index` publishes its public key for the bootstrap step.
pub fn member_key_file(index: usize) -> PathBuf {
    committee_dir().join(format!("pk-{index:02}.ssz"))
}

/// Writes `bytes` so that a concurrent reader sees either the whole file or no
/// file at all: write a temporary, `fsync` it, `rename` over the target, then
/// `fsync` the directory so the rename itself survives a crash.
///
/// The same four steps the durable counter takes, for the same reason.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Blocks until `path` exists and returns its contents.
///
/// The containers come up in whatever order the runtime picks, so every node
/// starts by waiting for the file that makes its job possible: the run
/// identifier for a signer, the anchor for a verifier.
pub fn wait_for(path: &Path, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::read(path) {
            Ok(bytes) if !bytes.is_empty() => return Ok(bytes),
            _ if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} did not appear within {timeout:?}", path.display()),
                ));
            }
            _ => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// The run identifier, waiting for the bootstrap step to publish it.
pub fn wait_for_run_id(timeout: Duration) -> io::Result<Vec<u8>> {
    wait_for(&committee_dir().join(RUN_ID), timeout)
}

/// The anchor, waiting for the bootstrap step to assemble it.
pub fn wait_for_committee(timeout: Duration) -> io::Result<Committee> {
    let bytes = wait_for(&committee_dir().join(ANCHOR), timeout)?;
    Committee::from_bytes(&bytes).map_err(io::Error::other)
}

/// The XMSS seed for member `index`.
///
/// A demo shortcut with one job: survive a restart. A container that is killed
/// and started again must come back as the *same* member, or its counter file
/// would belong to a key that no longer exists and the anchor would name a key
/// nobody holds. Deriving the seed makes the identity reproducible without ever
/// writing a secret key to a volume.
///
/// `secret` is private to one container and `run_id` is common to the network,
/// so no node can derive another's key, and a new run derives ten new ones.
/// A production member generates its key from a real entropy source and keeps it
/// in hardware; nothing here is a model for that.
pub fn member_seed(secret: &str, run_id: &[u8], index: usize) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"drot-demo/member-seed/v1");
    h.update(secret.as_bytes());
    h.update(run_id);
    h.update((index as u64).to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// The published record for `version`. Sorting by name sorts by version, which
/// is what lets a reader find the freshest one without an index.
pub fn record_name(version: u32) -> String {
    format!("status-{version:05}.ssz")
}

fn version_of(name: &str) -> Option<u32> {
    name.strip_prefix("status-")?
        .strip_suffix(".ssz")?
        .parse()
        .ok()
}

/// Publishes a record to the shared storage volume.
pub fn publish(version: u32, bytes: &[u8]) -> io::Result<PathBuf> {
    let path = storage_dir().join(record_name(version));
    write_atomic(&path, bytes)?;
    Ok(path)
}

/// Every published record, newest declared version first.
///
/// The version here is only the *filename*, which nobody has authenticated: it
/// orders the candidates and decides nothing. Both verification paths bind the
/// version into the signed message, so a record whose name overstates it fails
/// verification like any other forgery.
pub fn published_records() -> Vec<(u32, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(storage_dir()) else {
        return Vec::new();
    };
    let mut found: Vec<(u32, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let version = version_of(path.file_name()?.to_str()?)?;
            Some((version, path))
        })
        .collect();
    found.sort_by_key(|(v, _)| std::cmp::Reverse(*v));
    found
}

/// The newest published record, or `None` on an empty storage volume.
pub fn latest_record() -> Option<(u32, Vec<u8>)> {
    published_records()
        .into_iter()
        .find_map(|(v, p)| std::fs::read(p).ok().map(|b| (v, b)))
}
