//! The cross-process guarantee, checked with two **actual** processes.
//!
//! `atomic_slot_counter`'s unit tests cover the lock from a second thread, which
//! is not the property the module claims. The claim is that two *processes*
//! cannot hand out the same slot for one key — and a same-process test cannot
//! distinguish a real `flock` from a `static Mutex` that happens to be in the
//! binary. This one re-executes the test binary and lets the operating system
//! arbitrate, which is the only way the answer means anything.
//!
//! It matters more than the usual concurrency test because of what the failure
//! costs. XMSS is stateful: two live holders of one key both issuing slot `s`
//! means two signatures under `(key, s)`, which leaks the WOTS hash chains and
//! destroys the key. The counter is the only thing standing between "two nodes
//! were started from the same state directory" — an ordinary operational mistake,
//! a copied unit file, a container restarted before the old one died — and that.
//!
//! ## How the two halves talk
//!
//! [`child_probe`] is `#[ignore]`d so it never runs in an ordinary `cargo test`.
//! The parent re-execs this same binary with `--ignored --exact child_probe` and
//! a path in the environment, and reads one marker line back off stdout. Running
//! `cargo test -- --ignored` by hand is harmless: with no environment set, the
//! probe reports that it was invoked directly and returns.

use std::path::{Path, PathBuf};
use std::process::Command;

use decentralized_root_of_trust::atomic_slot_counter::{AtomicSlotCounter, AtomicSlotCounterError};
use lean_multisig::{XmssPublicKey, xmss_key_gen_from_seed};

const GENESIS: u32 = 100;
const WINDOW: u32 = 16;

/// The environment variable carrying the state path from parent to child.
const PROBE_ENV: &str = "DROT_LOCK_PROBE_PATH";

/// Markers the child prints. Parsed, not just grepped for, so a child that dies
/// before printing anything cannot be mistaken for a child that reported `busy`.
const BUSY: &str = "PROBE=busy";
const ACQUIRED: &str = "PROBE=acquired:";
const DIRECT: &str = "PROBE=invoked-directly";

/// Seeds are `[FILE, ns, member, 0, ..]`, file 4 here — see
/// `tests/snark_path.rs` for why the tag exists. Nothing in this file signs, so
/// no slot is ever consumed by a key; the seed only has to be *stable* across the
/// two processes, since the counter's state file is bound to the key's
/// fingerprint and the child must present the same one.
fn key() -> XmssPublicKey {
    let mut seed = [0u8; 32];
    seed[0] = 4;
    // leanVM v0.9 takes an activation slot and a slot *count*, half-open, and
    // returns `(public, secret)`.
    xmss_key_gen_from_seed(seed, u64::from(GENESIS), u64::from(WINDOW) + 1)
        .expect("keygen")
        .0
}

/// Runs the probe in a fresh process and returns its marker line.
fn probe(state: &Path) -> String {
    let exe = std::env::current_exe().expect("current exe");
    let out = Command::new(exe)
        .args(["--exact", "child_probe", "--ignored", "--nocapture"])
        .env(PROBE_ENV, state)
        .output()
        .expect("could not spawn the probe process");

    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find(|l| l.starts_with("PROBE="))
        .unwrap_or_else(|| {
            panic!(
                "the probe printed no marker (exit {:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            )
        })
        .to_string()
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("drot-lock2p-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The child half. Ignored so it is never collected by a normal run; the parent
/// invokes it explicitly. It reports rather than asserts — deciding what the
/// answer *should* be is the parent's job, and a child that panicked would be
/// indistinguishable from one that could not start.
#[test]
#[ignore]
fn child_probe() {
    let Some(path) = std::env::var_os(PROBE_ENV) else {
        println!("{DIRECT}");
        return;
    };

    match AtomicSlotCounter::open(PathBuf::from(path), &key(), GENESIS + WINDOW) {
        Err(AtomicSlotCounterError::Busy) => println!("{BUSY}"),
        Ok(counter) => println!("{ACQUIRED}{}", counter.next_slot()),
        Err(e) => println!("PROBE=error:{e}"),
    }
}

#[test]
fn a_second_process_cannot_hold_one_key_at_the_same_time() {
    let dir = scratch();
    let state = dir.join("member-0");
    let pk = key();

    let mut counter = AtomicSlotCounter::create(&state, &pk, GENESIS, GENESIS + WINDOW)
        .expect("first process initialises the counter");

    // Spend two slots, so the state on disk says something the child can be
    // checked against later rather than merely "it opened".
    assert_eq!(counter.reserve().expect("slot"), GENESIS);
    assert_eq!(counter.reserve().expect("slot"), GENESIS + 1);
    assert_eq!(counter.next_slot(), GENESIS + 2);

    // --- the property ---
    // A second process, same key, same state file, while the first still holds it.
    assert_eq!(
        probe(&state),
        BUSY,
        "a second process was allowed to open a counter the first still holds — \
         both would issue slot {}, and the key is gone",
        counter.next_slot()
    );

    // Still held after the refusal: being probed must not disturb the holder.
    assert_eq!(counter.reserve().expect("slot"), GENESIS + 2);

    // --- the negative control ---
    // Without this the test would pass just as well if `open` always failed, and
    // it would be proving nothing at all. Dropping the counter closes the lock
    // file, which releases the advisory lock.
    drop(counter);

    let marker = probe(&state);
    assert_eq!(
        marker,
        format!("{ACQUIRED}{}", GENESIS + 3),
        "after the holder exits the lock must be free — and the new process must \
         resume from the slot the first one durably burned, not from the start of \
         the window"
    );
}

/// `create` is the more dangerous of the two entry points: it is the one that
/// writes `next_free` back to the beginning of the window. Its existence check
/// runs *under* the lock precisely so that a second process cannot decide against
/// a stale observation, so the refusal must hold there too.
#[test]
fn a_second_process_cannot_reinitialise_a_live_counter() {
    let dir = scratch().join("create");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let state = dir.join("member-0");
    let pk = key();

    let mut holder = AtomicSlotCounter::create(&state, &pk, GENESIS, GENESIS + WINDOW)
        .expect("first process initialises the counter");
    assert_eq!(holder.reserve().expect("slot"), GENESIS);

    // Same process, but the interesting half is that `create` refuses at all: it
    // must never rewind a counter that already exists, whichever check fires.
    match AtomicSlotCounter::create(&state, &pk, GENESIS, GENESIS + WINDOW) {
        Err(AtomicSlotCounterError::Busy) | Err(AtomicSlotCounterError::State(_)) => {}
        Ok(_) => panic!("create() reset a live counter: every spent slot is now free again"),
        Err(e) => panic!("create() refused for an unrelated reason: {e}"),
    }

    // And from a real second process, where the lock is what does the refusing.
    assert_eq!(probe(&state), BUSY);

    drop(holder);
    assert_eq!(probe(&state), format!("{ACQUIRED}{}", GENESIS + 1));
}
