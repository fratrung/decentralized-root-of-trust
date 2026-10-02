//! `check_prover_output` must never accept a prover run it could not fully
//! validate: an `anchor.bin` that exists but cannot be read, or an unreadable
//! update, is a failure and never "zero records checked, nothing to report".
//! Every case here is a directory that benchmark.sh would otherwise have to
//! trust, and each must be refused with a non-zero exit and a summary line
//! that shows fewer valid records than expected.
//!
//! A directory in place of a file is the deterministic way to inject a read
//! error: it is listed like a file but `std::fs::read` fails on it, with no
//! dependence on permissions (which a root CI runner would ignore).
//!
//! The accepting path needs twenty real proofs and is exercised end to end by
//! benchmark.sh itself, where every prover execution goes through this binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use decentralized_root_of_trust::params::N_UPDATES;
use decentralized_root_of_trust::protocol::committee::Committee;
use leanvm::xmss::key_gen_from_seed;

/// Distinguishes this file's seeds from every other test's namespace.
const FILE: u8 = 11;
const GENESIS: u32 = 0;
const WINDOW: u32 = 4;

fn anchor_bytes() -> Vec<u8> {
    let mut seed = [0u8; 32];
    seed[0] = FILE;
    let (_, public) = key_gen_from_seed(seed, GENESIS, GENESIS + WINDOW).expect("keygen");
    Committee::new(vec![public], 1, GENESIS).to_bytes()
}

/// A fresh directory per case, so parallel cases cannot see each other.
fn scratch(case: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("check-prover-output-{case}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The complete honest file set, with a real anchor and undecodable records.
fn populate(dir: &Path, anchor: &[u8]) {
    std::fs::write(dir.join("anchor.bin"), anchor).unwrap();
    for i in 0..N_UPDATES {
        std::fs::write(dir.join(format!("update-{i:02}.bin")), b"not a record").unwrap();
    }
    std::fs::write(dir.join("canonical.bin"), b"not a record").unwrap();
}

/// Replaces a file with a directory of the same name: listed, but unreadable.
fn make_unreadable(dir: &Path, name: &str) {
    let path = dir.join(name);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
}

/// Runs the checker and asserts it refused: non-zero exit, and a summary line
/// reporting failures and fewer valid records than expected. Returns stdout.
fn assert_refused(args: &[&Path]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_check_prover_output"))
        .args(args)
        .output()
        .expect("run check_prover_output");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        !output.status.success(),
        "the checker accepted a directory it could not validate:\n{stdout}"
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("PROVER_OUTPUT_CHECK "))
        .unwrap_or_else(|| panic!("no summary line:\n{stdout}"));
    let field = |key: &str| -> usize {
        line.split_whitespace()
            .find_map(|kv| kv.strip_prefix(key))
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("no {key} in {line}"))
    };
    assert!(field("failures=") > 0, "refused without a failure: {line}");
    assert!(
        field("n_valid=") < field("expected="),
        "refused, yet reports every record valid: {line}"
    );
    stdout
}

#[test]
fn unreadable_anchor_is_refused() {
    // A listed but unreadable anchor: zero records checked is not a success.
    let dir = scratch("anchor-unreadable");
    populate(&dir, b"placeholder");
    make_unreadable(&dir, "anchor.bin");
    assert!(assert_refused(&[&dir]).contains("cannot read anchor.bin"));
    // The same with a fixture directory.
    let missing_fixture = dir.join("no-such-fixture");
    assert_refused(&[&dir, &missing_fixture]);
}

#[test]
fn missing_or_malformed_anchor_is_refused() {
    let dir = scratch("anchor-missing");
    populate(&dir, b"placeholder");
    std::fs::remove_file(dir.join("anchor.bin")).unwrap();
    assert!(assert_refused(&[&dir]).contains("missing anchor.bin"));

    let dir = scratch("anchor-malformed");
    populate(&dir, b"not an anchor");
    assert!(assert_refused(&[&dir]).contains("malformed anchor.bin"));
}

#[test]
fn missing_output_directory_is_refused() {
    let dir = scratch("no-outdir").join("absent");
    assert_refused(&[&dir]);
}

#[test]
fn unreadable_or_invalid_records_are_refused() {
    let anchor = anchor_bytes();

    // Undecodable records: nothing valid, however complete the file set looks.
    let dir = scratch("records-invalid");
    populate(&dir, &anchor);
    let out = assert_refused(&[&dir]);
    assert!(out.contains(&format!("only 0 of {N_UPDATES} updates are valid")));

    // An unreadable intermediate update is a failure, not a skipped file.
    let dir = scratch("update-unreadable");
    populate(&dir, &anchor);
    make_unreadable(&dir, "update-07.bin");
    assert!(assert_refused(&[&dir]).contains("cannot read update-07.bin"));

    // An unreadable canonical record.
    let dir = scratch("canonical-unreadable");
    populate(&dir, &anchor);
    make_unreadable(&dir, "canonical.bin");
    assert!(assert_refused(&[&dir]).contains("cannot read canonical.bin"));

    // A short run.
    let dir = scratch("short-run");
    populate(&dir, &anchor);
    std::fs::remove_file(dir.join(format!("update-{:02}.bin", N_UPDATES - 1))).unwrap();
    assert!(assert_refused(&[&dir]).contains("missing update-"));

    // A foreign record next to the honest set.
    let dir = scratch("extra-record");
    populate(&dir, &anchor);
    std::fs::write(dir.join("update-99.bin"), b"stale").unwrap();
    assert!(assert_refused(&[&dir]).contains("unexpected update-99.bin"));
}

#[test]
fn unreadable_fixture_is_refused() {
    let dir = scratch("fixture-missing");
    populate(&dir, &anchor_bytes());
    let fixture = dir.join("no-such-fixture");
    assert!(assert_refused(&[&dir, &fixture]).contains("cannot read fixture anchor"));
}
