//! Acceptance check for one measured `prover` run: benchmark support, never a
//! measured role.
//!
//! A prover's exit status shows that it did not crash, not that its records
//! verify, and the verifier target measures a corpus written by a different
//! prover invocation. Without this check a timing could be reported for a run
//! whose output no relying party would accept. `benchmark.sh` runs this binary
//! after every prover process, outside that process's timers and RSS, and a
//! non-zero exit withholds the run.
//!
//! With a fixture directory, the output must be exactly the honest set
//! (`anchor.bin`, `update-00..`, `canonical.bin`), the anchor must be the
//! fixture's byte for byte, and each update must carry the fixture's version,
//! algorithm and list and pass the complete SNARK predicate. Without one (the
//! self-contained prover generates its own committee) there is no external
//! reference: the records are checked against their own anchor, versions
//! `0..N_UPDATES` and the one-entry-per-version list growth, which is weaker and
//! reported as such.
//!
//! Success requires positive evidence, not the absence of complaints: every
//! one of the `N_UPDATES` records must have been read, decoded and accepted.
//! Any I/O error is itself a failure, because an unreadable file is not an
//! empty one: an `anchor.bin` that exists but cannot be read must not end in
//! success with zero records checked. With a fixture, the signer
//! set proven in each aggregate must also be exactly the one the fixture's
//! bitmap names, so the check attests the benchmark's workload and not merely
//! some valid quorum.
//!
//! Usage: check_prover_output <prover-outdir> [fixture-dir]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use decentralized_root_of_trust::node::snark_verifier::PQSNARKVerifierModule;
use decentralized_root_of_trust::params::N_UPDATES;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{SnarkStatusList, StatusList};
use leanvm::xmss::XmssPublicKey;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        eprintln!("usage: check_prover_output <prover-outdir> [fixture-dir]");
        return ExitCode::from(2);
    }
    let outdir = Path::new(&args[0]);
    let fixture = args.get(1).map(Path::new);
    let mut failures = Vec::<String>::new();
    let valid = check(outdir, fixture, &mut failures);
    report(failures, valid, fixture.is_some())
}

/// Returns how many updates passed every check. Anything that stops a record
/// from being examined is pushed to `failures`; nothing is skipped silently.
fn check(outdir: &Path, fixture: Option<&Path>, failures: &mut Vec<String>) -> usize {
    // Exactly the honest set. A missing update is a short run; an extra file
    // (an attack artifact, a stale record) means the directory is not the output
    // of one honest-only aggregation.
    let expected: BTreeSet<String> = ["anchor.bin".to_string(), "canonical.bin".to_string()]
        .into_iter()
        .chain((0..N_UPDATES).map(|i| format!("update-{i:02}.bin")))
        .collect();
    let mut present = BTreeSet::new();
    match std::fs::read_dir(outdir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        present.insert(entry.file_name().to_string_lossy().into_owned());
                    }
                    Err(e) => failures.push(format!("cannot list {}: {e}", outdir.display())),
                }
            }
        }
        Err(e) => {
            failures.push(format!(
                "cannot read prover output {}: {e}",
                outdir.display()
            ));
            return 0;
        }
    }
    for name in expected.difference(&present) {
        failures.push(format!("missing {name}"));
    }
    // The self-contained prover always writes its forgeries next to the updates
    // (only fixture mode honours BENCH_HONEST_ONLY), so they are tolerated there.
    for name in present.difference(&expected) {
        if fixture.is_none() && name.starts_with("attack-") {
            continue;
        }
        failures.push(format!("unexpected {name}"));
    }

    let anchor = match std::fs::read(outdir.join("anchor.bin")) {
        Ok(anchor) => anchor,
        Err(e) => {
            failures.push(format!("cannot read anchor.bin: {e}"));
            return 0;
        }
    };
    if let Some(fixture) = fixture {
        match std::fs::read(fixture.join("anchor.bin")) {
            Ok(reference) if reference == anchor => {}
            Ok(_) => failures.push("anchor.bin differs from the fixture anchor".into()),
            Err(e) => {
                failures.push(format!("cannot read fixture anchor: {e}"));
                return 0;
            }
        }
    }
    let committee = match Committee::from_bytes(&anchor) {
        Ok(committee) => committee,
        Err(e) => {
            failures.push(format!("malformed anchor.bin: {e}"));
            return 0;
        }
    };
    let verifier = PQSNARKVerifierModule::new(committee, 0);
    let members = verifier.committee_as_ref().members();

    let mut valid = 0usize;
    let mut previous_list: Option<Vec<[u8; 32]>> = None;
    let mut last_update = None;
    for index in 0..N_UPDATES {
        let failures_before = failures.len();
        let name = format!("update-{index:02}.bin");
        let bytes = match std::fs::read(outdir.join(&name)) {
            Ok(bytes) => bytes,
            Err(e) => {
                failures.push(format!("cannot read {name}: {e}"));
                previous_list = None;
                last_update = None;
                continue;
            }
        };
        let decoded = match SnarkStatusList::from_bytes(&bytes).and_then(SnarkStatusList::decode) {
            Ok(decoded) => decoded,
            Err(e) => {
                failures.push(format!("{name}: does not decode: {e}"));
                previous_list = None;
                last_update = None;
                continue;
            }
        };
        let record = decoded.record();
        if record.version() != index as u32 {
            failures.push(format!("{name}: version {} != {index}", record.version()));
        }
        match fixture {
            Some(fixture) => {
                let raw_path = fixture.join(format!("raw-update-{index:02}.bin"));
                match std::fs::read(&raw_path)
                    .map_err(|e| e.to_string())
                    .and_then(|raw| StatusList::from_bytes(&raw))
                {
                    Ok(raw) => {
                        if raw.alg != record.alg
                            || raw.version() != record.version()
                            || raw.list() != record.list()
                        {
                            failures.push(format!(
                                "{name}: algorithm, version or list differs from {}",
                                raw_path.display()
                            ));
                        }
                        // The exact signers the fixture handed to the prover, as
                        // keys of this anchor. An index past the anchor is itself a
                        // mismatch rather than a panic.
                        let mut wanted: Vec<Option<&XmssPublicKey>> =
                            raw.signer_indices().map(|i| members.get(i)).collect();
                        wanted.sort();
                        let mut proven: Vec<Option<&XmssPublicKey>> =
                            match decoded.aggregate().xmss_signers() {
                                [(_, _, keys)] => keys.iter().map(Some).collect(),
                                _ => Vec::new(), // the predicate below rejects this shape
                            };
                        proven.sort();
                        if wanted != proven {
                            failures.push(format!(
                                "{name}: proven signer set differs from the fixture's"
                            ));
                        }
                    }
                    Err(e) => failures.push(format!("{}: {e}", raw_path.display())),
                }
            }
            None => {
                // The self-contained prover appends one entry per version.
                let grows_by_one = record.list().len() == index + 1
                    && previous_list
                        .as_deref()
                        .is_none_or(|previous| record.list().starts_with(previous));
                if !grows_by_one {
                    failures.push(format!(
                        "{name}: list is not the previous list plus one entry"
                    ));
                }
                previous_list = Some(record.list_cloned());
            }
        }
        if !verifier.verify_decoded(&decoded) {
            failures.push(format!("{name}: rejected by the SNARK predicate"));
        }
        if failures.len() == failures_before {
            valid += 1;
        }
        last_update = Some(bytes);
    }

    // `last_update` is the final update only if it was read: an unreadable last
    // record resets it above, so an earlier one cannot stand in for it.
    let canonical = std::fs::read(outdir.join("canonical.bin"));
    match (canonical, last_update) {
        (Ok(canonical), Some(last)) if canonical == last => {}
        (Ok(_), Some(_)) => failures.push("canonical.bin is not the last update".into()),
        (Err(e), _) => failures.push(format!("cannot read canonical.bin: {e}")),
        (Ok(_), None) => failures.push("the last update is unavailable for comparison".into()),
    }

    if valid != N_UPDATES {
        failures.push(format!("only {valid} of {N_UPDATES} updates are valid"));
    }
    valid
}

fn report(failures: Vec<String>, valid: usize, against_fixture: bool) -> ExitCode {
    for failure in &failures {
        println!("  FAIL {failure}");
    }
    println!(
        "PROVER_OUTPUT_CHECK n_valid={valid} expected={N_UPDATES} reference={} failures={}",
        if against_fixture { "fixture" } else { "self" },
        failures.len()
    );
    if failures.is_empty() && valid == N_UPDATES {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
