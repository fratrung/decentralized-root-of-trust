//! Verifier side of the split deployment — the constrained one.
//!
//! Calls **only** `setup_verifier()`. It never touches `setup_prover()`, so it
//! avoids both the arena + DFT-twiddle allocations and, more importantly,
//! `enable_arena()`'s `mallopt(M_TRIM_THRESHOLD, -1)`: this process returns
//! freed memory to the OS, a prover process never does.
//!
//! Note what this file does *not* import: `params`. A verifier hardcodes nothing
//! but its anchor — `N`, `t` and the member keys all come from `anchor.bin`.
//! That is the whole point of the trust model.
//!
//! Files named `update-*` must verify; files named `attack-*` must be rejected.
//! Exits non-zero if any expectation is violated.
//!
//! It then runs the DHT freshness layer: `select_freshest` picks the newest valid
//! record, and a persistent high-water mark (`verifier-highwater.state`, keyed to
//! the anchor; override with `VERIFIER_STATE`) refuses any replay of an older but
//! still-valid record. That mark is local verifier state — never publish it.
//!
//! Usage: cargo run --release --bin verifier -- [dir]      (default ./artifacts)

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use decentralized_root_of_trust::committee::Committee;
use decentralized_root_of_trust::freshness::{Decision, HighWaterMark};
use decentralized_root_of_trust::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::snark_verifier_node::PQSNARKVerifierModule;
use decentralized_root_of_trust::stats::Series;
use decentralized_root_of_trust::status_list::SnarkStatusList;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Artifacts in `dir` whose file name starts with `prefix`, sorted by name.
fn artifacts(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        })
        .collect();
    paths.sort();
    paths
}

fn main() -> ExitCode {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "artifacts".into());
    let dir = Path::new(&dir);
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    let rss_baseline = rss_now_mb();

    // The anchor is read *before* setup because the verifier module is built around
    // it: `PQSNARKVerifierModule::new` owns both the anchor and the `setup_verifier()`
    // the aggregation bytecode needs. Reading ~6 kB from disk costs nothing that the
    // RSS sample below can see, and the trust model is unchanged — a production
    // verifier embeds this at compile time, and either way what matters is only that
    // the anchor is authentic.
    let anchor =
        std::fs::read(dir.join("anchor.bin")).unwrap_or_else(|e| panic!("cannot read anchor: {e}"));
    let committee = Committee::from_bytes(&anchor).expect("malformed anchor");

    // The durable mark is loaded here rather than at the freshness section further
    // down, so the module can be built with the version this verifier has actually
    // accepted instead of a placeholder. Nothing advances it in between.
    let state_path = std::env::var_os("VERIFIER_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("verifier-highwater.state"));
    let mut hwm = HighWaterMark::load(&state_path, &anchor);

    println!("verifier: setup...");
    let t_setup = Instant::now();
    // `new` performs the one-time `setup_verifier()`, so this is the same
    // measurement as before plus one clone of a 200-key anchor.
    //
    // The second argument feeds `PQSNARKVerifierModule::is_newer`, a *stateless*
    // convenience this binary does not use: freshness here is the durable
    // `HighWaterMark` below, which survives restarts and is what actually stops a
    // rollback. `unwrap_or(0)` on a fresh state is therefore not load-bearing.
    let verifier = PQSNARKVerifierModule::new(committee, hwm.current().unwrap_or(0));
    let setup_time = t_setup.elapsed();
    let rss_after_setup = rss_now_mb();

    let committee = verifier.committee_as_ref();
    println!(
        "anchor: N={} t={} ({} B)\n",
        committee.members().len(),
        committee.threshold(),
        anchor.len()
    );

    let mut verify_ts = Vec::new();
    let mut failures = 0usize;
    let mut rss_max = rss_after_setup;

    // Legitimate updates: every one must be accepted.
    for (idx, path) in artifacts(dir, "update-").into_iter().enumerate() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).expect("cannot read update");
        // Decoding is timed with verification: on an untrusted transport it is
        // part of the cost an attacker can force, and it is not free — leanVM
        // recomputes the bytecode claim while deserializing.
        let t = Instant::now();
        let ok = match SnarkStatusList::from_bytes(&bytes) {
            Ok(sl) => verifier.verify(&sl),
            Err(e) => {
                println!("  {name:<22} DECODE FAILED: {e}");
                failures += 1;
                continue;
            }
        };
        let elapsed = t.elapsed();
        let rss = rss_now_mb();
        rss_max = rss_max.max(rss);
        if !ok {
            failures += 1;
        }
        println!(
            "  {name:<22} verify={:>8.1?}  {} B  {}",
            elapsed,
            bytes.len(),
            if ok { "ACCEPTED" } else { "REJECTED <- BUG" }
        );
        if emit_samples {
            println!(
                "SAMPLE target=verifier idx={idx} verify_ms={:.3} bytes={} rss_mb={rss}",
                ms(elapsed),
                bytes.len()
            );
        }
        verify_ts.push(elapsed);
    }

    // Forgeries: every one must be rejected. A decode failure counts as a
    // rejection — refusing to parse is a valid way to refuse.
    println!("\nForgeries (expected: all REJECTED)");
    for path in artifacts(dir, "attack-") {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).expect("cannot read attack artifact");
        let accepted = SnarkStatusList::from_bytes(&bytes)
            .map(|sl| verifier.verify(&sl))
            .unwrap_or(false);
        if accepted {
            failures += 1;
        }
        println!(
            "  {name:<22} {}",
            if accepted {
                "ACCEPTED <- SECURITY FAILURE"
            } else {
                "rejected"
            }
        );
    }

    // ---- DHT freshness layer + persistent anti-rollback ----
    // Two stages that compose: crypto first, freshness second.
    //   1. `select_freshest` picks the newest *valid* record among the ones a
    //      lookup returned (updates + a hostile inflated-version forgery).
    //   2. the high-water mark refuses anything not strictly newer than what this
    //      verifier has already accepted, across restarts.
    // Stage 2 is what stops a replay: an old status list still verifies (that is
    // stateless), so without the mark a peer could serve it and re-grant access a
    // node had lost. The mark is local verifier state, keyed to this anchor.
    println!("\nDHT freshness + anti-rollback");
    match hwm.current() {
        Some(v) => println!("  high-water mark (persisted): version {v}"),
        None => println!("  high-water mark: none yet for this committee"),
    }

    let mut candidates: Vec<Vec<u8>> = artifacts(dir, "update-")
        .iter()
        .map(|p| std::fs::read(p).expect("cannot read update"))
        .collect();
    if let Ok(forgery) = std::fs::read(dir.join("attack-version.bin")) {
        candidates.push(forgery); // a hostile peer advertising a fake-fresh version
    }
    // The mark is passed *into* the selection, not merely consulted after it. A
    // record at or below the mark would verify and then be refused as stale, so
    // paying for its proof first buys nothing — and the stale case is the common
    // one, since a node polling an unchanged list hits it every round.
    let floor = hwm.current();
    // How many candidates the floor removes, counted by *decoding* only — no proof
    // is verified to produce this number. That is the point: the diagnostic below
    // must not undo the saving it is reporting on.
    let pruned = match floor {
        Some(f) => candidates
            .iter()
            .filter(|b| {
                SnarkStatusList::from_bytes(b).is_ok_and(|sl: SnarkStatusList| sl.version() <= f)
            })
            .count(),
        None => 0,
    };
    match verifier.select_freshest_above(&candidates, floor) {
        Some(sl) => match hwm.try_advance(sl.version()) {
            Decision::Accepted => {
                println!(
                    "  selected version {} -> accepted, high-water advanced",
                    sl.version()
                )
            }
            // Unreachable while `floor` comes from this same mark: anything the
            // floor let through is strictly above it, and the gate applies the same
            // rule. Reaching it means the filter and the gate disagree, which is a
            // bug in one of them and not a quiet "nothing to do".
            Decision::Stale(hw) => {
                println!(
                    "  selected version {} -> not newer than high-water {hw} <- BUG (the floor let it through)",
                    sl.version()
                );
                failures += 1;
            }
        },
        // Nothing came back, and the two reasons are not the same thing: the floor
        // may have removed everything worth verifying (a re-run over an unchanged
        // corpus — correct, and the case the floor exists for), or nothing verified
        // at all with no floor in play (a bug). `pruned` tells them apart without
        // verifying anything, which is the whole point — re-running the selection
        // unfloored to produce a nicer message would undo the saving being reported.
        //
        // The condition is `pruned > 0`, not "everything was pruned": the planted
        // forgery declares a version *above* the mark, so it always survives the
        // floor and always fails to verify. That is the artifact doing its job, not
        // a bug. And this branch is not where a broken update would be caught
        // anyway — every update is verified individually in the loop above, which
        // prints `REJECTED <- BUG` and counts a failure for each one.
        None if pruned > 0 => println!(
            "  nothing newer than high-water {}: {pruned} of {} candidates pruned before verifying any proof",
            floor.expect("a non-zero prune count requires a floor"),
            candidates.len()
        ),
        None => {
            println!(
                "  no valid record among {} candidates <- BUG",
                candidates.len()
            );
            failures += 1;
        }
    }

    // Rollback attack: a hostile peer replays an old but validly signed record. It
    // passes verification (stateless) yet must be refused as stale by the mark.
    //
    // Every way of *not* running this test is itself a failure. The chain used to
    // be one `if let` sequence, so a missing artifact — the corpus regenerated with
    // a single update, a renamed file — skipped the whole check with no output and
    // nothing added to `failures`. A security test that silently declines to run is
    // worse than one that fails, because the summary still reads clean.
    let replayed = artifacts(dir, "update-")
        .into_iter()
        .next()
        .and_then(|p| std::fs::read(&p).ok())
        .and_then(|bytes| verifier.select_freshest(std::slice::from_ref(&bytes)));

    match (hwm.current(), replayed) {
        (Some(_), Some(sl)) => match hwm.try_advance(sl.version()) {
            Decision::Stale(hw) => println!(
                "  rollback: replayed version {} refused (high-water {})",
                sl.version(),
                hw
            ),
            Decision::Accepted => {
                println!(
                    "  rollback: replayed version {} ACCEPTED <- SECURITY FAILURE",
                    sl.version()
                );
                failures += 1;
            }
        },
        (None, _) => {
            println!("  rollback: NOT TESTED (no high-water mark) <- SECURITY FAILURE");
            failures += 1;
        }
        (_, None) => {
            println!("  rollback: NOT TESTED (no replayable update) <- SECURITY FAILURE");
            failures += 1;
        }
    }

    let verify = Series::new(verify_ts.iter().map(|d| ms(*d)));
    let (vf_min, vf_med, vf_max) = verify.min_med_max();

    println!("\nsetup_verifier         : {setup_time:.2?}");
    println!(
        "verified               : {} updates, {:.1} ms total",
        verify.len(),
        verify.sum()
    );
    println!("verify min/med/max     : {vf_min:.1} / {vf_med:.1} / {vf_max:.1} ms");
    println!("\nRAM (verify-only process)");
    println!("baseline (pre-setup)   : {rss_baseline} MB");
    println!("after setup (resident) : {rss_after_setup} MB");
    println!("max during verifies    : {rss_max} MB");
    println!("peak (VmHWM)           : {} MB", peak_rss_mb());

    // One-line machine-readable record, parsed by benchmark.sh.
    println!(
        "\nVERIFIER setup_ms={:.3} n_verified={} verify_med_ms={vf_med:.3} \
         verify_mean_ms={:.3} verify_sd_ms={:.3} verify_min_ms={vf_min:.3} \
         verify_max_ms={vf_max:.3} verify_total_ms={:.3} anchor_bytes={} \
         rss_setup_mb={rss_after_setup} rss_verify_max_mb={rss_max} peak_rss_mb={} \
         failures={failures}",
        ms(setup_time),
        verify.len(),
        verify.mean(),
        verify.stddev(),
        verify.sum(),
        anchor.len(),
        peak_rss_mb()
    );

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!("\n{failures} expectation(s) violated");
        ExitCode::FAILURE
    }
}
