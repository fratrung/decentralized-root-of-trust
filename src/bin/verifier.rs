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

use decentralized_root_of_trust::committee::{Committee, select_freshest, verify_proof};
use decentralized_root_of_trust::freshness::{Decision, HighWaterMark};
use decentralized_root_of_trust::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::stats::Series;
use decentralized_root_of_trust::status_list::StatusList;
use lean_multisig::setup_verifier;

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
    println!("verifier: setup...");
    let t_setup = Instant::now();
    setup_verifier();
    let setup_time = t_setup.elapsed();
    let rss_after_setup = rss_now_mb();

    // The fixed trust anchor. A production verifier embeds this at compile time;
    // loading it from a file changes nothing about the trust model, as long as
    // the anchor itself is authentic.
    let anchor =
        std::fs::read(dir.join("anchor.bin")).unwrap_or_else(|e| panic!("cannot read anchor: {e}"));
    let committee = Committee::from_bytes(&anchor).expect("malformed anchor");
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
        let ok = match StatusList::from_bytes(&bytes) {
            Ok(sl) => verify_proof(&committee, &sl),
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
        let accepted = StatusList::from_bytes(&bytes)
            .map(|sl| verify_proof(&committee, &sl))
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
    let state_path = std::env::var_os("VERIFIER_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("verifier-highwater.state"));
    let mut hwm = HighWaterMark::load(&state_path, &anchor);
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
    match select_freshest(&committee, &candidates) {
        Some(sl) => match hwm.try_advance(sl.version()) {
            Decision::Accepted => {
                println!(
                    "  selected version {} -> accepted, high-water advanced",
                    sl.version()
                )
            }
            Decision::Stale(hw) => println!(
                "  selected version {} -> not newer than high-water {}, nothing to do",
                sl.version(),
                hw
            ),
        },
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
    if hwm.current().is_some()
        && let Ok(stale) = std::fs::read(dir.join("update-01.bin"))
        && let Some(sl) = select_freshest(&committee, std::slice::from_ref(&stale))
    {
        match hwm.try_advance(sl.version()) {
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
