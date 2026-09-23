//! Verifier side of the split deployment, the constrained one.
//!
//! Calls **only** `setup_verifier()`. It never touches `setup_prover()`, so it
//! avoids both the arena + DFT-twiddle allocations and, more importantly,
//! `enable_arena()`'s `mallopt(M_TRIM_THRESHOLD, -1)`: this process returns
//! freed memory to the OS, a prover process never does.
//!
//! Note what this file does *not* import: `params`. A verifier hardcodes nothing
//! but its anchor: `N`, `t` and the member keys all come from `anchor.bin`.
//! That is the whole point of the trust model.
//!
//! Files named `update-*` must verify; files named `attack-*` must be rejected.
//! Exits non-zero if any expectation is violated.
//!
//! It then authenticates `canonical.bin`, the single current-record fixture an
//! external secure VDR would supply. A persistent high-water mark
//! (`verifier-highwater.state`, keyed to the anchor; override with
//! `VERIFIER_STATE`) refuses any replay of an older but still-valid record. The
//! VDR is outside this crate; the mark is local verifier state and is never
//! published.
//!
//! Usage:
//! - first initialization: `cargo run --release --bin verifier -- --init-state [dir]`
//! - normal startup: `cargo run --release --bin verifier -- [dir]`
//!
//! The artifact directory defaults to `./artifacts`. Initialization is an
//! explicit administrative operation and refuses to overwrite any existing
//! state; normal startup refuses missing, corrupt, unreadable, or foreign state.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::bench::stats::Series;
use decentralized_root_of_trust::node::snark_verifier::PQSNARKVerifierModule;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::SnarkStatusList;
use decentralized_root_of_trust::state::freshness::{Decision, HighWaterMark};

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

/// Decodes and authenticates one record under this verifier's fixed anchor.
fn authenticate(verifier: &PQSNARKVerifierModule, bytes: &[u8]) -> Option<SnarkStatusList> {
    let record = SnarkStatusList::from_bytes(bytes).ok()?;
    verifier.verify(&record).then_some(record)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    let (initialize_state, dir) = match first.as_deref() {
        Some("--init-state") => (true, args.next().unwrap_or_else(|| "artifacts".into())),
        Some(dir) => (false, dir.to_owned()),
        None => (false, "artifacts".into()),
    };
    if args.next().is_some() {
        eprintln!("usage: verifier [--init-state] [dir]");
        return ExitCode::from(2);
    }
    let dir = Path::new(&dir);
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    let rss_baseline = rss_now_mb();

    // Read before setup because `PQSNARKVerifierModule::new` owns both the anchor
    // and the `setup_verifier()` call. A production verifier embeds the anchor at
    // compile time; either way all that matters is that it is authentic.
    let anchor =
        std::fs::read(dir.join("anchor.bin")).unwrap_or_else(|e| panic!("cannot read anchor: {e}"));
    let committee = Committee::from_bytes(&anchor).expect("malformed anchor");

    // The durable mark is loaded here rather than at the freshness section further
    // down, so the module can be built with the version this verifier has actually
    // accepted instead of a placeholder. Nothing advances it in between.
    let state_path = std::env::var_os("VERIFIER_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("verifier-highwater.state"));
    if initialize_state {
        HighWaterMark::create(&state_path, &anchor).unwrap_or_else(|e| {
            panic!(
                "cannot initialize high-water mark {}: {e}",
                state_path.display()
            )
        });
        println!(
            "initialized empty high-water mark for this anchor at {}",
            state_path.display()
        );
        return ExitCode::SUCCESS;
    }
    let mut hwm = HighWaterMark::open(&state_path, &anchor)
        .unwrap_or_else(|e| panic!("cannot open high-water mark {}: {e}", state_path.display()));

    println!("verifier: setup...");
    let t_setup = Instant::now();
    // The second argument feeds `is_newer`, a stateless convenience this binary
    // does not use: freshness here is the durable `HighWaterMark` below, which
    // survives restarts. `unwrap_or(0)` is therefore not load-bearing.
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

    let mut decode_ts = Vec::new();
    let mut verify_only_ts = Vec::new();
    let mut verify_ts = Vec::new();
    let mut failures = 0usize;
    let mut rss_max = rss_after_setup;

    // Legitimate updates: every one must be accepted.
    for (idx, path) in artifacts(dir, "update-").into_iter().enumerate() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).expect("cannot read update");
        // Decoding is timed with verification: on an untrusted transport it is
        // part of the cost an attacker can force, and it is not free: leanVM
        // recomputes the bytecode claim while deserializing.
        let total_start = Instant::now();
        let decoded = SnarkStatusList::from_bytes(&bytes);
        let decode_time = total_start.elapsed();
        let record = match decoded {
            Ok(record) => record,
            Err(e) => {
                println!("  {name:<22} DECODE FAILED: {e}");
                failures += 1;
                continue;
            }
        };
        let verify_start = Instant::now();
        let ok = verifier.verify(&record);
        let verify_only_time = verify_start.elapsed();
        let elapsed = total_start.elapsed();
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
                "SAMPLE target=verifier idx={idx} decode_ms={:.3} verify_ms={:.3} total_ms={:.3} bytes={} rss_mb={rss}",
                ms(decode_time),
                ms(verify_only_time),
                ms(elapsed),
                bytes.len()
            );
        }
        decode_ts.push(decode_time);
        verify_only_ts.push(verify_only_time);
        verify_ts.push(elapsed);
    }

    // Forgeries: every one must be rejected. A decode failure counts as a
    // rejection: refusing to parse is a valid way to refuse.
    println!("\nForgeries (expected: all REJECTED)");
    let attacks = artifacts(dir, "attack-");
    for required in [
        "attack-outsider.bin",
        "attack-tampered.bin",
        "attack-version.bin",
    ] {
        if !dir.join(required).is_file() {
            println!("  {required:<22} MISSING <- SECURITY TEST NOT RUN");
            failures += 1;
        }
    }
    for path in attacks {
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

    // ---- one external-registry record + persistent anti-rollback ----
    // The external secure VDR is responsible for canonicality and global
    // latestness. This crate receives exactly one record, authenticates it under
    // its fixed anchor, and only then offers its version to the local gate.
    // An old status list remains cryptographically valid, so the mark is still
    // required to stop rollback across restarts.
    println!("\nExternal registry record + local anti-rollback");
    match hwm.current() {
        Some(v) => println!("  high-water mark (persisted): version {v}"),
        None => println!("  high-water mark: none yet for this committee"),
    }

    let canonical = std::fs::read(dir.join("canonical.bin"))
        .ok()
        .and_then(|bytes| authenticate(&verifier, &bytes));
    match canonical {
        Some(record) => match hwm.try_advance(record.version()) {
            Ok(Decision::Accepted) => {
                println!(
                    "  canonical version {} authenticated -> high-water advanced",
                    record.version()
                )
            }
            Ok(Decision::Stale(hw)) => {
                println!(
                    "  canonical version {} authenticated -> unchanged at high-water {hw}",
                    record.version()
                );
            }
            Err(e) => {
                println!(
                    "  canonical version {} -> high-water update failed: {e} <- SECURITY FAILURE",
                    record.version()
                );
                failures += 1;
            }
        },
        None => {
            println!("  canonical.bin missing, malformed, or unauthenticated <- BUG");
            failures += 1;
        }
    }

    // Rollback attack: a hostile peer replays an old but validly signed record. It
    // passes verification (stateless) yet must be refused as stale by the mark.
    //
    // Every way of *not* running this test is itself a failure. A missing artifact
    // must not skip the check silently: a security test that declines to run is
    // worse than one that fails, because the summary still reads clean.
    let replayed = artifacts(dir, "update-")
        .into_iter()
        .next()
        .and_then(|p| std::fs::read(&p).ok())
        .and_then(|bytes| authenticate(&verifier, &bytes));

    match (hwm.current(), replayed) {
        (Some(_), Some(sl)) => match hwm.try_advance(sl.version()) {
            Ok(Decision::Stale(hw)) => println!(
                "  rollback: replayed version {} refused (high-water {})",
                sl.version(),
                hw
            ),
            Ok(Decision::Accepted) => {
                println!(
                    "  rollback: replayed version {} ACCEPTED <- SECURITY FAILURE",
                    sl.version()
                );
                failures += 1;
            }
            Err(e) => {
                println!("  rollback: high-water update failed: {e} <- SECURITY FAILURE");
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

    let decode = Series::new(decode_ts.iter().map(|d| ms(*d)));
    let verify = Series::new(verify_only_ts.iter().map(|d| ms(*d)));
    let total = Series::new(verify_ts.iter().map(|d| ms(*d)));
    let (vf_min, vf_med, vf_max) = verify.min_med_max();
    let (total_min, total_med, total_max) = total.min_med_max();

    println!("\nsetup_verifier         : {setup_time:.2?}");
    println!(
        "verified               : {} updates, {:.1} ms total",
        verify.len(),
        total.sum()
    );
    println!("verify-only min/med/max: {vf_min:.1} / {vf_med:.1} / {vf_max:.1} ms");
    println!("decode+verify min/med/max: {total_min:.1} / {total_med:.1} / {total_max:.1} ms");
    println!("\nRAM (verify-only process)");
    println!("baseline (pre-setup)   : {rss_baseline} MB");
    println!("after setup (resident) : {rss_after_setup} MB");
    println!("max during verifies    : {rss_max} MB");
    println!("peak (VmHWM)           : {} MB", peak_rss_mb());

    // One-line machine-readable record, parsed by benchmark.sh.
    println!(
        "\nVERIFIER setup_ms={:.3} n_verified={} verify_med_ms={vf_med:.3} \
         verify_mean_ms={:.3} verify_sd_ms={:.3} verify_min_ms={vf_min:.3} \
         verify_max_ms={vf_max:.3} verify_total_ms={:.3} \
         decode_med_ms={:.3} decode_mean_ms={:.3} decode_sd_ms={:.3} \
         decode_min_ms={:.3} decode_max_ms={:.3} decode_total_ms={:.3} \
         total_med_ms={total_med:.3} total_mean_ms={:.3} total_sd_ms={:.3} \
         total_min_ms={total_min:.3} total_max_ms={total_max:.3} total_total_ms={:.3} anchor_bytes={} \
         rss_setup_mb={rss_after_setup} rss_verify_max_mb={rss_max} peak_rss_mb={} \
         failures={failures}",
        ms(setup_time),
        verify.len(),
        verify.mean(),
        verify.stddev(),
        verify.sum(),
        decode.median(),
        decode.mean(),
        decode.stddev(),
        decode.min(),
        decode.max(),
        decode.sum(),
        total.mean(),
        total.stddev(),
        total.sum(),
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
