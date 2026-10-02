//! Experiment: what does signing the statement digest change, compared with
//! signing the statement itself?
//!
//! Usage: mldsa_statement_experiment <t> <repetitions> <warm-up-ms> <L>...
//!
//! The protocol signs `SHAKE256(statement, 64)` (`Committee::statement_for`).
//! The alternative passes the whole statement, list included, to ML-DSA. This
//! binary measures both on the same keys, lists and machine, so the reason for
//! the digest stays reproducible without a second signing mode in the
//! protocol. It is not a benchmark target and is not run by `benchmark.sh`;
//! `tools/mldsa_statement_experiment.sh` drives it.
//!
//! Two variants, each timed from "the record is decoded" to "the whole quorum
//! is verified" (and, for signing, from "the list is known" to "one signature
//! exists"), so both pay for building the statement:
//!
//! - `statement`: build the statement, hand it to ML-DSA. ML-DSA first hashes
//!   `H(pk) || M`, a prefix that differs per signer, so every signature
//!   re-reads the whole statement.
//! - `digest`: build the statement, hash it once, hand the 64 bytes to ML-DSA.
//!
//! **Every comparison is made inside one process.** The CPU's clock state
//! differs between processes: under a load-following governor the same
//! per-signature work can take 0.065 ms in one process and 0.109 ms in another,
//! which is enough to invent a trend across list sizes. One process therefore
//! covers all the list sizes for its `t`: each repetition visits every list
//! size, in an order that rotates from one repetition to the next, and within a
//! list size the two variants alternate which goes first. A change of CPU state
//! shifts all of them together; the ratios between variants and between list
//! sizes do not depend on it. The script repeats the process and reports the
//! per-process medians and ratios.
//!
//! Before anything is timed the process spends `warm-up-ms` verifying a
//! signature in a loop. Every verification must succeed, and a signature made
//! over one message must not verify over the other or under another key.
//!
//! Besides the two variants the process times their building blocks alone:
//! building the statement, building it plus the application's SHAKE256 pass,
//! that pass alone over a statement already built, and ML-DSA's own
//! message-hashing step (`mu = H(tr || M')`, FIPS 204
//! Algorithm 7 line 6 and Algorithm 8 line 7) over the statement and over the
//! digest. The last two matter because the two passes do not come from the
//! same code: the application digest uses the `sha3` crate, ML-DSA its own
//! SHAKE256. Their relative speed depends on the compiler: built with Rust
//! 1.90.0 the second absorbs a long message about four times slower than the
//! first, built with Rust 1.98.1 the two are equal. The measured gain
//! therefore has a structural part (one pass instead of `t`) and a part that
//! can belong to the build, and the report separates them with these figures.

#[path = "support/mod.rs"]
mod support;

use std::time::Instant;

use drot_mldsa::status_list::STATEMENT_DIGEST_BYTES;
use drot_mldsa::{Committee, MlDsa65Signer, PublicKey, Signature, verify};
use ml_dsa::signature::digest::Update;

const MAX_T: usize = 2048;
const MAX_REPETITIONS: usize = 1000;
const MAX_WARMUP_MS: usize = 60_000;
/// Enough signatures for a stable median even when the quorum is tiny.
const MIN_SIGN_SAMPLES: usize = 64;

/// Everything measured for one list size.
struct Case {
    list: Vec<[u8; 32]>,
    statement_signatures: Vec<Signature>,
    digest_signatures: Vec<Signature>,
    sign_statement_ms: Vec<f64>,
    sign_digest_ms: Vec<f64>,
    verify_statement_ms: Vec<f64>,
    verify_digest_ms: Vec<f64>,
    preimage_ms: Vec<f64>,
    digest_ms: Vec<f64>,
    app_pass_ms: Vec<f64>,
    mu_statement_ms: Vec<f64>,
    mu_digest_ms: Vec<f64>,
}

fn quorum_verifies(members: &[PublicKey], message: &[u8], signatures: &[Signature]) -> bool {
    members
        .iter()
        .zip(signatures)
        .all(|(member, signature)| verify(member, message, signature))
}

/// ML-DSA's message-hashing step alone, as signing and verification run it
/// for the empty context: `mu = H(tr || 0 || 0 || message, 64)`.
fn mu_ms(member: &PublicKey, message: &[u8]) -> f64 {
    let start = Instant::now();
    let mu = member
        .compute_mu(
            |hasher| {
                hasher.update(message);
                Ok(())
            },
            b"",
        )
        .expect("computing mu failed");
    let elapsed = support::milliseconds(start.elapsed());
    std::hint::black_box(&mu);
    elapsed
}

/// The application's SHAKE256 pass alone, over a statement already built:
/// what `statement_digest` adds to `statement_preimage`.
fn app_pass_ms(statement: &[u8]) -> f64 {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let start = Instant::now();
    let mut hasher = sha3::Shake256::default();
    hasher.update(statement);
    let mut digest = [0u8; STATEMENT_DIGEST_BYTES];
    hasher.finalize_xof().read(&mut digest);
    let elapsed = support::milliseconds(start.elapsed());
    std::hint::black_box(&digest);
    elapsed
}

fn median(samples: &[f64]) -> f64 {
    support::summary(samples).median
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() >= 5,
        "usage: mldsa_statement_experiment <t> <repetitions> <warm-up-ms> <L>..."
    );
    let t = support::parse_count(&args[1], "t", MAX_T);
    let repetitions = support::parse_count(&args[2], "repetitions", MAX_REPETITIONS);
    let warmup_ms = if args[3] == "0" {
        0
    } else {
        support::parse_count(&args[3], "warm-up-ms", MAX_WARMUP_MS)
    };
    let list_sizes: Vec<usize> = args[4..]
        .iter()
        .map(|value| support::parse_count(value, "L", support::MAX_LIST_ENTRIES))
        .collect();
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();
    let version = 0;

    // Setup, untimed: a committee in which everybody signs, and one list per size.
    let signers: Vec<_> = (0..t)
        .map(|_| MlDsa65Signer::generate().expect("ML-DSA key generation failed"))
        .collect();
    let members: Vec<PublicKey> = signers.iter().map(MlDsa65Signer::public_key).collect();
    let committee = Committee::new(members.clone(), t).expect("invalid committee");
    let mut cases: Vec<Case> = list_sizes
        .iter()
        .map(|&entries| Case {
            list: (0..entries as u32).map(support::fingerprint).collect(),
            statement_signatures: Vec::with_capacity(t),
            digest_signatures: Vec::with_capacity(t),
            sign_statement_ms: Vec::new(),
            sign_digest_ms: Vec::new(),
            verify_statement_ms: Vec::with_capacity(repetitions),
            verify_digest_ms: Vec::with_capacity(repetitions),
            preimage_ms: Vec::with_capacity(repetitions),
            digest_ms: Vec::with_capacity(repetitions),
            app_pass_ms: Vec::with_capacity(repetitions),
            mu_statement_ms: Vec::with_capacity(repetitions),
            mu_digest_ms: Vec::with_capacity(repetitions),
        })
        .collect();
    let count = cases.len();

    // Warm-up, untimed: the experiment's own kind of work until the clock settles.
    let warm_message = committee.statement_for(&cases[0].list, version);
    let warm_signature = signers[0]
        .sign(&warm_message)
        .expect("ML-DSA signing failed");
    let warm_start = Instant::now();
    while warm_start.elapsed().as_millis() < warmup_ms as u128 {
        assert!(verify(&members[0], &warm_message, &warm_signature));
    }

    // Signing: one member's cost for one signature, statement built each time.
    // The list sizes are interleaved; the first `t` signatures of each variant
    // form the quorum verified below.
    let sign_samples = t.max(MIN_SIGN_SAMPLES);
    for index in 0..sign_samples {
        let signer = &signers[index % t];
        for offset in 0..count {
            let case = &mut cases[(index + offset) % count];
            let statement_first = (index + offset) % 2 == 0;
            for pass in 0..2 {
                if (pass == 0) == statement_first {
                    let start = Instant::now();
                    let message = committee.statement_preimage(&case.list, version);
                    let signature = signer.sign(&message).expect("ML-DSA signing failed");
                    case.sign_statement_ms
                        .push(support::milliseconds(start.elapsed()));
                    if index < t {
                        case.statement_signatures.push(signature);
                    }
                } else {
                    let start = Instant::now();
                    let message = committee.statement_for(&case.list, version);
                    let signature = signer.sign(&message).expect("ML-DSA signing failed");
                    case.sign_digest_ms
                        .push(support::milliseconds(start.elapsed()));
                    if index < t {
                        case.digest_signatures.push(signature);
                    }
                }
            }
        }
    }

    // Verification of the whole quorum, and the two building blocks alone.
    for repetition in 0..repetitions {
        for offset in 0..count {
            let position = (repetition + offset) % count;
            let entries = list_sizes[position];
            let case = &mut cases[position];
            let statement_first = (repetition + offset) % 2 == 0;
            for pass in 0..2 {
                if (pass == 0) == statement_first {
                    let start = Instant::now();
                    let message = committee.statement_preimage(&case.list, version);
                    let accepted = quorum_verifies(&members, &message, &case.statement_signatures);
                    let elapsed = support::milliseconds(start.elapsed());
                    assert!(accepted, "statement-variant quorum failed to verify");
                    case.verify_statement_ms.push(elapsed);
                    if emit_samples {
                        println!(
                            "SAMPLE list_entries={entries} variant=statement phase=verify_quorum \
                             rep={repetition} ms={elapsed:.4}"
                        );
                    }
                } else {
                    let start = Instant::now();
                    let message = committee.statement_for(&case.list, version);
                    let accepted = quorum_verifies(&members, &message, &case.digest_signatures);
                    let elapsed = support::milliseconds(start.elapsed());
                    assert!(accepted, "digest-variant quorum failed to verify");
                    case.verify_digest_ms.push(elapsed);
                    if emit_samples {
                        println!(
                            "SAMPLE list_entries={entries} variant=digest phase=verify_quorum \
                             rep={repetition} ms={elapsed:.4}"
                        );
                    }
                }
            }
            let start = Instant::now();
            let preimage = committee.statement_preimage(&case.list, version);
            case.preimage_ms
                .push(support::milliseconds(start.elapsed()));
            std::hint::black_box(&preimage);
            let start = Instant::now();
            let digest = committee.statement_for(&case.list, version);
            case.digest_ms.push(support::milliseconds(start.elapsed()));
            std::hint::black_box(&digest);
            case.app_pass_ms.push(app_pass_ms(&preimage));
            case.mu_statement_ms.push(mu_ms(&members[0], &preimage));
            case.mu_digest_ms.push(mu_ms(&members[0], &digest));
        }
    }

    // Controls: the two messages are different messages. A signature over one
    // never verifies over the other, and neither verifies under another key.
    let outsider = MlDsa65Signer::generate()
        .expect("outsider key generation failed")
        .public_key();
    let peak_rss_mb = support::rss_mb("VmHWM:");
    for (case, entries) in cases.iter().zip(&list_sizes) {
        let preimage = committee.statement_preimage(&case.list, version);
        let digest = committee.statement_for(&case.list, version);
        assert_eq!(digest.len(), STATEMENT_DIGEST_BYTES);
        let controls_ok = !verify(&members[0], &digest, &case.statement_signatures[0])
            && !verify(&members[0], &preimage, &case.digest_signatures[0])
            && !verify(&outsider, &preimage, &case.statement_signatures[0])
            && !verify(&outsider, &digest, &case.digest_signatures[0]);
        assert!(controls_ok, "a negative control verified for L={entries}");
        println!(
            "MLDSA_STATEMENT_EXPERIMENT t={t} list_entries={entries} statement_bytes={} \
             digest_bytes={STATEMENT_DIGEST_BYTES} repetitions={repetitions} \
             sign_samples={sign_samples} warmup_ms={warmup_ms} \
             sign_statement_med_ms={:.4} sign_digest_med_ms={:.4} \
             verify_statement_med_ms={:.4} verify_digest_med_ms={:.4} \
             preimage_med_ms={:.4} digest_med_ms={:.4} app_pass_med_ms={:.4} mu_statement_med_ms={:.4} \
             mu_digest_med_ms={:.4} peak_rss_mb={peak_rss_mb} controls_ok=1",
            preimage.len(),
            median(&case.sign_statement_ms),
            median(&case.sign_digest_ms),
            median(&case.verify_statement_ms),
            median(&case.verify_digest_ms),
            median(&case.preimage_ms),
            median(&case.digest_ms),
            median(&case.app_pass_ms),
            median(&case.mu_statement_ms),
            median(&case.mu_digest_ms),
        );
    }
}
