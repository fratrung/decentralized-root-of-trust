//! Measures one ML-DSA-65 member signing sequential status-list statements.
//!
//! Usage: mldsa_signer [updates] (default 20)

#[path = "support/mod.rs"]
mod support;

use std::time::Instant;

use drot_mldsa::status_list::SIGNATURE_BYTES;
use drot_mldsa::{Committee, MlDsa65Signer, verify};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(args.len() <= 2, "usage: mldsa_signer [updates]");
    let updates = args.get(1).map_or(20, |value| {
        support::parse_count(value, "updates", support::MAX_UPDATES)
    });
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();
    let rss_baseline = support::rss_mb("VmRSS:");

    let keygen_start = Instant::now();
    let signer = MlDsa65Signer::generate().expect("ML-DSA key generation failed");
    let keygen_time = keygen_start.elapsed();
    let committee = Committee::new(vec![signer.public_key()], 1).expect("single-member anchor");
    let rss_after_keygen = support::rss_mb("VmRSS:");
    let mut rss_rounds_max = rss_after_keygen;
    let mut list = Vec::with_capacity(updates);
    let mut sign_samples = Vec::with_capacity(updates);

    for index in 0..updates {
        list.push(support::fingerprint(index as u32));
        let message = committee.statement_for(&list, index as u32);
        let sign_start = Instant::now();
        let signature = signer.sign(&message).expect("ML-DSA signing failed");
        let sign_time = sign_start.elapsed();
        assert!(
            verify(&committee.members()[0], &message, &signature),
            "self-verification failed"
        );
        let rss = support::rss_mb("VmRSS:");
        rss_rounds_max = rss_rounds_max.max(rss);
        if emit_samples {
            println!(
                "SAMPLE target=mldsa_signer idx={index} sign_ms={:.3} sig_bytes={SIGNATURE_BYTES} rss_mb={rss}",
                support::milliseconds(sign_time)
            );
        }
        sign_samples.push(support::milliseconds(sign_time));
    }

    let sign = support::summary(&sign_samples);
    println!(
        "MLDSA_SIGNER keygen_ms={:.3} n_rounds={} sign_med_ms={:.3} \
         sign_mean_ms={:.3} sign_sd_ms={:.3} sign_min_ms={:.3} \
         sign_max_ms={:.3} sign_total_ms={:.3} sig_bytes={SIGNATURE_BYTES} \
         rss_baseline_mb={rss_baseline} rss_keygen_mb={rss_after_keygen} \
         rss_rounds_max_mb={rss_rounds_max} peak_rss_mb={} failures=0",
        support::milliseconds(keygen_time),
        sign.count,
        sign.median,
        sign.mean,
        sign.sd,
        sign.min,
        sign.max,
        sign.total,
        support::rss_mb("VmHWM:")
    );
}
