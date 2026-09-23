//! Measures the relying party's ML-DSA raw verification path.
//!
//! Usage: mldsa_raw_agg <fixture-dir> <updates>
//! Fixture creation, key generation, signing and file I/O are outside timings.

#[path = "support/mod.rs"]
mod support;

use std::path::Path;
use std::time::Instant;

use drot_mldsa::status_list::{MAX_RECORD_BYTES, MlDsaStatusList, SIGNATURE_BYTES};
use drot_mldsa::{Committee, RawVerifier, Signature};

const MAX_ANCHOR_FILE_BYTES: u64 = 4 * 1024 * 1024;

fn read_bounded(path: &Path, limit: u64) -> Vec<u8> {
    let metadata = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()));
    assert!(
        metadata.len() <= limit,
        "fixture {} exceeds the allowed size",
        path.display()
    );
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    assert!(
        bytes.len() as u64 <= limit,
        "fixture {} grew beyond the allowed size",
        path.display()
    );
    bytes
}

fn indexed_signatures(record: &MlDsaStatusList) -> Vec<(usize, Signature)> {
    record
        .signer_indices()
        .zip(record.signatures())
        .map(|(index, signature)| (index, signature.clone()))
        .collect()
}

fn negative_controls(verifier: &RawVerifier, directory: &Path) -> bool {
    let bytes = read_bounded(&directory.join("update-00000.ssz"), MAX_RECORD_BYTES as u64);
    let honest = MlDsaStatusList::from_bytes(&bytes).expect("invalid first fixture record");
    assert!(verifier.verify_status_list(&honest));
    let n = verifier.committee().member_count();
    let threshold = verifier.committee().threshold();
    let signatures = indexed_signatures(&honest);

    let mut changed_list = honest.list().to_vec();
    changed_list.push([0xff; 32]);
    let tampered =
        MlDsaStatusList::new(changed_list, honest.version(), n, signatures.clone()).unwrap();
    let relabelled = MlDsaStatusList::new(
        honest.list().to_vec(),
        honest.version() + 1,
        n,
        signatures.clone(),
    )
    .unwrap();
    let short = MlDsaStatusList::new(
        honest.list().to_vec(),
        honest.version(),
        n,
        signatures.into_iter().take(threshold - 1).collect(),
    )
    .unwrap();
    let outsider_bytes = read_bounded(
        &directory.join("attack-outsider.ssz"),
        MAX_RECORD_BYTES as u64,
    );
    let outsider =
        MlDsaStatusList::from_bytes(&outsider_bytes).expect("invalid outsider fixture record");

    let tamper_rejected = !verifier.verify_status_list(&tampered);
    let relabel_rejected = !verifier.verify_status_list(&relabelled);
    let short_rejected = !verifier.verify_status_list(&short);
    let outsider_rejected = !verifier.verify_status_list(&outsider);
    println!(
        "negative controls (list/version/quorum/outsider): \
         {tamper_rejected}/{relabel_rejected}/{short_rejected}/{outsider_rejected}"
    );
    tamper_rejected && relabel_rejected && short_rejected && outsider_rejected
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: mldsa_raw_agg <fixture-dir> <updates>"
    );
    let directory = Path::new(&args[1]);
    let updates = support::parse_count(&args[2], "updates", support::MAX_UPDATES);
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();
    let anchor_bytes = read_bounded(&directory.join("anchor.ssz"), MAX_ANCHOR_FILE_BYTES);
    let committee = Committee::from_bytes(&anchor_bytes).expect("invalid fixture anchor");
    let n = committee.member_count();
    let threshold = committee.threshold();
    let manifest_bytes = read_bounded(&directory.join("manifest.txt"), 128);
    let manifest = std::str::from_utf8(&manifest_bytes).expect("invalid fixture manifest");
    assert_eq!(
        manifest,
        format!("N={n}\nt={threshold}\nupdates={updates}\n"),
        "fixture N/t/update count differs from the requested run"
    );
    let verifier = RawVerifier::new(committee);
    let rss_anchor = support::rss_mb("VmRSS:");
    let mut rss_updates_max = rss_anchor;
    let mut decode_samples = Vec::with_capacity(updates);
    let mut verify_samples = Vec::with_capacity(updates);
    let mut total_samples = Vec::with_capacity(updates);
    let mut record_bytes = Vec::with_capacity(updates);

    for index in 0..updates {
        let path = directory.join(format!("update-{index:05}.ssz"));
        let bytes = read_bounded(&path, MAX_RECORD_BYTES as u64);
        let total_start = Instant::now();
        let record = MlDsaStatusList::from_bytes(&bytes).expect("invalid fixture record");
        let decode_time = total_start.elapsed();
        let verify_start = Instant::now();
        let accepted = verifier.verify_status_list(&record);
        let verify_time = verify_start.elapsed();
        let total_time = total_start.elapsed();
        assert_eq!(record.version(), index as u32, "fixture version mismatch");
        assert_eq!(record.signer_count(), threshold, "fixture quorum mismatch");
        assert!(accepted, "honest fixture failed ML-DSA verification");

        let rss = support::rss_mb("VmRSS:");
        rss_updates_max = rss_updates_max.max(rss);
        let decode_ms = support::milliseconds(decode_time);
        let verify_ms = support::milliseconds(verify_time);
        let total_ms = support::milliseconds(total_time);
        if emit_samples {
            println!(
                "SAMPLE target=mldsa_raw_agg idx={index} decode_ms={decode_ms:.3} \
                 verify_ms={verify_ms:.3} total_ms={total_ms:.3} bytes={} \
                 sig_bytes={SIGNATURE_BYTES} signatures_bytes={} rss_mb={rss}",
                bytes.len(),
                threshold * SIGNATURE_BYTES
            );
        }
        decode_samples.push(decode_ms);
        verify_samples.push(verify_ms);
        total_samples.push(total_ms);
        record_bytes.push(bytes.len() as f64);
    }

    let all_rejected = negative_controls(&verifier, directory);
    assert!(
        all_rejected,
        "at least one ML-DSA negative control was accepted"
    );
    let decode = support::summary(&decode_samples);
    let verify = support::summary(&verify_samples);
    let total = support::summary(&total_samples);
    let size = support::summary(&record_bytes);

    println!(
        "MLDSA_RAW_AGG n_members={n} t={threshold} n_updates={} \
         decode_med_ms={:.3} decode_mean_ms={:.3} decode_sd_ms={:.3} \
         decode_min_ms={:.3} decode_max_ms={:.3} decode_total_ms={:.3} \
         verify_med_ms={:.3} verify_mean_ms={:.3} verify_sd_ms={:.3} \
         verify_min_ms={:.3} verify_max_ms={:.3} verify_total_ms={:.3} \
         total_med_ms={:.3} total_mean_ms={:.3} total_sd_ms={:.3} \
         total_min_ms={:.3} total_max_ms={:.3} total_total_ms={:.3} \
         record_med_bytes={:.3} sig_bytes={SIGNATURE_BYTES} \
         signatures_bytes={} rss_anchor_mb={rss_anchor} \
         rss_updates_max_mb={rss_updates_max} peak_rss_mb={} \
         tamper_rejected=1 fixture_input=1",
        verify.count,
        decode.median,
        decode.mean,
        decode.sd,
        decode.min,
        decode.max,
        decode.total,
        verify.median,
        verify.mean,
        verify.sd,
        verify.min,
        verify.max,
        verify.total,
        total.median,
        total.mean,
        total.sd,
        total.min,
        total.max,
        total.total,
        size.median,
        threshold * SIGNATURE_BYTES,
        support::rss_mb("VmHWM:")
    );
}
