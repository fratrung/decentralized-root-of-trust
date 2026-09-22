//! Generates ML-DSA quorum records outside the measured verifier process.
//!
//! Usage: mldsa_fixture <new-output-dir> <N> <t> <updates>

#[path = "support/mod.rs"]
mod support;

use std::path::Path;

use drot_mldsa::status_list::{MAX_COMMITTEE_SIZE, MlDsaStatusList};
use drot_mldsa::{Committee, MlDsa65Signer, PublicKey, Signature};

fn write_new(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
}

fn signed_record(
    committee: &Committee,
    signers: &[MlDsa65Signer],
    list: &[[u8; 32]],
    version: u32,
) -> MlDsaStatusList {
    let message = committee.statement_for(list, version);
    let signatures: Vec<(usize, Signature)> = (0..committee.threshold())
        .map(|offset| {
            let index = (version as usize + offset) % committee.member_count();
            let signature = signers[index]
                .sign(&message)
                .expect("ML-DSA signing failed");
            (index, signature)
        })
        .collect();
    MlDsaStatusList::new(list.to_vec(), version, committee.member_count(), signatures)
        .expect("fixture record construction failed")
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "usage: mldsa_fixture <new-output-dir> <N> <t> <updates>"
    );
    let outdir = Path::new(&args[1]);
    let n = support::parse_count(&args[2], "N", MAX_COMMITTEE_SIZE);
    let threshold = support::parse_count(&args[3], "t", n);
    let updates = support::parse_count(&args[4], "updates", support::MAX_UPDATES);
    std::fs::create_dir(outdir)
        .unwrap_or_else(|error| panic!("cannot create new fixture directory: {error}"));

    let signers: Vec<_> = (0..n)
        .map(|_| MlDsa65Signer::generate().expect("ML-DSA key generation failed"))
        .collect();
    let members: Vec<PublicKey> = signers.iter().map(MlDsa65Signer::public_key).collect();
    let committee = Committee::new(members, threshold).expect("invalid committee");
    write_new(&outdir.join("anchor.ssz"), &committee.to_bytes());

    let mut list = Vec::with_capacity(updates);
    let mut first_record = None;
    for version in 0..updates {
        list.push(support::fingerprint(version as u32));
        let record = signed_record(&committee, &signers, &list, version as u32);
        if version == 0 {
            first_record = Some(record.to_bytes());
        }
        write_new(
            &outdir.join(format!("update-{version:05}.ssz")),
            &record.to_bytes(),
        );
    }

    // A valid outsider signature under the main anchor's statement, falsely
    // labelled as committee member 0. This is an untimed negative control.
    let first = MlDsaStatusList::from_bytes(
        first_record
            .as_deref()
            .expect("at least one update is required"),
    )
    .expect("first fixture record did not decode");
    let message = committee.statement_for(first.list(), first.version());
    let outsider = MlDsa65Signer::generate().expect("outsider key generation failed");
    let outsider_signature = outsider.sign(&message).expect("outsider signing failed");
    let mut indexed_signatures: Vec<_> = first
        .signer_indices()
        .zip(first.signatures())
        .map(|(index, signature)| (index, signature.clone()))
        .collect();
    let first_index = indexed_signatures[0].0;
    indexed_signatures[0] = (first_index, outsider_signature);
    let outsider_record = MlDsaStatusList::new(
        first.list().to_vec(),
        first.version(),
        n,
        indexed_signatures,
    )
    .expect("outsider control construction failed");
    write_new(
        &outdir.join("attack-outsider.ssz"),
        &outsider_record.to_bytes(),
    );

    // Written last: its presence means the complete fixture was generated.
    write_new(
        &outdir.join("manifest.txt"),
        format!("N={n}\nt={threshold}\nupdates={updates}\n").as_bytes(),
    );
    println!("MLDSA_FIXTURE n_members={n} t={threshold} n_updates={updates} status=ok");
}
