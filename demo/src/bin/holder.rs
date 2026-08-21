//! Node A: the relying party, and the only participant that holds no key.
//!
//! It knows the committee a priori, which in the demo means it loads the anchor
//! from the committee volume the way a real one would compile it in. Everything
//! else it learns from the network: which member it happens to dial, what
//! credential comes back, and which record the storage volume holds.
//!
//! The order matters and is the point of the whole exercise. The credential is
//! worth nothing on its own; what makes it meaningful is that its fingerprint
//! sits in a record which `t` members of a committee this node already trusted
//! signed. So the credential is received first and *verified afterwards*,
//! against bytes fetched from a volume nobody authenticates.
//!
//! Configured by environment: `DEMO_MODE`, `SUBJECT`, `TARGET_MEMBER`,
//! `VERIFY_ONLY`.

use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::rss_now_mb;
use decentralized_root_of_trust::node::raw_verifier::VerifierNode;
use decentralized_root_of_trust::node::snark_verifier::PQSNARKVerifierModule;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{SnarkStatusList, StatusList};
use decentralized_root_of_trust::state::freshness::{Decision, HighWaterMark};
use drot_demo::config::{self, MEMBER_IPS, Mode, N_MEMBERS};
use drot_demo::wire::{self, Failure, VcIssued, VcRequest};
use drot_demo::{report, storage, vc};
use lean_multisig::SIGNATURE_SSZ_LEN;
use rand::RngExt;
use ssz::{Decode as _, Encode as _};

const ANCHOR_WAIT: Duration = Duration::from_secs(300);

fn main() {
    let mode = Mode::from_env();
    let subject = std::env::var("SUBJECT").unwrap_or_else(|_| "did:demo:alice".into());

    let committee = storage::wait_for_committee(ANCHOR_WAIT).expect("no anchor to trust");
    println!(
        "node A: anchor loaded, {}-of-{} committee, genesis slot {}, {} B",
        committee.threshold(),
        committee.members().len(),
        committee.genesis_slot(),
        committee.to_bytes().len()
    );

    let issued = if std::env::var_os("VERIFY_ONLY").is_some() {
        println!("node A: verify-only, checking whatever is published");
        None
    } else {
        Some(request_credential(&subject))
    };

    let (version, bytes) = storage::latest_record().expect("nothing is published");
    println!(
        "\nnode A: fetched the freshest published record, v{version}, {} B",
        bytes.len()
    );

    let accepted = match mode {
        Mode::Raw => verify_raw(&committee, &bytes, issued.as_ref()),
        Mode::Snark => verify_snark(&committee, &bytes, issued.as_ref()),
    };

    // Only after the record has been authenticated is its version worth
    // recording. The gate is what stops a peer replaying a record that was
    // perfectly valid last week, which no signature check can catch.
    if accepted {
        let mut mark = HighWaterMark::load(
            storage::state_dir().join("highwater"),
            &committee.to_bytes(),
        );
        let previous = mark.current();
        report::rule("freshness");
        match mark.try_advance(version) {
            Decision::Accepted => println!(
                "  accepted: high-water {} -> {version}",
                previous.map_or("none".to_string(), |v| v.to_string())
            ),
            Decision::Stale(mark) => {
                println!("  refused: v{version} is not newer than the mark at v{mark}")
            }
        }
    }

    if !accepted {
        std::process::exit(1);
    }
}

/// Asks one member of the committee, chosen at random, for a credential.
///
/// At random because no member is special: whoever is dialled becomes the
/// aggregator for that round and holds the role for exactly as long as it takes.
fn request_credential(subject: &str) -> VcIssued {
    let target = std::env::var("TARGET_MEMBER")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| (rand::rng().random::<u64>() % N_MEMBERS as u64) as usize);

    println!(
        "node A: asking member {target} ({}) for a credential for {subject}",
        MEMBER_IPS[target]
    );
    let payload = VcRequest {
        subject: subject.as_bytes().to_vec(),
    }
    .as_ssz_bytes();

    let started = Instant::now();
    let (kind, reply) = wire::request(
        config::member_addr(target),
        config::request_timeout(),
        wire::MSG_VC_REQUEST,
        &payload,
    )
    .expect("the member did not answer");

    match kind {
        wire::MSG_VC_ISSUED => {
            let issued = VcIssued::from_ssz_bytes(&reply).expect("malformed credential");
            println!(
                "node A: credential received after {:.2?}\n",
                started.elapsed()
            );
            println!("{}", vc::pretty(&issued.credential));
            issued
        }
        _ => panic!("the round failed: {}", Failure::text(&reply)),
    }
}

/// The raw path: `t` independent signature checks, no setup, no circuit.
fn verify_raw(committee: &Committee, bytes: &[u8], issued: Option<&VcIssued>) -> bool {
    let before = rss_now_mb();
    let verifier = VerifierNode::new(committee.clone());
    let after = rss_now_mb();

    let record = match StatusList::from_bytes(bytes) {
        Ok(r) => r,
        Err(e) => {
            println!("node A: the record does not decode: {e}");
            return false;
        }
    };

    let started = Instant::now();
    let ok = verifier.verify_status_list(&record);
    let elapsed = started.elapsed();

    report::rule("verification, raw path");
    println!(
        "  signers               : {} of {}",
        record.signer_count(),
        record.signer_slots()
    );
    println!(
        "  indices               : {:?}",
        record.signer_indices().collect::<Vec<_>>()
    );
    println!("  quorum verified       : {ok} in {elapsed:.2?}");
    println!(
        "  per signature         : {:.2?}",
        elapsed / record.signatures().len().max(1) as u32
    );

    report::raw_sizes(
        bytes.len(),
        record.list().len(),
        record.signatures().len(),
        SIGNATURE_SSZ_LEN,
    );
    report::memory("anchor load", before, after);
    ok && contains_credential(record.list(), issued)
}

/// The SNARK path: one constant-time check, after a setup the raw path never
/// pays for.
fn verify_snark(committee: &Committee, bytes: &[u8], issued: Option<&VcIssued>) -> bool {
    let before = rss_now_mb();
    let started = Instant::now();
    // `new` is what runs `setup_verifier()`: the aggregation bytecode has to be
    // resident before a proof can even be deserialised, which is the fixed cost
    // this path carries and the raw one does not.
    let verifier = PQSNARKVerifierModule::new(committee.clone(), 0);
    let setup = started.elapsed();
    let after = rss_now_mb();

    let record = match SnarkStatusList::from_bytes(bytes) {
        Ok(r) => r,
        Err(e) => {
            println!("node A: the record does not decode: {e}");
            return false;
        }
    };

    let started = Instant::now();
    let ok = verifier.verify(&record);
    let elapsed = started.elapsed();

    report::rule("verification, SNARK path");
    println!("  setup_verifier()      : {setup:.2?}");
    println!("  proof verified        : {ok} in {elapsed:.2?}");
    println!("  quorum named in proof : {}", quorum_size(&record));

    report::snark_sizes(
        bytes.len(),
        record.list().len(),
        record.proof_bytes().len(),
        quorum_size(&record),
    );
    report::memory("setup_verifier", before, after);
    ok && contains_credential(record.list(), issued)
}

/// How many members the proof attests to. Available only after
/// `setup_verifier()`, since the aggregate cannot be deserialised without it.
fn quorum_size(record: &SnarkStatusList) -> usize {
    record
        .proof()
        .map(|agg| agg.info.pubkeys.len())
        .unwrap_or(0)
}

/// The last question, and the one the holder actually came for: is *my*
/// credential in the list the committee signed?
///
/// The fingerprint is recomputed from the credential as received, so this
/// answers "these bytes are registered" rather than "some credential is".
fn contains_credential(list: &[[u8; 32]], issued: Option<&VcIssued>) -> bool {
    let Some(issued) = issued else {
        return true;
    };
    let entry = vc::fingerprint(&issued.credential);
    let found = list.contains(&entry);
    report::rule("credential");
    println!("  fingerprint           : {}", vc::hex(&entry));
    println!("  present in the signed list: {found}");
    if !found {
        println!("  the committee signed a list this credential is not in");
    }
    found
}
