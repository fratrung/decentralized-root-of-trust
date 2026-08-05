//! End-to-end walkthrough of the **non-SNARK** path, at the smallest size that
//! still exercises every part: a one-member committee publishing two updates.
//!
//! A credential is canonicalized (JCS, RFC 8785), hashed into a status-list
//! entry, signed by a `SignerNode` at the slot the anchor derives, packed into a
//! `StatusList`, sent through its wire encoding, and checked by a `VerifierNode`
//! that knows nothing but the committee.
//!
//! No `setup_prover()`, no `setup_verifier()`, no circuit — see `raw_agg` for the
//! same path at committee scale, and `prover`/`verifier` for the SNARK one.

use decentralized_root_of_trust::{
    atomic_slot_counter::AtomicSlotCounter,
    committee::Committee,
    signer_node::SignerNode,
    status_list::{Algorithms, StatusList, hash_any, status_list_root_fe},
    verifier_node::VerifierNode,
};
use lean_multisig::xmss_key_gen;
use rand::RngExt;
use serde_json::{Value, json};

const SLOT_STATE: &str = "next_slot";
const GENESIS: u32 = 46;
const KEY_SLOTS: u32 = 128;

/// Wipes the durable slot state so the demo can be re-run.
///
/// Correct only because the key is regenerated on every run: the counter is
/// meaningless without the `sk` it was bound to, so the two die together. A real
/// node must never do this — deleting the state of a key that still exists is
/// how slots get reused, and a reused XMSS slot means a recoverable secret key.
fn reset_slot_state() {
    let _ = std::fs::remove_file(SLOT_STATE);
    let _ = std::fs::remove_file(std::path::Path::new(SLOT_STATE).with_extension("lock"));
}

/// A credential's status-list entry: canonical JSON, then SHA3-256.
///
/// Canonicalizing first is what makes the fingerprint stable. Two encodings of
/// the same credential — different key order, different spacing — must hash to
/// the same entry, or a revocation could be evaded by re-serializing.
fn vc_entry(vc: &Value) -> [u8; 32] {
    let canonical = serde_jcs::to_vec(vc).expect("canonicalization failed");
    hash_any(canonical)
}

fn device_vc(uuid: &str, model: &str, serial: &str) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": format!("urn:uuid:{uuid}"),
        "type": ["VerifiableCredential", "DeviceIdentityCredential"],
        "issuer": "Committee",
        "validFrom": "2026-07-30T00:00:00Z",
        "credentialSubject": {
            "id": format!("did:iiot:{uuid}"),
            "deviceModel": model,
            "serialNumber": serial
        },
        "credentialStatus": {
            "id": "https://committee.example/status/1#42",
            "type": "CommitteeStatusList",
            "statusListIndex": "42"
        }
    })
}

fn main() {
    reset_slot_state();
    let mut rng = rand::rng();

    println!("Start to generate WOTS+/XMSS keypairs");
    let (sk, pk) = xmss_key_gen(rng.random(), GENESIS, GENESIS + KEY_SLOTS, true)
        .unwrap_or_else(|e| panic!("keygen failed: {e:?}"));
    println!("WOTS+/XMSS Keypairs generated!");

    let counter = AtomicSlotCounter::create(SLOT_STATE, &pk, GENESIS, GENESIS + KEY_SLOTS)
        .unwrap_or_else(|e| panic!("slot state: {e}"));

    // A committee of one, threshold one. `GENESIS` is the slot round 0 signs at:
    // both the signer and the verifier derive every later slot from it, so
    // neither ever has to be told which one to use.
    let committee = Committee::new(vec![pk.clone()], 1, GENESIS);
    let verifier = VerifierNode::new(committee.clone());
    let mut signer = SignerNode::new(pk, sk, counter);

    let mut list: Vec<[u8; 32]> = Vec::new();

    for (version, vc) in [
        device_vc(
            "3f2b8c14-9d7e-4a11-b6c3-5e8a0f14d2b9",
            "BCM2711",
            "10000000abcd1234",
        ),
        device_vc(
            "3f5b8c14-9d7e-4a11-b6c3-5e8a0f14d2b9",
            "BCM2721",
            "10000000abcd1734",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let version = version as u32;
        list.push(vc_entry(&vc));

        let slot = committee.slot_for(version).expect("slot overflow");
        let message = status_list_root_fe(&list, version);
        let signature = signer
            .sign_at(&mut rng, &message, slot)
            .unwrap_or_else(|e| panic!("signing failed: {e}"));

        // Signer 0 is the only member, so the bitmap is a single set bit.
        let record = StatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            version,
            committee.members().len(),
            vec![(0, signature)],
        )
        .unwrap_or_else(|e| panic!("malformed record: {e}"));

        println!("\nStatus list v{version} creata e firmata (slot {slot}): {record}");

        // Publish and read back: a verifier only ever sees bytes.
        let wire = record.to_bytes();
        let received = StatusList::from_bytes(&wire).unwrap_or_else(|e| panic!("decode: {e}"));

        if verifier.verify_status_list(&received) {
            println!("Signature Verified ({} bytes on the wire)", wire.len());
        } else {
            eprintln!("Verification Failed");
            std::process::exit(1);
        }
    }

    // The slot the anchor would assign to the next round, and the ones this key
    // has left: `remaining` is what a node watches to start a re-key in time,
    // since an exhausted key cannot even sign its own replacement.
    println!(
        "\nnext slot {} ; {} of {} slots left",
        signer.next_slot(),
        signer.remaining_slots(),
        KEY_SLOTS + 1
    );
}
