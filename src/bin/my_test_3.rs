//! The **non-SNARK** path at committee scale: 30 signers, threshold 10, one
//! credential published as round 0 and verified against the anchor alone.
//!
//! Same shape as `my_test_2`, but with a real quorum rather than a committee of
//! one — so it exercises the part `my_test_2` cannot: only `t` of the `N` members
//! sign, and the record has to name which ones.

use decentralized_root_of_trust::{
    atomic_slot_counter::AtomicSlotCounter,
    committee::Committee,
    signer_node::SignerNode,
    status_list::{Algorithms, StatusList, hash_any},
    verifier_node::VerifierNode,
};
use lean_multisig::{XmssSignature, xmss_key_gen};
use serde_json::{Value, json};

const GENESIS: u32 = 46;
const KEY_SLOTS: u32 = 256;
const N_MEMBERS: u32 = 70;
const THRESHOLD: usize = 35;
/// Where each member's durable slot counter lives, one file per key.
const STATE_DIR: &str = "signers";

/// Wipes the durable slot state so the demo can be re-run.
///
/// Correct only because every key is regenerated on each run: a counter is
/// meaningless without the key it was bound to, so the two die together. A real
/// node must never do this — deleting the state of a key that still exists is how
/// slots get reused, and a reused XMSS slot means a recoverable secret key.
///
/// It also *creates* the directory. `AtomicSlotCounter::create` opens a lock file
/// next to the state file and does not create parent directories, so without this
/// the first member panics with a bare `NotFound` before anything else runs.
fn reset_slot_state() {
    let _ = std::fs::remove_dir_all(STATE_DIR);
    std::fs::create_dir_all(STATE_DIR).expect("cannot create the slot state directory");
}

fn vc_entry(vc: &Value) -> [u8; 32] {
    let canonical = serde_json::to_vec(vc).expect("canonicalization failed");
    hash_any(canonical)
}

fn get_signers(n: u32) -> Vec<SignerNode> {
    let mut signers = Vec::with_capacity(n as usize);
    let mut rng = rand::rng();
    for i in 0..n {
        let path = format!("{STATE_DIR}/node_{i}_slot");
        // leanVM v0.9: the RNG supplies the seed, the window is a slot *count*
        // (`KEY_SLOTS + 1`, since the counter's range is inclusive at both ends),
        // and the pair comes back public-first.
        let (pk, sk) = xmss_key_gen(&mut rng, u64::from(GENESIS), u64::from(KEY_SLOTS) + 1)
            .expect("XMSS Key Gen Error");
        let slot_counter = AtomicSlotCounter::create(path, &pk, GENESIS, GENESIS + KEY_SLOTS)
            .expect("slot counter error");
        signers.push(SignerNode::new(pk, sk, slot_counter));
    }
    signers
}

fn get_committee_from_signers(signers: &[SignerNode]) -> Committee {
    let mut members = Vec::with_capacity(signers.len());
    for signer in signers {
        members.push(signer.public_key().clone())
    }
    Committee::new(members, THRESHOLD, GENESIS)
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
    let mut signers = get_signers(N_MEMBERS);
    let committee = get_committee_from_signers(&signers);
    let verifier = VerifierNode::new(committee.clone());

    let vc1 = device_vc("asdvsa:dafnn:ddsa", "1", "bac3331");
    let status_list = vec![vc_entry(&vc1)];

    // `version` is the application counter and `slot` is the XMSS epoch the anchor
    // derives from it. They are two different numbers and must not be swapped:
    // every one of the three uses below has to agree with what the verifier
    // recomputes, which is `status_list_message(list, version)` at
    // `slot_for(version)`. Passing the slot where the version belongs is why this
    // file used to print nothing — the message matched but the slot did not.
    let version = 0u32;
    let slot = match committee.slot_for(version) {
        Some(slot) => slot,
        None => {
            eprintln!("Error to get slot from committee");
            std::process::exit(1);
        }
    };

    let status_list_poseidon2_digest =
        committee.message_for(Algorithms::WotsXmss, &status_list, version);

    // The first `t` members sign. The rest abstain, which is the point of a
    // threshold: the record still verifies without them.
    let mut signatures: Vec<(usize, XmssSignature)> = Vec::new();
    for (i, n) in signers.iter_mut().enumerate() {
        if signatures.len() >= committee.threshold() {
            break;
        }

        if i % 2 != 1 {
            continue;
        }

        let signature = n
            .sign_at(&status_list_poseidon2_digest, slot)
            .unwrap_or_else(|e| panic!("signing failed: {e}"));
        signatures.push((i, signature));
    }

    let record = StatusList::new(
        Algorithms::WotsXmss,
        status_list,
        version,
        committee.members().len(),
        signatures,
    )
    .expect("Error to create status list");

    // Publish and read back: a verifier only ever sees bytes.
    let wire = record.to_bytes();
    let received = StatusList::from_bytes(&wire).unwrap_or_else(|e| panic!("decode: {e}"));

    if verifier.verify_status_list(&received) {
        println!(
            "Success: v{version} at slot {slot}, {} of {} members, {} bytes on the wire",
            received.signer_count(),
            committee.members().len(),
            wire.len()
        );
    } else {
        // A silent failure is worse than a loud one: this used to print nothing at
        // all and still exit 0.
        eprintln!("Verification Failed");
        std::process::exit(1);
    }
}
