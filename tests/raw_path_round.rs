//! One full protocol round on the **non-SNARK path**, through the public API.
//!
//! The unit tests check each piece against its own contract. This one checks the
//! seam: durable slot counters feeding rotating quorums, the published record
//! verifying against the anchor, and the freshness gate deciding what the
//! cryptography deliberately does not.
//!
//! It stays on the raw path on purpose: `verify_proof` would pull in
//! `setup_prover()`, several seconds and a couple of gigabytes, for a property
//! this test is not about.

use decentralized_root_of_trust::node::raw_verifier::VerifierNode;
use decentralized_root_of_trust::node::signer::{SignerNode, SignerNodeError};
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{
    Algorithms, StatusList, hash_any, status_list_message,
};
use decentralized_root_of_trust::state::freshness::{Decision, HighWaterMark};
use decentralized_root_of_trust::state::slot_counter::{AtomicSlotCounter, AtomicSlotCounterError};
use lean_multisig::xmss_key_gen_from_seed;

const N: usize = 5;
const T: usize = 3;
const GENESIS: u32 = 100;
/// Last usable slot, inclusive: `GENESIS..=GENESIS + WINDOW`.
const WINDOW: u32 = 16;
/// The same window as the slot *count* leanVM v0.9's keygen takes.
const SLOT_COUNT: u64 = WINDOW as u64 + 1;

/// Seeds are `[FILE, ns, member, 0, ..]`. Each test gets its own `ns` because
/// each also gets its own scratch dir, so the durable slot counters do *not*
/// deduplicate across tests: without this, node 0 would sign slot `GENESIS` once
/// per test with one key, over messages that differ from test to test, which is
/// the repeat leanVM v0.9's derandomized signing does *not* make harmless. The window is not a namespace: leanVM derives the
/// one-time key from the seed alone (`gen_wots_secret_key(seed, slot,
/// gen_public_param(seed))`), so two keys with the same seed share every chain
/// however they were generated. `FILE` keeps this file disjoint from
/// `src/protocol/committee.rs`'s tests and `tests/snark_path.rs`.
const FILE: u8 = 2;

fn seed(ns: u8, member: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = FILE;
    s[1] = ns;
    s[2] = member;
    s
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("drot-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The committee, plus one signer node per member with its own durable counter:
/// the deployment the protocol actually describes, where no member can reach
/// another's state.
fn bring_up(dir: &std::path::Path, ns: u8) -> (VerifierNode, Vec<SignerNode>) {
    let mut nodes = Vec::with_capacity(N);
    let mut members = Vec::with_capacity(N);

    for i in 0..N {
        let (pk, sk) = xmss_key_gen_from_seed(seed(ns, i as u8), u64::from(GENESIS), SLOT_COUNT)
            .expect("keygen");
        let counter = AtomicSlotCounter::create(
            dir.join(format!("member-{i}")),
            &pk,
            GENESIS,
            GENESIS + WINDOW,
        )
        .expect("slot state");
        members.push(pk.clone());
        nodes.push(SignerNode::new(pk, sk, counter));
    }

    (
        VerifierNode::new(Committee::new(members, T, GENESIS)),
        nodes,
    )
}

/// One round: `signers` sign `(list, version)` at the slot the *anchor* derives,
/// and the result is packed into the record that would be published.
fn publish(
    committee: &Committee,
    nodes: &mut [SignerNode],
    list: &[[u8; 32]],
    version: u32,
    signers: &[usize],
) -> StatusList {
    let message = status_list_message(list, version);
    let slot = committee.slot_for(version).expect("slot");

    let signatures = signers
        .iter()
        .map(|&i| {
            let sig = nodes[i]
                .sign_at(&message, slot)
                .unwrap_or_else(|e| panic!("member {i} refused round {version}: {e}"));
            (i, sig)
        })
        .collect();

    StatusList::new(Algorithms::WotsXmss, list.to_vec(), version, N, signatures)
        .expect("well-formed record")
}

#[test]
fn two_rounds_with_a_rotating_quorum_verify_and_advance_the_gate() {
    let dir = scratch("round");
    let (verifier, mut nodes) = bring_up(&dir, 1);
    let mut hwm = HighWaterMark::load(dir.join("freshness"), &verifier.get_committee().to_bytes());

    // --- round 0: members 0,1,2 ---
    let mut list = vec![hash_any(b"revoke-alice")];
    let v0 = publish(verifier.get_committee(), &mut nodes, &list, 0, &[0, 1, 2]);

    assert!(
        verifier.verify_status_list(&v0),
        "honest round 0 must verify"
    );
    assert!(matches!(hwm.try_advance(v0.version()), Decision::Accepted));

    // --- round 1: members 2,3,4. Only member 2 overlaps, which is the case
    // per-member counters cannot handle and `slot_for` exists to fix.
    list.push(hash_any(b"revoke-bob"));
    let v1 = publish(verifier.get_committee(), &mut nodes, &list, 1, &[2, 3, 4]);

    assert!(
        verifier.verify_status_list(&v1),
        "honest round 1 must verify"
    );
    assert!(matches!(hwm.try_advance(v1.version()), Decision::Accepted));
    assert_eq!(hwm.current(), Some(1));

    // Members 3 and 4 sat out round 0. Reaching round 1's slot burned round 0's
    // rather than reclaiming it: skipping is free, reuse costs the key.
    assert_eq!(nodes[3].next_slot(), GENESIS + 2);
    assert_eq!(nodes[4].next_slot(), GENESIS + 2);

    // --- the rollback. The record is genuinely signed and still verifies: the
    // cryptography is stateless and cannot tell "old" from "current". Only the
    // gate can, which is the entire reason it exists.
    assert!(
        verifier.verify_status_list(&v0),
        "the stale record is still cryptographically valid"
    );
    assert!(matches!(hwm.try_advance(v0.version()), Decision::Stale(1)));
    assert_eq!(
        hwm.current(),
        Some(1),
        "a refusal must not disturb the mark"
    );
}

#[test]
fn a_member_cannot_be_made_to_sign_one_round_twice() {
    let dir = scratch("replay");
    let (verifier, mut nodes) = bring_up(&dir, 2);

    let list = vec![hash_any(b"revoke-alice")];
    let round0 = status_list_message(&list, 0);
    let slot0 = verifier.get_committee().slot_for(0).expect("slot");

    assert!(nodes[0].sign_at(&round0, slot0).is_ok());

    // A second *message* under the same (key, slot) is what leaks an XMSS secret
    // key, and it is exactly the case leanVM v0.9's derandomized signing leaves
    // fatal, since the derivation includes the message. The counter refuses before
    // the key is ever touched, and refusing is a normal outcome: the member
    // abstains and the quorum proceeds without it.
    let conflicting = status_list_message(&[hash_any(b"revoke-nobody")], 0);
    assert!(matches!(
        nodes[0].sign_at(&conflicting, slot0),
        Err(SignerNodeError::Slot(AtomicSlotCounterError::AlreadySpent {
            requested,
            next
        })) if requested == slot0 && next == slot0 + 1
    ));

    // The other four are untouched by member 0's refusal, so the round still
    // reaches quorum without it.
    let published = publish(verifier.get_committee(), &mut nodes, &list, 0, &[1, 2, 3]);
    assert!(verifier.verify_status_list(&published));
}

/// A crash is indistinguishable from a clean exit here: the counter is reopened
/// from disk and must not replay the slots the previous run spent.
#[test]
fn a_restart_does_not_replay_spent_slots() {
    let dir = scratch("restart");
    let (verifier, mut nodes) = bring_up(&dir, 3);

    let list = vec![hash_any(b"revoke-alice")];
    let _ = publish(verifier.get_committee(), &mut nodes, &list, 0, &[0, 1, 2]);
    drop(nodes); // releases every lock, as a process exit would

    let (pk, _) =
        xmss_key_gen_from_seed(seed(3, 0), u64::from(GENESIS), SLOT_COUNT).expect("keygen");
    let counter =
        AtomicSlotCounter::open(dir.join("member-0"), &pk, GENESIS + WINDOW).expect("reopen");
    assert_eq!(
        counter.next_slot(),
        GENESIS + 1,
        "slot {GENESIS} was spent before the restart"
    );
}
