//! [`SnarkNode`]: the composition of the SNARK predicate with the durable
//! anti-rollback gate, and the ordering between them.
//!
//! `tests/snark_path.rs` proves the five checks are load-bearing and
//! `src/state/freshness.rs` proves the gate is strict. What neither covers is the
//! seam: that a record which fails the predicate never reaches the gate. That is
//! the property a relying party is built out of, and the one every binary used to
//! re-implement by hand.
//!
//! ## Cost
//!
//! One aggregation plus `setup_prover()` and `setup_verifier()`: a few seconds
//! and about a gigabyte resident. One `#[test]`, for the reason spelled out in
//! `tests/snark_path.rs`: leanVM's arena is one shared region per process, and
//! libtest runs tests as threads.
//!
//! ## Slot discipline
//!
//! Seeds are tagged `[FILE, 0, member, 0, ..]` with a `FILE` of its own, so no
//! key here shares a hash chain with one in another test binary. One round is
//! signed, at one slot, by three members: no `(key, slot)` pair repeats.

use decentralized_root_of_trust::node::Outcome;
use decentralized_root_of_trust::node::snark_node::SnarkNode;
use decentralized_root_of_trust::node::snark_prover::PQSNARKProverModule;
use decentralized_root_of_trust::node::snark_verifier::PQSNARKVerifierModule;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{Algorithms, SnarkStatusList, hash_any};
use decentralized_root_of_trust::state::freshness::HighWaterMark;
use lean_multisig::{XmssPublicKey, XmssSignature, xmss_key_gen_from_seed, xmss_sign};

const N: usize = 5;
const T: usize = 3;
const GENESIS: u32 = 100;
/// Last usable slot, inclusive; `WINDOW + 1` is the count leanVM v0.9 takes.
const WINDOW: u32 = 8;
/// Matches `params::LOG_INV_RATE`, so this is the deployed configuration.
const LOG_INV_RATE: usize = 2;
/// The one round signed here. Not 0, so a hostile record can claim a version both
/// above and below it.
const ROUND: u32 = 2;

/// Distinguishes this file's seeds from every other test binary's.
const FILE: u8 = 10;

fn seed(member: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = FILE;
    s[2] = member;
    s
}

fn scratch(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("snarknode-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn the_gate_moves_only_for_a_proof_that_verified() {
    let prover = PQSNARKProverModule::init_prover();

    let keys: Vec<_> = (0..N)
        .map(|i| {
            xmss_key_gen_from_seed(seed(i as u8), u64::from(GENESIS), u64::from(WINDOW) + 1)
                .expect("keygen")
        })
        .collect();
    let members: Vec<XmssPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
    let committee = Committee::new(members, T, GENESIS);

    let list = vec![hash_any(b"revoke-alice")];
    let message = committee.message_for(Algorithms::WotsXmss, &list, ROUND);
    let slot = committee.slot_for(ROUND).expect("slot");
    let raws: Vec<(XmssPublicKey, XmssSignature)> = [0usize, 1, 2]
        .iter()
        .map(|&i| {
            let (pk, sk) = &keys[i];
            (pk.clone(), xmss_sign(sk, slot, &message).expect("sign"))
        })
        .collect();
    let proof = prover.make_proof(
        &committee,
        Algorithms::WotsXmss,
        raws,
        &list,
        ROUND,
        LOG_INV_RATE,
    );

    let mark = HighWaterMark::load(scratch("gate"), &committee.to_bytes());
    let mut node = SnarkNode::new(committee, mark);
    assert_eq!(node.high_water(), None, "a fresh node has accepted nothing");

    // --- a record that does not verify must not reach the gate ---------------
    //
    // The proof is genuine and the quorum is real; only the version is a lie,
    // which check 2 catches because the version is folded into the signed
    // message. If a claimed version could move the mark, this record alone would
    // push it to 9 and every honest round up to and including 9 would then be
    // refused as stale.
    let liar = SnarkStatusList::new(Algorithms::WotsXmss, list.clone(), 9, proof.clone());
    assert_eq!(node.accept(&liar.to_bytes()), Outcome::Refused);
    assert_eq!(node.high_water(), None, "the gate must not have moved");

    // Bytes that are not a record at all take the same path out.
    assert_eq!(node.accept(&[]), Outcome::Refused);
    assert_eq!(node.accept(&[0xff; 96]), Outcome::Refused);
    assert_eq!(node.high_water(), None);

    // --- the honest record ---------------------------------------------------
    let honest = SnarkStatusList::new(Algorithms::WotsXmss, list.clone(), ROUND, proof.clone());
    let bytes = honest.to_bytes();
    assert_eq!(node.accept(&bytes), Outcome::Accepted { version: ROUND });
    assert_eq!(node.high_water(), Some(ROUND));

    // The same bytes again: still a valid proof, and that is exactly the point.
    // Only the mark can tell a replay from an update.
    assert_eq!(
        node.accept(&bytes),
        Outcome::Stale {
            version: ROUND,
            mark: ROUND
        }
    );
    assert_eq!(node.high_water(), Some(ROUND));

    // --- selection among peers -----------------------------------------------
    //
    // Everything on offer is at or below the mark, so nothing is verified and
    // nothing is accepted: the floor is what keeps a stale answer from costing a
    // SNARK verification.
    assert_eq!(
        node.accept_best(&[bytes.clone(), liar.to_bytes(), vec![0u8; 8]]),
        Outcome::Refused
    );
    assert_eq!(node.high_water(), Some(ROUND));

    // --- the budget ----------------------------------------------------------
    //
    // The floor above only removes what a peer declares to be *old*, which is not
    // what a hostile peer declares. Records claiming versions above the mark pass
    // the floor untouched, and each one a selection reaches costs a full SNARK
    // verification — the most expensive thing an unauthenticated peer can buy
    // here. So the number verified is capped rather than the number offered.
    //
    // The genuine record is placed last, at the lowest surviving version, so that
    // what this asserts is the cap stopping the walk and not a lucky early hit.
    // A genuine record one round on. It cannot be the record above with a new
    // label: the version is folded into the signed message, so a relabelled proof
    // is exactly the forgery `liar` already covers. A second round means a second
    // aggregation — the reason this case lives here, in the file that already
    // pays for a prover, rather than in a test of its own.
    const NEXT: u32 = ROUND + 1;
    let next_list = vec![hash_any(b"revoke-alice"), hash_any(b"revoke-bob")];
    let next_message = node
        .committee()
        .message_for(Algorithms::WotsXmss, &next_list, NEXT);
    let next_slot = node.committee().slot_for(NEXT).expect("slot");
    let next_raws: Vec<(XmssPublicKey, XmssSignature)> = [0usize, 1, 2]
        .iter()
        .map(|&i| {
            let (pk, sk) = &keys[i];
            (
                pk.clone(),
                xmss_sign(sk, next_slot, &next_message).expect("sign"),
            )
        })
        .collect();
    let next_proof = prover.make_proof(
        node.committee(),
        Algorithms::WotsXmss,
        next_raws,
        &next_list,
        NEXT,
        LOG_INV_RATE,
    );
    let fresher =
        SnarkStatusList::new(Algorithms::WotsXmss, next_list, NEXT, next_proof).to_bytes();
    let mut flood: Vec<Vec<u8>> = (0..PQSNARKVerifierModule::MAX_VERIFICATIONS_PER_SELECTION + 4)
        .map(|i| {
            // Structurally a record, above the mark, with a proof that is not one.
            SnarkStatusList::new(
                Algorithms::WotsXmss,
                list.clone(),
                NEXT + 1 + i as u32,
                vec![0xAB; 64],
            )
            .to_bytes()
        })
        .collect();
    flood.push(fresher.clone());

    assert!(
        flood.len() > PQSNARKVerifierModule::MAX_VERIFICATIONS_PER_SELECTION,
        "the budget must bind, or this case is vacuous"
    );
    assert_eq!(
        node.accept_best(&flood),
        Outcome::Refused,
        "the walk must stop at the budget rather than digging out the real record"
    );
    assert_eq!(
        node.high_water(),
        Some(ROUND),
        "the gate must not have moved"
    );

    // And the record the budget hid is still perfectly acceptable on its own: the
    // cap bounds work, it does not blacklist anything.
    assert_eq!(node.accept(&fresher), Outcome::Accepted { version: NEXT });
}
