//! The two SNARK node modules, exercised the way the binaries use them.
//!
//! Each predicate exists exactly once, on its module. These tests are what keep
//! that single copy honest.
//!
//! What is asserted here, in order of how much it matters:
//!
//!   1. the prover derives the slot from the **anchor**, not from its caller,
//!      checked against the slot recorded inside the finished proof;
//!   2. the verifier module accepts an honest record and refuses a tampered list
//!      and a relabelled version, so it is really running the five checks;
//!   3. the freshness selection on the same module runs those checks too, and is
//!      not fooled by a forgery that merely *declares* a higher version;
//!   4. `is_newer` is strict, and is not a substitute for `freshness::HighWaterMark`;
//!   5. a version with no slot under the anchor panics instead of proving something
//!      unverifiable.
//!
//! ## Cost
//!
//! ONE aggregation plus `setup_prover()`: a few seconds. Everything after the first
//! record re-uses it, because every negative case here is about a *binding*: the
//! proof stays valid and the thing around it changes.
//!
//! One `#[test]`, for the same reason as `tests/snark_path.rs`: leanVM's arena has a
//! single shared region per process and `setup_prover`'s contract is "never generate
//! two proofs concurrently in one process", which a second `#[test]` in this binary
//! would violate, since libtest runs tests as threads.
//!
//! ## Slot discipline
//!
//! Seeds are tagged `[FILE, ns, member, 0, ..]` with `FILE = 8`, disjoint from
//! `committee.rs` (1), `raw_path_round.rs` (2), `snark_path.rs` (3),
//! `lock_two_processes.rs` (4), `hostile_bytes.rs` (5), `signer_node.rs` (6) and
//! `verifier_node.rs` (7). Exactly one `(member, slot)` pair is spent per member:
//! members 0, 1 and 2 sign round 0 at slot 100, once.

use decentralized_root_of_trust::node::snark_prover::PQSNARKProverModule;
use decentralized_root_of_trust::node::snark_verifier::PQSNARKVerifierModule;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{
    Algorithms, SnarkStatusList, hash_any, status_list_message,
};
use lean_multisig::{XmssPublicKey, XmssSignature, xmss_key_gen_from_seed, xmss_sign};

const N: usize = 5;
const T: usize = 3;
const GENESIS: u32 = 100;
/// Last usable slot, inclusive; `WINDOW + 1` is the count leanVM v0.9 takes.
const WINDOW: u32 = 8;
/// Matches `params::LOG_INV_RATE`, so this is the deployed configuration.
const LOG_INV_RATE: usize = 2;

const FILE: u8 = 8;

fn seed(member: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = FILE;
    s[2] = member;
    s
}

#[test]
fn the_modules_derive_the_slot_and_enforce_every_binding() {
    // `init_prover` is `setup_prover()`; the verifier module's `setup_verifier()` is
    // a `OnceLock` read after it. Prover first, so the ordering matches the binaries.
    let prover = PQSNARKProverModule::init_prover();

    let keys: Vec<_> = (0..N)
        .map(|i| {
            xmss_key_gen_from_seed(seed(i as u8), u64::from(GENESIS), u64::from(WINDOW) + 1)
                .expect("keygen")
        })
        .collect();
    let members: Vec<XmssPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
    let committee = Committee::new(members, T, GENESIS);

    // Round 0. The signers sign the message the *verifier* will recompute, at the
    // slot the anchor assigns: the prover module is handed `version`, never a slot.
    let version = 0u32;
    let list = vec![hash_any(b"row-a"), hash_any(b"row-b")];
    let message = status_list_message(&list, version);
    let slot = committee.slot_for(version).expect("slot in window");
    let raws: Vec<(XmssPublicKey, XmssSignature)> = (0..T)
        .map(|i| {
            (
                keys[i].0.clone(),
                xmss_sign(&keys[i].1, slot, &message).expect("sign"),
            )
        })
        .collect();

    let proof = prover.make_proof(&committee, raws, &list, version, LOG_INV_RATE);
    let honest = SnarkStatusList::new(Algorithms::WotsXmss, list.clone(), version, proof);

    // (1) The slot inside the finished proof is the one the anchor derives. This is
    // the assertion the module exists for: nothing in the call gave it a slot, so if
    // it ever started taking one from a caller instead, this is what would catch it.
    let inner = honest.proof().expect("the aggregate decodes");
    assert_eq!(
        inner.info.core.slot,
        committee.slot_for(version).expect("slot in window"),
        "the prover module did not sign at the slot the anchor assigns to this version"
    );
    assert_eq!(inner.info.core.slot, slot);

    // (2) The verifier module accepts it, and its anchor is the one it was given.
    let verifier = PQSNARKVerifierModule::new(committee.clone(), version);
    assert_eq!(verifier.committee_as_ref().threshold(), T);
    assert_eq!(verifier.committee_as_ref().genesis_slot(), GENESIS);
    assert_eq!(verifier.committee_as_ref().members().len(), N);
    assert!(
        verifier.verify(&honest),
        "an honest record produced through the prover module failed to verify"
    );

    // A tampered list carrying the same valid proof: the signed message binds the
    // list, so this is refused. Re-uses the proof, no second aggregation.
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION"));
    assert!(
        !verifier.verify(&SnarkStatusList::new(
            Algorithms::WotsXmss,
            tampered,
            version,
            honest.proof_bytes().to_vec(),
        )),
        "a row nobody signed was accepted"
    );

    // The same proof relabelled with a later version. Two bindings refuse it at
    // once (the message carries the version, and the slot is derived from it), and
    // that is the point: a record only ever verifies at the version it was signed
    // for, whichever check gets there first.
    assert!(
        !verifier.verify(&SnarkStatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            version + 1,
            honest.proof_bytes().to_vec(),
        )),
        "a relabelled version was accepted"
    );

    // (3) The DHT freshness selection is a method on this same module, so it runs
    // the same five checks rather than a second opinion. Handed the honest record
    // and the relabelled forgery (which *declares* the higher version and is
    // therefore tried first), it must skip the forgery and return the honest one.
    // A selection that trusted the declared version instead would return version 1.
    let liar = SnarkStatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        version + 1,
        honest.proof_bytes().to_vec(),
    );
    let picked = verifier
        .select_freshest(&[honest.to_bytes(), liar.to_bytes()])
        .expect("the honest record must survive the selection");
    assert_eq!(
        picked.version(),
        version,
        "the selection returned a record whose proof does not verify"
    );
    assert!(
        verifier.select_freshest(&[liar.to_bytes()]).is_none(),
        "a lookup that returned only forgeries must select nothing"
    );

    // (4) `is_newer` is strict. Accepting an equal version would let a peer replay
    // the record it already served, which is the whole reason it is not `>=`.
    //
    // Note what it is *not*: nothing here advances, and nothing survives a restart.
    // A module rebuilt at version 0 says "newer" to version 1 again, forever. That
    // is why the binaries gate on `freshness::HighWaterMark` and treat this as a
    // cheap pre-check at most.
    let at_zero = PQSNARKVerifierModule::new(committee.clone(), 0);
    assert!(!at_zero.is_newer(&honest), "version 0 is not newer than 0");
    let later = SnarkStatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        1,
        honest.proof_bytes().to_vec(),
    );
    assert!(at_zero.is_newer(&later));
    assert!(
        !PQSNARKVerifierModule::new(committee.clone(), 1).is_newer(&later),
        "an equal version must not read as newer"
    );
    // ...and being "newer" says nothing about being authentic: this record is the
    // relabelled forgery refused above.
    assert!(!at_zero.verify(&later));

    // (5) A version with no slot under this anchor: `genesis + version` overflows
    // `u32`, so there is nothing to sign at. The module panics rather than proving
    // something no verifier could ever accept. Nothing is aggregated on this path
    // (the derivation fails first), so catching the unwind costs nothing.
    assert_eq!(committee.slot_for(u32::MAX), None);
    let boom = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.make_proof(&committee, Vec::new(), &list, u32::MAX, LOG_INV_RATE)
    }));
    assert!(
        boom.is_err(),
        "a version outside the key window must not silently produce a proof"
    );
}
