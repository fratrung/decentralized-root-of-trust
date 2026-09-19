//! The five checks of `PQSNARKVerifierModule::verify`, each shown to be
//! load-bearing, plus the v0.10 aggregate statement-shape guard.
//!
//! Checks 1–4 use genuinely valid SNARKs and break exactly one cleartext binding.
//! Check 5 mutates only the proof body while preserving a decodable aggregate and
//! its complete public statement. Each case states that the other checks still
//! hold, so deleting one check makes its matching assertion fail.
//!
//! Everything lives in ONE `#[test]` on purpose. leanVM's arena allocator has a
//! single shared region per process and `setup_prover`'s contract is "never
//! generate two proofs concurrently in one process", which a second `#[test]` in
//! this binary would violate: libtest runs them as threads, not processes.
//!
//! It is deliberately not `#[ignore]`d: a security predicate whose test nobody
//! runs is the one that drifts. `Cargo.toml` optimizes dependencies in the dev
//! profile so that plain `cargo test` exercises the real prover.
//!
//! ## Slot discipline
//!
//! XMSS is stateful, so every `(key, slot)` pair used here is used at most once,
//! and "here" has to mean the whole suite, not this file. leanVM derives the
//! one-time key as `gen_wots_secret_key(seed, slot, gen_public_param(seed))`, so
//! the slot *window* never enters it: two keys born of the same seed share every
//! hash chain however they were generated. Seeds are therefore tagged
//! `[FILE, ns, member, 0, ..]` here, in `tests/raw_path_round.rs` and in
//! `src/protocol/committee.rs`'s unit tests, which is what keeps the three disjoint. The
//! per-slot budget is written out next to the constants below, and cases skip
//! rounds rather than reuse a slot.

use decentralized_root_of_trust::node::snark_prover::PQSNARKProverModule;
use decentralized_root_of_trust::node::snark_verifier::PQSNARKVerifierModule;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{Algorithms, SnarkStatusList, hash_any};
use leanvm::AggregateSignature;
use leanvm::xmss::{
    MESSAGE_LEN, XmssPublicKey, XmssSecretKey, XmssSignature, key_gen_from_seed, sign,
};

const N: usize = 5;
const T: usize = 3;
const GENESIS: u32 = 100;
/// Last usable offset, inclusive.
const WINDOW: u32 = 8;
/// Matches `params::LOG_INV_RATE`, so this exercises the deployed configuration.
const LOG_INV_RATE: usize = 2;

/// The round the honest quorum signs.
const ROUND: u32 = 2;

// The (signer, slot) budget, laid out once so a reused pair would be visible:
//
//     slot 102  round 2, honest        members 0, 1, 2
//     slot 100  round 1, wrong slot    members 0, 1, 2
//     slot 103  round 3, below quorum  members 0, 1
//     slot 104  round 4, outsider      outsider, 0, 1
//     slot 105  extra claim group      member 3
//
// Members 0 and 1 sign four times, at four distinct slots; member 2 twice, at two
// distinct slots; the outsider once. No pair repeats.

type Keypair = (XmssSecretKey, XmssPublicKey);

/// Distinguishes this file's seeds from `src/protocol/committee.rs`'s (1) and
/// `tests/raw_path_round.rs`'s (2). There is one test here, so `ns` is always 0.
const FILE: u8 = 3;

fn seed(member: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = FILE;
    s[2] = member;
    s
}

fn keypair(member: u8) -> Keypair {
    key_gen_from_seed(seed(member), GENESIS, GENESIS + WINDOW).expect("keygen")
}

fn committee() -> (Vec<Keypair>, Committee) {
    let keys: Vec<Keypair> = (0..N).map(|i| keypair(i as u8)).collect();
    let members = keys.iter().map(|(_, pk)| pk.clone()).collect();
    (keys, Committee::new(members, T, GENESIS))
}

/// Signs `message` at `slot` with the given keypairs.
fn sign_at(
    signers: &[&Keypair],
    message: [u8; MESSAGE_LEN],
    slot: u32,
) -> Vec<(XmssPublicKey, XmssSignature)> {
    let mut rng = leanvm::rand::rng();
    signers
        .iter()
        .map(|(sk, pk)| {
            (
                pk.clone(),
                sign(&mut rng, sk, &message, slot).expect("sign"),
            )
        })
        .collect()
}

fn record(list: Vec<[u8; 32]>, version: u32, proof: Vec<u8>) -> SnarkStatusList {
    SnarkStatusList::new(Algorithms::WotsXmss, list, version, proof)
}

/// Decodes a record's aggregate, so a case can state what the *other* checks see.
fn info_of(sl: &SnarkStatusList) -> AggregateSignature {
    sl.proof().expect("the aggregate itself is well-formed")
}

/// Extracts the one XMSS group this protocol accepts and owns the values so test
/// assertions cannot accidentally depend on leanVM's aggregate internals.
fn claims_of(sl: &SnarkStatusList) -> (u32, [u8; MESSAGE_LEN], Vec<XmssPublicKey>) {
    let agg = info_of(sl);
    assert!(agg.sphincs_signers().is_empty(), "unexpected SPHINCS claim");
    let [(slot, message, pubkeys)] = agg.xmss_signers() else {
        panic!("expected exactly one XMSS claim group");
    };
    (*slot, *message, pubkeys.clone())
}

#[test]
fn each_of_the_five_checks_rejects_on_its_own() {
    let prover = PQSNARKProverModule::init_prover();

    let (keys, c) = committee();
    let verifier = PQSNARKVerifierModule::new(c.clone(), 0);
    let list = vec![hash_any(b"vc-1"), hash_any(b"vc-2")];

    // ---------------------------------------------------------------- valid --
    // Three of five members, at the slot the anchor derives for this round.
    let slot = c.slot_for(ROUND).expect("slot");
    assert_eq!(slot, GENESIS + ROUND);
    let message = c.message_for(Algorithms::WotsXmss, &list, ROUND);
    let proof = prover.aggregate(
        sign_at(&[&keys[0], &keys[1], &keys[2]], message, slot),
        message,
        slot,
        LOG_INV_RATE,
    );
    let valid = record(list.clone(), ROUND, proof.clone());
    assert!(
        verifier.verify(&valid),
        "an honest quorum must verify, or every rejection below is vacuous"
    );

    // ...and it survives the wire encoding an external registry would store.
    let back = SnarkStatusList::from_bytes(&valid.to_bytes()).expect("record decodes");
    assert!(verifier.verify(&back));

    // ------------------------------------------- aggregate statement shape --
    // leanVM v0.10 can prove several XMSS (slot, message) groups at once. This
    // protocol authorizes exactly one statement, so an otherwise valid aggregate
    // containing the honest quorum plus a second group must not be accepted by
    // looking only at the first group.
    let extra_slot = c.slot_for(5).expect("slot");
    let extra_message = c.message_for(Algorithms::WotsXmss, &list, 5);
    let honest_child = info_of(&valid);
    let extra_signatures = sign_at(&[&keys[3]], extra_message, extra_slot)
        .into_iter()
        .map(|(pk, signature)| (pk, extra_slot, extra_message, signature))
        .collect();
    let mixed = leanvm::aggregate(
        &[honest_child],
        extra_signatures,
        Vec::new(),
        None,
        LOG_INV_RATE,
    )
    .expect("mixed-group aggregation");
    assert_eq!(mixed.xmss_signers().len(), 2, "test must carry two groups");
    assert!(
        mixed.verify().is_ok(),
        "the broader leanVM proof is genuine"
    );
    assert!(
        !verifier.verify(&record(list.clone(), ROUND, mixed.to_bytes())),
        "the protocol must reject a multi-statement aggregate"
    );

    // leanVM can also combine XMSS and SPHINCS claims. SPHINCS is deliberately
    // outside this protocol: even a genuine aggregate with the one permitted
    // XMSS group must be rejected when it carries any SPHINCS claim.
    let mut sphincs_rng = leanvm::rand::rng();
    let (sphincs_secret, sphincs_public) = leanvm::sphincs::key_gen(&mut sphincs_rng);
    let sphincs_message = [0x53; leanvm::sphincs::MESSAGE_LEN];
    let sphincs_signature =
        leanvm::sphincs::sign(&mut sphincs_rng, &sphincs_secret, &sphincs_message)
            .expect("SPHINCS adversarial fixture signs");
    let xmss_and_sphincs = leanvm::aggregate(
        &[info_of(&valid)],
        Vec::new(),
        vec![(sphincs_public, sphincs_message, sphincs_signature)],
        None,
        LOG_INV_RATE,
    )
    .expect("mixed-family aggregation");
    assert_eq!(
        xmss_and_sphincs.xmss_signers().len(),
        1,
        "test must preserve exactly one XMSS group"
    );
    assert_eq!(
        xmss_and_sphincs.sphincs_signers().len(),
        1,
        "test must add exactly one rejected SPHINCS claim"
    );
    assert!(
        xmss_and_sphincs.verify().is_ok(),
        "the broader leanVM proof is genuine"
    );
    assert!(
        !verifier.verify(&record(list.clone(), ROUND, xmss_and_sphincs.to_bytes())),
        "the XMSS-only protocol must reject every SPHINCS claim"
    );

    // ------------------------------------------------- check 2: the message --
    // A revocation nobody authorized, appended to a list carrying a real quorum.
    // Nothing else changes: same proof, same version, same slot.
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION"));
    let tampered = record(tampered, ROUND, proof.clone());
    {
        // Stated, not assumed. The record carries the honest proof untouched, so
        // membership, slot and quorum are all still the honest ones and the *only*
        // thing that has moved is the list the message is computed over.
        let (agg_slot, agg_message, pubkeys) = claims_of(&tampered);
        assert!(pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(c.slot_for(ROUND), Some(agg_slot));
        assert!(pubkeys.len() >= T);
        assert_ne!(
            agg_message,
            c.message_for(Algorithms::WotsXmss, tampered.list(), tampered.version()),
            "the tampered list must actually change the message, or this case is \
             vacuous"
        );
    }
    assert!(
        !verifier.verify(&tampered),
        "check 2 must bind the proof to THIS list"
    );

    // The same proof re-labelled as another round. The version is folded into the
    // signed message *and* fixes the slot, so this breaks checks 2 and 3 at once,
    // which is the point: there is no way to move a record between rounds.
    assert!(
        !verifier.verify(&record(list.clone(), ROUND - 1, proof.clone())),
        "check 2/3 must bind the proof to THIS version"
    );

    // ---------------------------------------------------- check 3: the slot --
    // A quorum that really did sign the round-1 message, but at a slot of its own
    // choosing instead of the one the anchor derives. The signatures are genuine
    // and internally consistent (the slot is authenticated inside each of them),
    // so what breaks is the *policy*: one slot per round, the same for everybody.
    let message_1 = c.message_for(Algorithms::WotsXmss, &list, 1);
    let chosen_slot = GENESIS;
    assert_ne!(c.slot_for(1), Some(chosen_slot));
    let wrong_slot = record(
        list.clone(),
        1,
        prover.aggregate(
            sign_at(&[&keys[0], &keys[1], &keys[2]], message_1, chosen_slot),
            message_1,
            chosen_slot,
            LOG_INV_RATE,
        ),
    );
    {
        // Everything but the slot is in order, so the rejection can only be check 3.
        let (agg_slot, agg_message, pubkeys) = claims_of(&wrong_slot);
        assert!(pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(agg_message, message_1);
        assert!(pubkeys.len() >= T);
        assert_eq!(agg_slot, chosen_slot);
    }
    assert!(
        !verifier.verify(&wrong_slot),
        "check 3 must pin the slot to the one the anchor derives"
    );

    // -------------------------------------------------- check 4: the quorum --
    // Two members against a threshold of three. A perfectly valid aggregate.
    let slot_3 = c.slot_for(3).expect("slot");
    let message_3 = c.message_for(Algorithms::WotsXmss, &list, 3);
    let thin = record(
        list.clone(),
        3,
        prover.aggregate(
            sign_at(&[&keys[0], &keys[1]], message_3, slot_3),
            message_3,
            slot_3,
            LOG_INV_RATE,
        ),
    );
    {
        let (agg_slot, agg_message, pubkeys) = claims_of(&thin);
        assert!(pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(agg_message, message_3);
        assert_eq!(agg_slot, slot_3);
        assert_eq!(pubkeys.len(), T - 1, "one short, and only that");
    }
    assert!(
        !verifier.verify(&thin),
        "check 4 must enforce the threshold"
    );

    // ---------------------------------------------- check 1: the membership --
    // Three signers, so the quorum is met by count, but one of them is not in the
    // anchor. Unlike the raw path, where a signer is named by an index and an
    // outsider is therefore unnameable, the SNARK path carries public keys and has
    // to look them up.
    // Member index 200: outside any committee, so it cannot collide with a seed
    // some future test claims for a real member.
    let outsider: Keypair = keypair(200);
    let slot_4 = c.slot_for(4).expect("slot");
    let message_4 = c.message_for(Algorithms::WotsXmss, &list, 4);
    let intruded = record(
        list.clone(),
        4,
        prover.aggregate(
            sign_at(&[&outsider, &keys[0], &keys[1]], message_4, slot_4),
            message_4,
            slot_4,
            LOG_INV_RATE,
        ),
    );
    {
        let (agg_slot, agg_message, pubkeys) = claims_of(&intruded);
        assert_eq!(agg_message, message_4);
        assert_eq!(agg_slot, slot_4);
        assert!(pubkeys.len() >= T, "the count alone is satisfied");
        assert_eq!(
            pubkeys
                .iter()
                .filter(|pk| !c.members().contains(pk))
                .count(),
            1,
            "exactly one stranger"
        );
    }
    assert!(
        !verifier.verify(&intruded),
        "check 1 must reject a signer the anchor does not name"
    );

    // --------------------------------------------------- check 5: the SNARK --
    // The hard case, and the reason the other four are not enough on their own: an
    // aggregate whose declared claims are the honest ones (so checks 1 to 4 pass
    // by construction), but whose proof body has one changed bit. v0.10 keeps
    // fields private, so the test mutates its canonical bytes and requires the
    // result to remain structurally decodable with identical claims. Only proof
    // verification can relate those claims to the computation.
    let honest_aggregate = info_of(&valid);
    let mut spliced_bytes = honest_aggregate.to_bytes();
    *spliced_bytes.last_mut().expect("proof bytes") ^= 1;
    let spliced = AggregateSignature::from_bytes(&spliced_bytes)
        .expect("changing a proof-body bit must preserve the aggregate shape");
    assert_eq!(spliced.xmss_signers(), honest_aggregate.xmss_signers());
    assert_eq!(
        spliced.sphincs_signers(),
        honest_aggregate.sphincs_signers()
    );
    assert!(
        spliced.verify().is_err(),
        "the changed proof must be invalid"
    );
    let forged = record(list.clone(), ROUND, spliced.to_bytes());
    {
        let (agg_slot, agg_message, pubkeys) = claims_of(&forged);
        assert!(pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(agg_message, message);
        assert_eq!(c.slot_for(ROUND), Some(agg_slot));
        assert!(pubkeys.len() >= T);
    }
    assert!(
        !verifier.verify(&forged),
        "checks 1-4 pass on this record: only check 5 stands between it and acceptance"
    );

    // ------------------------------------------------ the decoding boundary --
    // Padding a length-prefixed field is free and repeatable, so without this the
    // same logical update would have unboundedly many wire forms in an external
    // content-addressed registry.
    let mut padded = proof.clone();
    padded.push(0);
    assert!(
        !verifier.verify(&record(list.clone(), ROUND, padded)),
        "trailing bytes after the aggregate must not verify"
    );
    assert!(
        !verifier.verify(&record(list.clone(), ROUND, Vec::new())),
        "an empty proof must not verify"
    );
}
