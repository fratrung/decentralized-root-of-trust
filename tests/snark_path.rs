//! The five checks of [`verify_proof`], each shown to be load-bearing.
//!
//! The raw path is covered by unit tests in `committee.rs`; the SNARK path was
//! not, and it is the one the whole system exists to demonstrate. It is also the
//! path where a check had already been lost once — `snark_verifier_node` used to
//! carry its own copy of the predicate, with the slot check missing.
//!
//! Every negative case here is a *genuinely valid SNARK*. Corrupting the proof
//! bytes would prove nothing: that fails at deserialization, before any of the
//! five checks run, so it cannot tell you whether check 1 or check 4 still exists.
//! Instead each case aggregates real signatures and breaks exactly one binding,
//! and asserts that the other four still hold — so a `false` can only have come
//! from the check under test. Deleting any one of the five makes exactly one
//! assertion below fail.
//!
//! ## Cost
//!
//! Four aggregations plus `setup_prover()`: about 10 s and ~1 GB resident on the
//! reference host. That is small because the committee is: the deployed
//! configuration is `N = 200, t = 128` and this is `N = 5, t = 3`. The subject
//! here is the predicate, not the scale — `benchmark.sh` measures the scale.
//!
//! Everything lives in ONE `#[test]` on purpose. leanVM's arena allocator has a
//! single shared region per process and `setup_prover`'s contract is "never
//! generate two proofs concurrently in one process", which a second `#[test]` in
//! this binary would violate — libtest runs them as threads, not processes.
//!
//! It is deliberately not `#[ignore]`d: a security predicate whose test nobody
//! runs is the one that drifts. `Cargo.toml` optimizes dependencies in the dev
//! profile so that plain `cargo test` can afford it (at `opt-level = 0` leanVM's
//! prover turns minutes into hours).
//!
//! ## Slot discipline
//!
//! XMSS is stateful, so every `(key, slot)` pair used here is used at most once —
//! and "here" has to mean the whole suite, not this file. leanVM derives the
//! one-time key as `gen_wots_secret_key(seed, slot, gen_public_param(seed))`, so
//! the slot *window* never enters it: two keys born of the same seed share every
//! hash chain however they were generated. Seeds are therefore tagged
//! `[FILE, ns, member, 0, ..]` here, in `tests/raw_path_round.rs` and in
//! `src/committee.rs`'s unit tests, which is what keeps the three disjoint. The
//! per-slot budget is written out next to the constants below, and cases skip
//! rounds rather than reuse a slot.

use decentralized_root_of_trust::committee::Committee;
use decentralized_root_of_trust::snark_prover_node::PQSNARKProverModule;
use decentralized_root_of_trust::snark_verifier_node::PQSNARKVerifierModule;
use decentralized_root_of_trust::status_list::{
    Algorithms, SnarkStatusList, hash_any, status_list_root_fe,
};
use lean_multisig::{
    SingleMessageAggregateSignature, XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen,
    xmss_sign,
};

const N: usize = 5;
const T: usize = 3;
const GENESIS: u32 = 100;
const WINDOW: u32 = 8;
/// Matches `params::LOG_INV_RATE`, so this exercises the deployed configuration.
const LOG_INV_RATE: usize = 2;

/// The round the honest quorum signs. Not 0, so the freshness floor can be tested
/// from *below* as well as at and above it.
const ROUND: u32 = 2;

// The (signer, slot) budget, laid out once so a reused pair would be visible:
//
//     slot 102  round 2, honest        members 0, 1, 2
//     slot 100  round 1, wrong slot    members 0, 1, 2
//     slot 103  round 3, below quorum  members 0, 1
//     slot 104  round 4, outsider      outsider, 0, 1
//
// Members 0 and 1 sign four times, at four distinct slots; member 2 twice, at two
// distinct slots; the outsider once. No pair repeats.

type Keypair = (XmssSecretKey, XmssPublicKey);

/// Distinguishes this file's seeds from `src/committee.rs`'s (1) and
/// `tests/raw_path_round.rs`'s (2). There is one test here, so `ns` is always 0.
const FILE: u8 = 3;

fn seed(member: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = FILE;
    s[2] = member;
    s
}

fn committee() -> (Vec<Keypair>, Committee) {
    let keys: Vec<Keypair> = (0..N)
        .map(|i| xmss_key_gen(seed(i as u8), GENESIS, GENESIS + WINDOW, false).expect("keygen"))
        .collect();
    let members = keys.iter().map(|(_, pk)| pk.clone()).collect();
    (keys, Committee::new(members, T, GENESIS))
}

/// Signs `message` at `slot` with the given keypairs, in the shape
/// `aggregate_single_message_signatures` wants.
fn sign_at(
    signers: &[&Keypair],
    message: [backend::KoalaBear; 8],
    slot: u32,
) -> Vec<(XmssPublicKey, XmssSignature)> {
    let mut rng = rand::rng();
    signers
        .iter()
        .map(|(sk, pk)| {
            (
                pk.clone(),
                xmss_sign(&mut rng, sk, &message, slot).expect("sign"),
            )
        })
        .collect()
}

fn record(list: Vec<[u8; 32]>, version: u32, proof: Vec<u8>) -> SnarkStatusList {
    SnarkStatusList::new(Algorithms::WotsXmss, list, version, proof)
}

/// Decodes a record's aggregate, so a case can state what the *other* checks see.
fn info_of(sl: &SnarkStatusList) -> SingleMessageAggregateSignature {
    sl.proof().expect("the aggregate itself is well-formed")
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
    let message = status_list_root_fe(&list, ROUND);
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

    // ...and it survives the wire encoding the DHT would store it under.
    let back = SnarkStatusList::from_bytes(&valid.to_bytes()).expect("record decodes");
    assert!(verifier.verify(&back));

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
        let agg = info_of(&tampered);
        assert!(agg.info.pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(c.slot_for(ROUND), Some(agg.info.slot));
        assert!(agg.info.pubkeys.len() >= T);
        assert_ne!(
            agg.info.message,
            status_list_root_fe(tampered.list(), tampered.version()),
            "the tampered list must actually change the message, or this case is \
             vacuous"
        );
    }
    assert!(
        !verifier.verify(&tampered),
        "check 2 must bind the proof to THIS list"
    );

    // The same proof re-labelled as another round. The version is folded into the
    // signed message *and* fixes the slot, so this breaks checks 2 and 3 at once —
    // which is the point: there is no way to move a record between rounds.
    assert!(
        !verifier.verify(&record(list.clone(), ROUND - 1, proof.clone())),
        "check 2/3 must bind the proof to THIS version"
    );

    // ---------------------------------------------------- check 3: the slot --
    // A quorum that really did sign the round-1 message, but at a slot of its own
    // choosing instead of the one the anchor derives. The signatures are genuine
    // and internally consistent — the slot is authenticated inside each of them —
    // so what breaks is the *policy*: one slot per round, the same for everybody.
    let message_1 = status_list_root_fe(&list, 1);
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
        let agg = info_of(&wrong_slot);
        assert!(agg.info.pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(agg.info.message, message_1);
        assert!(agg.info.pubkeys.len() >= T);
        assert_eq!(agg.info.slot, chosen_slot);
    }
    assert!(
        !verifier.verify(&wrong_slot),
        "check 3 must pin the slot to the one the anchor derives"
    );

    // -------------------------------------------------- check 4: the quorum --
    // Two members against a threshold of three. A perfectly valid aggregate.
    let slot_3 = c.slot_for(3).expect("slot");
    let message_3 = status_list_root_fe(&list, 3);
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
        let agg = info_of(&thin);
        assert!(agg.info.pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(agg.info.message, message_3);
        assert_eq!(agg.info.slot, slot_3);
        assert_eq!(agg.info.pubkeys.len(), T - 1, "one short, and only that");
    }
    assert!(
        !verifier.verify(&thin),
        "check 4 must enforce the threshold"
    );

    // ---------------------------------------------- check 1: the membership --
    // Three signers, so the quorum is met by count — but one of them is not in the
    // anchor. Unlike the raw path, where a signer is named by an index and an
    // outsider is therefore unnameable, the SNARK path carries public keys and has
    // to look them up.
    // Member index 200: outside any committee, so it cannot collide with a seed
    // some future test claims for a real member.
    let outsider: Keypair =
        xmss_key_gen(seed(200), GENESIS, GENESIS + WINDOW, false).expect("keygen");
    let slot_4 = c.slot_for(4).expect("slot");
    let message_4 = status_list_root_fe(&list, 4);
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
        let agg = info_of(&intruded);
        assert_eq!(agg.info.message, message_4);
        assert_eq!(agg.info.slot, slot_4);
        assert!(agg.info.pubkeys.len() >= T, "the count alone is satisfied");
        assert_eq!(
            agg.info
                .pubkeys
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
    // aggregate whose *public inputs* are the honest ones — so checks 1 to 4 pass
    // by construction — carrying the proof body of a different execution. The four
    // cheap checks all look at `info`; only verifying the SNARK relates `info` to
    // the computation that is supposed to have produced it.
    let spliced = SingleMessageAggregateSignature {
        info: info_of(&valid).info,
        proof: info_of(&thin).proof,
    };
    let forged = record(
        list.clone(),
        ROUND,
        postcard::to_allocvec(&spliced).expect("re-encodes"),
    );
    {
        let agg = info_of(&forged);
        assert!(agg.info.pubkeys.iter().all(|pk| c.members().contains(pk)));
        assert_eq!(agg.info.message, message);
        assert_eq!(c.slot_for(ROUND), Some(agg.info.slot));
        assert!(agg.info.pubkeys.len() >= T);
    }
    assert!(
        !verifier.verify(&forged),
        "checks 1-4 pass on this record: only check 5 stands between it and acceptance"
    );

    // ------------------------------------------------ the decoding boundary --
    // Padding a length-prefixed field is free and repeatable, so without this the
    // same logical update would have unboundedly many wire forms — distinct keys
    // in a content-addressed DHT.
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

    // ----------------------------------------------------- freshness layer --
    // `select_freshest` orders candidates by their *declared* version, which is
    // attacker-controlled until check 2 has run. A peer that inflates it is tried
    // first and costs one wasted verification — it cannot win.
    let liar = record(list.clone(), 999, proof).to_bytes();
    let honest = valid.to_bytes();

    let picked = verifier
        .select_freshest(&[honest.clone(), liar.clone()])
        .expect("the honest record is still there behind the liar");
    assert_eq!(picked.version(), ROUND);
    // Order of arrival must not matter.
    let picked = verifier
        .select_freshest(&[liar.clone(), honest.clone()])
        .expect("same set, reversed order");
    assert_eq!(picked.version(), ROUND);
    // With nothing valid in hand it selects nothing, rather than falling back to
    // the best-looking candidate.
    assert!(
        verifier
            .select_freshest(std::slice::from_ref(&liar))
            .is_none()
    );
    assert!(verifier.select_freshest(&[]).is_none());

    // The floor prunes on the declared version *before* verifying anything. It is
    // not a security check — it can only discard records the caller was already
    // committed to refusing as stale. Two cases separate a correct floor from a
    // broken one: strictly below the honest record (must not prune it) and exactly
    // at it (must prune it, because the gate's rule is `>` and not `>=`). A floor
    // above the record is not a third case — it is indistinguishable from `at`.
    let both = vec![honest, liar];
    assert_eq!(
        verifier
            .select_freshest_above(&both, None)
            .map(|sl| sl.version()),
        Some(ROUND),
        "no floor must behave exactly as select_freshest"
    );
    assert_eq!(
        verifier
            .select_freshest_above(&both, Some(ROUND - 1))
            .map(|sl| sl.version()),
        Some(ROUND),
        "a floor below the record must not prune it"
    );
    assert!(
        verifier.select_freshest_above(&both, Some(ROUND)).is_none(),
        "the floor is strict: a record AT the mark is not newer, and the liar \
         above it does not verify"
    );
}
