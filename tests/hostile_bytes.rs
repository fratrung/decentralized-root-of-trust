//! What the three decoders do with bytes an attacker wrote.
//!
//! Every other test in this repository feeds the decoders records that some part
//! of this crate produced. That is the wrong shape for the threat model: records
//! arrive from a DHT, so *every* byte is attacker-chosen, and a verifier that
//! panics on a malformed one is a verifier that can be taken offline by anybody
//! who can serve it a record.
//!
//! Three properties, in increasing order of how much they matter:
//!
//! 1. **No panic.** `from_bytes` returns `Result`, so any panic — an index out of
//!    range, an `unwrap`, a capacity overflow — is a bug regardless of what the
//!    bytes were.
//! 2. **No allocation bomb.** SSZ offsets and lengths must describe regions that
//!    actually exist in the input; a malformed offset must be rejected rather
//!    than being trusted as an allocation request.
//! 3. **No forgery.** The one that would be a real break: a mutated record that
//!    `verify_status_list` accepts while *meaning* something different from the
//!    record it was derived from. Anything that verifies must carry exactly the
//!    original list, version and signer set.
//!
//! ## Scope, honestly stated
//!
//! This is the **raw** path. `SnarkStatusList` is decoded here but not verified:
//! `verify_proof` costs ~30 ms and `setup_verifier` a further several seconds, so
//! a run large enough to be interesting would take hours. Property 3 therefore
//! covers `verify_status_list` only; the SNARK predicate is covered case-by-case
//! in `tests/snark_path.rs`, which is the better tool for it anyway — a fuzzer is
//! very unlikely to stumble onto a valid aggregate.
//!
//! The seed is fixed, so a failure is reproducible and the suite does not become
//! nondeterministically red. That is the usual trade: this finds regressions
//! reliably and novel bugs only by luck. Raising `ITERATIONS` locally is the way
//! to go looking for the latter.

use decentralized_root_of_trust::committee::Committee;
use decentralized_root_of_trust::status_list::{
    Algorithms, SnarkStatusList, StatusList, hash_any, status_list_message,
};
use decentralized_root_of_trust::verifier_node::VerifierNode;
use lean_multisig::{xmss_key_gen_from_seed, xmss_sign};
use rand::{RngExt, SeedableRng};

const N: usize = 5;
const T: usize = 3;
const GENESIS: u32 = 100;
const VERSION: u32 = 0;

/// Enough to exercise every branch in the decoders many times over while keeping
/// the whole suite in single-digit seconds. Raise it when hunting.
const ITERATIONS: u32 = 60_000;

/// Seeds are `[FILE, ns, member, 0, ..]`; file 5 here. See `tests/snark_path.rs`
/// for why the tag exists — one `(key, slot)` pair must never be shared across
/// test files, and the slot window is not a namespace.
fn seed(member: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 5;
    s[2] = member;
    s
}

fn entries() -> Vec<[u8; 32]> {
    vec![hash_any(b"revoke-alice"), hash_any(b"revoke-bob")]
}

#[test]
fn a_hostile_encoder_cannot_panic_exhaust_or_forge() {
    let keys: Vec<_> = (0..N)
        .map(|i| xmss_key_gen_from_seed(seed(i as u8), u64::from(GENESIS), 9).expect("keygen"))
        .collect();
    let committee = Committee::new(keys.iter().map(|(pk, _)| pk.clone()).collect(), T, GENESIS);
    let verifier = VerifierNode::new(committee);
    let committee = verifier.get_committee();

    let list = entries();
    let message = status_list_message(&list, VERSION);
    let slot = committee.slot_for(VERSION).expect("slot");
    let signatures = (0..T)
        .map(|i| (i, xmss_sign(&keys[i].1, slot, &message).expect("sign")))
        .collect();

    let honest = StatusList::new(Algorithms::WotsXmss, list.clone(), VERSION, N, signatures)
        .expect("well-formed");
    assert!(
        verifier.verify_status_list(&honest),
        "the seed record must verify, or every negative below is vacuous"
    );

    let raw = honest.to_bytes();
    let snark = SnarkStatusList::new(Algorithms::WotsXmss, list.clone(), VERSION, vec![7u8; 128])
        .to_bytes();
    let anchor = committee.to_bytes();

    // The wire codec is canonical: decoding then encoding an accepted record
    // yields exactly the original bytes. A trailing byte is not an alternative
    // spelling of the same record under SSZ — and since leanVM v0.9 the same
    // holds *inside* each signature, which is a fixed 1208-byte SSZ object whose
    // field elements are refused at or above the modulus.
    assert_eq!(
        StatusList::from_bytes(&raw)
            .expect("honest raw record decodes")
            .to_bytes(),
        raw
    );
    assert_eq!(
        SnarkStatusList::from_bytes(&snark)
            .expect("well-formed SSZ container decodes")
            .to_bytes(),
        snark
    );
    let mut padded_raw = raw.clone();
    padded_raw.push(0);
    assert!(StatusList::from_bytes(&padded_raw).is_err());

    // --- property 2: hostile offset/length-shaped data ---
    // The pattern is spliced at every early offset. Under SSZ it may land in a
    // fixed field, an offset table, or payload; in each case decoding must stay
    // bounded and return an error when the resulting layout is invalid.
    for corpus in [&raw, &snark, &anchor] {
        for cut in 0..corpus.len().min(64) {
            let mut bytes = corpus[..cut].to_vec();
            bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
            bytes.extend_from_slice(&corpus[cut..]);
            // Returning `Err` is the expected outcome; the assertion is that we
            // reach the next line at all, in bounded memory.
            let _ = StatusList::from_bytes(&bytes);
            let _ = SnarkStatusList::from_bytes(&bytes);
            let _ = Committee::from_bytes(&bytes);
        }
    }

    // --- properties 1 and 3: structured mutation ---
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
    let mut decoded = 0u32;
    let mut verified = 0u32;

    for i in 0..ITERATIONS {
        let base = match i % 3 {
            0 => &raw,
            1 => &snark,
            _ => &anchor,
        };
        let mut bytes = base.clone();
        match rng.random_range(0..4) {
            // Truncation: every prefix must be refused, not read past.
            0 => {
                let n = rng.random_range(0..bytes.len());
                bytes.truncate(n);
            }
            // Bit flips: the closest thing to a targeted attack on a field.
            1 => {
                for _ in 0..rng.random_range(1..8) {
                    let p = rng.random_range(0..bytes.len());
                    bytes[p] ^= 1 << rng.random_range(0..8);
                }
            }
            // Insertion and deletion, which shift every later field and are what
            // turn a length prefix into a payload byte and vice versa.
            2 => {
                let p = rng.random_range(0..bytes.len());
                bytes.splice(p..p, [rng.random::<u8>(); 3]);
            }
            _ => {
                let p = rng.random_range(0..bytes.len());
                let q = rng.random_range(p..bytes.len());
                bytes.drain(p..q);
            }
        }

        if let Ok(sl) = StatusList::from_bytes(&bytes) {
            decoded += 1;
            if verifier.verify_status_list(&sl) {
                verified += 1;
                // The one that would be a break. A mutant may legitimately verify
                // — the mutation can be a no-op. What it may never do is verify
                // while meaning something else.
                assert_eq!(sl.version(), VERSION, "forged version");
                assert_eq!(sl.list(), entries().as_slice(), "forged list");
                assert_eq!(
                    sl.signer_indices().collect::<Vec<_>>(),
                    (0..T).collect::<Vec<_>>(),
                    "forged signer set"
                );
            }
        }
        let _ = SnarkStatusList::from_bytes(&bytes);
        let _ = Committee::from_bytes(&bytes);
    }

    // Not an assertion about a threshold — it is a guard against the whole loop
    // quietly becoming a no-op, e.g. if a future change made every mutant fail to
    // decode. A run that decodes nothing is testing nothing.
    assert!(
        decoded > ITERATIONS / 100,
        "only {decoded} of {ITERATIONS} mutants decoded: the corpus is no longer \
         exercising the verifier"
    );
    assert!(
        verified > 0,
        "no mutant reached verify_status_list at all: property 3 was never tested"
    );
}
