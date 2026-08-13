//! The prover: the one participant that turns `t` raw XMSS signatures into a
//! single SNARK.
//!
//! `setup_prover()` is paired with the proving calls by construction — holding a
//! `PQSNARKProverModule` *is* the proof that the aggregation bytecode was
//! initialised, so no caller has to remember to do it.
//!
//! The slot is **derived from the anchor** rather than accepted from the caller:
//! `Committee::slot_for` is meant to be the only place `genesis + version` is ever
//! computed, and a second entry point taking an unrelated `slot` alongside a
//! `version` is precisely how the two drift apart. A quorum that could choose its
//! own slot for a given version is what check 3 in
//! [`crate::snark_verifier_node::PQSNARKVerifierModule::verify`] exists to forbid.
//!
//! [`PQSNARKProverModule::aggregate`] is the exception, and deliberately so: it
//! takes an explicit slot because the *negative* tests need to build records the
//! honest path structurally cannot express.

use backend::KoalaBear;
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, aggregate_single_message_signatures, setup_prover,
    xmss_sign,
};

use crate::committee::Committee;
use crate::status_list::status_list_root_fe;

pub struct PQSNARKProverModule {}

impl PQSNARKProverModule {
    pub fn init_prover() -> Self {
        setup_prover();
        PQSNARKProverModule {}
    }

    /// Aggregates `raws` — signatures over `(status_list_elem, version)` — into one
    /// proof, at the slot `committee` assigns to `version`.
    ///
    /// This is the honest path: everything a publisher needs, with no way to name
    /// a slot the anchor did not derive.
    ///
    /// # Panics
    ///
    /// If `version` has no slot under this anchor (`genesis + version` overflows
    /// `u32`), which means the committee's key window ran out long ago.
    pub fn make_proof(
        &self,
        committee: &Committee,
        raws: Vec<(XmssPublicKey, XmssSignature)>,
        status_list_elem: &[[u8; 32]],
        version: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        let slot = committee
            .slot_for(version)
            .expect("version has no slot under this anchor");
        let message = status_list_root_fe(status_list_elem, version);
        self.aggregate(raws, message, slot, log_inv_rate)
    }

    /// Aggregates already-produced signatures at an **explicit** slot, returning
    /// the postcard bytes to store in `SnarkStatusList.zk_proof`. `message` is the
    /// Poseidon2 root of the status list — what the issuers actually signed.
    ///
    /// Prefer [`PQSNARKProverModule::make_proof`], which derives both from the
    /// anchor. This one exists for the adversarial tests, which have to produce
    /// the mismatches the derived path makes unrepresentable.
    pub fn aggregate(
        &self,
        raws: Vec<(XmssPublicKey, XmssSignature)>,
        message: [KoalaBear; 8],
        slot: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        let aggregate = aggregate_single_message_signatures(&[], raws, message, slot, log_inv_rate)
            .expect("aggregation failed");
        postcard::to_allocvec(&aggregate).expect("proof serialization failed")
    }

    /// Has the `signers` (indices into `keypairs`) sign `message` at `slot`, then
    /// aggregates their signatures into one proof.
    ///
    /// # Panics
    ///
    /// If `signers` contains a repeated index — see [`reject_repeated_signers`].
    pub fn sign_and_prove<R: rand::CryptoRng>(
        &self,
        keypairs: &[(XmssSecretKey, XmssPublicKey)],
        signers: &[usize],
        message: [KoalaBear; 8],
        slot: u32,
        log_inv_rate: usize,
        rng: &mut R,
    ) -> Vec<u8> {
        reject_repeated_signers(signers, slot);

        let raws: Vec<(XmssPublicKey, XmssSignature)> = signers
            .iter()
            .map(|&i| {
                let (sk, pk) = &keypairs[i];
                (
                    pk.clone(),
                    xmss_sign(rng, sk, &message, slot).expect("signing failed"),
                )
            })
            .collect();
        self.aggregate(raws, message, slot, log_inv_rate)
    }
}

/// Panics if one member appears twice in the quorum.
///
/// XMSS is stateful and one member appearing twice means one secret key signs at
/// one slot twice — and that is not the harmless case it looks like, even though
/// both signatures cover the *same* message: `xmss_sign` draws fresh randomness
/// per call (leanVM's `find_randomness_for_wots_encoding` rejection-samples until
/// the WOTS encoding is valid), so the two signatures reveal *different* hash-chain
/// positions. That is exactly the disclosure a stateful scheme exists to prevent.
///
/// It has to be checked *before* signing, because nothing downstream can: leanVM's
/// `aggregate_single_message_signatures` sorts and dedups its input, so the
/// finished aggregate looks perfectly ordinary and verifies. The key is already
/// damaged by then — the second signature was produced before the aggregator ever
/// saw it.
///
/// A panic rather than a `Result` because no legitimate caller can hit it: the
/// quorum is chosen by the protocol, and a repeated index is a bug in that choice,
/// not a runtime condition to recover from.
///
/// A free function rather than a method so the test below can reach it without
/// paying for `setup_prover()` — several seconds and hundreds of megabytes for a
/// guard that fires before any proving happens.
fn reject_repeated_signers(signers: &[usize], slot: u32) {
    let mut seen = signers.to_vec();
    seen.sort_unstable();
    let duplicated = seen.windows(2).find(|w| w[0] == w[1]).map(|w| w[0]);
    assert!(
        duplicated.is_none(),
        "member {} appears twice in the quorum: it would sign slot {slot} twice \
         and leak its key",
        duplicated.unwrap()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// leanVM sorts and dedups the aggregate's input, so a repeated signer is
    /// invisible in the finished proof — but both signatures were already
    /// produced, and `xmss_sign` randomises each one, so they reveal different
    /// WOTS chain positions. The guard has to fire before any signing happens,
    /// which is also why this test needs neither keys nor a prover.
    #[test]
    #[should_panic(expected = "appears twice in the quorum")]
    fn a_repeated_signer_is_refused_before_signing() {
        reject_repeated_signers(&[0, 1, 1], 100);
    }

    #[test]
    fn a_distinct_quorum_passes_the_guard() {
        reject_repeated_signers(&[4, 0, 2], 100);
        reject_repeated_signers(&[], 100);
    }
}
