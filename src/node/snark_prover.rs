//! SNARK aggregation for quorum XMSS signatures.
//!
//! Constructing [`PQSNARKProverModule`] performs leanVM setup. The honest API
//! derives slots from the anchor; [`PQSNARKProverModule::aggregate`] accepts one
//! explicitly only for adversarial tests.

use lean_multisig::{
    MESSAGE_LEN_BYTES, XmssPublicKey, XmssSecretKey, XmssSignature,
    aggregate_single_message_signatures, setup_prover, xmss_sign,
};

use crate::protocol::committee::Committee;
use crate::protocol::status_list::Algorithms;

pub struct PQSNARKProverModule {}

impl PQSNARKProverModule {
    pub fn init_prover() -> Self {
        setup_prover();
        PQSNARKProverModule {}
    }

    /// Aggregates signatures for `(status_list_elem, version)` at the anchor-derived slot.
    ///
    /// # Panics
    ///
    /// Panics if `version` has no slot under this anchor.
    pub fn make_proof(
        &self,
        committee: &Committee,
        alg: Algorithms,
        raws: Vec<(XmssPublicKey, XmssSignature)>,
        status_list_elem: &[[u8; 32]],
        version: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        let slot = committee
            .slot_for(version)
            .expect("version has no slot under this anchor");
        // Both derivations go through the anchor, and neither is spelled out
        // here: `slot_for` for the round, `message_for` for the domain. A second
        // copy of either is a second place to drift from the verifier.
        let message = committee.message_for(alg, status_list_elem, version);
        self.aggregate(raws, message, slot, log_inv_rate)
    }

    /// Aggregates at an explicit slot for adversarial tests. Production callers
    /// should use [`Self::make_proof`].
    pub fn aggregate(
        &self,
        raws: Vec<(XmssPublicKey, XmssSignature)>,
        message: [u8; MESSAGE_LEN_BYTES],
        slot: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        aggregate_single_message_signatures(&[], raws, message, slot, log_inv_rate)
            .expect("aggregation failed")
            .to_bytes()
    }

    /// Has the `signers` (indices into `keypairs`) sign `message` at `slot`, then
    /// aggregates their signatures into one proof.
    ///
    /// # Panics
    ///
    /// If `signers` contains a repeated index: leanVM dedups the aggregate, so the
    /// quorum would come out one key short of what the caller asked for.
    pub fn sign_and_prove(
        &self,
        keypairs: &[(XmssSecretKey, XmssPublicKey)],
        signers: &[usize],
        message: [u8; MESSAGE_LEN_BYTES],
        slot: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        reject_repeated_signers(signers, slot);

        let raws: Vec<(XmssPublicKey, XmssSignature)> = signers
            .iter()
            .map(|&i| {
                let (sk, pk) = &keypairs[i];
                (
                    pk.clone(),
                    xmss_sign(sk, slot, &message).expect("signing failed"),
                )
            })
            .collect();
        self.aggregate(raws, message, slot, log_inv_rate)
    }
}

/// Panics on a repeated signer before aggregation silently deduplicates it into a
/// below-threshold quorum. XMSS slot reuse remains the slot counter's concern.
fn reject_repeated_signers(signers: &[usize], slot: u32) {
    let mut seen = signers.to_vec();
    seen.sort_unstable();
    let duplicated = seen.windows(2).find(|w| w[0] == w[1]).map(|w| w[0]);
    assert!(
        duplicated.is_none(),
        "member {} appears twice in the quorum: slot {slot} would be aggregated \
         once, silently short of threshold",
        duplicated.unwrap()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shortfall is invisible in the finished proof and surfaces only at the
    /// verifier's quorum check, after the proof has been paid for. The guard fires
    /// before any signing, which is why this test needs neither keys nor a prover.
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
