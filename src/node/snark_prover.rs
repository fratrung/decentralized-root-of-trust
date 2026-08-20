//! The prover: the one participant that turns `t` raw XMSS signatures into a
//! single SNARK.
//!
//! `setup_prover()` is paired with the proving calls by construction: holding a
//! `PQSNARKProverModule` *is* the proof that the aggregation bytecode was
//! initialised, so no caller has to remember to do it.
//!
//! The slot is **derived from the anchor**, never accepted from the caller:
//! `Committee::slot_for` is the only place `genesis + version` is computed, and a
//! quorum free to pick its own slot for a version is what check 3 of
//! [`crate::node::snark_verifier::PQSNARKVerifierModule::verify`] forbids.
//!
//! [`PQSNARKProverModule::aggregate`] is the deliberate exception: it takes an
//! explicit slot, because the negative tests must build records the honest path
//! structurally cannot express.

use lean_multisig::{
    MESSAGE_LEN_BYTES, XmssPublicKey, XmssSecretKey, XmssSignature,
    aggregate_single_message_signatures, setup_prover, xmss_sign,
};

use crate::protocol::committee::Committee;
use crate::protocol::status_list::status_list_message;

pub struct PQSNARKProverModule {}

impl PQSNARKProverModule {
    pub fn init_prover() -> Self {
        setup_prover();
        PQSNARKProverModule {}
    }

    /// Aggregates `raws` (signatures over `(status_list_elem, version)`) into one
    /// proof, at the slot `committee` assigns to `version`.
    ///
    /// The honest path: everything a publisher needs, with no way to name a slot
    /// the anchor did not derive.
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
        let message = status_list_message(status_list_elem, version);
        self.aggregate(raws, message, slot, log_inv_rate)
    }

    /// Aggregates already-produced signatures at an **explicit** slot, returning
    /// the bytes to store in `SnarkStatusList.zk_proof`. `message` is the packed
    /// Poseidon2 root of the status list, what the issuers actually signed.
    ///
    /// Prefer [`PQSNARKProverModule::make_proof`], which derives both from the
    /// anchor. This exists for the adversarial tests, which must produce the
    /// mismatches the derived path makes unrepresentable.
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

/// Panics if one member appears twice in the quorum.
///
/// This guards a **silent quorum shortfall**, not key material.
/// `aggregate_single_message_signatures` sorts and dedups its input, so `t`
/// indices containing a repeat aggregate `t - 1` distinct keys. The proof is
/// valid and honestly says `t - 1`, which the verifier's check 4 then refuses,
/// after seconds and gigabytes have been spent on it. Failing here turns a wasted
/// proof into a loud caller bug.
///
/// It does not cover one key signing *two different messages* at one slot, which
/// is still fatal. That is unreachable from here (every signer in one call signs
/// one message) and belongs to [`crate::state::slot_counter`], which is why that
/// is a durable counter and not a check.
///
/// A panic, because the quorum is chosen by the protocol and a repeated index is
/// a bug in that choice, not a recoverable condition. A free function, so the test
/// can reach it without paying for `setup_prover()`.
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
