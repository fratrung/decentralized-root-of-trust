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

use lean_multisig::{
    MESSAGE_LEN_BYTES, XmssPublicKey, XmssSecretKey, XmssSignature,
    aggregate_single_message_signatures, setup_prover, xmss_sign,
};

use crate::committee::Committee;
use crate::status_list::status_list_message;

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
        let message = status_list_message(status_list_elem, version);
        self.aggregate(raws, message, slot, log_inv_rate)
    }

    /// Aggregates already-produced signatures at an **explicit** slot, returning
    /// the bytes to store in `SnarkStatusList.zk_proof`. `message` is the packed
    /// Poseidon2 root of the status list — what the issuers actually signed.
    ///
    /// Prefer [`PQSNARKProverModule::make_proof`], which derives both from the
    /// anchor. This one exists for the adversarial tests, which have to produce
    /// the mismatches the derived path makes unrepresentable.
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
    /// If `signers` contains a repeated index — see [`reject_repeated_signers`].
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
/// **What this guards changed in leanVM v0.9, and the guard survived the change.**
/// It used to be about key material: `xmss_sign` drew fresh randomness per call,
/// so one key signing one slot twice — even over the *same* message — published
/// two different WOTS chain positions, which is precisely the disclosure a
/// stateful scheme exists to prevent. v0.9 derives the randomness from
/// `(secret seed, slot, attempt, hashed message)`, so those two calls now return
/// the identical signature and nothing leaks.
///
/// What is left is a quorum bug, and a silent one.
/// `aggregate_single_message_signatures` sorts and *dedups* its input, so a
/// quorum of `t` indices containing a repeat aggregates `t - 1` distinct keys.
/// The finished proof is perfectly valid and says so — but it says `t - 1`, which
/// the verifier's check 4 then refuses, after the prover has spent seconds and
/// gigabytes on it. Catching it here turns a wasted proof into a loud caller bug.
///
/// Note what this does **not** cover, and cannot: one key signing *two different
/// messages* at one slot is still fatal in v0.9, and it is unreachable from here
/// because every signer in one call signs one message. That case belongs to
/// [`crate::atomic_slot_counter`], which is why it is a durable counter and not a
/// check.
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
    /// invisible in the finished proof: it silently aggregates one key fewer than
    /// the caller asked for, and the shortfall only surfaces at the verifier's
    /// quorum check, after the proof has been paid for. The guard fires before
    /// any signing happens, which is also why this test needs neither keys nor a
    /// prover.
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
