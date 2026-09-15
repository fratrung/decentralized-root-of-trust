//! SNARK aggregation for quorum XMSS signatures.
//!
//! Constructing [`PQSNARKProverModule`] performs leanVM setup. The honest API
//! derives slots from the anchor; [`PQSNARKProverModule::aggregate`] accepts one
//! explicitly only to aggregate already-produced signatures in adversarial tests.

use leanvm::xmss::{MESSAGE_LEN, XmssPublicKey, XmssSignature};
use leanvm::{aggregate, setup_prover};

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
        message: [u8; MESSAGE_LEN],
        slot: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        let xmss = raws
            .into_iter()
            .map(|(public, signature)| (public, slot, message, signature))
            .collect();
        aggregate(&[], xmss, Vec::new(), None, log_inv_rate)
            .expect("aggregation failed")
            .to_bytes()
    }
}
