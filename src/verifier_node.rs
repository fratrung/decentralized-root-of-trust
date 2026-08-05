use backend::{KoalaBearParameters, MontyField31};
use lean_multisig::{XmssPublicKey, XmssSignature, xmss_verify};

use crate::committee::{Committee, verify_proof, verify_quorum};
use crate::status_list::{SnarkStatusList, StatusList};

#[derive(Debug)]
pub enum VerifierError {
    SignatureVerificationError,
    NoCommittee,
    NotAMemberOfCommittee,
}

pub struct VerifierNode {
    committee: Committee,
}

impl VerifierNode {
    pub fn new(committee: Committee) -> Self {
        Self { committee }
    }

    pub fn verify(
        &self,
        pub_key: &XmssPublicKey,
        signature: &XmssSignature,
        message: &[MontyField31<KoalaBearParameters>; 8],
        slot: u32,
    ) -> Result<(), VerifierError> {
        if !self.committee.members().contains(pub_key) {
            return Err(VerifierError::NotAMemberOfCommittee);
        }

        xmss_verify(pub_key, message, signature, slot)
            .map_err(|_| VerifierError::SignatureVerificationError)
    }

    /// Verifies a whole raw quorum record: the `t` signatures plus the bitmap
    /// naming who produced them.
    ///
    /// Unlike [`VerifierNode::verify`], which answers "is this one signature from
    /// some member", this answers "is this update authorized" — the threshold is
    /// part of the question. Needs no `setup_verifier()` and no circuit.
    pub fn verify_status_list(&self, status_list: &StatusList) -> bool {
        verify_quorum(&self.committee, status_list)
    }

    /// Same question for the SNARK-attested form.
    ///
    /// Requires the aggregation bytecode: `setup_verifier()` MUST have been called
    /// first, or the proof cannot even be decoded.
    pub fn verify_aggregate_signature(&self, status_list: &SnarkStatusList) -> bool {
        verify_proof(&self.committee, status_list)
    }

    pub fn get_committee(&self) -> &Committee {
        &self.committee
    }
}
