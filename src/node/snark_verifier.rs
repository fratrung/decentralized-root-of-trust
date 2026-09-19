//! SNARK verification bound to a committee anchor.
//!
//! Constructing the module initializes leanVM verification. Freshness stays
//! outside this pure predicate in [`crate::state::freshness`].

use leanvm::setup_verifier;

use crate::protocol::committee::Committee;
use crate::protocol::status_list::{SnarkStatusList, status_list_message};

pub struct PQSNARKVerifierModule {
    committee: Committee,
    status_list_last_version: u32,
}

impl PQSNARKVerifierModule {
    pub fn new(committee: Committee, status_list_last_version: u32) -> Self {
        setup_verifier();
        Self {
            committee,
            status_list_last_version,
        }
    }

    pub fn committee_as_ref(&self) -> &Committee {
        &self.committee
    }

    /// Verifies membership, message binding, derived slot, threshold, and the
    /// aggregate itself against this anchor.
    pub fn verify(&self, status_list: &SnarkStatusList) -> bool {
        let agg = match status_list.proof() {
            Ok(a) => a,
            Err(_) => return false,
        };

        // v0.10 aggregates a general collection of XMSS epoch/message groups
        // and SPHINCS claims. This protocol accepts exactly one XMSS group and
        // no other signature family; accepting a broader statement here would
        // silently change what the five checks below mean.
        if !agg.sphincs_signers().is_empty() {
            return false;
        }
        let [(slot, message, pubkeys)] = agg.xmss_signers() else {
            return false;
        };

        // 1) every signer must belong to the committee
        if !pubkeys
            .iter()
            .all(|pk| self.committee.members().contains(pk))
        {
            return false;
        }

        // 2) bound to THIS committee, THIS algorithm, THIS list AND THIS version.
        //    Folding the version into the signed message is what makes the
        //    cleartext `version` field trustworthy, and so what lets freshness
        //    decisions rely on it. The domain adds the other two: the anchor, so a
        //    record cannot be carried to a committee it was not signed for, and
        //    the record's own `alg`, so relabelling it changes the message the
        //    proof would have to match.
        let domain = self.committee.domain(status_list.alg);
        if *message != status_list_message(&domain, status_list.list(), status_list.version()) {
            return false;
        }

        // 3) the aggregate must sit at the slot this version derives to. The slot
        //    is already authenticated inside every signature, so this adds no
        //    integrity; it pins the *policy*: one slot per round, derived rather
        //    than chosen. Without it a quorum re-signs a version at will.
        if self.committee.slot_for(status_list.version()) != Some(*slot) {
            return false;
        }

        // 4) quorum: at least `t` signers. Distinctness is free: leanVM requires
        //    `pubkeys` strictly sorted with no duplicates.
        if pubkeys.len() < self.committee.threshold() {
            return false;
        }

        // 5) the SNARK aggregate itself must verify
        if agg.verify().is_err() {
            return false;
        }
        true
    }

    /// Returns whether the record is newer than this module's initial version.
    /// This is stateless; use [`crate::state::freshness::HighWaterMark`] for
    /// persistent anti-rollback after verification.
    pub fn is_newer(&self, status_list: &SnarkStatusList) -> bool {
        status_list.version() > self.status_list_last_version
    }
}
