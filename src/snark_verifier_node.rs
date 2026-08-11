//! A relying party for the SNARK-attested form, bundled with the one-time
//! `setup_verifier()` the aggregation bytecode needs.
//!
//! This type **delegates** the actual checking to [`crate::committee::verify_proof`]
//! rather than reimplementing it. It used to carry its own copy of the five
//! checks, which had silently drifted: the slot check was missing, so a quorum
//! could re-sign a version at slots of its own choosing. Two copies of a security
//! predicate always drift, and the one that drifts is the one no benchmark
//! exercises — so there is only one copy now.
//!
//! Freshness is deliberately *not* part of `verify`. See [`crate::freshness`] for
//! the persistent anti-rollback gate, which is what a real verifier should use.

use lean_multisig::setup_verifier;

use crate::{
    committee::{Committee, verify_proof},
    status_list::SnarkStatusList,
};

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

    /// All five checks against the anchor: membership, the message/version
    /// binding, the derived slot, quorum, and the SNARK itself.
    pub fn verify(&self, status_list: &SnarkStatusList) -> bool {
        verify_proof(&self.committee, status_list)
    }

    /// Whether the record is **strictly** newer than the version this module was
    /// built with. Strict on purpose: accepting an equal version would let a peer
    /// replay the record it already served.
    ///
    /// This is a stateless convenience, not an anti-rollback gate — nothing here
    /// advances, and nothing survives a restart. Use
    /// [`crate::freshness::HighWaterMark`] for that, and call it only *after*
    /// [`PQSNARKVerifierModule::verify`] has authenticated the version.
    pub fn is_newer(&self, status_list: &SnarkStatusList) -> bool {
        status_list.version() > self.status_list_last_version
    }
}
