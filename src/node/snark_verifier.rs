//! SNARK verification bound to a committee anchor.
//!
//! Constructing the module initializes leanVM verification. Freshness stays
//! outside this pure predicate in [`crate::state::freshness`].

use lean_multisig::{setup_verifier, verify_single_message_aggregate};

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

        // 1) every signer must belong to the committee
        if !agg
            .info
            .pubkeys
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
        if agg.info.core.message
            != status_list_message(&domain, status_list.list(), status_list.version())
        {
            return false;
        }

        // 3) the aggregate must sit at the slot this version derives to. The slot
        //    is already authenticated inside every signature, so this adds no
        //    integrity; it pins the *policy*: one slot per round, derived rather
        //    than chosen. Without it a quorum re-signs a version at will.
        if self.committee.slot_for(status_list.version()) != Some(agg.info.core.slot) {
            return false;
        }

        // 4) quorum: at least `t` signers. Distinctness is free: leanVM requires
        //    `pubkeys` strictly sorted with no duplicates.
        if agg.info.pubkeys.len() < self.committee.threshold() {
            return false;
        }

        // 5) the SNARK aggregate itself must verify
        if verify_single_message_aggregate(&agg).is_err() {
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

    /// Returns the newest candidate that decodes and verifies.
    ///
    /// Declared versions only order candidates; they become trusted after
    /// verification binds them to the signed message.
    pub fn select_freshest(&self, candidates: &[Vec<u8>]) -> Option<SnarkStatusList> {
        self.select_freshest_above(candidates, None)
    }

    /// How many proofs one selection will verify before giving up.
    ///
    /// The floor below is a work saver, not a budget: it drops records at or
    /// *below* the mark, which is precisely what a hostile peer never sends. A
    /// peer that stamps `mark + 1 .. mark + K` onto K junk records survives the
    /// floor entirely, and each one costs a full SNARK verification — the most
    /// expensive thing an unauthenticated peer can make this node do.
    ///
    /// So the number of *verifications* is capped, not the number of candidates:
    /// decoding is cheap and bounded by the input, and a caller may legitimately
    /// hold many records of which most are stale. What is bounded is the
    /// expensive half.
    ///
    /// Four, because candidates are tried newest first: reaching the fifth means
    /// the four freshest records a lookup returned all failed to verify, which is
    /// not a network that is about to produce a good one. An honest lookup
    /// succeeds on the first.
    pub const MAX_VERIFICATIONS_PER_SELECTION: usize = 4;

    /// Like [`Self::select_freshest`], but ignores records at or below `floor`
    /// before verification.
    ///
    /// The floor saves work only: those records would be refused as stale anyway.
    /// The budget is what bounds the work an attacker can choose — see
    /// [`Self::MAX_VERIFICATIONS_PER_SELECTION`].
    pub fn select_freshest_above(
        &self,
        candidates: &[Vec<u8>],
        floor: Option<u32>,
    ) -> Option<SnarkStatusList> {
        let mut decoded: Vec<SnarkStatusList> = candidates
            .iter()
            .filter_map(|bytes| SnarkStatusList::from_bytes(bytes).ok())
            .filter(|sl| floor.is_none_or(|f| sl.version() > f))
            .collect();
        decoded.sort_by_key(|sl| std::cmp::Reverse(sl.version()));
        decoded
            .into_iter()
            .take(Self::MAX_VERIFICATIONS_PER_SELECTION)
            .find(|sl| self.verify(sl))
    }
}
