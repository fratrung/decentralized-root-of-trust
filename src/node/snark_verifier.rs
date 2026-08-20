//! A relying party for the SNARK-attested form, bundled with the one-time
//! `setup_verifier()` the aggregation bytecode needs.
//!
//! The five checks exist **once**, here. Holding the module is what proves
//! `setup_verifier()` ran, so the predicate and its precondition cannot be
//! separated. A second copy of a security predicate drifts, and the copy that
//! drifts is the one no benchmark exercises.
//!
//! Freshness is deliberately *not* part of `verify`. See [`crate::state::freshness`] for
//! the persistent anti-rollback gate.

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

    /// Verifies the committee proof carried by the status list.
    ///
    /// The anchor (`members`, threshold `t`) is the only input: anyone holding it
    /// can verify, without knowing in advance *who* signed. All five checks are
    /// load-bearing: dropping any one is exploitable, and `tests/snark_path.rs`
    /// breaks each in isolation to prove it.
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

        // 2) bound to THIS list AND THIS version. Folding the version into the
        //    signed message is what makes the cleartext `version` field
        //    trustworthy, and so what lets freshness decisions rely on it.
        if agg.info.core.message != status_list_message(status_list.list(), status_list.version()) {
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

    /// Whether the record is **strictly** newer than the version this module was
    /// built with. Strict, so a peer cannot replay the record it already served.
    ///
    /// Stateless convenience, not an anti-rollback gate: nothing advances and
    /// nothing survives a restart. Use [`crate::state::freshness::HighWaterMark`] for
    /// that, and only *after* [`PQSNARKVerifierModule::verify`] has authenticated
    /// the version.
    pub fn is_newer(&self, status_list: &SnarkStatusList) -> bool {
        status_list.version() > self.status_list_last_version
    }

    /// Picks the newest legitimate record out of what several peers returned: a
    /// DHT lookup yields many versions of one object, some stale, some hostile.
    ///
    /// Candidates are tried **newest-declared-version first**; the first that
    /// decodes and verifies wins, `None` if none does. The declared version only
    /// *orders* them: it is trusted after [`PQSNARKVerifierModule::verify`] has
    /// bound it to the signed message, so a peer inflating it to look freshest
    /// costs one wasted verification and cannot win.
    ///
    /// This selects among the records in hand. Monotonicity *across* lookups is a
    /// separate high-water mark the caller keeps; see
    /// [`PQSNARKVerifierModule::select_freshest_above`].
    pub fn select_freshest(&self, candidates: &[Vec<u8>]) -> Option<SnarkStatusList> {
        self.select_freshest_above(candidates, None)
    }

    /// [`PQSNARKVerifierModule::select_freshest`], plus what the caller already
    /// trusts: candidates not strictly above `floor` are dropped *before* any proof
    /// is verified.
    ///
    /// A work saver, not a check. Anything at or below the floor would verify, be
    /// handed back, and then be refused by [`crate::state::freshness::HighWaterMark`]
    /// anyway: the floor only decides whether a SNARK verification was paid for
    /// first. That matters because selection is the one place an unauthenticated
    /// peer chooses how much work we do, and the stale case is the common one: a
    /// node polling an unchanged list hits it every round.
    ///
    /// Sound for the same reason the ordering is. A hostile peer controls its own
    /// declared version, but each candidate carries its own, so understating one
    /// forfeits only a record that was going to be refused as stale.
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
        decoded.into_iter().find(|sl| self.verify(sl))
    }
}
