//! A relying party for the SNARK-attested form, bundled with the one-time
//! `setup_verifier()` the aggregation bytecode needs.
//!
//! This type once carried a *second* copy of the five checks alongside the one in
//! `committee.rs`, and the copy had silently drifted: the slot check was missing,
//! so a quorum could re-sign a version at slots of its own choosing. Two copies of
//! a security predicate always drift, and the one that drifts is the one no
//! benchmark exercises. There is exactly one copy now, and it is here — holding
//! the module is what proves `setup_verifier()` ran, so the check and its
//! precondition cannot be separated.
//!
//! Freshness is deliberately *not* part of `verify`. See [`crate::freshness`] for
//! the persistent anti-rollback gate, which is what a real verifier should use.

use lean_multisig::{setup_verifier, verify_single_message_aggregate};

use crate::committee::Committee;
use crate::status_list::{SnarkStatusList, status_list_message};

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
    /// The fixed trust anchor is the committee (`members`, threshold `t`): anyone
    /// who knows it can verify, without knowing in advance *who* signed the
    /// update.
    ///
    /// All five checks are load-bearing; dropping any one of them is exploitable.
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

        // 2) the proof must be bound to THIS list AND THIS version. Folding the
        //    version into the signed message (Option B) is what makes the cleartext
        //    `version` field trustworthy: once this check passes,
        //    status_list.version() is authentic and can safely drive the freshness
        //    / anti-rollback decisions the DHT layer makes in `select_freshest`.
        if agg.info.core.message != status_list_message(status_list.list(), status_list.version()) {
            return false;
        }

        // 3) the aggregate must sit at the slot the protocol assigns to this
        //    version. The slot is already authenticated inside every signature (it
        //    feeds the leaf hash, the WOTS tweaks and the Merkle path directions),
        //    so this does not add integrity — it pins the *policy*: one slot per
        //    round, the same one for everybody, derived rather than chosen. Without
        //    it a quorum could keep re-signing a version at slots of its own
        //    choosing.
        if self.committee.slot_for(status_list.version()) != Some(agg.info.core.slot) {
            return false;
        }

        // 4) quorum: at least `t` distinct signers. Distinctness comes for free:
        //    leanVM requires `pubkeys` to be strictly sorted with no duplicates.
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

    /// Freshness selection performed by the DHT layer over the records several
    /// peers return. A Kademlia lookup issues alpha RPCs to the k closest nodes and
    /// gets back several, possibly stale or hostile, versions of the same object;
    /// this is where the newest legitimate one is chosen.
    ///
    /// Candidates are tried **newest-declared-version first**; the first that both
    /// decodes and verifies against the anchor wins, and if it fails to verify the
    /// next-newest is tried, and so on. This is the caller's rule: take the newest
    /// valid record, fall back to older ones on failure.
    ///
    /// The declared version orders the candidates but is trusted only *after*
    /// [`PQSNARKVerifierModule::verify`] succeeds — that check is what binds the
    /// version to the signed message. So a peer that inflates the plaintext version
    /// to look freshest only costs one wasted verification before being skipped; it
    /// cannot win.
    ///
    /// Returns `None` if no candidate verifies. This selects the freshest among the
    /// records in hand; enforcing monotonicity *across* lookups (never accept a
    /// version below one already trusted) is a separate high-water mark the caller
    /// keeps — see [`PQSNARKVerifierModule::select_freshest_above`] for the cheaper
    /// composition of the two.
    pub fn select_freshest(&self, candidates: &[Vec<u8>]) -> Option<SnarkStatusList> {
        self.select_freshest_above(candidates, None)
    }

    /// [`PQSNARKVerifierModule::select_freshest`], but told what the caller already
    /// trusts: every candidate whose declared version is not strictly above `floor`
    /// is dropped *before* any proof is verified. `None` means no floor, which is
    /// exactly what `select_freshest` passes.
    ///
    /// This is not an extra security check — it removes work, not attacks. A record
    /// at or below the floor would verify, be handed back, and then be refused by
    /// [`crate::freshness::HighWaterMark`] anyway; the only difference is whether a
    /// SNARK verification was paid for first. That matters because the selection is
    /// the one place an unauthenticated peer gets to choose how much work we do: a
    /// lookup that returns nothing but stale records currently costs one full
    /// verification and buys nothing, and the stale case is the *common* one — a
    /// node polling a list that has not changed hits it on every round.
    ///
    /// Filtering on the declared version is sound precisely because the ordering
    /// already was. The version is attacker-controlled until check 2 of
    /// [`PQSNARKVerifierModule::verify`] has run, so a hostile peer can put any
    /// number there — but understating it cannot suppress a record that a
    /// *different*, honest peer served, since each candidate carries its own
    /// version, and understating one's own only forfeits a record that was going to
    /// be refused as stale. The floor can therefore only discard records the caller
    /// was already committed to rejecting.
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
