//! The relying party for the SNARK-attested form: the same composition as
//! [`crate::node::raw_node::RawNode`], over the other published shape.
//!
//! What the two demos and the two binaries actually differ in is this type and
//! nothing else — anchor, gate, and the order between them are identical, and
//! only the predicate underneath changes. Keeping that difference to one type is
//! the point: a deployment picks a form, not a workflow.
//!
//! Holding a `SnarkNode` also carries the guarantee that
//! [`PQSNARKVerifierModule`] carries, since it owns one: `setup_verifier()` has
//! run, and the aggregation bytecode is resident. That cost is per process and
//! not per record, which is what makes a long-lived relying party the shape this
//! path wants.
//!
//! As in the raw node, no transport: bytes in, verdict out.

use crate::node::Outcome;
use crate::node::snark_verifier::PQSNARKVerifierModule;
use crate::protocol::committee::Committee;
use crate::protocol::status_list::SnarkStatusList;
use crate::state::freshness::HighWaterMark;

pub struct SnarkNode {
    verifier: PQSNARKVerifierModule,
    mark: HighWaterMark,
}

impl SnarkNode {
    /// Runs `setup_verifier()` and takes ownership of the gate.
    ///
    /// The module's own `status_list_last_version` is seeded from the mark, which
    /// is where that number legitimately comes from: it feeds
    /// [`PQSNARKVerifierModule::is_newer`], a stateless convenience this type
    /// does not use, because the durable mark it holds is the real answer.
    pub fn new(committee: Committee, mark: HighWaterMark) -> Self {
        let last = mark.current().unwrap_or(0);
        Self {
            verifier: PQSNARKVerifierModule::new(committee, last),
            mark,
        }
    }

    pub fn committee(&self) -> &Committee {
        self.verifier.committee_as_ref()
    }

    /// The predicate on its own, for a caller that wants to check a record
    /// without offering it to the gate.
    pub fn verifier(&self) -> &PQSNARKVerifierModule {
        &self.verifier
    }

    /// The highest version accepted so far, or `None` if this node has accepted
    /// nothing under this anchor.
    pub fn high_water(&self) -> Option<u32> {
        self.mark.current()
    }

    /// Decode, verify the proof, then — and only then — offer the version to the
    /// gate.
    pub fn accept(&mut self, bytes: &[u8]) -> Outcome {
        let Ok(record) = SnarkStatusList::from_bytes(bytes) else {
            return Outcome::Refused;
        };
        if !self.verifier.verify(&record) {
            return Outcome::Refused;
        }
        Outcome::advance(&mut self.mark, record.version())
    }

    /// The freshest candidate that verifies, out of what several peers returned.
    ///
    /// The selection is [`PQSNARKVerifierModule::select_freshest_above`], given
    /// this node's mark as the floor: candidates at or below it are dropped
    /// before a proof is verified, which matters here more than on the raw path
    /// because a SNARK verification is the most expensive thing an
    /// unauthenticated peer can make this node do.
    ///
    /// Whatever comes back has already verified, so the gate is the only step
    /// left.
    pub fn accept_best(&mut self, candidates: &[Vec<u8>]) -> Outcome {
        match self
            .verifier
            .select_freshest_above(candidates, self.mark.current())
        {
            Some(record) => Outcome::advance(&mut self.mark, record.version()),
            None => Outcome::Refused,
        }
    }
}
