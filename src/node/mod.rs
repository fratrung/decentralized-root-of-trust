//! Long-lived roles that act on the protocol objects.

pub mod raw_node;
pub mod raw_verifier;
pub mod signer;
pub mod snark_node;
pub mod snark_prover;
pub mod snark_verifier;

use crate::state::freshness::{Decision, HighWaterMark};

/// What a relying party did with a record it was handed.
///
/// Three outcomes and not a `bool`, because "these signatures are good" and "this
/// is worth acting on" are different answers and a caller that cannot tell them
/// apart will eventually treat a replay as an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Authenticated under the anchor **and** strictly newer than anything
    /// accepted before. The mark advanced and is on disk before this is returned.
    Accepted { version: u32 },
    /// Authenticated, but not newer than `mark`. Nothing moved. This is the
    /// common case for a node polling a list that has not changed, and it is also
    /// what a replay looks like.
    Stale { version: u32, mark: u32 },
    /// It did not decode, or did not verify under this anchor. Nothing moved.
    ///
    /// The version it claimed is deliberately not reported: an unverified record
    /// is a peer's assertion, not a fact, and handing it back invites a caller to
    /// log it, order by it, or compare it against the mark.
    Refused,
}

impl Outcome {
    /// The version, if this record was accepted.
    pub fn accepted(self) -> Option<u32> {
        match self {
            Outcome::Accepted { version } => Some(version),
            _ => None,
        }
    }

    /// Offers an **already authenticated** version to the gate.
    ///
    /// The one place in this module where a mark moves, so that "verify first"
    /// is a property of two short functions rather than of every call site.
    pub(crate) fn advance(mark: &mut HighWaterMark, version: u32) -> Outcome {
        match mark.try_advance(version) {
            Decision::Accepted => Outcome::Accepted { version },
            Decision::Stale(mark) => Outcome::Stale { version, mark },
        }
    }
}
