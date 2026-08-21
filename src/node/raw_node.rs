//! The relying party for the raw form: an anchor, a durable mark, and the order
//! between them.
//!
//! [`VerifierNode`] answers *did `t` members of this committee sign this
//! record*, and that answer is timeless: a record that was valid last year still
//! verifies. [`HighWaterMark`] answers the other half, *have I already seen
//! something at least this new*, and is the only part that can refuse a replay.
//!
//! Neither is enough alone, and the order between them is not a matter of taste.
//! A mark that advances on a record which has not been authenticated is a mark an
//! unauthenticated peer can push to `u32::MAX`, after which every genuine update
//! is refused as stale: a denial of service that costs the attacker one forged
//! version number. So the mark may only move after the anchor has spoken, and
//! this type owns both halves so that there is no way to reach the second
//! without the first — the same reason [`crate::node::signer::SignerNode`] owns
//! its slot counter instead of trusting callers to burn a slot before signing.
//!
//! There is no I/O here beyond the mark's own file. The node is handed bytes and
//! returns a verdict; who to ask, how long to wait and how many peers to poll
//! belong to a transport above it. That is what keeps this testable with a byte
//! string instead of a socket.

use crate::node::Outcome;
use crate::node::raw_verifier::VerifierNode;
use crate::protocol::committee::Committee;
use crate::protocol::status_list::StatusList;
use crate::state::freshness::HighWaterMark;

pub struct RawNode {
    verifier: VerifierNode,
    mark: HighWaterMark,
}

impl RawNode {
    /// The anchor this node trusts and the mark it has already reached.
    ///
    /// The mark is injected rather than opened here: it is file-backed and scoped
    /// to a trust domain, and a node that built its own would decide where a
    /// deployment keeps its state. See [`HighWaterMark::load`].
    pub fn new(committee: Committee, mark: HighWaterMark) -> Self {
        Self {
            verifier: VerifierNode::new(committee),
            mark,
        }
    }

    pub fn committee(&self) -> &Committee {
        self.verifier.get_committee()
    }

    /// The predicate on its own, for a caller that wants to check a record
    /// without offering it to the gate.
    pub fn verifier(&self) -> &VerifierNode {
        &self.verifier
    }

    /// The highest version accepted so far, or `None` if this node has accepted
    /// nothing under this anchor.
    pub fn high_water(&self) -> Option<u32> {
        self.mark.current()
    }

    /// Decode, verify, then — and only then — offer the version to the gate.
    pub fn accept(&mut self, bytes: &[u8]) -> Outcome {
        let Ok(record) = StatusList::from_bytes(bytes) else {
            return Outcome::Refused;
        };
        self.accept_record(&record)
    }

    /// The freshest candidate that verifies, out of what several peers returned.
    ///
    /// A lookup yields many versions of one object: some stale, some hostile.
    /// Candidates are tried newest-declared-version first, and anything at or
    /// below the mark is dropped *before* a signature is checked — the same shape
    /// as
    /// [`crate::node::snark_verifier::PQSNARKVerifierModule::select_freshest_above`],
    /// and sound for the same reason: a peer controls only its own declared
    /// version, so understating one forfeits a record that was going to be
    /// refused as stale anyway.
    ///
    /// `Refused` when nothing above the mark verified, which includes the case
    /// where every candidate was simply old.
    pub fn accept_best(&mut self, candidates: &[Vec<u8>]) -> Outcome {
        let floor = self.mark.current();
        let mut decoded: Vec<StatusList> = candidates
            .iter()
            .filter_map(|bytes| StatusList::from_bytes(bytes).ok())
            .filter(|record| floor.is_none_or(|f| record.version() > f))
            .collect();
        decoded.sort_by_key(|record| std::cmp::Reverse(record.version()));

        for record in &decoded {
            if let outcome @ Outcome::Accepted { .. } = self.accept_record(record) {
                return outcome;
            }
        }
        Outcome::Refused
    }

    fn accept_record(&mut self, record: &StatusList) -> Outcome {
        if !self.verifier.verify_status_list(record) {
            return Outcome::Refused;
        }
        Outcome::advance(&mut self.mark, record.version())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::status_list::{Algorithms, hash_any, status_list_message};
    use lean_multisig::{
        XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen_from_seed, xmss_sign,
    };

    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;
    /// `GENESIS..=GENESIS + 8`, as the slot *count* leanVM v0.9 takes.
    const WINDOW: u64 = 9;

    /// This module's tag in the crate-wide seed namespace `[file, ns, member, 0, ..]`.
    /// See [`crate::node::raw_verifier`]'s tests for why the namespace must live in
    /// the seed and not in the slot window.
    const FILE: u8 = 9;

    fn seed(ns: u8, member: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = FILE;
        s[1] = ns;
        s[2] = member;
        s
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rawnode-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn keys_in(ns: u8) -> Vec<(XmssPublicKey, XmssSecretKey)> {
        (0..N)
            .map(|i| {
                xmss_key_gen_from_seed(seed(ns, i as u8), u64::from(GENESIS), WINDOW)
                    .expect("keygen")
            })
            .collect()
    }

    fn node_in(ns: u8, name: &str) -> (Vec<(XmssPublicKey, XmssSecretKey)>, RawNode) {
        let keys = keys_in(ns);
        let members: Vec<XmssPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let committee = Committee::new(members, T, GENESIS);
        let mark = HighWaterMark::load(scratch(name), &committee.to_bytes());
        (keys, RawNode::new(committee, mark))
    }

    /// A published record, signed by `signers` at the slot the anchor derives.
    fn record(
        keys: &[(XmssPublicKey, XmssSecretKey)],
        committee: &Committee,
        list: &[[u8; 32]],
        version: u32,
        signers: &[usize],
    ) -> Vec<u8> {
        let message = status_list_message(list, version);
        let slot = committee.slot_for(version).expect("slot");
        let signatures: Vec<(usize, XmssSignature)> = signers
            .iter()
            .map(|&i| (i, xmss_sign(&keys[i].1, slot, &message).expect("sign")))
            .collect();
        StatusList::new(Algorithms::WotsXmss, list.to_vec(), version, N, signatures)
            .expect("well-formed record")
            .to_bytes()
    }

    #[test]
    fn a_quorum_is_accepted_once_and_the_same_bytes_never_again() {
        let (keys, mut node) = node_in(1, "replay");
        let list = vec![hash_any(b"vc-1")];
        let bytes = record(&keys, node.committee(), &list, 0, &[0, 2, 4]);

        assert_eq!(node.accept(&bytes), Outcome::Accepted { version: 0 });
        assert_eq!(node.high_water(), Some(0));

        // The record is still perfectly valid: this is exactly what a replaying
        // peer serves, and the signatures cannot tell it apart from the first
        // delivery. Only the mark can.
        assert_eq!(
            node.accept(&bytes),
            Outcome::Stale {
                version: 0,
                mark: 0
            }
        );
        assert_eq!(node.high_water(), Some(0));
    }

    /// The attack the ordering exists to stop: a record that does not verify must
    /// not be allowed to move the mark, or one forged version number locks the
    /// node out of every genuine update that follows.
    #[test]
    fn a_record_that_does_not_verify_cannot_move_the_mark() {
        let (keys, mut node) = node_in(2, "forged");

        // A real signature, a real committee, one signer short of the threshold,
        // and a version far in the future.
        let list = vec![hash_any(b"vc-hostile")];
        let short = record(&keys, node.committee(), &list, 5, &[0, 1]);

        assert_eq!(node.accept(&short), Outcome::Refused);
        assert_eq!(node.high_water(), None, "the gate must not have moved");

        // And the node is still able to accept the honest round it would have been
        // locked out of.
        let list = vec![hash_any(b"vc-1")];
        let honest = record(&keys, node.committee(), &list, 0, &[0, 1, 2]);
        assert_eq!(node.accept(&honest), Outcome::Accepted { version: 0 });
    }

    #[test]
    fn bytes_that_are_not_a_record_are_refused_without_touching_the_gate() {
        let (_keys, mut node) = node_in(3, "garbage");

        assert_eq!(node.accept(&[]), Outcome::Refused);
        assert_eq!(node.accept(&[0xff; 64]), Outcome::Refused);
        assert_eq!(node.high_water(), None);
    }

    #[test]
    fn the_freshest_candidate_wins_and_a_second_lookup_finds_nothing_new() {
        let (keys, mut node) = node_in(4, "select");
        let committee = node.committee().clone();

        let v0 = record(&keys, &committee, &[hash_any(b"a")], 0, &[0, 1, 2]);
        let v1 = record(
            &keys,
            &committee,
            &[hash_any(b"a"), hash_any(b"b")],
            1,
            &[0, 1, 3],
        );
        let v2 = record(
            &keys,
            &committee,
            &[hash_any(b"a"), hash_any(b"b"), hash_any(b"c")],
            2,
            &[1, 2, 4],
        );

        // Offered out of order, and with one candidate that is not a record at all.
        let candidates = vec![v1.clone(), vec![0u8; 3], v2.clone(), v0.clone()];
        assert_eq!(
            node.accept_best(&candidates),
            Outcome::Accepted { version: 2 }
        );

        // The same peers, the same answers, one round later: everything is now at
        // or below the mark, so nothing is verified and nothing is accepted.
        assert_eq!(node.accept_best(&candidates), Outcome::Refused);
        assert_eq!(node.high_water(), Some(2));
    }
}
