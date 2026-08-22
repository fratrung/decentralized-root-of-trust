//! Raw-path relying party: anchor verification plus a durable freshness gate.
//!
//! Records are verified before their version can advance the mark, preventing an
//! unauthenticated peer from pinning the node to a forged high version.

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
    /// Builds a node from its anchor and an externally managed, anchor-scoped mark.
    pub fn new(committee: Committee, mark: HighWaterMark) -> Self {
        Self {
            verifier: VerifierNode::new(committee),
            mark,
        }
    }

    pub fn committee(&self) -> &Committee {
        self.verifier.get_committee()
    }

    /// Returns the underlying stateless verification predicate.
    pub fn verifier(&self) -> &VerifierNode {
        &self.verifier
    }

    /// Returns the highest accepted version, if any.
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

    /// Tries candidates newest first and accepts the first valid record above the
    /// current mark.
    ///
    /// Versions at or below the mark are skipped before signature verification.
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
