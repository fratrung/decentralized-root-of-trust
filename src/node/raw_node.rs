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
    use crate::protocol::status_list::{Algorithms, hash_any};
    use leanvm::xmss::{XmssPublicKey, XmssSecretKey, XmssSignature, key_gen_from_seed, sign};

    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;
    const MAX_VERSION: u32 = 8;

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

    fn keys_in(ns: u8) -> Vec<(XmssSecretKey, XmssPublicKey)> {
        (0..N)
            .map(|i| {
                key_gen_from_seed(seed(ns, i as u8), GENESIS, GENESIS + MAX_VERSION)
                    .expect("keygen")
            })
            .collect()
    }

    fn node_in(ns: u8, name: &str) -> (Vec<(XmssSecretKey, XmssPublicKey)>, RawNode) {
        let keys = keys_in(ns);
        let members: Vec<XmssPublicKey> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        let committee = Committee::new(members, T, GENESIS);
        let mark = HighWaterMark::create(scratch(name), &committee.to_bytes())
            .expect("create freshness state");
        (keys, RawNode::new(committee, mark))
    }

    /// A published record, signed by `signers` at the slot the anchor derives.
    fn record(
        keys: &[(XmssSecretKey, XmssPublicKey)],
        committee: &Committee,
        list: &[[u8; 32]],
        version: u32,
        signers: &[usize],
    ) -> Vec<u8> {
        let message = committee.message_for(Algorithms::WotsXmss, list, version);
        let slot = committee.slot_for(version).expect("slot");
        let mut rng = leanvm::rand::rng();
        let signatures: Vec<(usize, XmssSignature)> = signers
            .iter()
            .map(|&i| (i, sign(&mut rng, &keys[i].0, &message, slot).expect("sign")))
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
}
