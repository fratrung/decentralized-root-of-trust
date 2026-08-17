//! The trust anchor, and nothing else.
//!
//! This module used to carry the protocol predicates too —
//! `verify_status_list`, `verify_proof`, `make_proof`, the freshness selection.
//! They are now methods on the node types that own the anchor
//! ([`crate::verifier_node::VerifierNode`],
//! [`crate::snark_prover_node::PQSNARKProverModule`],
//! [`crate::snark_verifier_node::PQSNARKVerifierModule`]), so a participant is one
//! value with the operations its role can perform, rather than a bag of free
//! functions all taking `&Committee`.
//!
//! What stays here is what every role shares and nobody may reinterpret: who the
//! members are, what `t` is, and the single derivation `slot = genesis + version`.

use lean_multisig::XmssPublicKey;
use serde::{Deserialize, Serialize};

/// The FIXED trust anchor, embedded once in every verifier — the replacement for
/// the old single root-of-trust public key. It is the only thing a verifier must
/// know a priori; *who* signed a given update travels inside the proof.
/// The member order is part of the anchor, so a member's **index** is a stable,
/// authenticated identifier. That is what lets an update name its signers with a
/// bitmap instead of shipping their public keys.
#[derive(Serialize, Deserialize, Clone)]
pub struct Committee {
    members: Vec<XmssPublicKey>,
    t: usize,
    genesis_slot: u32,
}

impl Committee {
    /// Builds the committee from its members' public keys, the threshold `t`, and
    /// the XMSS slot round 0 is signed at.
    ///
    /// # Panics
    ///
    /// If `t` is not in `1..=members.len()`. Both bounds are load-bearing: `t = 0`
    /// makes a record with *no* signatures reach quorum (see the guard in
    /// [`crate::verifier_node::VerifierNode::verify_status_list`]), and `t > N`
    /// is an anchor no quorum can ever satisfy.
    /// Neither is a runtime condition — an anchor is built once, by its owner —
    /// so this is an assertion, not a `Result`.
    pub fn new(members: Vec<XmssPublicKey>, t: usize, genesis_slot: u32) -> Self {
        assert!(
            (1..=members.len()).contains(&t),
            "threshold {t} outside 1..={} for this committee",
            members.len()
        );
        Committee {
            members,
            t,
            genesis_slot,
        }
    }

    /// [`Committee::new`] without the `t` invariant, so the guard that backstops
    /// it in [`crate::verifier_node::VerifierNode::verify_status_list`] can be
    /// reached at all. Test-only and crate-visible: the fields are private, and
    /// the guard exists precisely for a construction path that does not go
    /// through `new`.
    #[cfg(test)]
    pub(crate) fn new_unchecked(members: Vec<XmssPublicKey>, t: usize, genesis_slot: u32) -> Self {
        Committee {
            members,
            t,
            genesis_slot,
        }
    }

    pub fn members(&self) -> &[XmssPublicKey] {
        &self.members
    }

    pub fn threshold(&self) -> usize {
        self.t
    }

    /// The slot round 0 is signed at. Every later round is derived from it.
    pub fn genesis_slot(&self) -> u32 {
        self.genesis_slot
    }

    /// The XMSS slot the whole committee signs round `version` at.
    ///
    /// Every member computes this from the anchor and the version, so no slot is
    /// ever negotiated. That matters because `t < N`: with each member advancing
    /// a counter of its own, the ones that sit out a round fall behind, and by the
    /// next round they no longer agree on a slot — which an aggregate over one
    /// shared slot cannot survive. Deriving it removes the disagreement rather
    /// than reconciling it.
    ///
    /// The derivation lives here and nowhere else. Signer and verifier must agree
    /// bit for bit, and two independent `genesis + version` expressions are two
    /// places to drift.
    ///
    /// `None` on overflow past `u32`, which also means past the key's window.
    pub fn slot_for(&self, version: u32) -> Option<u32> {
        self.genesis_slot.checked_add(version)
    }

    /// Wire encoding of the anchor. A real verifier compiles this in; the split
    /// demo ships it as a file the verifier loads once at startup.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("committee serialization failed")
    }

    /// Inverse of [`Committee::to_bytes`]. Rejects trailing bytes, and rejects a
    /// threshold outside `1..=N` — the same invariant [`Committee::new`] asserts,
    /// re-checked here because deserialization bypasses the constructor.
    ///
    /// It also insists the input is exactly what [`Committee::to_bytes`] would
    /// produce. Rejecting trailing bytes on its own does **not** make an encoding
    /// canonical: postcard's varint decoder only errors when the last permitted
    /// byte overflows the type, so `87 00` and `07` both decode to `7`, and every
    /// length prefix in the anchor admits the same padding. Two byte-different
    /// anchors that mean the same committee would otherwise both be accepted —
    /// which matters here because the anchor is what the freshness gate
    /// fingerprints to identify its trust domain, so a re-encoding would silently
    /// look like a committee rotation and reset the anti-rollback mark.
    ///
    /// The anchor is decoded once at startup, so the extra encode is free at the
    /// scale that matters.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (value, rest) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|e| format!("committee not deserializable: {e}"))?;
        if !rest.is_empty() {
            return Err(format!("{} trailing byte(s) after committee", rest.len()));
        }
        if !(1..=value.members.len()).contains(&value.t) {
            return Err(format!(
                "anchor threshold {} outside 1..={}",
                value.t,
                value.members.len()
            ));
        }
        if value.to_bytes() != bytes {
            return Err("anchor is not canonically encoded".to_string());
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lean_multisig::xmss_key_gen;

    /// Deliberately not a multiple of 8, so the bitmap has padding bits and the
    /// checks that police them are actually exercised — over in
    /// [`crate::verifier_node`], which is where the quorum predicate lives now.
    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;

    /// This file's tag in the crate-wide seed namespace `[file, ns, member, 0, ..]`.
    /// The full rationale — why the namespace must live in the *seed* and why the
    /// slot window is not one — is documented once, in `verifier_node::tests`.
    ///
    /// Nothing here signs anything: these tests only encode and decode anchors.
    /// The tag is kept anyway so the keys they generate can never coincide with a
    /// key some other module does sign with.
    const FILE: u8 = 1;

    fn seed(ns: u8, member: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = FILE;
        s[1] = ns;
        s[2] = member;
        s
    }

    fn committee_in(ns: u8) -> Committee {
        let members = (0..N)
            .map(|i| {
                xmss_key_gen(seed(ns, i as u8), GENESIS, GENESIS + 8, false)
                    .expect("keygen")
                    .1
            })
            .collect();
        Committee::new(members, T, GENESIS)
    }

    #[test]
    fn sibling_paths_do_not_alias_across_dotted_names() {
        use crate::atomic_slot_counter::sibling;
        use std::path::Path;

        // `with_extension` would map both of these onto `node-1.lock`.
        let a = sibling(Path::new("keys/node-1.2"), "lock");
        let b = sibling(Path::new("keys/node-1.3"), "lock");
        assert_ne!(a, b);
        assert_eq!(a, Path::new("keys/node-1.2.lock"));
        assert_eq!(
            sibling(Path::new("member-0"), "tmp"),
            Path::new("member-0.tmp")
        );
    }

    #[test]
    fn the_anchor_round_trips() {
        let c = committee_in(2);
        let decoded = Committee::from_bytes(&c.to_bytes()).expect("round trip");
        assert_eq!(decoded.members().len(), N);
        assert_eq!(decoded.threshold(), T);
        assert_eq!(decoded.genesis_slot(), GENESIS);
    }

    /// The anchor identifies the trust domain the freshness gate is scoped to, so
    /// two byte-different encodings of one committee would read as two domains and
    /// silently reset the anti-rollback mark. Rejecting trailing bytes does not
    /// cover this: postcard accepts non-minimal varints, and `members` is the first
    /// field, so byte 0 is its length prefix — `83 00` is a padded `3`.
    #[test]
    fn a_non_canonically_encoded_anchor_is_refused() {
        let c = committee_in(3);
        let canonical = c.to_bytes();
        assert_eq!(
            canonical[0], N as u8,
            "first byte is the member-count varint"
        );

        let mut padded = vec![0x80 | N as u8, 0x00];
        padded.extend_from_slice(&canonical[1..]);
        assert_ne!(padded, canonical);

        // It really is the same committee to a decoder that does not check.
        let (value, rest) = postcard::take_from_bytes::<Committee>(&padded).expect("still decodes");
        assert!(
            rest.is_empty(),
            "the padding is inside the varint, not trailing"
        );
        assert_eq!(value.members().len(), N);

        assert!(Committee::from_bytes(&padded).is_err());
    }

    #[test]
    fn trailing_bytes_after_the_anchor_are_refused() {
        let c = committee_in(4);
        let mut bytes = c.to_bytes();
        bytes.push(0);
        assert!(Committee::from_bytes(&bytes).is_err());
    }
}
