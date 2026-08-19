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
use ssz::{Decode as _, Encode as _};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

/// SSZ wire schema for the anchor. `XmssPublicKey` is a fixed 32-byte SSZ object
/// in leanVM v0.9, so `members` is an ordinary list of them and the container is
/// canonical by construction — see [`Committee::from_bytes`].
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct CommitteeWire {
    members: Vec<XmssPublicKey>,
    t: u64,
    genesis_slot: u32,
}

/// The FIXED trust anchor, embedded once in every verifier — the replacement for
/// the old single root-of-trust public key. It is the only thing a verifier must
/// know a priori; *who* signed a given update travels inside the proof.
/// The member order is part of the anchor, so a member's **index** is a stable,
/// authenticated identifier. That is what lets an update name its signers with a
/// bitmap instead of shipping their public keys.
#[derive(Clone)]
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
        CommitteeWire {
            members: self.members.clone(),
            t: self.t as u64,
            genesis_slot: self.genesis_slot,
        }
        .as_ssz_bytes()
    }

    /// Inverse of [`Committee::to_bytes`].
    ///
    /// The anchor must have exactly one wire form. It is what
    /// [`crate::freshness::HighWaterMark`] fingerprints to identify its trust
    /// domain, so a second encoding of the same committee would read as a
    /// rotation and silently reset the anti-rollback mark.
    ///
    /// SSZ gives that for free, and this is why the encoding is SSZ and not a
    /// self-describing format: every field here is fixed-width or a list of
    /// fixed-width items, so there are no length varints to pad, no alternative
    /// spelling of an integer, and trailing bytes are a decode error rather than
    /// something to check for afterwards. leanVM's own `XmssPublicKey` decoder
    /// additionally refuses a field element at or above the modulus, so a member
    /// key has one encoding too. The predecessor of this function had to re-encode
    /// the decoded value and byte-compare it to rule out postcard's padded
    /// varints; nothing here can express the ambiguity in the first place.
    ///
    /// What SSZ cannot know is the protocol invariant: `t` outside `1..=N` is
    /// refused here, the same bound [`Committee::new`] asserts, because
    /// deserialization bypasses the constructor.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value = CommitteeWire::from_ssz_bytes(bytes)
            .map_err(|e| format!("committee is not valid SSZ: {e:?}"))?;
        let t = usize::try_from(value.t).map_err(|_| format!("anchor threshold {} too large", value.t))?;
        if !(1..=value.members.len()).contains(&t) {
            return Err(format!(
                "anchor threshold {t} outside 1..={}",
                value.members.len()
            ));
        }
        Ok(Committee {
            members: value.members,
            t,
            genesis_slot: value.genesis_slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lean_multisig::xmss_key_gen_from_seed;

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

    /// The key window as leanVM v0.9 states it: an activation slot and a *count*,
    /// half-open, where the old API took an inclusive `(start, end)` pair. Nine
    /// slots is `GENESIS..=GENESIS + 8`.
    const WINDOW: u64 = 9;

    fn committee_in(ns: u8) -> Committee {
        let members = (0..N)
            .map(|i| {
                xmss_key_gen_from_seed(seed(ns, i as u8), u64::from(GENESIS), WINDOW)
                    .expect("keygen")
                    .0
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
    /// silently reset the anti-rollback mark.
    ///
    /// Under the old postcard encoding that took an explicit re-encode-and-compare,
    /// because a varint has padded spellings (`83 00` is a padded `3`). SSZ has no
    /// varints: the only degree of freedom left is *inside* a member key, where a
    /// field element could be written at or above the KoalaBear modulus and still
    /// reduce to a legal value. leanVM's own decoder refuses that, which is what
    /// makes the anchor canonical end to end rather than only at the container
    /// level.
    #[test]
    fn a_member_key_outside_the_field_is_refused() {
        let c = committee_in(3);
        let mut bytes = c.to_bytes();
        assert!(Committee::from_bytes(&bytes).is_ok());

        // Fixed section: the `members` offset (4) + `t` (8) + `genesis_slot` (4).
        // The member list therefore starts at byte 16, and its first four bytes are
        // member 0's first field element, little-endian.
        const FIXED_LEN: usize = 4 + 8 + 4;
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            FIXED_LEN,
            "the members list starts right after the fixed section"
        );
        bytes[FIXED_LEN..FIXED_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(
            Committee::from_bytes(&bytes).is_err(),
            "a field element at or above the modulus must not decode"
        );
    }

    /// The invariant SSZ cannot know. `t = 0` would make a record nobody signed
    /// reach quorum — see the guard in
    /// [`crate::verifier_node::VerifierNode::verify_status_list`] — and `t > N` is
    /// an anchor no quorum can satisfy. `new` asserts both; deserialization
    /// bypasses `new`, so `from_bytes` re-checks them.
    #[test]
    fn a_threshold_outside_the_committee_is_refused() {
        let c = committee_in(5);
        let bytes = c.to_bytes();
        assert!(Committee::from_bytes(&bytes).is_ok());

        // `t` sits in the fixed section, right after the 4-byte members offset.
        for bad in [0u64, N as u64 + 1] {
            let mut forged = bytes.clone();
            forged[4..12].copy_from_slice(&bad.to_le_bytes());
            assert!(
                Committee::from_bytes(&forged).is_err(),
                "threshold {bad} outside 1..={N} must be refused"
            );
        }
    }

    #[test]
    fn trailing_bytes_after_the_anchor_are_refused() {
        let c = committee_in(4);
        let mut bytes = c.to_bytes();
        bytes.push(0);
        assert!(Committee::from_bytes(&bytes).is_err());
    }
}
