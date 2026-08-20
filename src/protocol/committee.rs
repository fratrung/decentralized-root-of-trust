//! The trust anchor, and nothing else: who the members are, what `t` is, and the
//! single derivation `slot = genesis + version`.
//!
//! The protocol predicates are methods on the node types that own an anchor
//! ([`crate::node::raw_verifier::VerifierNode`],
//! [`crate::node::snark_verifier::PQSNARKVerifierModule`]), so a participant is one
//! value carrying the operations its role can perform, not a bag of free
//! functions all taking `&Committee`.

use lean_multisig::XmssPublicKey;
use ssz::{Decode as _, Encode as _};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

/// SSZ wire schema for the anchor. `XmssPublicKey` is a fixed 32-byte SSZ object
/// in leanVM v0.9, so `members` is an ordinary list of them and the container is
/// canonical by construction; see [`Committee::from_bytes`].
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct CommitteeWire {
    members: Vec<XmssPublicKey>,
    t: u64,
    genesis_slot: u32,
}

/// The fixed trust anchor, embedded once in every verifier: what replaces the
/// single root-of-trust key. The only thing a verifier must know a priori; *who*
/// signed a given update travels inside the record.
///
/// Member order is part of the anchor, so an index is a stable, authenticated
/// identifier, which is what lets a record name its signers with a bitmap
/// instead of shipping their public keys.
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
    /// lets a record with *no* signatures reach quorum, `t > N` is unsatisfiable.
    /// An anchor is built once by its owner, so this asserts rather than returning
    /// a `Result`.
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

    /// [`Committee::new`] without the `t` invariant, so the guard backstopping it
    /// in [`crate::node::raw_verifier::VerifierNode::verify_status_list`] is reachable
    /// at all. Test-only: that guard exists for construction paths that bypass
    /// `new`, and this is the only way to build one.
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

    /// Where this key sits in the anchor, or `None` if it is not a member.
    ///
    /// A signer naming itself in a record must produce exactly the number the
    /// verifier will use to look it up, so the lookup lives here rather than being
    /// spelled out at each call site: the same reason [`Committee::slot_for`] is
    /// the only place `genesis + version` is computed.
    ///
    /// The index is a property of the anchor, not something assigned over the
    /// network: nobody has to be trusted to hand it out, and a committee rotation
    /// renumbers everyone by construction.
    ///
    /// It answers *where is this key*, not *is this key allowed*. Membership is
    /// the verification predicates' business, and on the raw path there is
    /// nothing to decide, because an index **is** a member there.
    pub fn index_of(&self, member: &XmssPublicKey) -> Option<usize> {
        self.members.iter().position(|pk| pk == member)
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
    /// Derived from the anchor by every member, so no slot is ever negotiated.
    /// That matters because `t < N`: members advancing counters of their own fall
    /// out of step the moment they sit out a round, and an aggregate over one
    /// shared slot cannot survive that. Deriving removes the disagreement instead
    /// of reconciling it.
    ///
    /// This is the only place `genesis + version` is computed: signer and verifier
    /// must agree bit for bit.
    ///
    /// `None` on overflow past `u32`, which is also past the key's window.
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
    /// The anchor must have exactly **one** wire form:
    /// [`crate::state::freshness::HighWaterMark`] fingerprints it to identify its trust
    /// domain, so a second encoding of the same committee would read as a rotation
    /// and silently reset the anti-rollback mark.
    ///
    /// That is why the encoding is SSZ. Every field is fixed-width or a list of
    /// fixed-width items: no length varints to pad, no alternative spelling of an
    /// integer, trailing bytes a decode error, and leanVM's `XmssPublicKey`
    /// decoder refuses a field element at or above the modulus. Canonicity is
    /// structural rather than checked.
    ///
    /// What SSZ cannot know is the protocol invariant, so `t` outside `1..=N` is
    /// refused here too: deserialization bypasses [`Committee::new`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value = CommitteeWire::from_ssz_bytes(bytes)
            .map_err(|e| format!("committee is not valid SSZ: {e:?}"))?;
        let t = usize::try_from(value.t)
            .map_err(|_| format!("anchor threshold {} too large", value.t))?;
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

    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;

    /// This file's tag in the crate-wide seed namespace `[file, ns, member, 0, ..]`,
    /// documented once in `verifier_node::tests`. Nothing here signs, but the tag
    /// keeps these keys from ever coinciding with one that another module does.
    const FILE: u8 = 1;

    fn seed(ns: u8, member: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = FILE;
        s[1] = ns;
        s[2] = member;
        s
    }

    /// A slot *count*, as leanVM v0.9 takes it: nine slots is `GENESIS..=GENESIS + 8`.
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
        use crate::state::slot_counter::sibling;
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

    /// Two byte-different encodings of one committee would read as two trust
    /// domains and silently reset the freshness gate. SSZ makes the container
    /// canonical; the one degree of freedom left is *inside* a member key, where a
    /// field element could be written at or above the KoalaBear modulus and still
    /// reduce to a legal value. leanVM's decoder refuses that, which is what makes
    /// the anchor canonical end to end and not merely at the container level.
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

    /// The invariant SSZ cannot know: `t = 0` lets a record nobody signed reach
    /// quorum, `t > N` is unsatisfiable. `new` asserts both, and deserialization
    /// bypasses `new`.
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

    /// Every member finds itself, and only itself. The round trip through
    /// `members()` is what makes this an *inverse* and not a lookup that happens
    /// to agree today.
    #[test]
    fn every_member_finds_its_own_index_and_an_outsider_finds_none() {
        let c = committee_in(6);

        for i in 0..N {
            let pk = xmss_key_gen_from_seed(seed(6, i as u8), u64::from(GENESIS), WINDOW)
                .expect("keygen")
                .0;
            let found = c.index_of(&pk).expect("a member must find itself");
            assert_eq!(found, i, "member {i} reported index {found}");
            assert_eq!(
                &c.members()[found],
                &pk,
                "index_of is not the inverse of members()"
            );
        }

        // Index 200 is outside any committee this suite builds, so it cannot
        // collide however many tests are added.
        let outsider = xmss_key_gen_from_seed(seed(6, 200), u64::from(GENESIS), WINDOW)
            .expect("keygen")
            .0;
        assert_eq!(c.index_of(&outsider), None);
    }

    #[test]
    fn trailing_bytes_after_the_anchor_are_refused() {
        let c = committee_in(4);
        let mut bytes = c.to_bytes();
        bytes.push(0);
        assert!(Committee::from_bytes(&bytes).is_err());
    }
}
