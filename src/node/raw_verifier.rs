//! A relying party on the **raw** path: it holds the anchor and answers the two
//! questions a verifier can ask without a circuit.
//!
//! `verify` asks "is this one signature from some member". `verify_status_list`
//! asks the question that actually authorizes an update: "did at least `t`
//! distinct members sign *this* list at *this* version", and the threshold is
//! part of it.
//!
//! Neither needs `setup_verifier()`, the aggregation bytecode, or a gigabyte of
//! resident state. That is the honest comparison against
//! [`crate::node::snark_verifier::PQSNARKVerifierModule`]: `t` independent
//! Poseidon2 verifications, linear in `t` where the SNARK is constant, on a
//! verifier far too small to hold the circuit.

use lean_multisig::{MESSAGE_LEN_BYTES, XmssPublicKey, XmssSignature, xmss_verify};

use crate::protocol::committee::Committee;
use crate::protocol::status_list::StatusList;

#[derive(Debug)]
pub enum VerifierError {
    SignatureVerificationError,
    NoCommittee,
    NotAMemberOfCommittee,
}

pub struct VerifierNode {
    committee: Committee,
}

impl VerifierNode {
    pub fn new(committee: Committee) -> Self {
        Self { committee }
    }

    /// One signature, against one claimed member.
    ///
    /// The two failures are kept apart on purpose. A stranger holding a perfectly
    /// valid signature is refused for *membership*, not for cryptography, and
    /// reporting that as a verification error would send whoever reads the log
    /// hunting a broken signature that is in fact correct.
    pub fn verify(
        &self,
        pub_key: &XmssPublicKey,
        signature: &XmssSignature,
        message: &[u8; MESSAGE_LEN_BYTES],
        slot: u32,
    ) -> Result<(), VerifierError> {
        if !self.committee.members().contains(pub_key) {
            return Err(VerifierError::NotAMemberOfCommittee);
        }

        xmss_verify(pub_key, slot, message, signature)
            .map_err(|_| VerifierError::SignatureVerificationError)
    }

    /// Verifies a [`StatusList`] against this node's anchor: the `t` XMSS
    /// signatures it carries, plus the bitmap naming who produced them.
    ///
    /// A method and never a free function: every answer is relative to the anchor
    /// this node holds. Bitmap width, which key each bit names, the slot the
    /// version derives to and `t` itself all come from it, so the same bytes
    /// verify under one committee and not another.
    ///
    /// All five checks are load-bearing; dropping any one is exploitable.
    pub fn verify_status_list(&self, status_list: &StatusList) -> bool {
        let members = self.committee.members();
        let n = members.len();

        // 0) a degenerate anchor. `Committee::new` and `from_bytes` both reject
        //    `t = 0`, so this is unreachable through them, but a `true` here
        //    authorizes an update, and at `t = 0` every check below passes
        //    vacuously for a record with an empty bitmap and no signatures. One
        //    branch is cheap insurance against a future construction path.
        if self.committee.threshold() == 0 {
            return false;
        }

        // 1) the bitmap must name exactly this committee. A `BitList` length is a
        //    count of *bits*, recovered from the sentinel on decode rather than a
        //    byte width rounded up, so a record built for 197 members does not
        //    pass here as one for 200.
        //
        //    This is also what makes indexing `members` below infallible: every
        //    index `signer_indices` yields is `< signer_slots()`, and this line
        //    ties that to `n`.
        if status_list.signer_slots() != n {
            return false;
        }

        // 2) quorum. Distinctness is structural rather than checked: a member is
        //    one bit and cannot be counted twice. The second half of this condition
        //    is what keeps the bits and the signatures aligned when zipped below.
        let count = status_list.signer_count();
        if count < self.committee.threshold() || count != status_list.signatures().len() {
            return false;
        }

        // 3) the slot the protocol assigns to this round, derived from the anchor,
        //    so a quorum cannot pick its own. `None` means the version ran past
        //    `u32`.
        let Some(slot) = self.committee.slot_for(status_list.version()) else {
            return false;
        };

        // 4) the message every member must have signed. Binding the version into
        //    it is what makes the cleartext `version` trustworthy afterwards, and
        //    the domain binds the two fields a signature would otherwise say
        //    nothing about: the anchor, so this record cannot have been signed for
        //    another committee, and the record's own `alg`, so relabelling the
        //    algorithm invalidates the evidence produced under the old one.
        //    Exactly as in the SNARK path.
        let message =
            self.committee
                .message_for(status_list.alg, status_list.list(), status_list.version());

        // 5) every signature, against the key its bit names. Membership needs no
        //    check of its own: an index *is* a member, so a non-member is
        //    unnameable rather than rejected. The SNARK predicate receives public
        //    keys instead, and has to look them up.
        status_list
            .signer_indices()
            .zip(status_list.signatures())
            .all(|(i, sig)| xmss_verify(&members[i], slot, &message, sig).is_ok())
    }

    pub fn get_committee(&self) -> &Committee {
        &self.committee
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::status_list::{Algorithms, hash_any};
    use lean_multisig::{XmssSecretKey, xmss_key_gen_from_seed, xmss_sign};

    /// Deliberately not a multiple of 8, so the bitmap's sentinel does not land on
    /// a byte boundary and the encoding is exercised where it is easiest to break.
    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;

    /// This file's tag in the crate-wide seed namespace `[file, ns, member, 0, ..]`.
    ///
    /// Nearly every test here signs round 0, so without a namespace one secret key
    /// would sign slot `GENESIS` a dozen times per `cargo test` over *different*
    /// messages: the case that destroys an XMSS key. (v0.9 derandomized signing
    /// makes a repeated slot with the *same* message harmless; two messages are as
    /// fatal as ever.)
    ///
    /// The namespace must live in the **seed**. leanVM derives the one-time key as
    /// `gen_wots_secret_key(seed, slot, gen_public_param(seed))`: both arguments
    /// are functions of the seed alone, so two keys born of one seed share every
    /// hash chain whatever window they were generated over. Varying the window is
    /// not a namespace.
    ///
    /// `file` separates this module from the others, `ns` separates the tests here
    /// from each other, and `member` is unbounded, so an outsider key takes an
    /// index no committee reaches instead of a magic constant to check by hand.
    const FILE: u8 = 7;

    fn seed(ns: u8, member: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = FILE;
        s[1] = ns;
        s[2] = member;
        s
    }

    /// `GENESIS..=GENESIS + 8`, as the slot *count* leanVM v0.9 takes.
    const WINDOW: u64 = 9;

    fn keypair(ns: u8, member: u8) -> (XmssSecretKey, XmssPublicKey) {
        let (pk, sk) =
            xmss_key_gen_from_seed(seed(ns, member), u64::from(GENESIS), WINDOW).expect("keygen");
        (sk, pk)
    }

    fn committee_in(ns: u8) -> (Vec<(XmssSecretKey, XmssPublicKey)>, VerifierNode) {
        let keys: Vec<_> = (0..N).map(|i| keypair(ns, i as u8)).collect();
        let members = keys.iter().map(|(_, pk)| pk.clone()).collect();
        (keys, VerifierNode::new(Committee::new(members, T, GENESIS)))
    }

    /// Signs `(list, version)` with `signers`, at the slot the anchor derives.
    fn quorum(
        keys: &[(XmssSecretKey, XmssPublicKey)],
        c: &Committee,
        list: &[[u8; 32]],
        version: u32,
        signers: &[usize],
    ) -> Vec<(usize, XmssSignature)> {
        let message = c.message_for(Algorithms::WotsXmss, list, version);
        let slot = c.slot_for(version).expect("slot");
        signers
            .iter()
            .map(|&i| (i, xmss_sign(&keys[i].0, slot, &message).expect("sign")))
            .collect()
    }

    fn record(list: Vec<[u8; 32]>, version: u32, sigs: Vec<(usize, XmssSignature)>) -> StatusList {
        StatusList::new(Algorithms::WotsXmss, list, version, N, sigs).expect("well-formed")
    }

    // --- `verify`: one signature, one member ---------------------------------

    /// `verify` has two distinct ways to say no, and they must not be confused.
    #[test]
    fn a_signature_is_refused_for_the_right_reason() {
        let (keys, node) = committee_in(1);
        let list = vec![hash_any(b"vc-1")];
        let message = node
            .get_committee()
            .message_for(Algorithms::WotsXmss, &list, 0);
        let slot = GENESIS;

        // Member 0, at slot 100. This is the only time this pair signs.
        let sig = xmss_sign(&keys[0].0, slot, &message).expect("sign");
        assert!(node.verify(&keys[0].1, &sig, &message, slot).is_ok());

        // An outsider's own valid signature: refused for membership.
        let (out_sk, out_pk) = keypair(1, 200);
        let out_sig = xmss_sign(&out_sk, slot, &message).expect("outsider sign");
        assert!(matches!(
            node.verify(&out_pk, &out_sig, &message, slot),
            Err(VerifierError::NotAMemberOfCommittee)
        ));

        // A member's signature against the wrong message, then the wrong slot. Both
        // re-use the signature above: no `(key, slot)` pair signs twice.
        let other = node
            .get_committee()
            .message_for(Algorithms::WotsXmss, &[hash_any(b"vc-2")], 0);
        assert!(matches!(
            node.verify(&keys[0].1, &sig, &other, slot),
            Err(VerifierError::SignatureVerificationError)
        ));
        assert!(matches!(
            node.verify(&keys[0].1, &sig, &message, slot + 1),
            Err(VerifierError::SignatureVerificationError)
        ));
    }

    /// The node must hand back the anchor it was built with, unchanged. Everything
    /// downstream derives slots through it, so a node that quietly held a different
    /// `genesis_slot` than the one it was given would put signer and verifier on
    /// different rounds.
    #[test]
    fn the_node_exposes_the_anchor_it_was_built_with() {
        let (keys, node) = committee_in(3);
        let c = node.get_committee();

        assert_eq!(c.threshold(), T);
        assert_eq!(c.genesis_slot(), GENESIS);
        assert_eq!(c.members().len(), N);
        for (i, (_, pk)) in keys.iter().enumerate() {
            assert_eq!(&c.members()[i], pk, "member {i} is not the key supplied");
        }
        assert_eq!(c.slot_for(0), Some(GENESIS));
        assert_eq!(c.slot_for(7), Some(GENESIS + 7));
    }

    // --- `verify_status_list`: the predicate that authorizes an update -------

    #[test]
    fn a_legitimate_quorum_verifies() {
        let (keys, node) = committee_in(5);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 2, 4]);
        let sl = record(list.clone(), 0, sigs);

        assert_eq!(sl.signer_count(), 3);
        assert_eq!(sl.signer_indices().collect::<Vec<_>>(), vec![0, 2, 4]);
        assert!(node.verify_status_list(&sl));

        // ...and it survives a round trip through the wire encoding.
        let bytes = sl.to_bytes();
        let back = StatusList::from_bytes(&bytes).expect("decodes");
        assert!(node.verify_status_list(&back));
    }

    /// A member names itself with `Committee::index_of`, and the index it gets
    /// back is the one the predicate expects.
    ///
    /// This is the seam a gossip layer will sit on: a signer holds a key, not a
    /// seat number, so the index that goes into the bitmap has to be *derived*
    /// from the anchor rather than configured alongside it. If the two ever
    /// disagreed, the record would name the wrong member and the signature would
    /// be checked against the wrong public key, which is why the test asserts
    /// both halves: the derived index verifies, and any other index does not.
    #[test]
    fn a_member_names_itself_with_index_of_and_the_predicate_agrees() {
        let (keys, node) = committee_in(16);
        let c = node.get_committee();
        let list = vec![hash_any(b"vc-1")];
        let message = c.message_for(Algorithms::WotsXmss, &list, 0);
        let slot = c.slot_for(0).expect("slot");

        // Each signer looks up its own seat rather than being told one.
        let mine: Vec<usize> = [0usize, 2, 4]
            .iter()
            .map(|&i| c.index_of(&keys[i].1).expect("a member finds itself"))
            .collect();
        assert_eq!(mine, vec![0, 2, 4]);

        let sigs: Vec<(usize, XmssSignature)> = mine
            .iter()
            .map(|&i| (i, xmss_sign(&keys[i].0, slot, &message).expect("sign")))
            .collect();
        assert!(node.verify_status_list(&record(list.clone(), 0, sigs.clone())));

        // The same signatures under any other seat: member 4's signature filed
        // under seat 3 is checked against member 3's key, and fails.
        let mut mislabelled = sigs;
        mislabelled[2].0 = 3;
        assert!(!node.verify_status_list(&record(list, 0, mislabelled)));

        // An outsider has no seat to claim in the first place.
        let (_, out_pk) = keypair(16, 200);
        assert_eq!(c.index_of(&out_pk), None);
    }

    /// The signers are named out of order and get sorted into canonical form, so
    /// the same set always produces the same bytes.
    #[test]
    fn signer_order_does_not_change_the_encoding() {
        let (keys, node) = committee_in(6);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 2, 4]);
        let mut shuffled = sigs.clone();
        shuffled.reverse();

        let a = record(list.clone(), 0, sigs);
        let b = record(list.clone(), 0, shuffled);
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert!(node.verify_status_list(&b));
    }

    #[test]
    fn a_member_cannot_stand_in_for_the_quorum_twice() {
        let (keys, node) = committee_in(7);
        let list = vec![hash_any(b"vc-1")];
        let mut sigs = quorum(&keys, node.get_committee(), &list, 0, &[0]);
        sigs.push(sigs[0].clone());
        sigs.push(sigs[0].clone());

        assert_eq!(sigs.len(), T);
        assert!(StatusList::new(Algorithms::WotsXmss, list, 0, N, sigs).is_err());
    }

    #[test]
    fn below_threshold_is_refused() {
        let (keys, node) = committee_in(8);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[1, 3]);
        assert!(!node.verify_status_list(&record(list, 0, sigs)));
    }

    /// A valid quorum re-labelled with another version. The version is folded into
    /// the signed message *and* fixes the slot, so both bindings break at once.
    #[test]
    fn a_relabelled_version_is_refused() {
        let (keys, node) = committee_in(9);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1, 2]);
        assert!(!node.verify_status_list(&record(list, 1, sigs)));
    }

    /// A row nobody authorized, appended to a list carrying a real quorum.
    #[test]
    fn a_tampered_list_is_refused() {
        let (keys, node) = committee_in(10);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1, 2]);
        let mut tampered = list.clone();
        tampered.push(hash_any(b"FAKE-REVOCATION"));
        assert!(!node.verify_status_list(&record(tampered, 0, sigs)));
    }

    /// Signatures re-attributed to members who never produced them. Nothing about
    /// the record is malformed: the bits simply name the wrong keys.
    #[test]
    fn signatures_cannot_be_re_attributed() {
        let (keys, node) = committee_in(11);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1, 2]);
        let moved = sigs
            .into_iter()
            .map(|(i, s)| (i + 2, s)) // 0,1,2 -> 2,3,4
            .collect();
        assert!(!node.verify_status_list(&record(list, 0, moved)));
    }

    /// Locates the signer bitmap through the SSZ container's offset table.
    ///
    /// The fixed section is `alg: u8`, `list: offset`, `version: u32`,
    /// `signers: offset`, `signatures: offset`; the signer bytes occupy the
    /// interval between the last two offsets. Reading the schema is deliberate:
    /// searching a signature blob for a byte value can mutate a signature instead
    /// of the bitmap and turn a security test into a false positive.
    fn read_offset(bytes: &[u8], at: usize) -> usize {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("SSZ offset")) as usize
    }

    fn bitmap_byte(bytes: &[u8], expected: u8) -> usize {
        const SIGNERS_OFFSET: usize = 1 + 4 + 4;
        const SIGNATURES_OFFSET: usize = SIGNERS_OFFSET + 4;
        let at = read_offset(bytes, SIGNERS_OFFSET);
        let end = read_offset(bytes, SIGNATURES_OFFSET);
        assert_eq!(end, at + 1, "test records carry a one-byte bitmap");
        assert_eq!(
            bytes[at], expected,
            "SSZ bitmap offset {at} is {:#010b}, expected {expected:#010b}",
            bytes[at]
        );
        at
    }

    /// `t = 0` makes a record with **no signatures at all** reach quorum: the
    /// count check becomes `0 >= 0`, the bitmap is empty so the width and padding
    /// checks pass, and `.all()` over an empty iterator is `true`. The predicate
    /// whose `true` authorizes an update would return `true` for a record nobody
    /// signed.
    ///
    /// Both constructors reject `t = 0`, so this is unreachable through the public
    /// API, which is exactly why it went untested: the guard is insurance against
    /// a future construction path, and no future construction path exists yet to
    /// write a test against. `Committee::new_unchecked` is that path, test-only.
    #[test]
    fn a_degenerate_anchor_cannot_authorize_an_unsigned_record() {
        // Deliberately not `Committee::new`: it asserts `t >= 1`, which is the
        // check being backstopped here.
        let degenerate = Committee::new_unchecked(Vec::new(), 0, GENESIS);
        let encoded = degenerate.to_bytes();
        let node = VerifierNode::new(degenerate);

        let empty = StatusList::new(Algorithms::WotsXmss, vec![hash_any(b"vc-1")], 0, 0, vec![])
            .expect("a record with no signers is well-formed, just worthless");
        assert_eq!(empty.signer_count(), 0);
        assert_eq!(empty.signatures().len(), 0);

        assert!(
            !node.verify_status_list(&empty),
            "a threshold of zero must never authorize anything"
        );

        // And the constructors keep it unreachable in the first place.
        assert!(Committee::from_bytes(&encoded).is_err());
    }

    /// A `BitList` length is a number of bits, not a byte width rounded up, so a
    /// record built for a committee of 8 does not pass as one built for 5, even
    /// though both fit in a single byte.
    #[test]
    fn a_record_built_for_another_committee_size_is_refused() {
        let (keys, node) = committee_in(15);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[1, 2, 3]);

        // Same signatures, same list, same version; only the committee size the
        // record was sized for differs.
        let honest = record(list.clone(), 0, sigs.clone());
        assert!(node.verify_status_list(&honest));
        assert_eq!(honest.signer_slots(), N);

        let mis_sized = StatusList::new(Algorithms::WotsXmss, list, 0, 8, sigs)
            .expect("well-formed, just built for the wrong committee");
        assert_eq!(mis_sized.signer_slots(), 8);
        assert_eq!(
            mis_sized.signer_indices().collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the signer set is the honest one; only the width differs"
        );
        assert!(
            !node.verify_status_list(&mis_sized),
            "a bitmap sized for another committee must be refused"
        );
    }

    /// A bit set in addition to the honest ones is caught at the decoding
    /// boundary, because the bitmap then names more signers than there are
    /// signatures. That relation is between two different fields, so no schema
    /// can express it and the check stays hand-written.
    #[test]
    fn an_extra_bit_is_caught_at_the_decoding_boundary() {
        let (keys, node) = committee_in(12);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1, 2]);
        let sl = record(list.clone(), 0, sigs);
        assert!(node.verify_status_list(&sl));

        // Members 0, 1, 2 are bits 0..2; bit 5 is the BitList sentinel that makes
        // the length 5. Member 3 joins without a signature to go with it.
        let mut bytes = sl.to_bytes();
        let at = bitmap_byte(&bytes, 0b0010_0111);
        bytes[at] |= 1 << 3;
        assert!(
            StatusList::from_bytes(&bytes).is_err(),
            "4 bits against 3 signatures must not decode"
        );
    }

    /// The invariant that makes `members[i]` infallible, asserted exhaustively
    /// rather than argued.
    ///
    /// The attack this forecloses: a record that decodes cleanly and reaches the
    /// quorum check naming member 7 of a committee of 5: a remote panic any peer
    /// could trigger with two bit flips and no key of its own. A `BitList` cannot
    /// represent it, because the sentinel *is* the length: moving a bit upward
    /// changes the declared length instead of smuggling an index past the end.
    ///
    /// At `N = 5` the bitmap is one byte, so this pins **all 256 values**. Each
    /// must either fail to decode or name only members the record has room for,
    /// and only the honest byte may verify.
    #[test]
    fn no_bitmap_byte_can_name_a_member_the_committee_does_not_have() {
        let (keys, node) = committee_in(14);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[1, 2, 3]);
        let sl = record(list.clone(), 0, sigs);
        assert!(node.verify_status_list(&sl), "the record starts out honest");

        let bytes = sl.to_bytes();
        // Bits 1, 2, 3 are the signers; bit 5 is the sentinel carrying the length.
        const HONEST: u8 = 0b0010_1110;
        let at = bitmap_byte(&bytes, HONEST);

        let mut decoded = 0;
        let mut accepted = 0;
        for byte in 0..=u8::MAX {
            let mut forged = bytes.clone();
            forged[at] = byte;

            let Ok(sl) = StatusList::from_bytes(&forged) else {
                continue; // refusing to parse is a valid way to refuse
            };
            decoded += 1;

            let slots = sl.signer_slots();
            for i in sl.signer_indices() {
                assert!(
                    i < slots,
                    "bitmap {byte:#010b}: index {i} is outside the {slots} declared"
                );
            }

            if node.verify_status_list(&sl) {
                accepted += 1;
                assert_eq!(
                    byte, HONEST,
                    "bitmap {byte:#010b} verified, and it is not the honest one"
                );
            }
        }

        assert_eq!(accepted, 1, "exactly one bitmap may authorize this record");
        assert!(
            decoded > 1,
            "only {decoded} of 256 bitmaps decoded, so the in-range assertion \
             above was barely exercised"
        );
    }

    /// An outsider's signature cannot be carried at all: the record names signers
    /// by index, and every index is a member by construction.
    #[test]
    fn an_outsider_has_no_index_to_occupy() {
        let (keys, node) = committee_in(13);
        let list = vec![hash_any(b"vc-1")];
        // Member index 200: outside any committee, so it cannot collide with a
        // namespace no matter how many tests are added.
        let (out_sk, _) = keypair(13, 200);

        let message = node
            .get_committee()
            .message_for(Algorithms::WotsXmss, &list, 0);
        let slot = node.get_committee().slot_for(0).expect("slot");
        let outsider = xmss_sign(&out_sk, slot, &message).expect("sign");
        let mut sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1]);
        // The outsider takes member 2's seat: the only way in, and it fails
        // because seat 2 is checked against member 2's key.
        sigs.push((2, outsider.clone()));
        assert!(!node.verify_status_list(&record(list.clone(), 0, sigs)));

        // Claiming a seat the committee does not have is refused at construction,
        // so an outsider cannot be appended alongside a full honest quorum either.
        //
        // Round 1, not 0: members 0 and 1 already signed round 0 above, and round
        // 0 is slot `GENESIS` for both. Reusing it here would have this test do
        // exactly what the repeated-signer guard in `snark_prover_node` exists to
        // forbid. `StatusList::new` rejects on the index alone, so which round the
        // signatures cover makes no difference to what is being asserted.
        let mut beyond = quorum(&keys, node.get_committee(), &list, 1, &[0, 1, 2]);
        beyond.push((N, outsider));
        assert!(StatusList::new(Algorithms::WotsXmss, list, 1, N, beyond).is_err());
    }
}
