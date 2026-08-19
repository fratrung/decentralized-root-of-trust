//! A relying party on the **raw** path: it holds the anchor and answers the two
//! questions a verifier can ask without a circuit.
//!
//! `verify` asks "is this one signature from some member". `verify_status_list`
//! asks the question that actually authorizes an update — "did at least `t`
//! distinct members sign *this* list at *this* version" — and the threshold is
//! part of it.
//!
//! Neither needs `setup_verifier()`, neither needs the aggregation bytecode, and
//! neither costs a gigabyte of resident state. This is the counterpart of
//! [`crate::snark_verifier_node::PQSNARKVerifierModule`], and the honest
//! comparison between the two paths: `t` independent Poseidon2 verifications,
//! linear in `t` where the SNARK's cost is constant, on a verifier far too small
//! to hold the circuit.

use lean_multisig::{MESSAGE_LEN_BYTES, XmssPublicKey, XmssSignature, xmss_verify};

use crate::committee::Committee;
use crate::status_list::{StatusList, status_list_message};

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
    /// Unlike [`VerifierNode::verify`], which answers "is this one signature from
    /// some member", this answers "is this update authorized" — the threshold is
    /// part of the question.
    ///
    /// It is a method on the node, and never a free function, because *every*
    /// answer it gives is relative to the committee this node holds: the bitmap
    /// width, which key each bit names, the slot the version derives to, and `t`
    /// itself all come from the anchor. The same bytes verify under one committee
    /// and not under another, so there is no anchor-free way to ask the question.
    ///
    /// All five checks are load-bearing; dropping any one of them is exploitable.
    pub fn verify_status_list(&self, status_list: &StatusList) -> bool {
        let members = self.committee.members();
        let n = members.len();

        // 0) a degenerate anchor. `Committee::new` and `from_bytes` both reject
        //    `t = 0`, so this is unreachable through them — but this is the
        //    predicate whose `true` authorizes an update, and with `t = 0` every
        //    check below passes vacuously for a record carrying an empty bitmap
        //    and no signatures at all. One branch is cheap insurance against a
        //    future construction path.
        if self.committee.threshold() == 0 {
            return false;
        }

        // 1) the bitmap must name exactly this committee. It is an SSZ `BitList`,
        //    so its length is a count of *bits* recovered from the sentinel bit on
        //    decode, not a byte width rounded up — a record built for a committee
        //    of 197 does not pass here as one for 200.
        //
        //    This is also what makes indexing `members` below infallible: every
        //    index `signer_indices` yields is `< signer_slots()`, and this line
        //    ties that to `n`. It used to take two checks — a byte width and a
        //    sweep for set padding bits — because a byte array leaves the bits
        //    above member `n - 1` free, so one signer set had several encodings
        //    and an index past the end of the committee was representable. A
        //    `BitList` cannot express either, so the encoding enforces what the
        //    second check used to.
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

        // 3) the slot the protocol assigns to this round — derived from the anchor,
        //    so a quorum cannot pick its own. `None` means the version ran past
        //    `u32`.
        let Some(slot) = self.committee.slot_for(status_list.version()) else {
            return false;
        };

        // 4) the message every member must have signed. Binding the version into it
        //    (Option B) is what makes the cleartext `version` trustworthy
        //    afterwards, exactly as in the SNARK path.
        let message = status_list_message(status_list.list(), status_list.version());

        // 5) every signature, against the key its bit names. Committee membership
        //    needs no separate check here — unlike the SNARK predicate, which
        //    receives public keys and must look them up. An index *is* a member, so
        //    a non-member is unnameable rather than merely rejected.
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
    use crate::status_list::{Algorithms, hash_any};
    use lean_multisig::{XmssSecretKey, xmss_key_gen_from_seed, xmss_sign};

    /// Deliberately not a multiple of 8, so the bitmap has padding bits and the
    /// checks that police them are actually exercised.
    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;

    /// Nearly every test in this module signs round 0, hence slot `GENESIS`.
    /// Sharing one set of seeds across them would therefore have one secret key
    /// sign one slot a dozen times per `cargo test` — and those calls do not all
    /// carry the same message, which is the case that destroys a key. (leanVM
    /// v0.9 derandomized signing, so a repeated *message* at a repeated slot is
    /// now bit-identical and harmless; a repeated slot with two messages is as
    /// fatal as it ever was.)
    ///
    /// The namespace has to live in the **seed** and nowhere else. leanVM derives
    /// the one-time key as `gen_wots_secret_key(seed, slot, gen_public_param(seed))`
    /// — both arguments are functions of the seed alone, so the *slot window* never
    /// enters it and two keys born of one seed share every hash chain no matter
    /// what range they were generated over. Varying the window is not a namespace.
    ///
    /// The layout is `[file, ns, member, 0, ..]`, which is collision-free by
    /// construction rather than by arithmetic: `file` separates this module from
    /// `committee.rs`, `signer_node.rs`, `tests/snark_path.rs` and the rest, `ns`
    /// separates the tests here from each other, and `member` is unbounded, so an
    /// outsider key can take an index no committee will ever reach instead of a
    /// magic constant that has to be checked against every namespace by hand.
    ///
    /// These keys authorize nothing, so nothing is at risk either way. The point
    /// is that an invariant the whole design rests on should not be one the tests
    /// are the first to break.
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
        let message = status_list_message(list, version);
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
        let message = status_list_message(&list, 0);
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
        let other = status_list_message(&[hash_any(b"vc-2")], 0);
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
    /// the record is malformed — the bits simply name the wrong keys.
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
    /// API — which is exactly why it went untested: the guard is insurance against
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

    /// The bitmap must name *this* committee, and since it is an SSZ `BitList`
    /// its length is a number of bits rather than a byte width rounded up. A
    /// record built for a committee of 8 therefore no longer passes as one built
    /// for a committee of 5: under the old byte array both were one byte wide and
    /// only a sweep for set padding bits could tell them apart.
    #[test]
    fn a_record_built_for_another_committee_size_is_refused() {
        let (keys, node) = committee_in(15);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[1, 2, 3]);

        // Same signatures, same list, same version — only the committee size the
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
    /// The predecessor of this test flipped one specific pair of bits, because
    /// under a byte array a moved padding bit produced a record that decoded
    /// cleanly and arrived at the quorum check naming member 7 of a committee of
    /// 5 — a remote panic any peer could trigger with two bit flips and no key of
    /// its own. A `BitList` cannot represent that: the highest set bit *is* the
    /// length, so moving a bit upward moves the sentinel and changes the declared
    /// length rather than smuggling an index past the end.
    ///
    /// With `N = 5` the bitmap is a single byte, so the case worth pinning is not
    /// one mutation but **all 256 of them**. Each must either fail to decode or
    /// name only members the record declares room for, and only the honest byte
    /// may verify.
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

        let message = status_list_message(&list, 0);
        let slot = node.get_committee().slot_for(0).expect("slot");
        let outsider = xmss_sign(&out_sk, slot, &message).expect("sign");
        let mut sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1]);
        // The outsider takes member 2's seat — the only way in, and it fails
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
