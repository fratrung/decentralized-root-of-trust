//! A relying party on the **raw** path: it holds the anchor and answers the two
//! questions a verifier can ask without a circuit.
//!
//! `verify` asks "is this one signature from some member". `verify_quorum` asks
//! the question that actually authorizes an update — "did at least `t` distinct
//! members sign *this* list at *this* version" — and the threshold is part of it.
//!
//! Neither needs `setup_verifier()`, neither needs the aggregation bytecode, and
//! neither costs a gigabyte of resident state. This is the counterpart of
//! [`crate::snark_verifier_node::PQSNARKVerifierModule`], and the honest
//! comparison between the two paths: `t` independent Poseidon2 verifications,
//! linear in `t` where the SNARK's cost is constant, on a verifier far too small
//! to hold the circuit.

use backend::{KoalaBearParameters, MontyField31};
use lean_multisig::{XmssPublicKey, XmssSignature, xmss_verify};

use crate::committee::Committee;
use crate::status_list::{StatusList, status_list_root_fe};

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
        message: &[MontyField31<KoalaBearParameters>; 8],
        slot: u32,
    ) -> Result<(), VerifierError> {
        if !self.committee.members().contains(pub_key) {
            return Err(VerifierError::NotAMemberOfCommittee);
        }

        xmss_verify(pub_key, message, signature, slot)
            .map_err(|_| VerifierError::SignatureVerificationError)
    }

    /// Verifies the raw quorum carried by a [`StatusList`]: the `t` XMSS
    /// signatures themselves, plus the bitmap naming who produced them.
    ///
    /// Unlike [`VerifierNode::verify`], which answers "is this one signature from
    /// some member", this answers "is this update authorized" — the threshold is
    /// part of the question.
    ///
    /// All six checks are load-bearing; dropping any one of them is exploitable.
    pub fn verify_quorum(&self, status_list: &StatusList) -> bool {
        let members = self.committee.members();
        let n = members.len();
        let bitmap = status_list.signers_bitmap();

        // 0) a degenerate anchor. `Committee::new` and `from_bytes` both reject
        //    `t = 0`, so this is unreachable through them — but this is the
        //    predicate whose `true` authorizes an update, and with `t = 0` every
        //    check below passes vacuously for a record carrying an empty bitmap
        //    and no signatures at all. One branch is cheap insurance against a
        //    future construction path.
        if self.committee.threshold() == 0 {
            return false;
        }

        // 1) the bitmap must be exactly as wide as the committee...
        if bitmap.len() != n.div_ceil(8) {
            return false;
        }
        // ...and every bit past member `n - 1` must be clear. Otherwise one signer
        // set has several valid encodings: records that differ byte for byte while
        // meaning the same thing, which defeats deduplication wherever they are
        // content-addressed. Together these two checks also guarantee that every
        // index `signer_indices` yields is `< n`, which is what makes indexing
        // `members` below infallible.
        if !n.is_multiple_of(8)
            && let Some(last) = bitmap.last()
            && (last >> (n % 8)) != 0
        {
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
        let message = status_list_root_fe(status_list.list(), status_list.version());

        // 5) every signature, against the key its bit names. Committee membership
        //    needs no separate check here — unlike the SNARK predicate, which
        //    receives public keys and must look them up. An index *is* a member, so
        //    a non-member is unnameable rather than merely rejected.
        status_list
            .signer_indices()
            .zip(status_list.signatures())
            .all(|(i, sig)| xmss_verify(&members[i], &message, sig, slot).is_ok())
    }

    pub fn get_committee(&self) -> &Committee {
        &self.committee
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_list::{Algorithms, hash_any};
    use lean_multisig::{XmssSecretKey, xmss_key_gen, xmss_sign};

    /// Deliberately not a multiple of 8, so the bitmap has padding bits and the
    /// checks that police them are actually exercised.
    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;

    /// Nearly every test in this module signs round 0, hence slot `GENESIS`.
    /// Sharing one set of seeds across them would therefore have one secret key
    /// sign one slot a dozen times per `cargo test` — the exact thing this codebase
    /// treats as fatal, and which leanVM warns about even for a repeated *message*
    /// (`xmss.rs:234`), since `xmss_sign` rejection-samples fresh randomness per
    /// call.
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

    fn committee_in(ns: u8) -> (Vec<(XmssSecretKey, XmssPublicKey)>, VerifierNode) {
        let keys: Vec<_> = (0..N)
            .map(|i| xmss_key_gen(seed(ns, i as u8), GENESIS, GENESIS + 8, false).expect("keygen"))
            .collect();
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
        let message = status_list_root_fe(list, version);
        let slot = c.slot_for(version).expect("slot");
        let mut rng = rand::rng();
        signers
            .iter()
            .map(|&i| {
                (
                    i,
                    xmss_sign(&mut rng, &keys[i].0, &message, slot).expect("sign"),
                )
            })
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
        let message = status_list_root_fe(&list, 0);
        let slot = GENESIS;
        let mut rng = rand::rng();

        // Member 0, at slot 100. This is the only time this pair signs.
        let sig = xmss_sign(&mut rng, &keys[0].0, &message, slot).expect("sign");
        assert!(node.verify(&keys[0].1, &sig, &message, slot).is_ok());

        // An outsider's own valid signature: refused for membership.
        let (out_sk, out_pk) =
            xmss_key_gen(seed(1, 200), GENESIS, GENESIS + 8, false).expect("outsider keygen");
        let out_sig = xmss_sign(&mut rng, &out_sk, &message, slot).expect("outsider sign");
        assert!(matches!(
            node.verify(&out_pk, &out_sig, &message, slot),
            Err(VerifierError::NotAMemberOfCommittee)
        ));

        // A member's signature against the wrong message, then the wrong slot. Both
        // re-use the signature above: no `(key, slot)` pair signs twice.
        let other = status_list_root_fe(&[hash_any(b"vc-2")], 0);
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

    // --- `verify_quorum`: the predicate that authorizes an update -------------

    #[test]
    fn a_legitimate_quorum_verifies() {
        let (keys, node) = committee_in(5);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 2, 4]);
        let sl = record(list.clone(), 0, sigs);

        assert_eq!(sl.signer_count(), 3);
        assert_eq!(sl.signer_indices().collect::<Vec<_>>(), vec![0, 2, 4]);
        assert!(node.verify_quorum(&sl));

        // ...and it survives a round trip through the wire encoding.
        let bytes = sl.to_bytes();
        let back = StatusList::from_bytes(&bytes).expect("decodes");
        assert!(node.verify_quorum(&back));
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
        assert!(node.verify_quorum(&b));
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
        assert!(!node.verify_quorum(&record(list, 0, sigs)));
    }

    /// A valid quorum re-labelled with another version. The version is folded into
    /// the signed message *and* fixes the slot, so both bindings break at once.
    #[test]
    fn a_relabelled_version_is_refused() {
        let (keys, node) = committee_in(9);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1, 2]);
        assert!(!node.verify_quorum(&record(list, 1, sigs)));
    }

    /// A row nobody authorized, appended to a list carrying a real quorum.
    #[test]
    fn a_tampered_list_is_refused() {
        let (keys, node) = committee_in(10);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1, 2]);
        let mut tampered = list.clone();
        tampered.push(hash_any(b"FAKE-REVOCATION"));
        assert!(!node.verify_quorum(&record(tampered, 0, sigs)));
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
        assert!(!node.verify_quorum(&record(list, 0, moved)));
    }

    /// Where the signer bitmap sits inside `StatusList::to_bytes`, derived from
    /// the postcard layout rather than searched for:
    ///
    /// ```text
    /// alg | list len | 32 * n_entries | version | bitmap len | BITMAP | sigs len | ...
    ///  1        1                          1          1
    /// ```
    ///
    /// Valid only while `n_entries`, the version and the bitmap length each fit in
    /// one varint byte, which the callers below ensure. `bitmap_byte` asserts the
    /// arithmetic landed on the value it expected, so a layout change fails here
    /// rather than silently patching a byte in the middle of a signature.
    ///
    /// Searching was the original approach and it was wrong: the bitmap for
    /// signers `{0,1,2}` is `0b0000_0111`, and `0x07` occurs *all over* a 4.4 kB
    /// blob of signatures. `rposition` found one at offset 4434 instead of 36, so
    /// the test was corrupting a signature and then congratulating itself when the
    /// record failed to verify — for entirely the wrong reason.
    fn bitmap_byte(bytes: &[u8], n_entries: usize, expected: u8) -> usize {
        let at = 1 + 1 + 32 * n_entries + 1 + 1;
        assert_eq!(
            bytes[at], expected,
            "postcard layout moved: offset {at} is {:#010b}, expected {expected:#010b}",
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
            !node.verify_quorum(&empty),
            "a threshold of zero must never authorize anything"
        );

        // And the constructors keep it unreachable in the first place.
        assert!(Committee::from_bytes(&encoded).is_err());
    }

    /// The bitmap must be exactly `ceil(N / 8)` bytes. A *wider* one is the case
    /// the padding check cannot catch: that check only inspects `bitmap.last()`,
    /// so a second byte carrying only low bits reads as clean padding — `1 >> 5`
    /// is `0` — while `signer_indices` happily yields index 8 for a committee of
    /// five.
    ///
    /// As with the moved padding bit, the two checks together are what keep
    /// `members[i]` in range, and the reachable outcome of dropping this one is a
    /// panic rather than a false accept. The bit is placed on the *last* signer so
    /// the genuine pairs ahead of it keep `.all()` going long enough to reach it.
    #[test]
    fn a_bitmap_wider_than_the_committee_is_refused() {
        let (keys, node) = committee_in(15);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[1, 2, 3]);
        let sl = record(list.clone(), 0, sigs);
        assert!(node.verify_quorum(&sl), "the record starts out honest");

        let mut bytes = sl.to_bytes();
        let at = bitmap_byte(&bytes, list.len(), 0b0000_1110);
        // Widen `signers` from one byte to two: members 1 and 2 stay, member 3's
        // bit moves into a second byte that the committee has no room for.
        assert_eq!(bytes[at - 1], 1, "the byte before the bitmap is its length");
        bytes[at - 1] = 2;
        bytes[at] = 0b0000_0110;
        bytes.insert(at + 1, 0b0000_0001);

        let forged = StatusList::from_bytes(&bytes)
            .expect("three bits against three signatures still decodes");
        assert_eq!(forged.signers_bitmap().len(), 2, "wider than ceil(5 / 8)");
        assert_eq!(
            forged.signer_indices().collect::<Vec<_>>(),
            vec![1, 2, 8],
            "index 8 is past member {}",
            N - 1
        );
        // The padding check alone would let this through, which is why the width
        // check is not redundant with it.
        assert_eq!(
            forged.signers_bitmap().last().copied().unwrap() >> (N % 8),
            0,
            "the last byte looks like clean padding"
        );

        assert!(
            !node.verify_quorum(&forged),
            "a bitmap wider than the committee must be refused"
        );
    }

    /// Padding bits past member `N - 1` must be clear. Setting one *in addition*
    /// to the honest bits is caught at the decoding boundary, because the bitmap's
    /// population no longer matches the signature count.
    #[test]
    fn an_extra_padding_bit_is_caught_at_the_decoding_boundary() {
        let (keys, node) = committee_in(12);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1, 2]);
        let sl = record(list.clone(), 0, sigs);
        assert!(node.verify_quorum(&sl));

        // Set a bit above member 4 directly in the encoding: `StatusList::new`
        // would never produce it, so a forgery has to come off the wire.
        let mut bytes = sl.to_bytes();
        let at = bitmap_byte(&bytes, list.len(), 0b0000_0111);
        bytes[at] |= 0b1000_0000;
        assert!(
            StatusList::from_bytes(&bytes).is_err(),
            "4 bits against 3 signatures must not decode"
        );
    }

    /// The padding case that actually reaches [`VerifierNode::verify_quorum`], and
    /// the reason the check there is not redundant with the decoder's.
    ///
    /// Adding a bit changes the population, so the decoder catches it. *Moving*
    /// one does not: clear member 0's bit and set the padding bit 7, and the
    /// record still carries three bits and three signatures. It decodes cleanly
    /// and arrives at the quorum check naming member 7 of a committee of 5.
    ///
    /// So the check is not only about canonicity. It is what makes `members[i]`
    /// infallible: without it this record indexes past the end of the member list
    /// and the verifier **panics** — a remote crash any peer can trigger with 25
    /// bytes, on a record it never had to sign.
    ///
    /// The previous version of this test could not see that. It only ever set an
    /// extra bit, so it always exited through the decoder and never reached the
    /// quorum check with a padding bit at all — the whole check could be deleted
    /// and the entire suite still passed.
    ///
    /// Reaching the panic takes one more step than it looks. The zip runs under
    /// `.all()`, which short-circuits, so the out-of-range index is only touched
    /// if every index *before* it verified. Moving the **last** signer's bit is
    /// what does it: the earlier pairs are genuine and pass, and the iterator then
    /// reaches `members[7]`. That is not a contrived input — a peer holding one
    /// honestly published record can produce it by flipping two bits, with no key
    /// and no signature of its own.
    #[test]
    fn a_moved_padding_bit_reaches_the_quorum_check_and_is_refused_there() {
        let (keys, node) = committee_in(14);
        let list = vec![hash_any(b"vc-1")];
        // Signers 1, 2, 3 — the *highest* one is the bit that will be moved, so
        // the two genuine pairs ahead of it keep `.all()` going.
        let sigs = quorum(&keys, node.get_committee(), &list, 0, &[1, 2, 3]);
        let sl = record(list.clone(), 0, sigs);
        assert!(node.verify_quorum(&sl), "the record starts out honest");

        let mut bytes = sl.to_bytes();
        let at = bitmap_byte(&bytes, list.len(), 0b0000_1110);
        // 0b0000_1110 -> 0b1000_0110: member 3's bit moves to the padding bit 7.
        // Still three bits against three signatures, so the decoder sees nothing
        // wrong; the record now claims members 1, 2 and 7 of a committee of 5.
        bytes[at] = 0b1000_0110;

        let forged = StatusList::from_bytes(&bytes)
            .expect("the population still matches, so the decoder lets this through");
        assert_eq!(forged.signer_count(), 3);
        assert_eq!(forged.signatures().len(), 3);
        assert_eq!(
            forged.signer_indices().collect::<Vec<_>>(),
            vec![1, 2, 7],
            "index 7 is past member {} — this is the value that must never reach \
             the anchor",
            N - 1
        );

        assert!(
            !node.verify_quorum(&forged),
            "a bitmap naming a member the committee does not have must be refused"
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
        let (out_sk, _) = xmss_key_gen(seed(13, 200), GENESIS, GENESIS + 8, false).expect("keygen");

        let message = status_list_root_fe(&list, 0);
        let slot = node.get_committee().slot_for(0).expect("slot");
        let mut rng = rand::rng();
        let outsider = xmss_sign(&mut rng, &out_sk, &message, slot).expect("sign");
        let mut sigs = quorum(&keys, node.get_committee(), &list, 0, &[0, 1]);
        // The outsider takes member 2's seat — the only way in, and it fails
        // because seat 2 is checked against member 2's key.
        sigs.push((2, outsider.clone()));
        assert!(!node.verify_quorum(&record(list.clone(), 0, sigs)));

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
