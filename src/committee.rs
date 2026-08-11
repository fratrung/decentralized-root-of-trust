use backend::KoalaBear;
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, aggregate_single_message_signatures,
    verify_single_message_aggregate, xmss_sign, xmss_verify,
};
use serde::{Deserialize, Serialize};

use crate::status_list::{SnarkStatusList, StatusList, status_list_root_fe};

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
    /// [`verify_quorum`]), and `t > N` is an anchor no quorum can ever satisfy.
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

/// Runs the prover: takes the signatures already produced by the issuers plus
/// the parameters, aggregates them into ONE SNARK proof and returns the
/// (postcard) bytes to store in `SnarkStatusList.zk_proof`. `message` is the
/// Poseidon2 root of the status list (what the issuers signed).
pub fn make_proof(
    raws: Vec<(XmssPublicKey, XmssSignature)>,
    message: [KoalaBear; 8],
    slot: u32,
    log_inv_rate: usize,
) -> Vec<u8> {
    let aggregate = aggregate_single_message_signatures(&[], raws, message, slot, log_inv_rate)
        .expect("aggregation failed");
    postcard::to_allocvec(&aggregate).expect("proof serialization failed")
}

/// Has the `signers` (indices into `keypairs`) sign `message` at `slot`, then
/// aggregates their signatures into one proof.
///
/// # Panics
///
/// If `signers` contains a repeated index. XMSS is stateful and one member
/// appearing twice means one secret key signs at one slot twice — and that is not
/// the harmless case it looks like, even though both signatures cover the *same*
/// message: `xmss_sign` draws fresh randomness per call (leanVM's
/// `find_randomness_for_wots_encoding` rejection-samples until the WOTS encoding
/// is valid), so the two signatures reveal *different* hash-chain positions. That
/// is exactly the disclosure a stateful scheme exists to prevent.
///
/// It has to be checked here, before signing, because nothing downstream can:
/// leanVM's `aggregate_single_message_signatures` sorts and dedups its input, so
/// the finished aggregate looks perfectly ordinary and verifies. The key is
/// already damaged by then — the second signature was produced before the
/// aggregator ever saw it.
///
/// A panic rather than a `Result` because no legitimate caller can hit it: the
/// quorum is chosen by the protocol, and a repeated index is a bug in that
/// choice, not a runtime condition to recover from.
pub fn sign_and_prove<R: rand::CryptoRng>(
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    message: [KoalaBear; 8],
    slot: u32,
    log_inv_rate: usize,
    rng: &mut R,
) -> Vec<u8> {
    let mut seen = signers.to_vec();
    seen.sort_unstable();
    let duplicated = seen.windows(2).find(|w| w[0] == w[1]).map(|w| w[0]);
    assert!(
        duplicated.is_none(),
        "member {} appears twice in the quorum: it would sign slot {slot} twice \
         and leak its key",
        duplicated.unwrap()
    );

    let raws: Vec<(XmssPublicKey, XmssSignature)> = signers
        .iter()
        .map(|&i| {
            let (sk, pk) = &keypairs[i];
            (
                pk.clone(),
                xmss_sign(rng, sk, &message, slot).expect("signing failed"),
            )
        })
        .collect();
    make_proof(raws, message, slot, log_inv_rate)
}

/// Verifies the committee proof carried by the status list.
/// The fixed trust anchor is the committee (`members`, threshold `t`): anyone
/// who knows it can verify, without knowing in advance *who* signed the update.
///
/// All five checks are load-bearing; dropping any one of them is exploitable.
pub fn verify_proof(committee: &Committee, status_list: &SnarkStatusList) -> bool {
    let agg = match status_list.proof() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // 1) every signer must belong to the committee
    if !agg
        .info
        .pubkeys
        .iter()
        .all(|pk| committee.members.contains(pk))
    {
        return false;
    }

    // 2) the proof must be bound to THIS list AND THIS version. Folding the
    //    version into the signed message (Option B) is what makes the cleartext
    //    `version` field trustworthy: once this check passes, status_list.version()
    //    is authentic and can safely drive the freshness / anti-rollback decisions
    //    the DHT layer makes in `select_freshest`.
    if agg.info.message != status_list_root_fe(status_list.list(), status_list.version()) {
        return false;
    }

    // 3) the aggregate must sit at the slot the protocol assigns to this version.
    //    The slot is already authenticated inside every signature (it feeds the
    //    leaf hash, the WOTS tweaks and the Merkle path directions), so this does
    //    not add integrity — it pins the *policy*: one slot per round, the same
    //    one for everybody, derived rather than chosen. Without it a quorum could
    //    keep re-signing a version at slots of its own choosing.
    if committee.slot_for(status_list.version()) != Some(agg.info.slot) {
        return false;
    }

    // 4) quorum: at least `t` distinct signers. Distinctness comes for free:
    //    leanVM requires `pubkeys` to be strictly sorted with no duplicates.
    if agg.info.pubkeys.len() < committee.t {
        return false;
    }

    // 5) the SNARK aggregate itself must verify
    if verify_single_message_aggregate(&agg).is_err() {
        return false;
    }
    true
}

/// Verifies the raw quorum carried by a [`StatusList`]: the `t` XMSS signatures
/// themselves, plus the bitmap naming who produced them.
///
/// The counterpart of [`verify_proof`], and the honest comparison between the two
/// paths. This one needs no circuit, no `setup_verifier()` and no gigabyte of
/// resident state — it is `t` independent Poseidon2 verifications, and its cost
/// grows linearly in `t` where the SNARK's is constant. A verifier too small to
/// hold the aggregation bytecode can still run this.
///
/// All five checks are load-bearing.
pub fn verify_quorum(committee: &Committee, status_list: &StatusList) -> bool {
    let n = committee.members.len();
    let bitmap = status_list.signers_bitmap();

    // 0) a degenerate anchor. Both constructors reject `t = 0`, so this is
    //    unreachable through them — but this is the predicate whose `true`
    //    authorizes an update, and with `t = 0` every check below passes
    //    vacuously for a record carrying an empty bitmap and no signatures at
    //    all. One branch is cheap insurance against a future construction path.
    if committee.t == 0 {
        return false;
    }

    // 1) the bitmap must be exactly as wide as the committee...
    if bitmap.len() != n.div_ceil(8) {
        return false;
    }
    // ...and every bit past member `n - 1` must be clear. Otherwise one signer set
    // has several valid encodings: records that differ byte for byte while meaning
    // the same thing, which defeats deduplication wherever they are
    // content-addressed. Together these two checks also guarantee that every index
    // `signer_indices` yields is `< n`, which is what makes indexing `members`
    // below infallible.
    if !n.is_multiple_of(8)
        && let Some(last) = bitmap.last()
        && (last >> (n % 8)) != 0
    {
        return false;
    }

    // 2) quorum. Distinctness is structural rather than checked: a member is one
    //    bit and cannot be counted twice. The second half of this condition is
    //    what keeps the bits and the signatures aligned when zipped below.
    let count = status_list.signer_count();
    if count < committee.t || count != status_list.signatures().len() {
        return false;
    }

    // 3) the slot the protocol assigns to this round — derived from the anchor, so
    //    a quorum cannot pick its own. `None` means the version ran past `u32`.
    let Some(slot) = committee.slot_for(status_list.version()) else {
        return false;
    };

    // 4) the message every member must have signed. Binding the version into it
    //    (Option B) is what makes the cleartext `version` trustworthy afterwards,
    //    exactly as in the SNARK path.
    let message = status_list_root_fe(status_list.list(), status_list.version());

    // 5) every signature, against the key its bit names. Committee membership
    //    needs no separate check here — unlike `verify_proof`, which receives
    //    public keys and must look them up. An index *is* a member, so a
    //    non-member is unnameable rather than merely rejected.
    status_list
        .signer_indices()
        .zip(status_list.signatures())
        .all(|(i, sig)| xmss_verify(&committee.members[i], &message, sig, slot).is_ok())
}

/// Freshness selection performed by the DHT layer over the records several peers
/// return. A Kademlia lookup issues alpha RPCs to the k closest nodes and gets
/// back several, possibly stale or hostile, versions of the same object; this is
/// where the newest legitimate one is chosen.
///
/// Candidates are tried **newest-declared-version first**; the first that both
/// decodes and verifies against `committee` wins, and if it fails to verify the
/// next-newest is tried, and so on. This is the caller's rule: take the newest
/// valid record, fall back to older ones on failure.
///
/// The declared version orders the candidates but is trusted only *after*
/// `verify_proof` succeeds — that check is what binds the version to the signed
/// message. So a peer that inflates the plaintext version to look freshest only
/// costs one wasted verification before being skipped; it cannot win.
///
/// Returns `None` if no candidate verifies. This selects the freshest among the
/// records in hand; enforcing monotonicity *across* lookups (never accept a
/// version below one already trusted) is a separate high-water-mark the caller
/// keeps — see [`select_freshest_above`] for the cheaper composition of the two.
pub fn select_freshest(committee: &Committee, candidates: &[Vec<u8>]) -> Option<SnarkStatusList> {
    select_freshest_above(committee, candidates, None)
}

/// [`select_freshest`], but told what the caller already trusts: every candidate
/// whose declared version is not strictly above `floor` is dropped *before* any
/// proof is verified. `None` means no floor, which is exactly what
/// [`select_freshest`] passes.
///
/// This is not an extra security check — it removes work, not attacks. A record
/// at or below the floor would verify, be handed back, and then be refused by
/// [`crate::freshness::HighWaterMark`] anyway; the only difference is whether a
/// SNARK verification was paid for first. That matters because the selection is
/// the one place an unauthenticated peer gets to choose how much work we do: a
/// lookup that returns nothing but stale records currently costs one full
/// verification and buys nothing, and the stale case is the *common* one — a node
/// polling a list that has not changed hits it on every round.
///
/// Filtering on the declared version is sound precisely because the ordering
/// already was. The version is attacker-controlled until check 2 of
/// [`verify_proof`] has run, so a hostile peer can put any number there — but
/// understating it cannot suppress a record that a *different*, honest peer
/// served, since each candidate carries its own version, and understating one's
/// own only forfeits a record that was going to be refused as stale. The floor
/// can therefore only discard records the caller was already committed to
/// rejecting.
pub fn select_freshest_above(
    committee: &Committee,
    candidates: &[Vec<u8>],
    floor: Option<u32>,
) -> Option<SnarkStatusList> {
    let mut decoded: Vec<SnarkStatusList> = candidates
        .iter()
        .filter_map(|bytes| SnarkStatusList::from_bytes(bytes).ok())
        .filter(|sl| floor.is_none_or(|f| sl.version() > f))
        .collect();
    decoded.sort_by_key(|sl| std::cmp::Reverse(sl.version()));
    decoded.into_iter().find(|sl| verify_proof(committee, sl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_list::{Algorithms, StatusList, hash_any};
    use lean_multisig::xmss_key_gen;

    /// Deliberately not a multiple of 8, so the bitmap has padding bits and the
    /// checks that police them are actually exercised.
    const N: usize = 5;
    const T: usize = 3;
    const GENESIS: u32 = 100;

    /// Every test in this module signs round 0, hence slot `GENESIS`. Sharing one
    /// set of seeds across them would therefore have one secret key sign one slot
    /// a dozen times per `cargo test` — the exact thing this codebase treats as
    /// fatal, and which leanVM warns about even for a repeated *message*
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
    /// `tests/snark_path.rs` and `tests/raw_path_round.rs`, `ns` separates the
    /// tests here from each other, and `member` is unbounded, so an outsider key
    /// can take an index no committee will ever reach instead of a magic constant
    /// that has to be checked against every namespace by hand.
    ///
    /// These keys authorize nothing, so nothing is at risk either way. The point
    /// is that an invariant the whole design rests on should not be one the tests
    /// are the first to break.
    const FILE: u8 = 1;

    fn seed(ns: u8, member: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = FILE;
        s[1] = ns;
        s[2] = member;
        s
    }

    fn committee_in(ns: u8) -> (Vec<(XmssSecretKey, XmssPublicKey)>, Committee) {
        let keys: Vec<_> = (0..N)
            .map(|i| xmss_key_gen(seed(ns, i as u8), GENESIS, GENESIS + 8, false).expect("keygen"))
            .collect();
        let members = keys.iter().map(|(_, pk)| pk.clone()).collect();
        (keys, Committee::new(members, T, GENESIS))
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

    /// leanVM sorts and dedups the aggregate's input, so a repeated signer is
    /// invisible in the finished proof — but both signatures were already
    /// produced, and `xmss_sign` randomises each one, so they reveal different
    /// WOTS chain positions. The guard has to fire before any signing happens.
    #[test]
    #[should_panic(expected = "appears twice in the quorum")]
    fn a_repeated_signer_is_refused_before_signing() {
        let (keys, c) = committee_in(1);
        let list = vec![hash_any(b"x")];
        let message = status_list_root_fe(&list, 0);
        let slot = c.slot_for(0).expect("slot");
        let mut rng = rand::rng();
        sign_and_prove(&keys, &[0, 1, 1], message, slot, 2, &mut rng);
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
        let (_, c) = committee_in(2);
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
        let (_, c) = committee_in(3);
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
        let (_, c) = committee_in(4);
        let mut bytes = c.to_bytes();
        bytes.push(0);
        assert!(Committee::from_bytes(&bytes).is_err());
    }

    #[test]
    fn a_legitimate_quorum_verifies() {
        let (keys, c) = committee_in(5);
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 0, quorum(&keys, &c, &list, 0, &[0, 2, 4]));

        assert_eq!(sl.signer_count(), 3);
        assert_eq!(sl.signer_indices().collect::<Vec<_>>(), vec![0, 2, 4]);
        assert!(verify_quorum(&c, &sl));

        // ...and it survives a round trip through the wire encoding.
        let bytes = sl.to_bytes();
        let back = StatusList::from_bytes(&bytes).expect("decodes");
        assert!(verify_quorum(&c, &back));
    }

    /// The signers are named out of order and get sorted into canonical form, so
    /// the same set always produces the same bytes.
    #[test]
    fn signer_order_does_not_change_the_encoding() {
        let (keys, c) = committee_in(6);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, &c, &list, 0, &[0, 2, 4]);
        let mut shuffled = sigs.clone();
        shuffled.reverse();

        let a = record(list.clone(), 0, sigs);
        let b = record(list.clone(), 0, shuffled);
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert!(verify_quorum(&c, &b));
    }

    #[test]
    fn a_member_cannot_stand_in_for_the_quorum_twice() {
        let (keys, c) = committee_in(7);
        let list = vec![hash_any(b"vc-1")];
        let mut sigs = quorum(&keys, &c, &list, 0, &[0]);
        sigs.push(sigs[0].clone());
        sigs.push(sigs[0].clone());

        assert_eq!(sigs.len(), T);
        assert!(StatusList::new(Algorithms::WotsXmss, list, 0, N, sigs).is_err());
    }

    #[test]
    fn below_threshold_is_refused() {
        let (keys, c) = committee_in(8);
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 0, quorum(&keys, &c, &list, 0, &[1, 3]));
        assert!(!verify_quorum(&c, &sl));
    }

    /// A valid quorum re-labelled with another version. The version is folded into
    /// the signed message *and* fixes the slot, so both bindings break at once.
    #[test]
    fn a_relabelled_version_is_refused() {
        let (keys, c) = committee_in(9);
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 1, quorum(&keys, &c, &list, 0, &[0, 1, 2]));
        assert!(!verify_quorum(&c, &sl));
    }

    /// A row nobody authorized, appended to a list carrying a real quorum.
    #[test]
    fn a_tampered_list_is_refused() {
        let (keys, c) = committee_in(10);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, &c, &list, 0, &[0, 1, 2]);
        let mut tampered = list.clone();
        tampered.push(hash_any(b"FAKE-REVOCATION"));
        assert!(!verify_quorum(&c, &record(tampered, 0, sigs)));
    }

    /// Signatures re-attributed to members who never produced them. Nothing about
    /// the record is malformed — the bits simply name the wrong keys.
    #[test]
    fn signatures_cannot_be_re_attributed() {
        let (keys, c) = committee_in(11);
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, &c, &list, 0, &[0, 1, 2]);
        let moved = sigs
            .into_iter()
            .map(|(i, s)| (i + 2, s)) // 0,1,2 -> 2,3,4
            .collect();
        assert!(!verify_quorum(&c, &record(list, 0, moved)));
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
    /// write a test against. Building the value directly is the only way to
    /// exercise it, and this module can, because the fields are private *to the
    /// module*.
    #[test]
    fn a_degenerate_anchor_cannot_authorize_an_unsigned_record() {
        // Deliberately not `Committee::new`: it asserts `t >= 1`, which is the
        // check being backstopped here.
        let degenerate = Committee {
            members: Vec::new(),
            t: 0,
            genesis_slot: GENESIS,
        };
        let empty = StatusList::new(Algorithms::WotsXmss, vec![hash_any(b"vc-1")], 0, 0, vec![])
            .expect("a record with no signers is well-formed, just worthless");
        assert_eq!(empty.signer_count(), 0);
        assert_eq!(empty.signatures().len(), 0);

        assert!(
            !verify_quorum(&degenerate, &empty),
            "a threshold of zero must never authorize anything"
        );

        // And the constructors keep it unreachable in the first place.
        assert!(Committee::from_bytes(&degenerate.to_bytes()).is_err());
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
        let (keys, c) = committee_in(15);
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 0, quorum(&keys, &c, &list, 0, &[1, 2, 3]));
        assert!(verify_quorum(&c, &sl), "the record starts out honest");

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
            !verify_quorum(&c, &forged),
            "a bitmap wider than the committee must be refused"
        );
    }

    /// Padding bits past member `N - 1` must be clear. Setting one *in addition*
    /// to the honest bits is caught at the decoding boundary, because the bitmap's
    /// population no longer matches the signature count.
    #[test]
    fn an_extra_padding_bit_is_caught_at_the_decoding_boundary() {
        let (keys, c) = committee_in(12);
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 0, quorum(&keys, &c, &list, 0, &[0, 1, 2]));
        assert!(verify_quorum(&c, &sl));

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

    /// The padding case that actually reaches [`verify_quorum`], and the reason
    /// the check there is not redundant with the decoder's.
    ///
    /// Adding a bit changes the population, so the decoder catches it. *Moving*
    /// one does not: clear member 0's bit and set the padding bit 7, and the
    /// record still carries three bits and three signatures. It decodes cleanly
    /// and arrives at `verify_quorum` naming member 7 of a committee of 5.
    ///
    /// So the check is not only about canonicity. It is what makes
    /// `committee.members[i]` infallible: without it this record indexes past the
    /// end of the member list and the verifier **panics** — a remote crash any
    /// peer can trigger with 25 bytes, on a record it never had to sign.
    ///
    /// The previous version of this test could not see that. It only ever set an
    /// extra bit, so it always exited through the decoder and never called
    /// `verify_quorum` with a padding bit at all — the whole `verify_quorum` check
    /// could be deleted and the entire suite still passed.
    ///
    /// Reaching the panic takes one more step than it looks. The zip runs under
    /// `.all()`, which short-circuits, so the out-of-range index is only touched
    /// if every index *before* it verified. Moving the **last** signer's bit is
    /// what does it: the earlier pairs are genuine and pass, and the iterator then
    /// reaches `members[7]`. That is not a contrived input — a peer holding one
    /// honestly published record can produce it by flipping two bits, with no key
    /// and no signature of its own.
    #[test]
    fn a_moved_padding_bit_reaches_verify_quorum_and_is_refused_there() {
        let (keys, c) = committee_in(14);
        let list = vec![hash_any(b"vc-1")];
        // Signers 1, 2, 3 — the *highest* one is the bit that will be moved, so
        // the two genuine pairs ahead of it keep `.all()` going.
        let sl = record(list.clone(), 0, quorum(&keys, &c, &list, 0, &[1, 2, 3]));
        assert!(verify_quorum(&c, &sl), "the record starts out honest");

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
            !verify_quorum(&c, &forged),
            "a bitmap naming a member the committee does not have must be refused"
        );
    }

    /// An outsider's signature cannot be carried at all: the record names signers
    /// by index, and every index is a member by construction.
    #[test]
    fn an_outsider_has_no_index_to_occupy() {
        let (keys, c) = committee_in(13);
        let list = vec![hash_any(b"vc-1")];
        // Member index 200: outside any committee, so it cannot collide with a
        // namespace no matter how many tests are added.
        let (out_sk, _) = xmss_key_gen(seed(13, 200), GENESIS, GENESIS + 8, false).expect("keygen");

        let message = status_list_root_fe(&list, 0);
        let slot = c.slot_for(0).expect("slot");
        let mut rng = rand::rng();
        let outsider = xmss_sign(&mut rng, &out_sk, &message, slot).expect("sign");
        let mut sigs = quorum(&keys, &c, &list, 0, &[0, 1]);
        // The outsider takes member 2's seat — the only way in, and it fails
        // because seat 2 is checked against member 2's key.
        sigs.push((2, outsider.clone()));
        assert!(!verify_quorum(&c, &record(list.clone(), 0, sigs)));

        // Claiming a seat the committee does not have is refused at construction,
        // so an outsider cannot be appended alongside a full honest quorum either.
        //
        // Round 1, not 0: members 0 and 1 already signed round 0 above, and round
        // 0 is slot `GENESIS` for both. Reusing it here would have this test do
        // exactly what `a_repeated_signer_is_refused_before_signing` exists to
        // forbid. `StatusList::new` rejects on the index alone, so which round the
        // signatures cover makes no difference to what is being asserted.
        let mut beyond = quorum(&keys, &c, &list, 1, &[0, 1, 2]);
        beyond.push((N, outsider));
        assert!(StatusList::new(Algorithms::WotsXmss, list, 1, N, beyond).is_err());
    }
}
