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
    pub fn new(members: Vec<XmssPublicKey>, t: usize, genesis_slot: u32) -> Self {
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

    /// Inverse of [`Committee::to_bytes`]. Rejects trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (value, rest) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|e| format!("committee not deserializable: {e}"))?;
        if !rest.is_empty() {
            return Err(format!("{} trailing byte(s) after committee", rest.len()));
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
/// XMSS is stateful: the caller must guarantee that no `(key, slot)` pair is
/// ever used twice.
pub fn sign_and_prove<R: rand::CryptoRng>(
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    message: [KoalaBear; 8],
    slot: u32,
    log_inv_rate: usize,
    rng: &mut R,
) -> Vec<u8> {
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
/// keeps.
pub fn select_freshest(committee: &Committee, candidates: &[Vec<u8>]) -> Option<SnarkStatusList> {
    let mut decoded: Vec<SnarkStatusList> = candidates
        .iter()
        .filter_map(|bytes| SnarkStatusList::from_bytes(bytes).ok())
        .collect();
    decoded.sort_by(|a, b| b.version().cmp(&a.version()));
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

    fn committee() -> (Vec<(XmssSecretKey, XmssPublicKey)>, Committee) {
        let keys: Vec<_> = (0..N)
            .map(|i| xmss_key_gen([i as u8 + 1; 32], GENESIS, GENESIS + 8, false).expect("keygen"))
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

    #[test]
    fn a_legitimate_quorum_verifies() {
        let (keys, c) = committee();
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
        let (keys, c) = committee();
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
        let (keys, c) = committee();
        let list = vec![hash_any(b"vc-1")];
        let mut sigs = quorum(&keys, &c, &list, 0, &[0]);
        sigs.push(sigs[0].clone());
        sigs.push(sigs[0].clone());

        assert_eq!(sigs.len(), T);
        assert!(StatusList::new(Algorithms::WotsXmss, list, 0, N, sigs).is_err());
    }

    #[test]
    fn below_threshold_is_refused() {
        let (keys, c) = committee();
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 0, quorum(&keys, &c, &list, 0, &[1, 3]));
        assert!(!verify_quorum(&c, &sl));
    }

    /// A valid quorum re-labelled with another version. The version is folded into
    /// the signed message *and* fixes the slot, so both bindings break at once.
    #[test]
    fn a_relabelled_version_is_refused() {
        let (keys, c) = committee();
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 1, quorum(&keys, &c, &list, 0, &[0, 1, 2]));
        assert!(!verify_quorum(&c, &sl));
    }

    /// A row nobody authorized, appended to a list carrying a real quorum.
    #[test]
    fn a_tampered_list_is_refused() {
        let (keys, c) = committee();
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
        let (keys, c) = committee();
        let list = vec![hash_any(b"vc-1")];
        let sigs = quorum(&keys, &c, &list, 0, &[0, 1, 2]);
        let moved = sigs
            .into_iter()
            .map(|(i, s)| (i + 2, s)) // 0,1,2 -> 2,3,4
            .collect();
        assert!(!verify_quorum(&c, &record(list, 0, moved)));
    }

    /// Padding bits past member N - 1 must be clear, or one signer set has several
    /// valid encodings.
    #[test]
    fn padding_bits_past_the_committee_are_refused() {
        let (keys, c) = committee();
        let list = vec![hash_any(b"vc-1")];
        let sl = record(list.clone(), 0, quorum(&keys, &c, &list, 0, &[0, 1, 2]));
        assert!(verify_quorum(&c, &sl));

        // Flip a bit above member 4 directly in the encoding: `StatusList::new`
        // would never produce it, so a forgery has to come off the wire.
        let mut bytes = sl.to_bytes();
        let byte = bytes
            .iter()
            .rposition(|b| *b == 0b0000_0111)
            .expect("bitmap byte");
        bytes[byte] |= 0b1000_0000;
        match StatusList::from_bytes(&bytes) {
            // Either boundary may catch it: the population no longer matches the
            // signature count, or the padding check does. Both are refusals.
            Err(_) => {}
            Ok(forged) => assert!(!verify_quorum(&c, &forged)),
        }
    }

    /// An outsider's signature cannot be carried at all: the record names signers
    /// by index, and every index is a member by construction.
    #[test]
    fn an_outsider_has_no_index_to_occupy() {
        let (keys, c) = committee();
        let list = vec![hash_any(b"vc-1")];
        let (out_sk, _) = xmss_key_gen([99u8; 32], GENESIS, GENESIS + 8, false).expect("keygen");

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
        let mut beyond = quorum(&keys, &c, &list, 0, &[0, 1, 2]);
        beyond.push((N, outsider));
        assert!(StatusList::new(Algorithms::WotsXmss, list, 0, N, beyond).is_err());
    }
}
