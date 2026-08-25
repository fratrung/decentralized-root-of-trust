//! Published status-list records.
//!
//! [`StatusList`] carries raw XMSS signatures and a signer bitmap;
//! [`SnarkStatusList`] carries a leanVM aggregate. Both bind the same
//! `(list, version)` to a committee anchor.

use std::fmt;

use backend::*;
use lean_multisig::{SingleMessageAggregateSignature, XmssSignature};
use sha3::{Digest, Sha3_256};
use ssz::{BitList, Decode as _, Encode as _};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

/// Compile-time ceiling required by SSZ `BitList`; the anchor supplies the actual
/// committee size.
pub const MAX_COMMITTEE_SIZE: usize = 2048;
type MaxCommittee = typenum::U2048;
const _: () = assert!(MAX_COMMITTEE_SIZE == <MaxCommittee as typenum::Unsigned>::USIZE);

/// One bit per committee member. `BitList` preserves the exact bit length, so
/// out-of-range signer indices and padding variants are unrepresentable.
type SignerBits = BitList<MaxCommittee>;

#[derive(Clone, Copy)]
pub enum Algorithms {
    WotsXmss,
}

/// SSZ wire schema for the raw form. leanVM's `XmssSignature` is canonical SSZ.
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct RawStatusListWire {
    alg: u8,
    status_list: Vec<[u8; 32]>,
    version: u32,
    signers: SignerBits,
    signatures: Vec<XmssSignature>,
}

/// SSZ wire schema for the SNARK form. The proof remains bytes because decoding it
/// requires leanVM setup; [`SnarkStatusList::proof`] validates its canonical form.
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct SnarkStatusListWire {
    alg: u8,
    status_list: Vec<[u8; 32]>,
    version: u32,
    zk_proof: Vec<u8>,
}

fn algorithm_tag(alg: Algorithms) -> u8 {
    match alg {
        Algorithms::WotsXmss => 0,
    }
}

fn algorithm_from_tag(tag: u8) -> Result<Algorithms, String> {
    match tag {
        0 => Ok(Algorithms::WotsXmss),
        _ => Err(format!("unknown status-list algorithm tag {tag}")),
    }
}

/// SHA3-256 of arbitrary bytes, used to build status-list entries.
pub fn hash_any(data: impl AsRef<[u8]>) -> [u8; 32] {
    let d = Sha3_256::digest(data.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Maps an entry to `[KoalaBear; 8]`; each input byte is already canonical.
pub fn entry_to_field(entry: &[u8; 32]) -> [KoalaBear; 8] {
    let mut lo = [KoalaBear::ZERO; 16];
    let mut hi = [KoalaBear::ZERO; 16];
    for i in 0..16 {
        lo[i] = KoalaBear::from_u32(u32::from(entry[i]));
        hi[i] = KoalaBear::from_u32(u32::from(entry[16 + i]));
    }
    poseidon16_compress_pair(&poseidon16_compress(lo), &poseidon16_compress(hi))
}

/// Generation of the signed-message construction.
///
/// It is **not** the wire schema's version — the SSZ containers are unchanged by
/// it. It is the epoch of what a signature *means*. Bumping it makes every
/// previously signed message stop verifying, which is the intended effect when
/// the construction below changes shape.
const MESSAGE_FORMAT: u32 = 1;

/// The trust domain a signed message belongs to.
///
/// Without this the message was `(list, version)` and nothing else, which made a
/// signature say only "some key signed these entries at this number". Two status
/// lists governed by one committee then had *interchangeable* records: a record
/// published for one verified, in full, as a record of the other — same quorum,
/// same version, same derived slot, all five checks green. One anchor could
/// therefore govern exactly one list, and nothing in the code said so.
///
/// The domain closes that by starting the fold from a committee-specific IV
/// instead of `[0; 8]`. It binds three things:
///
/// - the **anchor**, through a fingerprint of its canonical encoding, so every
///   member key, `t` and the genesis slot are all covered. A different committee
///   is a different domain, and — deliberately — a *rotated* committee is too,
///   which is the same trust-domain notion [`crate::state::freshness::HighWaterMark`]
///   already uses to decide when to reset its mark;
/// - the **algorithm**, so a record cannot be relabelled from one signature
///   scheme to another while keeping evidence produced under the first. Today
///   only one tag decodes, so this is latent; it stops being latent the moment a
///   second one exists, and by then the format would be frozen;
/// - the **construction generation** ([`MESSAGE_FORMAT`]).
///
/// Prefixed, not appended, and that is the part worth keeping: a Merkle–Damgård
/// chain that starts from a shared IV lets every domain share its intermediate
/// states, so one internal collision found against attacker-chosen entries would
/// be reusable across all of them. Starting from a domain-specific IV means two
/// domains have no common prefix to attack.
///
/// It is unforgeable by construction rather than checked: there is no way to
/// compute a message without naming a domain, because [`status_list_message`]
/// takes one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Domain([KoalaBear; 8]);

impl Domain {
    /// Builds the domain from a fingerprint of the anchor's canonical encoding.
    ///
    /// Callers should go through [`crate::protocol::committee::Committee::domain`]
    /// rather than here: the anchor is what owns its own fingerprint, exactly as
    /// it owns `slot_for`, and a second place to compute either is a second place
    /// to drift.
    pub fn new(anchor_fingerprint: &[u8; 32], alg: Algorithms) -> Self {
        let mut tag = [KoalaBear::ZERO; 8];
        tag[0] = KoalaBear::from_u32(MESSAGE_FORMAT);
        tag[1] = KoalaBear::from_u32(u32::from(algorithm_tag(alg)));
        Domain(poseidon16_compress_pair(
            &entry_to_field(anchor_fingerprint),
            &tag,
        ))
    }
}

/// Folds the entries and version into a Poseidon2 root, under `domain`.
///
/// The version is split into 16-bit limbs to avoid field aliasing, binding the
/// cleartext version to the signed list.
pub fn status_list_root_fe(domain: &Domain, list: &[[u8; 32]], version: u32) -> [KoalaBear; 8] {
    let mut acc = domain.0;
    for e in list {
        acc = poseidon16_compress_pair(&acc, &entry_to_field(e));
    }
    let mut ver = [KoalaBear::ZERO; 8];
    ver[0] = KoalaBear::from_u32(version & 0xFFFF);
    ver[1] = KoalaBear::from_u32(version >> 16);
    poseidon16_compress_pair(&acc, &ver)
}

/// Canonically packs the root into the 32-byte message signed by XMSS.
///
/// Each limb is its canonical little-endian `u32`, making the packing injective.
pub fn status_list_message(domain: &Domain, list: &[[u8; 32]], version: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, fe) in out
        .chunks_exact_mut(4)
        .zip(status_list_root_fe(domain, list, version))
    {
        chunk.copy_from_slice(&fe.as_canonical_u32().to_le_bytes());
    }
    out
}

/// The SNARK-attested form: one succinct proof in place of the `t` signatures.
pub struct SnarkStatusList {
    pub alg: Algorithms,
    status_list: Vec<[u8; 32]>,
    version: u32,
    zk_proof: Vec<u8>,
}

impl SnarkStatusList {
    pub fn new(
        alg: Algorithms,
        status_list: Vec<[u8; 32]>,
        version: u32,
        zk_proof: Vec<u8>,
    ) -> Self {
        SnarkStatusList {
            alg,
            status_list,
            version,
            zk_proof,
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// Raw bytes of the aggregated proof, in leanVM's own encoding.
    pub fn proof_bytes(&self) -> &[u8] {
        &self.zk_proof
    }

    pub fn list(&self) -> &[[u8; 32]] {
        &self.status_list
    }

    pub fn list_cloned(&self) -> Vec<[u8; 32]> {
        self.status_list.clone()
    }

    /// Deserializes and canonicalizes the leanVM aggregate in `zk_proof`.
    ///
    /// `setup_prover()` or `setup_verifier()` must have initialized the bytecode.
    pub fn proof(&self) -> Result<SingleMessageAggregateSignature, String> {
        let value = SingleMessageAggregateSignature::from_bytes(&self.zk_proof)
            .ok_or("proof not deserializable")?;
        if value.to_bytes() != self.zk_proof {
            return Err("proof is not canonically encoded".to_string());
        }
        Ok(value)
    }

    /// Canonical SSZ wire encoding of the published object.
    pub fn to_bytes(&self) -> Vec<u8> {
        SnarkStatusListWire {
            alg: algorithm_tag(self.alg),
            status_list: self.status_list.clone(),
            version: self.version,
            zk_proof: self.zk_proof.clone(),
        }
        .as_ssz_bytes()
    }

    /// Decodes the canonical SSZ container. Call [`Self::proof`] to validate the
    /// aggregate after leanVM setup.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value = SnarkStatusListWire::from_ssz_bytes(bytes)
            .map_err(|e| format!("SNARK status list is not valid SSZ: {e:?}"))?;
        Ok(Self {
            alg: algorithm_from_tag(value.alg)?,
            status_list: value.status_list,
            version: value.version,
            zk_proof: value.zk_proof,
        })
    }
}

/// Raw XMSS evidence: signatures paired with a bitmap of anchor indices.
///
/// Do not derive deserialization: it could bypass the invariants enforced by
/// [`Self::new`] and [`Self::from_bytes`].
pub struct StatusList {
    pub alg: Algorithms,
    status_list: Vec<[u8; 32]>,
    version: u32,
    /// One bit per member; its length is checked against the anchor.
    signers: SignerBits,
    /// One signature per set bit, in ascending index order.
    signatures: Vec<XmssSignature>,
}

impl StatusList {
    /// Builds a canonical record from `(member index, signature)` pairs.
    ///
    /// Pairs are sorted and duplicate or out-of-range indices are rejected.
    pub fn new(
        alg: Algorithms,
        status_list: Vec<[u8; 32]>,
        version: u32,
        n_members: usize,
        signatures: Vec<(usize, XmssSignature)>,
    ) -> Result<Self, String> {
        let mut signatures = signatures;
        signatures.sort_by_key(|(i, _)| *i);
        if signatures.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err("duplicate signer index".into());
        }
        if let Some((i, _)) = signatures.last()
            && *i >= n_members
        {
            return Err(format!(
                "signer index {i} outside a committee of {n_members}"
            ));
        }

        let mut signers = SignerBits::with_capacity(n_members).map_err(|_| {
            format!("committee of {n_members} exceeds the ceiling of {MAX_COMMITTEE_SIZE}")
        })?;
        for (i, _) in &signatures {
            signers
                .set(*i, true)
                .expect("index bounded by n_members above");
        }
        Ok(StatusList {
            alg,
            status_list,
            version,
            signers,
            signatures: signatures.into_iter().map(|(_, s)| s).collect(),
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn list(&self) -> &[[u8; 32]] {
        &self.status_list
    }

    pub fn list_cloned(&self) -> Vec<[u8; 32]> {
        self.status_list.clone()
    }

    /// How many members the bitmap is sized for: the committee this record
    /// claims to target. Meaningful only against an anchor, which is where it is
    /// checked.
    pub fn signer_slots(&self) -> usize {
        self.signers.len()
    }

    /// How many members signed.
    pub fn signer_count(&self) -> usize {
        self.signers.num_set_bits()
    }

    /// The signing members' indices, ascending, the same order as
    /// [`StatusList::signatures`], so the two zip. Every index is `<
    /// signer_slots()` by construction.
    pub fn signer_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.signers
            .iter()
            .enumerate()
            .filter_map(|(i, set)| set.then_some(i))
    }

    pub fn signatures(&self) -> &[XmssSignature] {
        &self.signatures
    }

    /// Canonical SSZ wire encoding of the published object.
    pub fn to_bytes(&self) -> Vec<u8> {
        RawStatusListWire {
            alg: algorithm_tag(self.alg),
            status_list: self.status_list.clone(),
            version: self.version,
            signers: self.signers.clone(),
            signatures: self.signatures.clone(),
        }
        .as_ssz_bytes()
    }

    /// Inverse of [`StatusList::to_bytes`].
    ///
    /// Decodes the SSZ schema and rejects a bitmap whose population does not
    /// match the number of signatures, the one relation between two fields that
    /// no schema can express. The signatures are decoded by leanVM's own
    /// SSZ implementation, which fixes their length at 1208 bytes and refuses a
    /// field element outside the modulus, so a non-canonical encoding cannot be
    /// smuggled inside an otherwise canonical container.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value = RawStatusListWire::from_ssz_bytes(bytes)
            .map_err(|e| format!("raw status list is not valid SSZ: {e:?}"))?;
        let value = Self {
            alg: algorithm_from_tag(value.alg)?,
            status_list: value.status_list,
            version: value.version,
            signers: value.signers,
            signatures: value.signatures,
        };
        if value.signer_count() != value.signatures.len() {
            return Err(format!(
                "bitmap names {} signers but {} signatures are present",
                value.signer_count(),
                value.signatures.len()
            ));
        }
        Ok(value)
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

impl fmt::Display for Algorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithms::WotsXmss => write!(f, "WOTS-XMSS"),
        }
    }
}

/// The header both records share: algorithm, version, then the entries.
fn write_common(
    f: &mut fmt::Formatter<'_>,
    alg: &Algorithms,
    version: u32,
    entries: &[[u8; 32]],
) -> fmt::Result {
    writeln!(f, "  alg        : {alg}")?;
    writeln!(f, "  version    : {version}")?;
    writeln!(
        f,
        "  status_list: {} entr{}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    )?;
    for (i, entry) in entries.iter().enumerate() {
        write!(f, "      [{i}] 0x")?;
        write_hex(f, entry)?;
        writeln!(f)?;
    }
    Ok(())
}

impl fmt::Display for SnarkStatusList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SnarkStatusList {{")?;
        write_common(f, &self.alg, self.version, &self.status_list)?;
        write!(f, "  proof      : {} bytes 0x", self.zk_proof.len())?;
        write_hex(f, &self.zk_proof)?;
        writeln!(f)?;
        write!(f, "}}")
    }
}

impl fmt::Display for StatusList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "StatusList {{")?;
        write_common(f, &self.alg, self.version, &self.status_list)?;
        write!(f, "  signers    : {} of ", self.signer_count())?;
        // Exact, not a hint: a BitList knows its own length in bits, so a
        // committee of 200 and one of 197 are told apart here.
        writeln!(f, "{} members [", self.signers.len())?;
        write!(f, "      ")?;
        for (n, i) in self.signer_indices().enumerate() {
            if n > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{i}")?;
        }
        writeln!(f, "\n  ]")?;
        writeln!(f, "  signatures : {}", self.signatures.len())?;
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<[u8; 32]> {
        vec![hash_any(b"vc-1"), hash_any(b"vc-2")]
    }

    /// One fixed domain for the tests that are about the fold rather than about
    /// the domain. `domain_separation_is_a_prefix` is the one that varies it.
    fn dom() -> Domain {
        Domain::new(&[0x5A; 32], Algorithms::WotsXmss)
    }

    /// The packing is the new seam between this crate's Poseidon2 fold and
    /// leanVM's byte-oriented XMSS API, and every binding argument in the protocol
    /// rests on it being injective. It cannot be tested exhaustively, so what is
    /// pinned here is the property that makes it injective: each of the eight
    /// 4-byte groups is a field element's *canonical* representative, and the map
    /// from the eight elements to the 32 bytes is a bijection onto that set.
    #[test]
    fn the_message_is_the_canonical_packing_of_the_root() {
        let list = entries();
        let root = status_list_root_fe(&dom(), &list, 3);
        let message = status_list_message(&dom(), &list, 3);

        for (i, (chunk, fe)) in message.chunks_exact(4).zip(root).enumerate() {
            let value = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
            assert_eq!(value, fe.as_canonical_u32(), "limb {i} is not the element");
            assert!(
                value < KoalaBear::ORDER_U32,
                "limb {i} is outside the field, so the packing is not canonical"
            );
        }
        assert_eq!(
            message,
            status_list_message(&dom(), &list, 3),
            "the message must be a function of (list, version) alone"
        );
    }

    /// Check 2 of both verification paths is "the proof is bound to THIS list and
    /// THIS version". That is only worth anything if the message actually moves
    /// when either does: the packing must not collapse the distinction the fold
    /// makes.
    #[test]
    fn the_message_moves_with_both_the_list_and_the_version() {
        let list = entries();
        let base = status_list_message(&dom(), &list, 0);

        assert_ne!(
            base,
            status_list_message(&dom(), &list, 1),
            "version not bound"
        );
        assert_ne!(
            base,
            status_list_message(&dom(), &[list[0]], 0),
            "a removed entry left the message unchanged"
        );

        let mut appended = list.clone();
        appended.push(hash_any(b"FAKE-REVOCATION"));
        assert_ne!(
            base,
            status_list_message(&dom(), &appended, 0),
            "an appended entry left the message unchanged"
        );

        // The version is folded in as 16-bit limbs, so the high half has to reach
        // the message too: a `u32 & 0xFFFF` truncation would alias these two.
        assert_ne!(
            status_list_message(&dom(), &list, 1),
            status_list_message(&dom(), &list, 1 + (1 << 16)),
            "versions differing only above bit 16 must not alias"
        );
    }

    /// The property the domain exists for, and the one a "simplification" back to
    /// a `[0; 8]` IV would silently undo.
    ///
    /// Before the domain, a signed message was `(list, version)` and nothing more.
    /// Two status lists under one committee therefore had interchangeable records:
    /// the evidence published for one authorized the other, because there was
    /// nothing in the signed bytes to tell them apart. What pins the fix is not
    /// that the messages differ by luck but that **every** input to the domain
    /// moves them: a different anchor, a different algorithm, or a different
    /// construction generation must each produce a different message for the same
    /// `(list, version)`.
    #[test]
    fn one_list_and_version_signs_differently_under_different_domains() {
        let list = entries();

        let a = Domain::new(&[0xAA; 32], Algorithms::WotsXmss);
        let b = Domain::new(&[0xBB; 32], Algorithms::WotsXmss);
        assert_ne!(
            status_list_message(&a, &list, 7),
            status_list_message(&b, &list, 7),
            "two committees must not sign the same bytes for one (list, version)"
        );

        // A single-bit change in the anchor fingerprint is still a different
        // committee, so it must still be a different domain.
        let mut nearly = [0xAA; 32];
        nearly[31] ^= 1;
        assert_ne!(
            status_list_message(&a, &list, 7),
            status_list_message(&Domain::new(&nearly, Algorithms::WotsXmss), &list, 7),
            "the domain must depend on the whole fingerprint, not a prefix of it"
        );

        // And the domain really is the *start* of the chain, not something folded
        // in at the end: the fold over an empty list already differs.
        assert_ne!(
            status_list_message(&a, &[], 0),
            status_list_message(&b, &[], 0),
            "the domain must seed the fold, not close it"
        );
    }

    /// A documented gap, pinned so it cannot change silently: the fold is
    /// sequential, so one logical revocation set has `n!` distinct roots. Sorting
    /// inside the fold would fix it and would break the wire format, which is why
    /// it has not been done; see AGENTS.md, "Known gaps in the model".
    #[test]
    fn the_fold_is_order_sensitive() {
        let list = entries();
        let reversed = vec![list[1], list[0]];
        assert_ne!(
            status_list_message(&dom(), &list, 0),
            status_list_message(&dom(), &reversed, 0)
        );
    }
}
