//! The published revocation record, in its two forms.
//!
//! Both carry the same payload — a list of credential fingerprints and a version
//! — and both are signed by the same `t`-of-`N` committee over the same message.
//! They differ only in how the quorum is *evidenced*:
//!
//! * [`StatusList`] ships the `t` raw XMSS signatures plus a bitmap naming their
//!   signers. Verifying is `t` independent checks and needs no circuit at all.
//! * [`SnarkStatusList`] ships one succinct proof that such a quorum existed.
//!   Verifying is a single constant-time check, at the price of a prover that
//!   needs seconds and gigabytes.
//!
//! Neither is self-describing, and deliberately so: a record names its signers by
//! *index*, never by public key, so it discloses no key material and its size does
//! not grow with `N`. Both forms are meaningless without the anchor — which is the
//! one thing every verifier already has.

use std::fmt;

use backend::*;
use lean_multisig::{SingleMessageAggregateSignature, XmssSignature};
use sha3::{Digest, Sha3_256};
use ssz::{Decode as _, Encode as _};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

#[derive(Clone, Copy)]
pub enum Algorithms {
    WotsXmss,
}

/// SSZ wire schema for the raw form.
///
/// `signatures` holds leanVM's own type directly: since v0.9 `XmssSignature`
/// implements SSZ natively as a fixed 1208-byte object whose field elements are
/// canonical little-endian `u32`s, rejected on decode when out of range. It used
/// to be an opaque byte-list carrying a postcard blob that this module had to
/// re-encode and byte-compare to prove canonical; the schema now says what the
/// bytes are, and the decoder enforces it.
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct RawStatusListWire {
    alg: u8,
    status_list: Vec<[u8; 32]>,
    version: u32,
    signers: Vec<u8>,
    signatures: Vec<XmssSignature>,
}

/// SSZ wire schema for the SNARK form.  `zk_proof` is an opaque byte-list here
/// because leanVM requires verifier setup before its aggregate can be
/// deserialized, so it cannot be a typed field; [`SnarkStatusList::proof`] checks
/// its inner encoding before verification.
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

/// Maps a 32-byte status-list entry into a field message `[F; 8]`.
/// Each byte (0..=255) is already canonical for KoalaBear, so no modular
/// reduction is needed.
pub fn entry_to_field(entry: &[u8; 32]) -> [KoalaBear; 8] {
    let mut lo = [KoalaBear::ZERO; 16];
    let mut hi = [KoalaBear::ZERO; 16];
    for i in 0..16 {
        lo[i] = KoalaBear::from_u32(u32::from(entry[i]));
        hi[i] = KoalaBear::from_u32(u32::from(entry[16 + i]));
    }
    poseidon16_compress_pair(&poseidon16_compress(lo), &poseidon16_compress(hi))
}

/// Poseidon2 "hash-tree root" of the status list *and its version*: a fold over
/// the entries, closed by one more compression that mixes in the version.
///
/// This is the digest the whole protocol is built on. What the committee actually
/// signs is [`status_list_message`], its canonical 32-byte packing — leanVM's XMSS
/// takes raw bytes since v0.9 and does the field embedding itself.
///
/// Folding the version in (Option B) is what makes the cleartext `version` field
/// trustworthy: a proof attests to `(list, version)` jointly, so the version
/// cannot be altered after the fact without breaking verification. The version is
/// split into 16-bit limbs so each stays below the KoalaBear modulus — a bare
/// `u32` can exceed it and alias two distinct versions to the same field value.
pub fn status_list_root_fe(list: &[[u8; 32]], version: u32) -> [KoalaBear; 8] {
    let mut acc = [KoalaBear::ZERO; 8];
    for e in list {
        acc = poseidon16_compress_pair(&acc, &entry_to_field(e));
    }
    let mut ver = [KoalaBear::ZERO; 8];
    ver[0] = KoalaBear::from_u32(version & 0xFFFF);
    ver[1] = KoalaBear::from_u32(version >> 16);
    poseidon16_compress_pair(&acc, &ver)
}

/// The 32-byte message the committee signs, and the one the proof is bound to.
///
/// leanVM's XMSS API takes a raw `[u8; 32]` and hashes it into the eight field
/// elements the WOTS encoding consumes, so the Poseidon2 fold above is closed by
/// a packing step instead of being handed to the signer as field elements. Each
/// element goes out as its canonical `u32`, little-endian — exactly the encoding
/// leanVM uses for its own SSZ objects.
///
/// The packing is injective, which is the only property the binding argument
/// needs: a KoalaBear element has exactly one canonical representative below the
/// modulus, so two distinct roots cannot pack to one message. Everything check 2
/// of [`crate::snark_verifier_node::PQSNARKVerifierModule::verify`] claims about
/// `(list, version)` therefore carries over unchanged from the fold.
pub fn status_list_message(list: &[[u8; 32]], version: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, fe) in out
        .chunks_exact_mut(4)
        .zip(status_list_root_fe(list, version))
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

    /// Deserializes the leanVM aggregate stored in `zk_proof`.
    ///
    /// Requires the aggregation bytecode to be initialized: `setup_prover()`
    /// or `setup_verifier()` MUST be called first.
    ///
    /// The aggregate keeps leanVM's own encoding — it is the one object here that
    /// cannot be an SSZ field, since decoding it needs the process-global bytecode.
    /// It is canonicalized instead: `from_bytes` already refuses trailing bytes,
    /// and re-encoding must reproduce the stored blob byte for byte, which is what
    /// rules out the padded-varint spellings the format would otherwise admit. A
    /// record therefore has exactly one wire form, proof included.
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

    /// Inverse of [`SnarkStatusList::to_bytes`].
    ///
    /// SSZ rejects invalid offsets, non-minimal container layouts and trailing
    /// bytes. The aggregate itself is checked by [`SnarkStatusList::proof`],
    /// since leanVM requires verifier setup before it can be deserialized.
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

/// The raw form: the `t` XMSS signatures themselves, plus a bitmap saying who
/// produced them.
///
/// A signer is named by its **index into the committee's member list**, which the
/// anchor already fixes and authenticates. Against a list of identifiers — public
/// keys, DIDs, names — that buys:
///
/// * **Structural distinctness.** A bit is set or it is not, so one member cannot
///   appear twice. With a list you must remember to reject duplicates, and
///   forgetting turns a `t`-of-`N` threshold into "one member signs `t` times".
/// * **A canonical encoding.** A signer set has exactly one bitmap, where a list
///   of `t` identifiers has `t!` orderings, all valid and all distinct on the
///   wire — which breaks deduplication once records are content-addressed.
/// * **No key material on the wire.** 25 bytes name any subset of 200 members.
///
/// It does not hide the participation pattern: anyone holding the anchor learns
/// who signed. That is unavoidable — a verifier cannot check a signature without
/// knowing whose key to check it against.
// Deliberately NOT `#[derive(Serialize, Deserialize)]`. The published encoding is
// SSZ, via `to_bytes`/`from_bytes` and the `RawStatusListWire` schema. A derived
// `Deserialize` is generated inside this module, so it builds the struct field by
// field regardless of their privacy — a second construction path that skips both
// `new` (sorting, duplicate and bound checks) and `from_bytes` (bitmap population
// against signature count). That would make the guarantee `new` documents below
// false for any caller who reached for serde instead.
pub struct StatusList {
    pub alg: Algorithms,
    status_list: Vec<[u8; 32]>,
    version: u32,
    /// One bit per committee member, LSB-first within each byte: member `i` is
    /// bit `i % 8` of byte `i / 8`. Its length is `ceil(N / 8)`, which only the
    /// anchor knows — see
    /// [`crate::verifier_node::VerifierNode::verify_status_list`], which also
    /// rejects the padding bits past `N` being set, since two encodings of one
    /// signer set would otherwise both be valid.
    signers: Vec<u8>,
    /// One signature per set bit, in ascending index order.
    signatures: Vec<XmssSignature>,
}

impl StatusList {
    /// Assembles a record from `(member index, signature)` pairs.
    ///
    /// The pairs are sorted here and duplicates refused, so a `StatusList` that
    /// exists at all is already in canonical form: callers cannot produce the
    /// out-of-order or repeated-signer variants that a verifier would then have to
    /// defend against.
    ///
    /// `n_members` sizes the bitmap and must be the committee this record targets.
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

        let mut signers = vec![0u8; n_members.div_ceil(8)];
        for (i, _) in &signatures {
            signers[i / 8] |= 1 << (i % 8);
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

    /// The raw signer bitmap. Interpreting it requires the anchor.
    pub fn signers_bitmap(&self) -> &[u8] {
        &self.signers
    }

    /// How many members signed. Cheap: one popcount per byte.
    pub fn signer_count(&self) -> usize {
        self.signers.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// The signing members' indices, ascending — the same order as
    /// [`StatusList::signatures`], so the two zip.
    pub fn signer_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.signers.iter().enumerate().flat_map(|(byte, bits)| {
            let bits = *bits;
            (0..8).filter_map(move |b| ((bits >> b) & 1 == 1).then_some(byte * 8 + b))
        })
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
    /// match the number of signatures. The signatures are decoded by leanVM's own
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
        // The bitmap's width is the only hint the record carries about N, and it
        // is a rounded-up one: a committee of 200 and one of 197 look identical.
        writeln!(f, "<= {} members [", self.signers.len() * 8)?;
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

    /// The packing is the new seam between this crate's Poseidon2 fold and
    /// leanVM's byte-oriented XMSS API, and every binding argument in the protocol
    /// rests on it being injective. It cannot be tested exhaustively, so what is
    /// pinned here is the property that makes it injective: each of the eight
    /// 4-byte groups is a field element's *canonical* representative, and the map
    /// from the eight elements to the 32 bytes is a bijection onto that set.
    #[test]
    fn the_message_is_the_canonical_packing_of_the_root() {
        let list = entries();
        let root = status_list_root_fe(&list, 3);
        let message = status_list_message(&list, 3);

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
            status_list_message(&list, 3),
            "the message must be a function of (list, version) alone"
        );
    }

    /// Check 2 of both verification paths is "the proof is bound to THIS list and
    /// THIS version". That is only worth anything if the message actually moves
    /// when either does — the packing must not collapse the distinction the fold
    /// makes.
    #[test]
    fn the_message_moves_with_both_the_list_and_the_version() {
        let list = entries();
        let base = status_list_message(&list, 0);

        assert_ne!(base, status_list_message(&list, 1), "version not bound");
        assert_ne!(
            base,
            status_list_message(&[list[0]], 0),
            "a removed entry left the message unchanged"
        );

        let mut appended = list.clone();
        appended.push(hash_any(b"FAKE-REVOCATION"));
        assert_ne!(
            base,
            status_list_message(&appended, 0),
            "an appended entry left the message unchanged"
        );

        // The version is folded in as 16-bit limbs, so the high half has to reach
        // the message too: a `u32 & 0xFFFF` truncation would alias these two.
        assert_ne!(
            status_list_message(&list, 1),
            status_list_message(&list, 1 + (1 << 16)),
            "versions differing only above bit 16 must not alias"
        );
    }

    /// A documented gap, pinned so it cannot change silently: the fold is
    /// sequential, so one logical revocation set has `n!` distinct roots. Sorting
    /// inside the fold would fix it and would break the wire format, which is why
    /// it has not been done — see AGENTS.md, "Known gaps in the model".
    #[test]
    fn the_fold_is_order_sensitive() {
        let list = entries();
        let reversed = vec![list[1], list[0]];
        assert_ne!(
            status_list_message(&list, 0),
            status_list_message(&reversed, 0)
        );
    }
}
