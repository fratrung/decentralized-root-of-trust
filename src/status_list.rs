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
use lean_multisig::XmssSignature;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use ssz::{Decode as _, Encode as _};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum Algorithms {
    WotsXmss,
}

/// SSZ wire schema for the raw form.  LeanVM's signature type is external to
/// this crate, so its canonical postcard representation is carried as an opaque
/// SSZ byte-list and checked while decoding.
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct RawStatusListWire {
    alg: u8,
    status_list: Vec<[u8; 32]>,
    version: u32,
    signers: Vec<u8>,
    signatures: Vec<Vec<u8>>,
}

/// SSZ wire schema for the SNARK form.  `zk_proof` remains an opaque byte-list
/// here because leanVM requires verifier setup before its aggregate can be
/// deserialized; [`SnarkStatusList::proof`] checks its inner encoding before
/// verification.
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

fn canonical_signature_bytes(signature: &XmssSignature) -> Vec<u8> {
    postcard::to_allocvec(signature).expect("XMSS signature serialization failed")
}

fn decode_canonical_signature(bytes: &[u8]) -> Result<XmssSignature, String> {
    let (signature, rest) = postcard::take_from_bytes::<XmssSignature>(bytes)
        .map_err(|e| format!("signature not deserializable: {e}"))?;
    if !rest.is_empty() {
        return Err(format!("{} trailing byte(s) after signature", rest.len()));
    }
    if canonical_signature_bytes(&signature) != bytes {
        return Err("signature is not canonically encoded".into());
    }
    Ok(signature)
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
/// the entries, closed by one more compression that mixes in the version. The
/// output is already `[F; 8]`, i.e. the native message format of leanVM's XMSS.
/// This is the message the committee signs and the proof is bound to.
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

/// The SNARK-attested form: one succinct proof in place of the `t` signatures.
#[derive(Serialize, Deserialize)]
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

    /// Raw bytes of the aggregated proof (postcard-encoded leanVM aggregate).
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
    /// The aggregate remains postcard-encoded because that is leanVM's native
    /// representation. It is canonicalized here: after decoding, its unique
    /// postcard encoding must byte-match the stored blob. This closes the only
    /// non-SSZ field before the verifier trusts the record.
    pub fn proof(&self) -> Result<lean_multisig::SingleMessageAggregateSignature, String> {
        let (value, rest) = postcard::take_from_bytes::<
            lean_multisig::SingleMessageAggregateSignature,
        >(&self.zk_proof)
        .map_err(|e| format!("proof not deserializable: {e}"))?;
        if !rest.is_empty() {
            return Err(format!("{} trailing byte(s) after proof", rest.len()));
        }
        if postcard::to_allocvec(&value).expect("proof serialization failed") != self.zk_proof {
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
#[derive(Serialize, Deserialize)]
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
            signatures: self
                .signatures
                .iter()
                .map(canonical_signature_bytes)
                .collect(),
        }
        .as_ssz_bytes()
    }

    /// Inverse of [`StatusList::to_bytes`].
    ///
    /// Decodes the SSZ schema and rejects a bitmap whose population does not
    /// match the number of signatures. Each embedded leanVM signature must also
    /// be its unique postcard representation, so no non-canonical encoding is
    /// smuggled inside an otherwise canonical SSZ container.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value = RawStatusListWire::from_ssz_bytes(bytes)
            .map_err(|e| format!("raw status list is not valid SSZ: {e:?}"))?;
        let signatures: Vec<XmssSignature> = value
            .signatures
            .iter()
            .map(|bytes| decode_canonical_signature(bytes))
            .collect::<Result<_, _>>()?;
        let value = Self {
            alg: algorithm_from_tag(value.alg)?,
            status_list: value.status_list,
            version: value.version,
            signers: value.signers,
            signatures,
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
