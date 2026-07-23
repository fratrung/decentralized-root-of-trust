use std::fmt;

use backend::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Serialize, Deserialize)]
pub enum Algorithms {
    WotsXmss,
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

/// Poseidon2 "hash-tree root" of the status list: a fold over its entries.
/// The output is already `[F; 8]`, i.e. the native message format of leanVM's
/// XMSS. This is the message the committee signs and the proof is bound to.
pub fn status_list_root_fe(list: &[[u8; 32]]) -> [KoalaBear; 8] {
    let mut acc = [KoalaBear::ZERO; 8];
    for e in list {
        acc = poseidon16_compress_pair(&acc, &entry_to_field(e));
    }
    acc
}

#[derive(Serialize, Deserialize)]
pub struct StatusList {
    pub alg: Algorithms,
    status_list: Vec<[u8; 32]>,
    version: u32,
    zk_proof: Vec<u8>,
}

impl StatusList {
    pub fn new(
        alg: Algorithms,
        status_list: Vec<[u8; 32]>,
        version: u32,
        zk_proof: Vec<u8>,
    ) -> Self {
        StatusList {
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

    /// Deserializes the leanVM aggregate stored in `zk_proof`.
    ///
    /// Requires the aggregation bytecode to be initialized: `setup_prover()`
    /// or `setup_verifier()` MUST be called first.
    pub fn proof(&self) -> Result<lean_multisig::SingleMessageAggregateSignature, String> {
        postcard::from_bytes(&self.zk_proof).map_err(|e| format!("proof not deserializable: {e}"))
    }

    /// Wire encoding of the published object — this is what would go into the DHT.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("status list serialization failed")
    }

    /// Inverse of [`StatusList::to_bytes`].
    ///
    /// Rejects trailing bytes, so the encoding is canonical: a published object
    /// has exactly one valid byte representation. That matters as soon as the
    /// structure is content-addressed, as it is in a DHT.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (value, rest) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|e| format!("status list not deserializable: {e}"))?;
        if !rest.is_empty() {
            return Err(format!("{} trailing byte(s) after status list", rest.len()));
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

impl fmt::Display for StatusList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "StatusList {{")?;
        writeln!(f, "  alg        : {}", self.alg)?;
        writeln!(f, "  version    : {}", self.version)?;
        writeln!(
            f,
            "  status_list: {} entr{}",
            self.status_list.len(),
            if self.status_list.len() == 1 {
                "y"
            } else {
                "ies"
            }
        )?;
        for (i, entry) in self.status_list.iter().enumerate() {
            write!(f, "      [{i}] 0x")?;
            write_hex(f, entry)?;
            writeln!(f)?;
        }
        write!(f, "  proof      : {} bytes 0x", self.zk_proof.len())?;
        write_hex(f, &self.zk_proof)?;
        writeln!(f)?;
        write!(f, "}}")
    }
}
