//! Canonical SSZ record for the raw ML-DSA-65 quorum form.
//!
//! Structural validity is not authorization. The committee and quorum checks
//! are performed by RawVerifier after decoding.

use ssz::{BitList, Decode as _, Encode as _};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

use crate::Signature;

/// The same bitmap ceiling as the XMSS record. Actual `N` comes from an anchor.
pub const MAX_COMMITTEE_SIZE: usize = 2048;
/// Limit untrusted record decoding and avoid records larger than this at creation.
pub const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
/// ML-DSA-65's fixed signature encoding length, per FIPS 204.
pub const SIGNATURE_BYTES: usize = 3309;

/// Distinct from the existing XMSS wire tag 1. A future wire break needs a new tag.
const ALGORITHM_TAG: u8 = 2;
/// Binds the signed statement to this application and construction generation.
const STATEMENT_DOMAIN: &[u8] = b"decentralized-root-of-trust/ml-dsa-65/status-list/v1\0";
/// Derived from the canonical committee anchor by Committee.
pub const ANCHOR_ID_BYTES: usize = 48;

type SignerBits = BitList<typenum::U2048>;

/// Published SSZ container. Each signature is a fixed-size byte vector, so a
/// list of them has no per-signature offsets or length prefixes.
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct StatusListWire {
    alg: u8,
    status_list: Vec<[u8; 32]>,
    version: u32,
    signers: SignerBits,
    signatures: Vec<[u8; SIGNATURE_BYTES]>,
}

/// The statement signed directly with FIPS 204 ML-DSA.Sign (not HashML-DSA).
/// The bitmap and signatures cannot be part of it: they are assembled only
/// after independent members have signed the common statement.
#[derive(SszEncode)]
#[ssz(struct_behaviour = "container")]
struct StatementWire {
    alg: u8,
    anchor_id: [u8; ANCHOR_ID_BYTES],
    version: u32,
    status_list: Vec<[u8; 32]>,
}

/// Canonical, domain-separated bytes all members sign for one update.
///
/// Only the trusted [`crate::Committee`] exposes this construction publicly,
/// ensuring callers cannot substitute an arbitrary anchor identifier. It
/// performs no application-level pre-hash: pass the complete result to
/// `MlDsa65Signer::sign`.
pub(crate) fn statement_bytes(
    anchor_id: &[u8; ANCHOR_ID_BYTES],
    list: &[[u8; 32]],
    version: u32,
) -> Vec<u8> {
    let statement = StatementWire {
        alg: ALGORITHM_TAG,
        anchor_id: *anchor_id,
        version,
        status_list: list.to_vec(),
    }
    .as_ssz_bytes();
    let mut bytes = Vec::with_capacity(STATEMENT_DOMAIN.len() + statement.len());
    bytes.extend_from_slice(STATEMENT_DOMAIN);
    bytes.extend_from_slice(&statement);
    bytes
}

fn record_len(n_members: usize, list_len: usize, signature_count: usize) -> Option<usize> {
    // SSZ fixed container: u8 tag, u32 version, three u32 variable offsets.
    17usize
        .checked_add(list_len.checked_mul(32)?)?
        .checked_add((n_members + 8) / 8)? // BitList's length sentinel.
        .checked_add(signature_count.checked_mul(SIGNATURE_BYTES)?)
}

fn check_member_count(n_members: usize) -> Result<(), String> {
    if (1..=MAX_COMMITTEE_SIZE).contains(&n_members) {
        Ok(())
    } else {
        Err(format!(
            "committee size {n_members} outside 1..={MAX_COMMITTEE_SIZE}"
        ))
    }
}

/// Raw ML-DSA-65 signatures plus the committee-index bitmap naming their owners.
///
/// No public fields: constructors and decoding enforce one signature per set
/// bit, sorted by member index. A structurally valid value may still have too
/// few signatures or invalid signatures; RawVerifier checks those.
pub struct MlDsaStatusList {
    status_list: Vec<[u8; 32]>,
    version: u32,
    signers: SignerBits,
    signatures: Vec<Signature>,
}

impl MlDsaStatusList {
    /// Build a canonical record from `(member index, signature)` pairs.
    ///
    /// The list may be empty, but its order is significant and is never
    /// silently sorted. No quorum is enforced here without a trusted anchor.
    pub fn new(
        status_list: Vec<[u8; 32]>,
        version: u32,
        n_members: usize,
        mut signatures: Vec<(usize, Signature)>,
    ) -> Result<Self, String> {
        check_member_count(n_members)?;
        if signatures.len() > n_members {
            return Err("more signatures than committee members".into());
        }
        if record_len(n_members, status_list.len(), signatures.len())
            .is_none_or(|len| len > MAX_RECORD_BYTES)
        {
            return Err("ML-DSA status list exceeds the record byte limit".into());
        }
        signatures.sort_by_key(|(index, _)| *index);
        if signatures.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err("duplicate signer index".into());
        }
        if let Some((index, _)) = signatures.last()
            && *index >= n_members
        {
            return Err(format!("signer index {index} outside committee"));
        }

        let mut signers = SignerBits::with_capacity(n_members)
            .map_err(|_| "committee bitmap exceeds SSZ limit".to_string())?;
        for (index, _) in &signatures {
            signers
                .set(*index, true)
                .expect("indices checked against bitmap size above");
        }
        Ok(Self {
            status_list,
            version,
            signers,
            signatures: signatures
                .into_iter()
                .map(|(_, signature)| signature)
                .collect(),
        })
    }

    pub fn list(&self) -> &[[u8; 32]] {
        &self.status_list
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn signer_slots(&self) -> usize {
        self.signers.len()
    }

    pub fn signer_count(&self) -> usize {
        self.signers.num_set_bits()
    }

    /// Ascending signer indices, aligned one-to-one with `signatures()`.
    pub fn signer_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.signers
            .iter()
            .enumerate()
            .filter_map(|(index, set)| set.then_some(index))
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Serialize the entire published record, including the bitmap and signatures.
    pub fn to_bytes(&self) -> Vec<u8> {
        StatusListWire {
            alg: ALGORITHM_TAG,
            status_list: self.status_list.clone(),
            version: self.version,
            signers: self.signers.clone(),
            signatures: self
                .signatures
                .iter()
                .map(|signature| {
                    let encoded = signature.encode();
                    let mut bytes = [0u8; SIGNATURE_BYTES];
                    bytes.copy_from_slice(encoded.as_ref());
                    bytes
                })
                .collect(),
        }
        .as_ssz_bytes()
    }

    /// Decode one bounded, canonical SSZ record and each ML-DSA signature.
    ///
    /// This checks representation, not signature validity or quorum.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("ML-DSA status list exceeds the record byte limit".into());
        }
        let wire = StatusListWire::from_ssz_bytes(bytes)
            .map_err(|error| format!("invalid ML-DSA status-list SSZ: {error:?}"))?;
        if wire.alg != ALGORITHM_TAG {
            return Err(format!("unexpected status-list algorithm tag {}", wire.alg));
        }
        check_member_count(wire.signers.len())?;
        if wire.signatures.len() != wire.signers.num_set_bits() {
            return Err("bitmap population differs from signature count".into());
        }
        if wire.as_ssz_bytes() != bytes {
            return Err("non-canonical status-list SSZ".into());
        }
        let signatures = wire
            .signatures
            .iter()
            .map(|raw| {
                let signature = Signature::try_from(raw.as_slice())
                    .map_err(|_| "malformed ML-DSA signature".to_string())?;
                let canonical = signature.encode();
                let canonical_bytes: &[u8] = canonical.as_ref();
                if canonical_bytes != raw.as_slice() {
                    return Err("non-canonical ML-DSA signature".into());
                }
                Ok(signature)
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            status_list: wire.status_list,
            version: wire.version,
            signers: wire.signers,
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlDsa65Signer, verify};

    #[test]
    fn round_trip_preserves_sorted_signer_mapping() {
        let first = MlDsa65Signer::generate().unwrap();
        let second = MlDsa65Signer::generate().unwrap();
        let list = vec![[7; 32], [8; 32]];
        let anchor = [3; ANCHOR_ID_BYTES];
        let message = statement_bytes(&anchor, &list, 9);
        let record = MlDsaStatusList::new(
            list.clone(),
            9,
            5,
            vec![
                (4, second.sign(&message).unwrap()),
                (1, first.sign(&message).unwrap()),
            ],
        )
        .unwrap();
        let encoded = record.to_bytes();
        assert_eq!(encoded.len(), 17 + 2 * 32 + 1 + 2 * SIGNATURE_BYTES);
        let decoded = MlDsaStatusList::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.to_bytes(), encoded);
        assert_eq!(decoded.list(), list);
        assert_eq!(decoded.version(), 9);
        assert_eq!(decoded.signer_slots(), 5);
        assert_eq!(decoded.signer_indices().collect::<Vec<_>>(), vec![1, 4]);
        assert!(verify(
            &first.public_key(),
            &message,
            &decoded.signatures()[0]
        ));
        assert!(verify(
            &second.public_key(),
            &message,
            &decoded.signatures()[1]
        ));
    }

    #[test]
    fn empty_snapshot_round_trips() {
        let signer = MlDsa65Signer::generate().unwrap();
        let anchor = [3; ANCHOR_ID_BYTES];
        let message = statement_bytes(&anchor, &[], 0);
        let record =
            MlDsaStatusList::new(vec![], 0, 1, vec![(0, signer.sign(&message).unwrap())]).unwrap();
        let decoded = MlDsaStatusList::from_bytes(&record.to_bytes()).unwrap();
        assert!(decoded.list().is_empty());
        assert_eq!(decoded.signer_indices().collect::<Vec<_>>(), vec![0]);
        assert!(verify(
            &signer.public_key(),
            &message,
            &decoded.signatures()[0]
        ));
    }

    #[test]
    fn statement_binds_anchor_algorithm_version_order_and_list() {
        let anchor = [3; ANCHOR_ID_BYTES];
        let list = [[7; 32], [8; 32]];
        let message = statement_bytes(&anchor, &list, 9);
        let signer = MlDsa65Signer::generate().unwrap();
        let signature = signer.sign(&message).unwrap();
        let mut wrong_algorithm = STATEMENT_DOMAIN.to_vec();
        wrong_algorithm.extend_from_slice(
            &StatementWire {
                alg: 1,
                anchor_id: anchor,
                version: 9,
                status_list: list.to_vec(),
            }
            .as_ssz_bytes(),
        );
        for other in [
            wrong_algorithm,
            statement_bytes(&[4; ANCHOR_ID_BYTES], &list, 9),
            statement_bytes(&anchor, &list, 10),
            statement_bytes(&anchor, &list[..1], 9),
            statement_bytes(&anchor, &[list[1], list[0]], 9),
        ] {
            assert_ne!(message, other);
            assert!(!verify(&signer.public_key(), &other, &signature));
        }
        assert!(message.starts_with(STATEMENT_DOMAIN));
    }

    #[test]
    fn rejects_duplicate_out_of_range_and_oversized_committee() {
        let signer = MlDsa65Signer::generate().unwrap();
        let signature = signer.sign(b"fixture").unwrap();
        assert!(MlDsaStatusList::new(vec![], 0, 0, vec![]).is_err());
        assert!(MlDsaStatusList::new(vec![], 0, 2049, vec![]).is_err());
        assert!(MlDsaStatusList::new(vec![], 0, 1, vec![(1, signature.clone())]).is_err());
        assert!(
            MlDsaStatusList::new(vec![], 0, 2, vec![(1, signature.clone()), (1, signature)],)
                .is_err()
        );
    }

    #[test]
    fn rejects_mismatched_bitmap_and_wrong_algorithm_tag() {
        let signer = MlDsa65Signer::generate().unwrap();
        let signature = signer.sign(b"fixture").unwrap();
        let record = MlDsaStatusList::new(vec![], 0, 2, vec![(1, signature)]).unwrap();
        let mut wire = StatusListWire::from_ssz_bytes(&record.to_bytes()).unwrap();
        wire.alg = 1;
        assert!(
            MlDsaStatusList::from_bytes(&wire.as_ssz_bytes())
                .err()
                .unwrap()
                .contains("algorithm tag")
        );
        wire.alg = ALGORITHM_TAG;
        wire.signatures.clear();
        assert!(MlDsaStatusList::from_bytes(&wire.as_ssz_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_signature_and_ssz_offset() {
        let signer = MlDsa65Signer::generate().unwrap();
        let signature = signer.sign(b"fixture").unwrap();
        let record = MlDsaStatusList::new(vec![], 0, 2, vec![(1, signature)]).unwrap();
        let mut wire = StatusListWire::from_ssz_bytes(&record.to_bytes()).unwrap();
        wire.signatures[0] = [0xff; SIGNATURE_BYTES];
        assert!(MlDsaStatusList::from_bytes(&wire.as_ssz_bytes()).is_err());

        let mut bytes = record.to_bytes();
        bytes[1] = 16; // The first variable offset must equal the 17-byte header.
        assert!(MlDsaStatusList::from_bytes(&bytes).is_err());
    }
}
