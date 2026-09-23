//! Canonical ML-DSA-65 committee trust anchor.
//!
//! This module defines only the fixed public trust anchor and the statement it
//! authorizes members to sign. It does not verify a StatusList quorum.

use std::collections::HashSet;

use ml_dsa::{EncodedVerifyingKey, MlDsa65};
use sha3::{Digest, Sha3_384};
use ssz::{Decode as _, Encode as _};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

use crate::PublicKey;
use crate::status_list::{ANCHOR_ID_BYTES, MAX_COMMITTEE_SIZE, statement_bytes};

/// FIPS 204 ML-DSA-65 public-key encoding size.
pub const PUBLIC_KEY_BYTES: usize = 1952;

const ANCHOR_ID_DOMAIN: &[u8] = b"decentralized-root-of-trust/ml-dsa-65/anchor-id/v1\0";
// The fixed SSZ container has one variable-field offset and one u64 threshold.
const COMMITTEE_FIXED_WIRE_BYTES: usize = 4 + 8;
const MAX_COMMITTEE_WIRE_BYTES: usize =
    COMMITTEE_FIXED_WIRE_BYTES + MAX_COMMITTEE_SIZE * PUBLIC_KEY_BYTES;

/// Canonical SSZ representation of the trust anchor.
#[derive(SszEncode, SszDecode)]
#[ssz(struct_behaviour = "container")]
struct CommitteeWire {
    members: Vec<[u8; PUBLIC_KEY_BYTES]>,
    threshold: u64,
}

/// A fixed committee of ML-DSA-65 public keys and its threshold.
///
/// Member order is authenticated by the anchor. It gives every member a stable
/// index for the StatusList bitmap; it is not an order chosen by a publisher.
#[derive(Clone)]
pub struct Committee {
    members: Vec<PublicKey>,
    threshold: usize,
    anchor_id: [u8; ANCHOR_ID_BYTES],
}

/// Return the canonical FIPS 204 encoding of one ML-DSA-65 public key.
pub fn encode_public_key(public_key: &PublicKey) -> [u8; PUBLIC_KEY_BYTES] {
    let encoded = public_key.encode();
    let encoded_bytes: &[u8] = encoded.as_ref();
    let mut bytes = [0u8; PUBLIC_KEY_BYTES];
    bytes.copy_from_slice(encoded_bytes);
    bytes
}

/// Decode and enforce the canonical FIPS 204 encoding of one public key.
pub fn decode_public_key(bytes: &[u8; PUBLIC_KEY_BYTES]) -> Result<PublicKey, String> {
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice())
        .map_err(|_| "invalid ML-DSA-65 public-key length".to_string())?;
    let public_key = PublicKey::decode(&encoded);
    if encode_public_key(&public_key) != *bytes {
        return Err("non-canonical ML-DSA-65 public key".into());
    }
    Ok(public_key)
}

fn validate_members(members: &[PublicKey]) -> Result<(), String> {
    if members.is_empty() {
        return Err("committee must contain at least one member".into());
    }
    if members.len() > MAX_COMMITTEE_SIZE {
        return Err(format!(
            "committee names {} members, above the ceiling of {MAX_COMMITTEE_SIZE}",
            members.len()
        ));
    }

    let mut seen = HashSet::with_capacity(members.len());
    if members
        .iter()
        .any(|member| !seen.insert(encode_public_key(member)))
    {
        return Err("committee contains duplicate member public keys".into());
    }
    Ok(())
}

fn validate_threshold(threshold: usize, member_count: usize) -> Result<(), String> {
    if !(1..=member_count).contains(&threshold) {
        return Err(format!(
            "committee threshold {threshold} outside 1..={member_count}"
        ));
    }
    Ok(())
}

fn wire_bytes(members: &[PublicKey], threshold: usize) -> Vec<u8> {
    CommitteeWire {
        members: members.iter().map(encode_public_key).collect(),
        threshold: threshold as u64,
    }
    .as_ssz_bytes()
}

/// SHA3-384 of a domain-separated canonical SSZ anchor encoding.
///
/// The 48-byte result retains the category-3 collision-security target of
/// ML-DSA-65. It is derived locally, never supplied by a publisher.
fn anchor_id_from_canonical_bytes(bytes: &[u8]) -> [u8; ANCHOR_ID_BYTES] {
    let mut hasher = Sha3_384::new();
    hasher.update(ANCHOR_ID_DOMAIN);
    hasher.update(bytes);
    let digest = hasher.finalize();

    let mut anchor_id = [0u8; ANCHOR_ID_BYTES];
    anchor_id.copy_from_slice(&digest);
    anchor_id
}

impl Committee {
    /// Creates a checked anchor from ordered ML-DSA-65 public keys.
    ///
    /// The threshold is t in a t-of-N committee. Duplicate public keys are
    /// rejected because one key must never occupy multiple bitmap identities.
    pub fn new(members: Vec<PublicKey>, threshold: usize) -> Result<Self, String> {
        validate_members(&members)?;
        validate_threshold(threshold, members.len())?;
        let bytes = wire_bytes(&members, threshold);
        Ok(Self {
            members,
            threshold,
            anchor_id: anchor_id_from_canonical_bytes(&bytes),
        })
    }

    /// Decodes a bounded, canonical SSZ anchor and rechecks its invariants.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_COMMITTEE_WIRE_BYTES {
            return Err(format!(
                "committee wire size {} B is above the ceiling of {} B",
                bytes.len(),
                MAX_COMMITTEE_WIRE_BYTES
            ));
        }

        let wire = CommitteeWire::from_ssz_bytes(bytes)
            .map_err(|error| format!("invalid ML-DSA committee SSZ: {error:?}"))?;
        let threshold = usize::try_from(wire.threshold)
            .map_err(|_| format!("committee threshold {} is too large", wire.threshold))?;
        let members = wire
            .members
            .iter()
            .map(decode_public_key)
            .collect::<Result<Vec<_>, _>>()?;

        validate_members(&members)?;
        validate_threshold(threshold, members.len())?;

        if wire_bytes(&members, threshold) != bytes {
            return Err("non-canonical ML-DSA committee SSZ".into());
        }

        Ok(Self {
            members,
            threshold,
            anchor_id: anchor_id_from_canonical_bytes(bytes),
        })
    }

    /// Canonical SSZ encoding of this anchor.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire_bytes(&self.members, self.threshold)
    }

    /// Ordered public keys embedded by a verifier.
    pub fn members(&self) -> &[PublicKey] {
        &self.members
    }

    /// The t in this t-of-N committee.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The committee size N.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// The index of a public key in this anchor, if the key is a member.
    pub fn index_of(&self, member: &PublicKey) -> Option<usize> {
        self.members
            .iter()
            .position(|candidate| candidate == member)
    }

    /// The fixed 48-byte identifier bound into every StatusList statement.
    pub fn anchor_id(&self) -> &[u8; ANCHOR_ID_BYTES] {
        &self.anchor_id
    }

    /// The sole public constructor for the bytes a committee member signs.
    ///
    /// It is a normal FIPS 204 ML-DSA message. It contains a protocol domain,
    /// algorithm tag, this anchor identifier, version, and ordered list; it is
    /// not an application-level pre-hash.
    pub fn statement_for(&self, status_list: &[[u8; 32]], version: u32) -> Vec<u8> {
        statement_bytes(&self.anchor_id, status_list, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlDsa65Signer, verify};

    fn signers(count: usize) -> Vec<MlDsa65Signer> {
        (0..count)
            .map(|_| MlDsa65Signer::generate().unwrap())
            .collect()
    }

    fn public_keys(signers: &[MlDsa65Signer]) -> Vec<PublicKey> {
        signers.iter().map(MlDsa65Signer::public_key).collect()
    }

    #[test]
    fn canonical_anchor_round_trips_and_preserves_member_indices() {
        let signers = signers(3);
        let committee = Committee::new(public_keys(&signers), 2).unwrap();
        let encoded = committee.to_bytes();
        let decoded = Committee::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.to_bytes(), encoded);
        assert_eq!(decoded.threshold(), 2);
        assert_eq!(decoded.member_count(), 3);
        assert_eq!(decoded.index_of(&signers[0].public_key()), Some(0));
        assert_eq!(decoded.index_of(&signers[2].public_key()), Some(2));
        assert_eq!(decoded.anchor_id(), committee.anchor_id());
    }

    #[test]
    fn statement_is_bound_to_this_exact_anchor() {
        let signers = signers(3);
        let keys = public_keys(&signers);
        let committee = Committee::new(keys.clone(), 2).unwrap();
        let other_threshold = Committee::new(keys.clone(), 3).unwrap();
        let other_order =
            Committee::new(vec![keys[1].clone(), keys[0].clone(), keys[2].clone()], 2).unwrap();
        let list = [[0x11; 32], [0x22; 32]];
        let statement = committee.statement_for(&list, 7);
        let signature = signers[1].sign(&statement).unwrap();

        assert!(verify(&committee.members()[1], &statement, &signature));
        assert_ne!(statement, other_threshold.statement_for(&list, 7));
        assert_ne!(statement, other_order.statement_for(&list, 7));
        assert!(!verify(
            &committee.members()[1],
            &other_threshold.statement_for(&list, 7),
            &signature
        ));
    }

    #[test]
    fn rejects_invalid_threshold_duplicate_member_and_malformed_ssz() {
        let signer = MlDsa65Signer::generate().unwrap();
        let key = signer.public_key();

        assert!(Committee::new(vec![], 1).is_err());
        assert!(Committee::new(vec![key.clone()], 0).is_err());
        assert!(Committee::new(vec![key.clone()], 2).is_err());
        assert!(Committee::new(vec![key.clone(), key], 1).is_err());

        let committee = Committee::new(public_keys(&signers(2)), 1).unwrap();
        let mut bad_offset = committee.to_bytes();
        bad_offset[0] = 13;
        assert!(Committee::from_bytes(&bad_offset).is_err());

        let duplicated_key = encode_public_key(&committee.members()[0]);
        let duplicate_wire = CommitteeWire {
            members: vec![duplicated_key, duplicated_key],
            threshold: 1,
        }
        .as_ssz_bytes();
        assert!(Committee::from_bytes(&duplicate_wire).is_err());
    }
}
