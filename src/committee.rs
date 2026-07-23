use backend::KoalaBear;
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, aggregate_single_message_signatures, xmss_sign,
    verify_single_message_aggregate,
};
use serde::{Deserialize, Serialize};

use crate::status_list::{StatusList, status_list_root_fe};

/// The FIXED trust anchor, embedded once in every verifier — the replacement for
/// the old single root-of-trust public key. It is the only thing a verifier must
/// know a priori; *who* signed a given update travels inside the proof.
#[derive(Serialize, Deserialize)]
pub struct Committee {
    members: Vec<XmssPublicKey>,
    t: usize,
}

impl Committee {
    /// Builds the committee from its members' public keys and the threshold `t`.
    pub fn new(members: Vec<XmssPublicKey>, t: usize) -> Self {
        Committee { members, t }
    }

    pub fn members(&self) -> &[XmssPublicKey] {
        &self.members
    }

    pub fn threshold(&self) -> usize {
        self.t
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
/// (postcard) bytes to store in `StatusList.zk_proof`. `message` is the
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
/// All four checks are load-bearing; dropping any one of them is exploitable.
pub fn verify_proof(committee: &Committee, status_list: &StatusList) -> bool {
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

    // 2) the proof must be bound to THIS list (its Poseidon2 root)
    if agg.info.message != status_list_root_fe(status_list.list()) {
        return false;
    }

    // 3) quorum: at least `t` distinct signers. Distinctness comes for free:
    //    leanVM requires `pubkeys` to be strictly sorted with no duplicates.
    if agg.info.pubkeys.len() < committee.t {
        return false;
    }

    // 4) the SNARK aggregate itself must verify
    if verify_single_message_aggregate(&agg).is_err() {
        return false;
    }
    true
}
