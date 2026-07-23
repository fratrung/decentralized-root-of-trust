use backend::KoalaBear;
use lean_multisig::{
    XmssPublicKey, XmssSignature, aggregate_single_message_signatures,
    verify_single_message_aggregate,
};

use crate::status_list::{StatusList, status_list_root_fe};

pub struct Committee {
    members: Vec<XmssPublicKey>,
    t: usize,
}

impl Committee {
    /// Builds the committee from its members' public keys and the threshold `t`.
    pub fn new(members: Vec<XmssPublicKey>, t: usize) -> Self {
        Committee { members, t }
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

/// Verifies the committee proof carried by the status list.
/// The fixed trust anchor is the committee (`members`, threshold `t`): anyone
/// who knows it can verify, without knowing in advance *who* signed the update.
pub fn verify_proof(committee: Committee, status_list: &StatusList) -> bool {
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

    // 3) quorum: at least `t` distinct signers
    if agg.info.pubkeys.len() < committee.t {
        return false;
    }

    // 4) the SNARK aggregate itself must verify
    if verify_single_message_aggregate(&agg).is_err() {
        return false;
    }
    true
}
