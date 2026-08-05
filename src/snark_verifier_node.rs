use lean_multisig::{setup_verifier, verify_single_message_aggregate};

use crate::{
    committee::Committee,
    status_list::{SnarkStatusList, status_list_root_fe},
};

pub struct PQSNARKVerifierModule {
    committee: Committee,
    status_list_last_version: u32,
}

impl PQSNARKVerifierModule {
    pub fn new(committee: Committee, status_list_last_version: u32) -> Self {
        setup_verifier();
        Self {
            committee,
            status_list_last_version: status_list_last_version,
        }
    }

    pub fn committee_as_ref(&self) -> &Committee {
        &self.committee
    }

    pub fn verify(&self, status_list: &SnarkStatusList) -> bool {
        let agg = match status_list.proof() {
            Ok(a) => a,
            Err(_) => return false,
        };

        // check committee signature
        if !agg
            .info
            .pubkeys
            .iter()
            .all(|pk| self.committee.members().contains(pk))
        {
            return false;
        }

        if agg.info.message != status_list_root_fe(status_list.list(), status_list.version()) {
            return false;
        }

        if agg.info.pubkeys.len() < self.committee.threshold() {
            return false;
        }

        if status_list.version() < self.status_list_last_version {
            return false;
        }

        if verify_single_message_aggregate(&agg).is_err() {
            return false;
        }

        return true;
    }
}
