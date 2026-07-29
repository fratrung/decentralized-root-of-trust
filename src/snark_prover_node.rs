use lean_multisig::{
    XmssPublicKey, XmssSignature, aggregate_single_message_signatures, setup_prover,
};

use crate::status_list::status_list_root_fe;

pub struct PQSNARKProverModule {}

impl PQSNARKProverModule {
    pub fn init_prover() -> Self {
        setup_prover();
        PQSNARKProverModule {}
    }

    pub fn make_proof(
        &self,
        raws: Vec<(XmssPublicKey, XmssSignature)>,
        status_list_elem: &Vec<[u8; 32]>,
        slot: u32,
        version: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        let message = status_list_root_fe(status_list_elem, version);
        let aggregate = aggregate_single_message_signatures(&[], raws, message, slot, log_inv_rate)
            .expect("aggregation failed");
        postcard::to_allocvec(&aggregate).expect("proof serialization failed")
    }
}
