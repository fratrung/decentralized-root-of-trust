//! Prover-side wrapper over [`crate::committee::make_proof`].
//!
//! Like its verifier twin, this type owns no policy: it exists to pair
//! `setup_prover()` with the proving call. The slot is **derived from the anchor**
//! rather than accepted from the caller — `Committee::slot_for` is meant to be the
//! only place `genesis + version` is ever computed, and a second entry point
//! taking an unrelated `slot` alongside a `version` is precisely how the two drift
//! apart. A quorum that could choose its own slot for a given version is what
//! check 3 in [`crate::committee::verify_proof`] exists to forbid.

use lean_multisig::{XmssPublicKey, XmssSignature, setup_prover};

use crate::committee::{Committee, make_proof};
use crate::status_list::status_list_root_fe;

pub struct PQSNARKProverModule {}

impl PQSNARKProverModule {
    pub fn init_prover() -> Self {
        setup_prover();
        PQSNARKProverModule {}
    }

    /// Aggregates `raws` — signatures over `(status_list_elem, version)` — into one
    /// proof, at the slot `committee` assigns to `version`.
    ///
    /// # Panics
    ///
    /// If `version` has no slot under this anchor (`genesis + version` overflows
    /// `u32`), which means the committee's key window ran out long ago.
    pub fn make_proof(
        &self,
        committee: &Committee,
        raws: Vec<(XmssPublicKey, XmssSignature)>,
        status_list_elem: &[[u8; 32]],
        version: u32,
        log_inv_rate: usize,
    ) -> Vec<u8> {
        let slot = committee
            .slot_for(version)
            .expect("version has no slot under this anchor");
        let message = status_list_root_fe(status_list_elem, version);
        make_proof(raws, message, slot, log_inv_rate)
    }
}
