use crate::committee::{ Committee};

pub struct VerifierNode {
    committee: Committee,
}

impl VerifierNode {
    pub fn new(committee: Committee) -> Self {
        Self { committee }
    }

    pub fn verify_signature(&self) -> bool {
        todo!("Da implementare")
    }

    pub fn verify_aggregate_signature(&self) -> bool {
        todo!("Da implementare")
    }
    pub fn get_committee(&self) -> &Committee {
        &self.committee
    }
}