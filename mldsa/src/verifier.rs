//! Stateless authorization predicate for one raw ML-DSA status-list record.

use crate::committee::Committee;
use crate::status_list::MlDsaStatusList;
use crate::verify;

/// Verifies one record against a locally trusted committee anchor.
///
/// Freshness is a separate decision: a previously valid version remains
/// cryptographically valid even after a newer version is published.
pub struct RawVerifier {
    committee: Committee,
}

impl RawVerifier {
    pub fn new(committee: Committee) -> Self {
        Self { committee }
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// Check a record already decoded from its canonical SSZ representation.
    ///
    /// Callers measure or handle decoding separately with
    /// MlDsaStatusList::from_bytes before invoking this predicate.
    /// Every set bit must identify one anchor member whose signature verifies.
    pub fn verify_status_list(&self, record: &MlDsaStatusList) -> bool {
        if record.signer_slots() != self.committee.member_count()
            || record.signer_count() < self.committee.threshold()
            || record.signer_count() != record.signatures().len()
        {
            return false;
        }

        let statement = self
            .committee
            .statement_for(record.list(), record.version());
        record
            .signer_indices()
            .zip(record.signatures())
            .all(|(index, signature)| {
                verify(&self.committee.members()[index], &statement, signature)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlDsa65Signer;

    #[test]
    fn authenticates_quorum_and_rejects_every_changed_binding() {
        let signers: Vec<_> = (0..3).map(|_| MlDsa65Signer::generate().unwrap()).collect();
        let members = signers.iter().map(MlDsa65Signer::public_key).collect();
        let committee = Committee::new(members, 2).unwrap();
        let verifier = RawVerifier::new(committee.clone());
        let list = vec![[1; 32], [2; 32]];
        let version = 7;
        let statement = committee.statement_for(&list, version);
        let first = signers[0].sign(&statement).unwrap();
        let second = signers[2].sign(&statement).unwrap();
        let signatures = vec![(0, first.clone()), (2, second.clone())];

        let record = MlDsaStatusList::new(list.clone(), version, 3, signatures.clone()).unwrap();
        let decoded = MlDsaStatusList::from_bytes(&record.to_bytes()).unwrap();
        assert!(verifier.verify_status_list(&decoded));

        let short =
            MlDsaStatusList::new(list.clone(), version, 3, vec![(0, first.clone())]).unwrap();
        assert!(!verifier.verify_status_list(&short));
        let wrong_bitmap_length =
            MlDsaStatusList::new(list.clone(), version, 4, signatures.clone()).unwrap();
        assert!(!verifier.verify_status_list(&wrong_bitmap_length));
        let wrong_list =
            MlDsaStatusList::new(vec![[3; 32]], version, 3, signatures.clone()).unwrap();
        assert!(!verifier.verify_status_list(&wrong_list));
        let wrong_version =
            MlDsaStatusList::new(list.clone(), version + 1, 3, signatures.clone()).unwrap();
        assert!(!verifier.verify_status_list(&wrong_version));
        let wrong_signer =
            MlDsaStatusList::new(list.clone(), version, 3, vec![(0, first), (1, second)]).unwrap();
        assert!(!verifier.verify_status_list(&wrong_signer));

        let outsider = MlDsa65Signer::generate().unwrap();
        let outsider_signature = outsider.sign(&statement).unwrap();
        let outsider_record = MlDsaStatusList::new(
            list.clone(),
            version,
            3,
            vec![(0, outsider_signature), (2, signatures[1].1.clone())],
        )
        .unwrap();
        assert!(!verifier.verify_status_list(&outsider_record));

        let other_anchor = Committee::new(committee.members().to_vec(), 3).unwrap();
        assert!(!RawVerifier::new(other_anchor).verify_status_list(&record));
        assert!(MlDsaStatusList::from_bytes(&record.to_bytes()[..12]).is_err());
    }
}
