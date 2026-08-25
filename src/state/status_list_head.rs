//! In-memory head of the status-list history a committee member has signed.
//!
//! The storage/DHT supplies candidates, not authority. During one process
//! lifetime a member advances this head only after spending the XMSS slot for a
//! proposal, so replacing the published record cannot make it sign a fork. One
//! version may append a batch of entries; the guard only fixes the already-signed
//! prefix.

use crate::protocol::status_list::{Domain, status_list_message};

/// Parent reference used by the first status-list version.
pub const GENESIS_PREDECESSOR: [u8; 32] = [0; 32];

/// The exact state this member most recently signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedHead {
    version: u32,
    len: usize,
    digest: [u8; 32],
}

impl SignedHead {
    /// Rebuilds the head from a record authenticated by the caller.
    ///
    /// This computes the digest but does not verify a quorum or a DHT record
    /// signature. Recovery must perform those checks before calling it.
    pub fn from_authenticated(domain: &Domain, version: u32, list: &[[u8; 32]]) -> Self {
        Self {
            version,
            len: list.len(),
            digest: status_list_message(domain, list, version),
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Number of entries covered by this digest.
    pub fn entries(&self) -> usize {
        self.len
    }

    /// Validates one append-only transition without mutating the current head.
    /// The caller commits the returned head only after the slot is spent.
    pub fn successor(
        domain: &Domain,
        current: Option<&Self>,
        predecessor: &[u8; 32],
        version: u32,
        list: &[[u8; 32]],
    ) -> Result<Self, String> {
        if list.is_empty() {
            return Err("a proposal must contain at least one entry".into());
        }

        match current {
            None => {
                if predecessor != &GENESIS_PREDECESSOR {
                    return Err("v0 does not name the genesis predecessor".into());
                }
                if version != 0 {
                    return Err(format!(
                        "nothing has been signed yet, so only v0 is valid, got v{version}"
                    ));
                }
            }
            Some(head) => {
                if predecessor != &head.digest {
                    return Err(format!(
                        "predecessor digest does not match the signed head at v{}",
                        head.version
                    ));
                }
                let expected = head
                    .version
                    .checked_add(1)
                    .ok_or("the signed head is already at the final version")?;
                if version != expected {
                    return Err(format!(
                        "v{version} does not follow the signed head at v{}",
                        head.version
                    ));
                }
                if list.len() <= head.len {
                    return Err(format!(
                        "proposal with {} entries does not append to the signed {}-entry prefix at v{}",
                        list.len(),
                        head.len,
                        head.version
                    ));
                }
                let recomputed = status_list_message(domain, &list[..head.len], head.version);
                if recomputed != head.digest {
                    return Err(format!(
                        "the proposed prefix is not the signed list at v{}",
                        head.version
                    ));
                }
            }
        }

        Ok(Self::from_authenticated(domain, version, list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::status_list::Algorithms;

    fn entry(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// Any fixed domain does: these tests are about the transition rule, not
    /// about which committee it runs under. What matters is that the *same*
    /// domain is used throughout, since a head under one domain is meaningless
    /// under another — which is the property `domains_do_not_interoperate` pins.
    fn domain() -> Domain {
        Domain::new(&[0xD0; 32], Algorithms::WotsXmss)
    }

    #[test]
    fn advances_only_from_the_signed_digest_and_list() {
        let d = domain();
        let v0 = SignedHead::successor(&d, None, &GENESIS_PREDECESSOR, 0, &[entry(1), entry(2)])
            .unwrap();
        let v1 = SignedHead::successor(
            &d,
            Some(&v0),
            &v0.digest(),
            1,
            &[entry(1), entry(2), entry(3), entry(4)],
        )
        .unwrap();

        assert_eq!(v1.version(), 1);
        assert_eq!(v1.entries(), 4);
        assert_eq!(
            v1.digest(),
            status_list_message(&d, &[entry(1), entry(2), entry(3), entry(4)], 1)
        );
    }

    #[test]
    fn refuses_a_decodable_but_unauthenticated_predecessor() {
        let d = domain();
        let authentic = SignedHead::from_authenticated(&d, 7, &[entry(1), entry(2)]);
        let forged_parent = SignedHead::from_authenticated(&d, 7, &[entry(1)]);

        assert!(
            SignedHead::successor(
                &d,
                Some(&authentic),
                &forged_parent.digest(),
                8,
                &[entry(1), entry(2), entry(3)],
            )
            .is_err()
        );

        assert!(
            SignedHead::successor(
                &d,
                Some(&authentic),
                &authentic.digest(),
                8,
                &[entry(1), entry(2)],
            )
            .is_err(),
            "quoting the head without appending entries must not advance it"
        );

        // Copying the authentic public digest is insufficient: the proposed
        // list must also extend the exact list held under that digest.
        assert!(
            SignedHead::successor(
                &d,
                Some(&authentic),
                &authentic.digest(),
                8,
                &[entry(1), entry(3), entry(4)],
            )
            .is_err()
        );
    }

    #[test]
    fn genesis_has_an_explicit_parent_reference() {
        let d = domain();
        assert!(SignedHead::successor(&d, None, &[9; 32], 0, &[entry(1)]).is_err());
        assert!(SignedHead::successor(&d, None, &GENESIS_PREDECESSOR, 1, &[entry(1)]).is_err());
        assert!(SignedHead::successor(&d, None, &GENESIS_PREDECESSOR, 0, &[]).is_err());
        assert!(
            SignedHead::successor(
                &d,
                None,
                &GENESIS_PREDECESSOR,
                0,
                &[entry(1), entry(2), entry(3)]
            )
            .is_ok()
        );
    }

    /// The head is a digest, and a digest only means something inside the domain
    /// that produced it. A member that recovered its head under one anchor must
    /// not be able to continue the chain under another: the successor check would
    /// otherwise compare a digest from committee A against a list re-folded under
    /// committee B and, for the prefix case, silently pass on a collision-shaped
    /// coincidence rather than on a rule.
    #[test]
    fn domains_do_not_interoperate() {
        let a = Domain::new(&[0xAA; 32], Algorithms::WotsXmss);
        let b = Domain::new(&[0xBB; 32], Algorithms::WotsXmss);

        let head_a = SignedHead::successor(&a, None, &GENESIS_PREDECESSOR, 0, &[entry(1)]).unwrap();
        let head_b = SignedHead::successor(&b, None, &GENESIS_PREDECESSOR, 0, &[entry(1)]).unwrap();
        assert_ne!(
            head_a.digest(),
            head_b.digest(),
            "one list at one version must not share a digest across domains"
        );

        // The head from domain A, offered as the parent of a transition in B.
        assert!(
            SignedHead::successor(
                &b,
                Some(&head_a),
                &head_a.digest(),
                1,
                &[entry(1), entry(2)]
            )
            .is_err(),
            "a head from another domain must not extend this one"
        );
    }
}
