//! In-memory head of the status-list history a committee member has signed.
//!
//! The storage/DHT supplies candidates, not authority. During one process
//! lifetime a member advances this head only after spending the XMSS slot for a
//! proposal, so replacing the published record cannot make it sign a fork.

use crate::protocol::status_list::status_list_message;

/// Parent reference used by the first status-list version.
pub const GENESIS_PREDECESSOR: [u8; 32] = [0; 32];

/// The exact state this member most recently signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedHead {
    version: u32,
    digest: [u8; 32],
}

impl SignedHead {
    /// Rebuilds the head from a record authenticated by the caller.
    ///
    /// This computes the digest but does not verify a quorum or a DHT record
    /// signature. Recovery must perform those checks before calling it.
    pub fn from_authenticated(version: u32, list: &[[u8; 32]]) -> Self {
        Self {
            version,
            digest: status_list_message(list, version),
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Validates one append-only transition without mutating the current head.
    /// The caller commits the returned head only after the slot is spent.
    pub fn successor(
        current: Option<&Self>,
        predecessor: &[u8; 32],
        version: u32,
        list: &[[u8; 32]],
    ) -> Result<Self, String> {
        if list.is_empty() {
            return Err("a proposal must append one entry".into());
        }

        match current {
            None => {
                if predecessor != &GENESIS_PREDECESSOR {
                    return Err("v0 does not name the genesis predecessor".into());
                }
                if version != 0 || list.len() != 1 {
                    return Err(format!(
                        "nothing has been signed yet, so only v0 with one entry is valid, got v{version} with {}",
                        list.len()
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
                let recomputed = status_list_message(&list[..list.len() - 1], head.version);
                if recomputed != head.digest {
                    return Err(format!(
                        "the proposed prefix is not the signed list at v{}",
                        head.version
                    ));
                }
            }
        }

        Ok(Self::from_authenticated(version, list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn advances_only_from_the_signed_digest_and_list() {
        let v0 = SignedHead::successor(None, &GENESIS_PREDECESSOR, 0, &[entry(1)]).unwrap();
        let v1 = SignedHead::successor(Some(&v0), &v0.digest(), 1, &[entry(1), entry(2)]).unwrap();

        assert_eq!(v1.version(), 1);
        assert_eq!(v1.digest(), status_list_message(&[entry(1), entry(2)], 1));
    }

    #[test]
    fn refuses_a_decodable_but_unauthenticated_predecessor() {
        let authentic = SignedHead::from_authenticated(7, &[entry(1), entry(2)]);
        let forged_parent = SignedHead::from_authenticated(7, &[entry(1)]);

        assert!(
            SignedHead::successor(
                Some(&authentic),
                &forged_parent.digest(),
                8,
                &[entry(1), entry(3)],
            )
            .is_err()
        );

        // Copying the authentic public digest is insufficient: the proposed
        // list must also extend the exact list held under that digest.
        assert!(
            SignedHead::successor(
                Some(&authentic),
                &authentic.digest(),
                8,
                &[entry(1), entry(3)],
            )
            .is_err()
        );
    }

    #[test]
    fn genesis_has_an_explicit_parent_reference() {
        assert!(SignedHead::successor(None, &[9; 32], 0, &[entry(1)]).is_err());
        assert!(SignedHead::successor(None, &GENESIS_PREDECESSOR, 1, &[entry(1)]).is_err());
        assert!(SignedHead::successor(None, &GENESIS_PREDECESSOR, 0, &[]).is_err());
    }
}
