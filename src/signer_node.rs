//! A committee member: one XMSS keypair plus the durable slot counter that keeps
//! its statefulness honest.
//!
//! All the crash-safety reasoning lives in [`crate::atomic_slot_counter`]. What
//! this module adds is the one place where a slot is actually spent, and the
//! guarantee that it is spent *forward only*.

use backend::KoalaBear;
use lean_multisig::{XmssPublicKey, XmssSecretKey, XmssSignature, xmss_sign};

use crate::atomic_slot_counter::{AtomicSlotCounter, AtomicSlotCounterError};

/// Why a signature could not be produced.
///
/// Both variants leave the counter advanced: a failure never returns a slot.
#[derive(Debug)]
pub enum SignerNodeError {
    /// No slot could be issued (window exhausted, unusable state, lock held, I/O).
    Slot(AtomicSlotCounterError),
    /// A slot was issued but leanVM refused to sign with it. The slot is burned.
    Sign(String),
}

impl std::fmt::Display for SignerNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Slot(e) => write!(f, "{e}"),
            Self::Sign(m) => write!(f, "signing failed: {m}"),
        }
    }
}

impl std::error::Error for SignerNodeError {}

impl From<AtomicSlotCounterError> for SignerNodeError {
    fn from(e: AtomicSlotCounterError) -> Self {
        Self::Slot(e)
    }
}

pub struct SignerNode {
    pk: XmssPublicKey,
    sk: XmssSecretKey,
    a_slot_counter: AtomicSlotCounter,
}

impl SignerNode {
    pub fn new(pk: XmssPublicKey, sk: XmssSecretKey, a_slot_counter: AtomicSlotCounter) -> Self {
        Self {
            pk,
            sk,
            a_slot_counter,
        }
    }

    /// The member's public key, as it appears in the committee anchor.
    pub fn public_key(&self) -> &XmssPublicKey {
        &self.pk
    }

    /// The slot the next signature would use.
    pub fn next_slot(&self) -> u32 {
        self.a_slot_counter.next_slot()
    }

    /// Signatures this key can still produce before a re-key is required.
    pub fn remaining_slots(&self) -> u64 {
        self.a_slot_counter.remaining()
    }

    /// Signs `message`, returning the slot it was signed at.
    ///
    /// The two statements below are in the only safe order. `reserve` makes the
    /// slot durably spent *before* the key ever touches it, so a crash between
    /// them can lose a signature but can never produce a second one under the same
    /// slot. Signing first and recording afterwards would leave exactly that
    /// window open, and a reused XMSS slot means a recoverable secret key.
    ///
    /// Consequently the slot is gone the moment it is issued. If `xmss_sign`
    /// fails, if the caller drops the signature, if the aggregate does not verify,
    /// if the update is never published — the counter has already moved on and
    /// that slot is never handed out again. There is no rollback path, on purpose:
    /// every one of those situations costs one slot out of `2^32`, while retrying
    /// on the same slot costs the key.
    pub fn sign<R: rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &[KoalaBear; 8],
    ) -> Result<(u32, XmssSignature), SignerNodeError> {
        let slot = self.a_slot_counter.reserve()?;
        let signature = xmss_sign(rng, &self.sk, message, slot)
            .map_err(|e| SignerNodeError::Sign(format!("{e:?} at slot {slot}")))?;
        Ok((slot, signature))
    }

    /// Signs `message` at the slot the *protocol* assigned to this round —
    /// `Committee::slot_for(version)` — instead of the next slot this member
    /// happens to be on. The slot is not returned: the caller derived it.
    ///
    /// The ordering guarantee of [`SignerNode::sign`] is unchanged, and so is its
    /// consequence: reserving burns the slot whatever happens next.
    ///
    /// [`AtomicSlotCounterError::AlreadySpent`] is a normal failure here, not a
    /// fault. It means this member is past that round, so it **abstains** rather
    /// than signing a second message under a spent slot. It catches up as soon as
    /// the published version passes its counter.
    pub fn sign_at<R: rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &[KoalaBear; 8],
        slot: u32,
    ) -> Result<XmssSignature, SignerNodeError> {
        self.a_slot_counter.reserve_at(slot)?;
        xmss_sign(rng, &self.sk, message, slot)
            .map_err(|e| SignerNodeError::Sign(format!("{e:?} at slot {slot}")))
    }
}

// Test

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_list::{hash_any, status_list_root_fe};
    use lean_multisig::{xmss_key_gen, xmss_verify};
    use std::path::PathBuf;

    const START: u32 = 100;
    const END: u32 = 110;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("signer-{name}-{}", std::process::id()));
        for ext in ["", "lock", "tmp"] {
            let _ = std::fs::remove_file(if ext.is_empty() {
                p.clone()
            } else {
                p.with_extension(ext)
            });
        }
        p
    }

    fn node(path: &PathBuf, counter_end: u32) -> SignerNode {
        let (sk, pk) = xmss_key_gen([3u8; 32], START, END, false).expect("keygen");
        let counter = AtomicSlotCounter::create(path, &pk, START, counter_end).expect("counter");
        SignerNode::new(pk, sk, counter)
    }

    #[test]
    fn signs_consecutive_slots_and_the_signatures_verify() {
        let path = scratch("ok");
        let mut signer = node(&path, END);
        let mut rng = rand::rng();
        let list = vec![hash_any(b"vc-1")];

        for expected in START..START + 3 {
            let message = status_list_root_fe(&list, expected);
            let (slot, sig) = signer.sign(&mut rng, &message).expect("sign");
            assert_eq!(slot, expected);
            assert!(xmss_verify(signer.public_key(), &message, &sig, slot).is_ok());
        }
        assert_eq!(signer.next_slot(), START + 3);
    }

    /// The property the whole design exists for: a failed signature still burns
    /// its slot. Here the counter is allowed past the key's real window, so
    /// leanVM rejects the slot — and the counter moves on regardless.
    #[test]
    fn a_failed_signature_still_consumes_its_slot() {
        let path = scratch("burn");
        let mut signer = node(&path, END + 5); // counter outlives the key window
        let mut rng = rand::rng();
        let message = status_list_root_fe(&[hash_any(b"vc")], 0);

        // Drain the slots the key can actually sign.
        for _ in START..=END {
            signer.sign(&mut rng, &message).expect("in-window sign");
        }
        assert_eq!(signer.next_slot(), END + 1);

        // Now leanVM refuses: the slot is outside the key's range.
        assert!(matches!(
            signer.sign(&mut rng, &message),
            Err(SignerNodeError::Sign(_))
        ));
        // ...and the slot was spent anyway. This is the point.
        assert_eq!(signer.next_slot(), END + 2);

        // A second failure burns another one rather than retrying END + 1.
        assert!(signer.sign(&mut rng, &message).is_err());
        assert_eq!(signer.next_slot(), END + 3);
    }

    #[test]
    fn exhaustion_is_reported_not_wrapped_around() {
        let path = scratch("exhaust");
        let mut signer = node(&path, START + 1);
        let mut rng = rand::rng();
        let message = status_list_root_fe(&[hash_any(b"vc")], 0);

        signer.sign(&mut rng, &message).expect("first");
        signer.sign(&mut rng, &message).expect("second");
        assert_eq!(signer.remaining_slots(), 0);
        assert!(matches!(
            signer.sign(&mut rng, &message),
            Err(SignerNodeError::Slot(
                AtomicSlotCounterError::Exhausted { .. }
            ))
        ));
    }
}
