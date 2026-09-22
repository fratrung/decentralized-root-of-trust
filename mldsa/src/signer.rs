use getrandom::SysRng;
use ml_dsa::{Generate, Keypair, MlDsa65, SigningKey, VerifyingKey};

pub use ml_dsa::Seed;

/// An ML-DSA-65 public key.
pub type PublicKey = VerifyingKey<MlDsa65>;

/// An ML-DSA-65 signature.
pub type Signature = ml_dsa::Signature<MlDsa65>;

/// One stateless ML-DSA-65 committee member.
///
/// Unlike XMSS, ML-DSA does not consume a leaf/slot when signing. The caller
/// must nevertheless preserve this member's secret seed securely across
/// restarts; generate alone creates a fresh identity each time.
pub struct MlDsa65Signer {
    signing_key: SigningKey<MlDsa65>,
}

impl MlDsa65Signer {
    /// Generate a new member identity using the operating system's CSPRNG.
    ///
    /// Returns an error if system randomness is unavailable.
    pub fn generate() -> Result<Self, getrandom::Error> {
        Ok(Self {
            signing_key: SigningKey::try_generate()?,
        })
    }

    /// Restore a member identity from its secret seed.
    ///
    /// The caller is responsible for reading and protecting that seed.
    pub fn from_seed(seed: &Seed) -> Self {
        Self {
            signing_key: SigningKey::from_seed(seed),
        }
    }

    /// Export the 32-byte secret seed for secure, durable storage.
    ///
    /// This is private key material, not a public identifier. Copies returned
    /// by this method must be protected and explicitly erased by the caller.
    pub fn export_seed(&self) -> Seed {
        self.signing_key.to_seed()
    }

    /// Return this member's public verification key.
    pub fn public_key(&self) -> PublicKey {
        self.signing_key.verifying_key()
    }

    /// Randomized (hedged) ML-DSA-65 signature of a byte message.
    ///
    /// This generic API uses the empty FIPS 204 context. Protocol callers must
    /// define their own unambiguous, domain-separated message framing; this
    /// signer does not create a status-list message or select a version.
    /// Each call obtains fresh randomness and fails if the OS CSPRNG fails.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, ml_dsa::Error> {
        self.signing_key
            .expanded_key()
            .sign_randomized(message, b"", &mut SysRng)
    }
}

/// Verify one ML-DSA-65 signature under the empty FIPS 204 context.
///
/// This only checks the cryptographic signature. It does not establish
/// committee membership, quorum, list/version binding, or freshness.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify_with_context(message, b"", signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_reject_wrong_message_or_key() {
        let signer = MlDsa65Signer::generate().unwrap();
        let other = MlDsa65Signer::generate().unwrap();
        let message = b"message of arbitrary length";
        let signature = signer.sign(message).unwrap();

        assert!(verify(&signer.public_key(), message, &signature));
        assert!(!verify(&other.public_key(), message, &signature));
        assert!(!verify(
            &signer.public_key(),
            b"a different message",
            &signature
        ));
        assert!(
            !signer
                .public_key()
                .verify_with_context(message, b"other", &signature)
        );
    }

    #[test]
    fn accepts_empty_and_non_32_byte_messages() {
        let signer = MlDsa65Signer::generate().unwrap();
        let messages: [&[u8]; 3] = [b"", b"short", &[0x42; 257]];
        for message in messages {
            let signature = signer.sign(message).unwrap();
            assert!(verify(&signer.public_key(), message, &signature));
        }
    }

    #[test]
    fn seed_restores_identity_and_repeated_signing_is_safe() {
        let signer = MlDsa65Signer::generate().unwrap();
        let seed = signer.export_seed();
        let restored = MlDsa65Signer::from_seed(&seed);
        let message = [0x24; 32];

        assert_eq!(signer.public_key(), restored.public_key());
        let first = signer.sign(&message).unwrap();
        let second = restored.sign(&message).unwrap();
        assert!(verify(&signer.public_key(), &message, &first));
        assert!(verify(&signer.public_key(), &message, &second));
        assert_ne!(first.encode(), second.encode());
    }
}
