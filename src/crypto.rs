//! Narrow compatibility boundary around leanVM v0.10.
//!
//! The protocol uses count-based XMSS ranges and one-message aggregates. leanVM
//! v0.10 exposes inclusive epoch ranges and general mixed XMSS/SPHINCS
//! aggregates, so those translations live here instead of being copied across
//! signers, verifiers, binaries and the network demo.

use rand::RngExt as _;

pub use leanvm::xmss::{SIGNATURE_SSZ_LEN, XmssPublicKey, XmssSecretKey, XmssSignature};
pub use leanvm::{
    AggregateSignature, AggregateVerifyError, AggregationError, setup_prover,
    setup_prover_without_arena, setup_verifier,
};

pub const MESSAGE_LEN_BYTES: usize = leanvm::xmss::MESSAGE_LEN;
pub type SingleMessageAggregateSignature = AggregateSignature;

fn inclusive_epoch_range(start: u64, count: u64) -> Result<(u32, u32), String> {
    if count == 0 {
        return Err("an XMSS key must cover at least one epoch".to_string());
    }
    let end = start
        .checked_add(count - 1)
        .ok_or("XMSS epoch range overflows u64")?;
    let start = u32::try_from(start).map_err(|_| "XMSS start epoch exceeds u32")?;
    let end = u32::try_from(end).map_err(|_| "XMSS end epoch exceeds u32")?;
    Ok((start, end))
}

/// Generates a key for `count` epochs starting at `start`.
///
/// This preserves this crate's existing count-based contract while adapting it
/// once to leanVM v0.10's inclusive `start..=end` API. A seed is drawn from the
/// caller's rand 0.10 RNG, avoiding a rand-trait mismatch with leanVM's rand 0.9.
pub fn xmss_key_gen(
    rng: &mut impl rand::CryptoRng,
    start: u64,
    count: u64,
) -> Result<(XmssPublicKey, XmssSecretKey), String> {
    let seed: [u8; 32] = rng.random();
    xmss_key_gen_from_seed(seed, start, count)
}

/// Deterministic counterpart to [`xmss_key_gen`].
pub fn xmss_key_gen_from_seed(
    seed: [u8; 32],
    start: u64,
    count: u64,
) -> Result<(XmssPublicKey, XmssSecretKey), String> {
    let (start, end) = inclusive_epoch_range(start, count)?;
    let (secret, public) = leanvm::xmss::key_gen_from_seed(seed, start, end)
        .map_err(|e| format!("XMSS key generation failed: {e}"))?;
    Ok((public, secret))
}

/// Signs one 32-byte message at one epoch.
///
/// v0.10 randomizes every XMSS signature. The durable slot allocator therefore
/// remains mandatory even when a retry would sign identical message bytes.
pub fn xmss_sign(
    secret: &XmssSecretKey,
    epoch: u32,
    message: &[u8; MESSAGE_LEN_BYTES],
) -> Result<XmssSignature, String> {
    let mut rng = leanvm::rand::rng();
    leanvm::xmss::sign(&mut rng, secret, message, epoch)
        .map_err(|e| format!("XMSS signing failed: {e}"))
}

pub fn xmss_verify(
    public: &XmssPublicKey,
    epoch: u32,
    message: &[u8; MESSAGE_LEN_BYTES],
    signature: &XmssSignature,
) -> Result<(), String> {
    leanvm::xmss::verify(public, message, signature, epoch)
        .map_err(|e| format!("XMSS verification failed: {e}"))
}

/// Aggregates this protocol's single XMSS `(epoch, message)` group.
pub fn aggregate_single_message_signatures(
    children: &[AggregateSignature],
    signatures: Vec<(XmssPublicKey, XmssSignature)>,
    message: [u8; MESSAGE_LEN_BYTES],
    epoch: u32,
    log_inv_rate: usize,
) -> Result<AggregateSignature, AggregationError> {
    let signatures = signatures
        .into_iter()
        .map(|(public, signature)| (public, epoch, message, signature))
        .collect();
    leanvm::aggregate(children, signatures, Vec::new(), None, log_inv_rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_range_is_translated_to_an_inclusive_end() {
        assert_eq!(inclusive_epoch_range(100, 3).unwrap(), (100, 102));
        assert!(inclusive_epoch_range(100, 0).is_err());
        assert!(inclusive_epoch_range(u64::from(u32::MAX), 2).is_err());
    }
}
