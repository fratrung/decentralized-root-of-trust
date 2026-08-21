//! The credential the holder asks for, and the fingerprint the committee signs.
//!
//! The status list holds fingerprints, never credentials: 32 bytes per entry,
//! and nothing about the subject on a volume everybody reads. What makes the
//! fingerprint checkable by the holder is that it is taken over the credential's
//! **canonical** form, so the bytes it hashes are the bytes the issuer hashed.
//! JCS fixes key order and number formatting; without it, two serialisers of the
//! same credential produce two fingerprints and only one of them is in the list.

use decentralized_root_of_trust::protocol::status_list::hash_any;
use rand::RngExt;
use serde_json::json;

/// Mints a credential for `subject`, recording the list version it is being
/// registered in and the member that issued it.
///
/// The identifier is random so that two runs, or two requests from one holder,
/// never produce the same fingerprint. Distinct entries are what make the list
/// grow; a repeated one would be indistinguishable from a replay.
pub fn issue(subject: &str, version: u32, issuer_index: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let id: [u8; 16] = rng.random();
    let credential = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "DemoStatusCredential"],
        "id": format!("urn:uuid:{}", hex(&id)),
        "issuer": format!("did:demo:committee#member-{issuer_index}"),
        "credentialSubject": { "id": subject },
        "credentialStatus": {
            "type": "CommitteeStatusList",
            "statusListVersion": version,
        },
    });
    serde_jcs::to_vec(&credential).expect("a credential is always serialisable")
}

/// The 32-byte entry a credential occupies in the status list.
///
/// Taken over the canonical bytes as they travel, so the holder recomputes it
/// from what it received rather than from a re-serialisation of its own.
pub fn fingerprint(credential: &[u8]) -> [u8; 32] {
    hash_any(credential)
}

/// The credential as it should be read by a human, for the demo log.
pub fn pretty(credential: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(credential)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or_else(|_| String::from_utf8_lossy(credential).into_owned())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
