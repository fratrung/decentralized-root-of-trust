//! Network bootstrap: the step that turns ten independent key holders into a
//! committee.
//!
//! It publishes the run identifier, waits for every member to drop its public
//! key on the shared volume, and assembles the anchor in **index order**, which
//! is what makes a bitmap position mean something later on. Then it exits: there
//! is no coordinator in this system, and the one component that looks like one
//! is not running while the protocol is.
//!
//! It never sees a secret key. Members derive their own from a per-container
//! secret and the run identifier, so this step learns exactly what a relying
//! party learns: ten public keys and their order.
//!
//! Idempotent on purpose. A restart with the run identifier already in place
//! re-assembles the same anchor from the same keys rather than rotating the
//! committee under counters that are still live.

use std::time::{Duration, Instant};

use decentralized_root_of_trust::params::SLOT;
use decentralized_root_of_trust::protocol::committee::Committee;
use drot_demo::config::{N_MEMBERS, THRESHOLD};
use drot_demo::storage;
use drot_demo::vc::hex;
use lean_multisig::XmssPublicKey;
use rand::RngExt;
use ssz::Decode as _;

/// How long to wait for the slowest member to publish its key.
const KEY_WAIT: Duration = Duration::from_secs(300);

fn main() {
    let dir = storage::committee_dir();
    let run_id_path = dir.join(storage::RUN_ID);

    let run_id = match std::fs::read(&run_id_path) {
        Ok(id) if !id.is_empty() => {
            println!("bootstrap: resuming run {}", hex(&id[..8.min(id.len())]));
            id
        }
        _ => {
            // A new run means new member keys, so anything left over from the
            // previous one names keys that no longer exist. Clearing here rather
            // than leaving it to the operator is what keeps a stale record from
            // being read as a verification failure.
            reset();
            let id: [u8; 32] = rand::rng().random();
            storage::write_atomic(&run_id_path, &id).expect("cannot publish the run identifier");
            println!("bootstrap: new run {}", hex(&id[..8]));
            id.to_vec()
        }
    };
    let _ = run_id;

    println!("bootstrap: waiting for {N_MEMBERS} member keys...");
    let deadline = Instant::now() + KEY_WAIT;
    let mut members: Vec<XmssPublicKey> = Vec::with_capacity(N_MEMBERS);
    for index in 0..N_MEMBERS {
        let path = storage::member_key_file(index);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let bytes = storage::wait_for(&path, remaining)
            .unwrap_or_else(|e| panic!("member {index} never published a key: {e}"));
        let pk = XmssPublicKey::from_ssz_bytes(&bytes)
            .unwrap_or_else(|e| panic!("member {index} published a malformed key: {e:?}"));
        println!(
            "  member {index:>2} at {:<15} key published",
            drot_demo::config::MEMBER_IPS[index]
        );
        members.push(pk);
    }

    // The order is the whole point: `members[i]` is the key that bit `i` of a
    // record's bitmap names, and the loop above fills the vector by index rather
    // than by arrival, so a slow member does not renumber the committee.
    let committee = Committee::new(members, THRESHOLD, SLOT);
    storage::write_atomic(&dir.join(storage::ANCHOR), &committee.to_bytes())
        .expect("cannot publish the anchor");

    println!(
        "\nbootstrap: anchor published, {}-of-{} committee, genesis slot {SLOT}",
        committee.threshold(),
        committee.members().len()
    );
    println!(
        "           {} bytes, and the only thing a verifier needs a priori",
        committee.to_bytes().len()
    );
}

/// Clears both shared volumes. Called only when there is no run identifier, that
/// is, when the committee about to be built is genuinely new.
fn reset() {
    for dir in [storage::committee_dir(), storage::storage_dir()] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}
