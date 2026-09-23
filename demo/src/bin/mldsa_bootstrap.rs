//! Bootstrap for the ML-DSA demo committee.

use std::time::{Duration, Instant};

use drot_demo::config::{N_MEMBERS, THRESHOLD};
use drot_demo::{storage, vc};
use drot_mldsa::{Committee, PUBLIC_KEY_BYTES, decode_public_key};
use rand::RngExt;

const KEY_WAIT: Duration = Duration::from_secs(300);

fn main() {
    let dir = storage::committee_dir();
    let run_id_path = dir.join(storage::RUN_ID);

    match std::fs::read(&run_id_path) {
        Ok(id) if !id.is_empty() => {
            println!(
                "bootstrap: resuming run {}",
                vc::hex(&id[..8.min(id.len())])
            );
        }
        _ => {
            reset();
            let id: [u8; 32] = rand::rng().random();
            storage::write_atomic(&run_id_path, &id).expect("cannot publish run identifier");
            println!("bootstrap: new run {}", vc::hex(&id[..8]));
        }
    }

    println!("bootstrap: waiting for {N_MEMBERS} ML-DSA-65 public keys...");
    let deadline = Instant::now() + KEY_WAIT;
    let mut members = Vec::with_capacity(N_MEMBERS);
    for index in 0..N_MEMBERS {
        let bytes = storage::wait_for(
            &storage::member_key_file(index),
            deadline.saturating_duration_since(Instant::now()),
        )
        .unwrap_or_else(|e| panic!("member {index} never published a key: {e}"));
        let raw: [u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("member {index} key has {} bytes", v.len()));
        let key = decode_public_key(&raw)
            .unwrap_or_else(|e| panic!("member {index} published an invalid key: {e}"));
        println!(
            "  member {index:>2} at {:<15} key published",
            drot_demo::config::MEMBER_IPS[index]
        );
        members.push(key);
    }

    let committee = Committee::new(members, THRESHOLD).expect("invalid ML-DSA committee");
    let anchor = committee.to_bytes();
    storage::write_atomic(&dir.join(storage::ANCHOR), &anchor)
        .expect("cannot publish ML-DSA anchor");
    println!(
        "\nbootstrap: ML-DSA-65 anchor published, {}-of-{} committee, {} bytes",
        committee.threshold(),
        committee.member_count(),
        anchor.len()
    );
}

fn reset() {
    for dir in [storage::committee_dir(), storage::storage_dir()] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}
