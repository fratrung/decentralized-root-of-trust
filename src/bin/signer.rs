//! One committee **member**, measured on its own: the third role, and the only
//! one the other binaries never isolate.
//!
//! In production nobody produces `t` signatures. Each member signs **once** per
//! round on its own machine and broadcasts; the aggregator receives `t`
//! signatures and produces none. So a `sign` figure taken from a process that
//! signs `t` times is the summed work of `t` machines attributed to one, which
//! describes no process that exists. This binary measures what a member actually
//! pays for a round: one `xmss_sign`, preceded by one durable slot burn.
//!
//! That makes the two published forms comparable by construction. The signing
//! cost is *identical* on the raw and SNARK paths (same key, same 32-byte
//! message, same derived slot), so what separates them is only how the quorum is
//! evidenced and what a relying party pays to check it.
//!
//! It is also the cheapest role by a wide margin: a signer holds one key and one
//! counter, and its resident memory is measured in megabytes where the
//! aggregator's is measured in gigabytes.
//!
//! Usage: cargo run --release --bin signer          (always --release)

use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::bench::stats::Series;
use decentralized_root_of_trust::node::signer::SignerNode;
use decentralized_root_of_trust::params::{KEY_SLOT_COUNT, KEY_SLOTS, N_UPDATES, SLOT};
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{Algorithms, hash_any};
use decentralized_root_of_trust::state::slot_counter::AtomicSlotCounter;
use lean_multisig::{xmss_key_gen, xmss_verify};
use rand::RngExt;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    // The counter outlives the process in a real deployment; here the key is
    // regenerated every run, so the two die together. Deleting the state of a key
    // that still exists is how slots get reused.
    let state = std::env::temp_dir().join(format!("signer-bench-{}", std::process::id()));
    for ext in ["", "lock", "tmp"] {
        let p = if ext.is_empty() {
            state.clone()
        } else {
            state.with_extension(ext)
        };
        let _ = std::fs::remove_file(p);
    }

    let rss_baseline = rss_now_mb();
    let mut rng = rand::rng();

    // One key, not `N`: a member generates its own and nobody else's. This is the
    // fixed cost a member pays, where `prover`/`raw_agg` report the whole
    // committee's because they stand in for all of it.
    println!("signer: keygen (one key, no circuit)...");
    let t_keygen = Instant::now();
    let (pk, sk) = xmss_key_gen(&mut rng, u64::from(SLOT), KEY_SLOT_COUNT).expect("keygen failed");
    let keygen_time = t_keygen.elapsed();

    let t_state = Instant::now();
    let counter =
        AtomicSlotCounter::create(&state, &pk, SLOT, SLOT + KEY_SLOTS).expect("slot state");
    let slot_state_time = t_state.elapsed();
    let rss_after_keygen = rss_now_mb();

    // The anchor is what turns a version into a slot. A member needs nothing else
    // from it to sign, so a one-member committee is enough here: `slot_for` reads
    // only the genesis slot, and deriving is the whole point: no member is ever
    // told which slot to use.
    let committee = Committee::new(vec![pk.clone()], 1, SLOT);
    let mut signer = SignerNode::new(pk, sk, counter);

    println!("{N_UPDATES} rounds, one signature each at the slot the anchor derives\n");

    let mut list: Vec<[u8; 32]> = Vec::new();
    let mut sign_ms = Vec::new();
    let mut failures = 0usize;
    let mut rss_max = rss_after_keygen;

    for i in 0..N_UPDATES {
        list.push(hash_any(rng.random::<[u8; 32]>()));
        let version = i as u32;
        let slot = committee.slot_for(version).expect("slot overflow");
        // Computing the digest is not timed: it is the same work for every member
        // and for the verifier, it is O(list), and it is not what this binary is
        // about. What is timed is the member's own cost: the durable burn and the
        // signature.
        let message = committee.message_for(Algorithms::WotsXmss, &list, version);

        let t_sign = Instant::now();
        let signature = signer.sign_at(&message, slot).expect("signing failed");
        let sign_time = t_sign.elapsed();

        // Not part of a member's job, and not timed: a cheap guard that the run
        // produced real signatures rather than measuring an error path.
        if xmss_verify(signer.public_key(), slot, &message, &signature).is_err() {
            failures += 1;
        }

        let rss = rss_now_mb();
        rss_max = rss_max.max(rss);
        println!(
            "  round {:2}/{}  v{}  slot {}  sign={:>8.1?}  {} B  RAM={} MB",
            i + 1,
            N_UPDATES,
            version,
            slot,
            sign_time,
            lean_multisig::SIGNATURE_SSZ_LEN,
            rss
        );
        if emit_samples {
            println!(
                "SAMPLE target=signer idx={i} sign_ms={:.3} bytes={} rss_mb={rss}",
                ms(sign_time),
                lean_multisig::SIGNATURE_SSZ_LEN
            );
        }
        sign_ms.push(ms(sign_time));
    }

    let sign = Series::new(sign_ms);
    let (sg_min, sg_med, sg_max) = sign.min_med_max();

    println!("\nkeygen (1 key)         : {keygen_time:.2?}");
    println!("slot state (1 counter) : {slot_state_time:.2?}   (durable, fsync'd)");
    println!("--- per round (one member): min / median / max ---");
    println!("sign     : {sg_min:.2} / {sg_med:.2} / {sg_max:.2} ms   (incl. durable slot burn)");
    println!(
        "signature size         : {} B",
        lean_multisig::SIGNATURE_SSZ_LEN
    );
    println!("\nRAM (signer process)");
    println!("baseline (pre-keygen)  : {rss_baseline} MB");
    println!("after keygen (resident): {rss_after_keygen} MB");
    println!("max during rounds      : {rss_max} MB");
    println!("peak (VmHWM)           : {} MB", peak_rss_mb());

    println!(
        "\nSIGNER keygen_ms={:.3} slot_state_ms={:.3} n_rounds={} \
         sign_med_ms={sg_med:.3} sign_mean_ms={:.3} sign_sd_ms={:.3} sign_min_ms={sg_min:.3} \
         sign_max_ms={sg_max:.3} sign_total_ms={:.3} sig_bytes={} \
         rss_keygen_mb={rss_after_keygen} rss_rounds_max_mb={rss_max} peak_rss_mb={} \
         failures={failures}",
        ms(keygen_time),
        ms(slot_state_time),
        sign.len(),
        sign.mean(),
        sign.stddev(),
        sign.sum(),
        lean_multisig::SIGNATURE_SSZ_LEN,
        peak_rss_mb(),
    );

    // The counter dies with the key it belongs to; see the note at the top.
    drop(signer);
    for ext in ["", "lock", "tmp"] {
        let p = if ext.is_empty() {
            state.clone()
        } else {
            state.with_extension(ext)
        };
        let _ = std::fs::remove_file(p);
    }

    if failures > 0 {
        eprintln!("\n{failures} signature(s) failed to verify");
        std::process::exit(1);
    }
}
