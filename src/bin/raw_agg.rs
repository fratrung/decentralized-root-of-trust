//! Baseline: the **crude** aggregate-signature path, with no SNARK at all.
//!
//! This is the yardstick the SNARK-aggregated prover/verifier are measured
//! against. Here an "aggregate" is nothing clever — it is just the bundle of the
//! `t` individual XMSS signatures a quorum produces for one update. There is no
//! proof to build and no proof to check: each update is signed with `t`
//! `xmss_sign` calls and verified with `t` `xmss_verify` calls, using the raw
//! leanVM APIs directly.
//!
//! Note what this binary does **not** call: neither `setup_prover()` nor
//! `setup_verifier()`. Raw XMSS sign/verify are pure Poseidon2 — no circuit, no
//! arena, no FFT twiddles. That absence is itself a result: it is the fixed cost
//! the SNARK path pays and this one does not.
//!
//! What the comparison exposes is the trade the SNARK makes. The crude path has
//! trivially cheap per-signature verification, but the wire payload grows with
//! `t` (you ship `t` full signatures) and the verifier's work grows with `t`
//! (you check `t` of them). The SNARK collapses both to a single constant-size
//! proof and one verification, at the price of an expensive prover. This file
//! quantifies the "before".
//!
//! Usage: cargo run --release --bin raw_agg          (always --release)

use std::time::{Duration, Instant};

use decentralized_root_of_trust::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::params::{KEY_SLOTS, N_MEMBERS, N_UPDATES, SLOT, T};
use decentralized_root_of_trust::stats::Series;
use decentralized_root_of_trust::status_list::{hash_any, status_list_root_fe};
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen, xmss_sign, xmss_verify,
};
use rand::RngExt;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    // Off by default so interactive runs stay readable; the benchmark harness
    // sets it to collect one row per update.
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    let rss_baseline = rss_now_mb();

    // ---- One-time cost: generate the committee's N keys. ----
    // This is the crude path's only fixed cost — the counterpart to the SNARK
    // path's setup_prover(). Each key covers a KEY_SLOTS-wide slot window.
    println!("raw_agg: keygen (no SNARK setup, no circuit)...");
    let mut rng = rand::rng();
    let t_keygen = Instant::now();
    let mut keypairs: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::with_capacity(N_MEMBERS);
    for _ in 0..N_MEMBERS {
        let seed: [u8; 32] = rng.random();
        keypairs.push(xmss_key_gen(seed, SLOT, SLOT + KEY_SLOTS, false).expect("keygen failed"));
    }
    let keygen_time = t_keygen.elapsed();
    let rss_after_keygen = rss_now_mb();

    println!("committee N={N_MEMBERS} t={T}; {N_UPDATES} updates rotating the signers");
    println!("aggregate = {T} raw XMSS signatures (no proof)\n");

    // ---- N_UPDATES updates. For each: t signers sign the (list, version) root,
    //      the t signatures ARE the aggregate, then all t are verified. ----
    let mut list: Vec<[u8; 32]> = Vec::new();
    let mut sign_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut agg_bytes = Vec::new();
    let mut total_verified = 0usize;
    let mut total_expected = 0usize;
    let mut rss_updates_max = rss_after_keygen;

    for i in 0..N_UPDATES {
        list.push(hash_any(rng.random::<[u8; 32]>()));
        // t signers out of N, rotating the window at each update.
        let signers: Vec<usize> = (0..T).map(|j| (i + j) % N_MEMBERS).collect();
        // slot is the XMSS epoch (stateful, one per update); version is the
        // application counter, both bound into the signed message.
        let slot = SLOT + i as u32;
        let version = i as u32;
        let message = status_list_root_fe(&list, version);

        // Sign: t plain XMSS signatures, no circuit. Scales linearly in t.
        let t_sign = Instant::now();
        let mut raws: Vec<(XmssPublicKey, XmssSignature)> = Vec::with_capacity(signers.len());
        for &k in &signers {
            let (sk, pk) = &keypairs[k];
            raws.push((
                pk.clone(),
                xmss_sign(&mut rng, sk, &message, slot).expect("signing failed"),
            ));
        }
        let sign_time = t_sign.elapsed();

        // The crude aggregate is exactly this bundle. Its serialized size is the
        // wire payload — the honest analog of the SNARK's proof_bytes, and the
        // number that grows with t while the SNARK's stays constant.
        let wire = postcard::to_allocvec(&raws).expect("aggregate serialization failed");

        // Verify: t independent xmss_verify calls, all of which must pass.
        let t_verify = Instant::now();
        let mut ok = 0usize;
        for (pk, sig) in &raws {
            if xmss_verify(pk, &message, sig, slot).is_ok() {
                ok += 1;
            }
        }
        let verify_time = t_verify.elapsed();
        total_verified += ok;
        total_expected += raws.len();
        assert_eq!(ok, raws.len(), "a legitimate signature failed to verify");

        let rss = rss_now_mb();
        rss_updates_max = rss_updates_max.max(rss);
        println!(
            "  update {:2}/{}  v{}  slot {}  sign={:>8.1?}  verify={:>8.1?}  {} B  RAM={} MB",
            i + 1,
            N_UPDATES,
            version,
            slot,
            sign_time,
            verify_time,
            wire.len(),
            rss
        );
        if emit_samples {
            println!(
                "SAMPLE target=raw_agg idx={i} sign_ms={:.3} verify_ms={:.3} bytes={} rss_mb={rss}",
                ms(sign_time),
                ms(verify_time),
                wire.len()
            );
        }
        sign_ms.push(ms(sign_time));
        verify_ms.push(ms(verify_time));
        agg_bytes.push(wire.len());
    }

    // ---- Sanity check: verification is not a no-op. A signature checked against
    //      the WRONG message (a version bump the signer never signed) must fail. ----
    let signers: Vec<usize> = (0..T).map(|j| j % N_MEMBERS).collect();
    let slot = SLOT;
    let good = status_list_root_fe(&list, 0);
    let (sk0, pk0) = &keypairs[signers[0]];
    let sig0 = xmss_sign(&mut rng, sk0, &good, slot).expect("signing failed");
    let wrong = status_list_root_fe(&list, 999);
    let tamper_rejected = xmss_verify(pk0, &wrong, &sig0, slot).is_err();

    // ---- Summary ----
    let sign = Series::new(sign_ms);
    let verify = Series::new(verify_ms);
    let (sg_min, sg_med, sg_max) = sign.min_med_max();
    let (vf_min, vf_med, vf_max) = verify.min_med_max();
    let agg_med = {
        let mut b = agg_bytes.clone();
        b.sort_unstable();
        b[b.len() / 2]
    };
    // Per-signature figures, derived from the medians: what one signature costs
    // in isolation, useful to project other t values.
    let per_sig_sign_us = sg_med * 1000.0 / T as f64;
    let per_sig_verify_us = vf_med * 1000.0 / T as f64;

    println!("\n{total_verified}/{total_expected} signatures verified (all updates)");
    println!("tamper check (wrong message rejected): {tamper_rejected}");

    println!("\nkeygen ({N_MEMBERS} keys)   : {keygen_time:.2?}");
    println!("--- per update (t={T}): min / median / max ---");
    println!("sign     : {sg_min:.1} / {sg_med:.1} / {sg_max:.1} ms");
    println!("verify   : {vf_min:.1} / {vf_med:.1} / {vf_max:.1} ms");
    println!("per signature : sign {per_sig_sign_us:.1} us  verify {per_sig_verify_us:.1} us");
    println!("aggregate size (median) : {agg_med} bytes  ({T} signatures)");

    println!("\nRAM (raw-multisig process, no SNARK)");
    println!("baseline (pre-keygen)  : {rss_baseline} MB");
    println!("after keygen (resident): {rss_after_keygen} MB");
    println!("max during updates     : {rss_updates_max} MB");
    println!("peak (VmHWM)           : {} MB", peak_rss_mb());

    // One-line machine-readable record, same convention as prover.rs / verifier.rs.
    // benchmark.sh maps work = verify (the metric that scales with t, unlike the
    // constant-time SNARK verify) and proof_size = the raw aggregate size.
    println!(
        "\nRAW_AGG keygen_ms={:.3} n_members={N_MEMBERS} t={T} n_updates={} \
         sign_med_ms={sg_med:.3} sign_mean_ms={:.3} sign_sd_ms={:.3} sign_min_ms={sg_min:.3} \
         sign_max_ms={sg_max:.3} sign_total_ms={:.3} verify_med_ms={vf_med:.3} \
         verify_mean_ms={:.3} verify_sd_ms={:.3} verify_min_ms={vf_min:.3} \
         verify_max_ms={vf_max:.3} verify_total_ms={:.3} \
         per_sig_sign_us={per_sig_sign_us:.3} per_sig_verify_us={per_sig_verify_us:.3} \
         agg_med_bytes={agg_med} rss_keygen_mb={rss_after_keygen} \
         rss_updates_max_mb={rss_updates_max} peak_rss_mb={} tamper_rejected={}",
        ms(keygen_time),
        sign.len(),
        sign.mean(),
        sign.stddev(),
        sign.sum(),
        verify.mean(),
        verify.stddev(),
        verify.sum(),
        peak_rss_mb(),
        tamper_rejected as u8,
    );
}
