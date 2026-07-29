//! Status list controlled by a t-of-N committee (leanVM).
//!  - one-time prover setup (measured: bytecode vs. extra)
//!  - N_UPDATES sequential updates, rotating the `t` signers over the `N`
//!    members at each update (each update = a new XMSS slot; the aggregated
//!    proof IS the signature of the update)
//!  - two final security tests that MUST be rejected:
//!      A) a tampered list carrying a valid proof of a DIFFERENT list
//!      B) a proof from signers OUTSIDE the committee

use std::time::{Duration, Instant};

use decentralized_root_of_trust::committee::{Committee, make_proof, sign_and_prove, verify_proof};
use decentralized_root_of_trust::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::params::{KEY_SLOTS, LOG_INV_RATE, N_MEMBERS, N_UPDATES, SLOT, T};
use decentralized_root_of_trust::status_list::{
    Algorithms, StatusList, hash_any, status_list_root_fe,
};
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, setup_prover, setup_verifier, xmss_key_gen,
    xmss_sign,
};
use rand::RngExt;
use rand::rngs::ThreadRng;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// (min, median, max) in ms of a series of durations.
fn dur_stats(v: &[Duration]) -> (f64, f64, f64) {
    let mut xs: Vec<f64> = v.iter().map(|d| ms(*d)).collect();
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    let median = if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    };
    (xs[0], median, xs[n - 1])
}

fn usize_median(v: &[usize]) -> usize {
    let mut xs = v.to_vec();
    xs.sort_unstable();
    xs[xs.len() / 2]
}

/// One round: the `signers` sign the root of `list` at `slot`, the signatures
/// are aggregated into ONE proof, the StatusList is built and verified against
/// the `committee`. Returns (status_list, sign_time, prove_time, verify_time).
fn run_flow(
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    list: Vec<[u8; 32]>,
    slot: u32,
    version: u32,
    committee: &Committee,
    rng: &mut ThreadRng,
) -> (StatusList, Duration, Duration, Duration) {
    // The signed message binds both the list and its version (Option B).
    let message = status_list_root_fe(&list, version);

    let t_sign = Instant::now();
    let mut raws: Vec<(XmssPublicKey, XmssSignature)> = Vec::new();
    for &i in signers {
        let (sk, pk) = &keypairs[i];
        let sig = xmss_sign(rng, sk, &message, slot).expect("signing failed");
        raws.push((pk.clone(), sig));
    }
    let sign_time = t_sign.elapsed();

    let t_prove = Instant::now();
    let zk_proof = make_proof(raws, message, slot, LOG_INV_RATE);
    let prove_time = t_prove.elapsed();

    let status_list = StatusList::new(Algorithms::WotsXmss, list, version, zk_proof);

    let t_verify = Instant::now();
    let ok = verify_proof(committee, &status_list);
    let verify_time = t_verify.elapsed();
    assert!(ok, "a legitimate update failed to verify");

    (status_list, sign_time, prove_time, verify_time)
}

/// Signs `(list, version)` with `signers` at `slot` and returns just the proof
/// bytes. `version` is bound into the message, so a proof made here is only valid
/// for that exact version.
fn make_signed_proof(
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    list: &[[u8; 32]],
    slot: u32,
    version: u32,
    rng: &mut ThreadRng,
) -> Vec<u8> {
    sign_and_prove(
        keypairs,
        signers,
        status_list_root_fe(list, version),
        slot,
        LOG_INV_RATE,
        rng,
    )
}

fn main() {
    let rss_baseline = rss_now_mb();

    println!("setup...");
    let t_v = Instant::now();
    setup_verifier();
    let setup_verifier_time = t_v.elapsed();
    let t_p = Instant::now();
    setup_prover();
    let setup_prover_extra = t_p.elapsed();
    let setup_prover_total = setup_verifier_time + setup_prover_extra;
    let rss_after_setup = rss_now_mb();

    let mut rng = rand::rng();

    // Committee: N_MEMBERS WOTS-XMSS keys.
    let mut keypairs: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..N_MEMBERS {
        let seed: [u8; 32] = rng.random();
        keypairs.push(xmss_key_gen(seed, SLOT, SLOT + KEY_SLOTS, false).expect("keygen failed"));
    }
    let members: Vec<XmssPublicKey> = keypairs.iter().map(|(_, pk)| pk.clone()).collect();
    // The fixed trust anchor, built once and shared by every verification below.
    let committee = Committee::new(members, T);
    println!("committee N={N_MEMBERS} t={T}; {N_UPDATES} updates rotating the signers\n");

    // ---- N_UPDATES updates, rotating the `t` signers over the `N` members ----
    let mut list: Vec<[u8; 32]> = Vec::new();
    let mut sign_ts = Vec::new();
    let mut prove_ts = Vec::new();
    let mut verify_ts = Vec::new();
    let mut proof_sizes = Vec::new();
    let mut rss_updates_max = rss_after_setup;

    let t_updates = Instant::now();
    for i in 0..N_UPDATES {
        list.push(hash_any(rng.random::<[u8; 32]>()));
        // t signers out of N, rotating the window at each update.
        let signers: Vec<usize> = (0..T).map(|j| (i + j) % N_MEMBERS).collect();
        // `slot` is the XMSS epoch (stateful, bounded by KEY_SLOTS); `version` is
        // the application counter bound into the signed message. They are
        // independent — the version keeps climbing across a future committee
        // re-key, when the slot window would reset.
        let slot = SLOT + i as u32;
        let version = i as u32;
        let (sl, s, p, v) = run_flow(
            &keypairs,
            &signers,
            list.clone(),
            slot,
            version,
            &committee,
            &mut rng,
        );
        let rss = rss_now_mb();
        rss_updates_max = rss_updates_max.max(rss);
        let who: String = signers
            .iter()
            .map(|&j| char::from(b'A' + j as u8))
            .collect();
        println!(
            "  update {:2}/{}  signers {}  v{}  slot {}  prove={:>8.1?}  verify={:>8.1?}  RAM={} MB  OK",
            i + 1,
            N_UPDATES,
            who,
            version,
            slot,
            p,
            v,
            rss
        );
        sign_ts.push(s);
        prove_ts.push(p);
        verify_ts.push(v);
        proof_sizes.push(sl.proof_bytes().len());
    }
    let updates_total = t_updates.elapsed();

    // ---- SECURITY TESTS (all must be REJECTED) ----
    let honest_slot = SLOT + N_UPDATES as u32;
    let honest_version = N_UPDATES as u32;
    let quorum: Vec<usize> = (0..T).collect();

    // A) tampered list carrying a valid proof of a DIFFERENT list.
    let good_proof = make_signed_proof(
        &keypairs,
        &quorum,
        &list,
        honest_slot,
        honest_version,
        &mut rng,
    );
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION")); // row not authorized by the committee
    let sl_tampered = StatusList::new(Algorithms::WotsXmss, tampered, honest_version, good_proof);
    let tamper_rejected = !verify_proof(&committee, &sl_tampered);

    // B) proof from signers OUTSIDE the committee (keys not in it).
    let mut outsiders: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..T {
        let seed: [u8; 32] = rng.random();
        outsiders.push(xmss_key_gen(seed, SLOT, SLOT + KEY_SLOTS, false).expect("outsider keygen"));
    }
    let out_list = vec![hash_any(rng.random::<[u8; 32]>())];
    let out_proof = make_signed_proof(&outsiders, &quorum, &out_list, SLOT, 0, &mut rng);
    let sl_outsider = StatusList::new(Algorithms::WotsXmss, out_list, 0, out_proof);
    let outsider_rejected = !verify_proof(&committee, &sl_outsider);

    // C) version spoof: a VALID proof of (list, version) re-labelled with a
    //    different version. Defeated only by the version binding of check 2 —
    //    before Option B, when `version` was cleartext-only, this was ACCEPTED.
    let spoof_slot = SLOT + N_UPDATES as u32 + 1;
    let signed_version = 5u32;
    let versioned_proof = make_signed_proof(
        &keypairs,
        &quorum,
        &list,
        spoof_slot,
        signed_version,
        &mut rng,
    );
    let sl_spoofed = StatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        signed_version + 1000,
        versioned_proof,
    );
    let version_rejected = !verify_proof(&committee, &sl_spoofed);

    let sec_ok = tamper_rejected && outsider_rejected && version_rejected;

    // summary
    let rss_peak = peak_rss_mb();
    let (sg_min, sg_med, sg_max) = dur_stats(&sign_ts);
    let (pv_min, pv_med, pv_max) = dur_stats(&prove_ts);
    let (vf_min, vf_med, vf_max) = dur_stats(&verify_ts);
    let proof_med = usize_median(&proof_sizes);

    println!("\n Security (expected: all REJECTED)");
    println!("A) tampered list + valid proof : rejected = {tamper_rejected}");
    println!("B) proof from outside signers  : rejected = {outsider_rejected}");
    println!("C) valid proof, spoofed version: rejected = {version_rejected}");
    println!("=> security OK: {sec_ok}");

    println!("\n Setup (one-time per process)");
    println!("setup_verifier (bytecode)      : {setup_verifier_time:.2?}");
    println!("setup_prover extra (arena+FFT) : {setup_prover_extra:.2?}");
    println!("setup_prover total             : {setup_prover_total:.2?}");

    println!("--- {N_UPDATES} updates: min / median / max ---");
    println!("sign     : {sg_min:.1} / {sg_med:.1} / {sg_max:.1} ms");
    println!("prove    : {pv_min:.1} / {pv_med:.1} / {pv_max:.1} ms");
    println!("verify   : {vf_min:.1} / {vf_med:.1} / {vf_max:.1} ms");
    println!("proof size (median) : {proof_med} bytes");
    println!("total {N_UPDATES} updates : {updates_total:.2?}");

    println!(" RAM ");
    println!("baseline (pre-setup)   : {rss_baseline} MB");
    println!("after setup (resident) : {rss_after_setup} MB");
    println!("max during updates     : {rss_updates_max} MB");
    println!("peak (VmHWM)           : {rss_peak} MB");

    // BENCH: ONE line, space-separated key=value fields, read by benchmark.sh.
    // Units: *_ms in ms, *_bytes in bytes, *_mb in MB, sec_ok in {0,1}.
    let bench = [
        format!("setup_verifier_ms={:.3}", ms(setup_verifier_time)),
        format!("setup_prover_extra_ms={:.3}", ms(setup_prover_extra)),
        format!("setup_total_ms={:.3}", ms(setup_prover_total)),
        format!("upd_sign_med_ms={sg_med:.3}"),
        format!("upd_prove_med_ms={pv_med:.3}"),
        format!("upd_prove_min_ms={pv_min:.3}"),
        format!("upd_prove_max_ms={pv_max:.3}"),
        format!("upd_verify_med_ms={vf_med:.3}"),
        format!("updates_total_ms={:.3}", ms(updates_total)),
        format!("proof_med_bytes={proof_med}"),
        format!("rss_setup_mb={rss_after_setup}"),
        format!("rss_updates_max_mb={rss_updates_max}"),
        format!("peak_rss_mb={rss_peak}"),
        format!("sec_ok={}", sec_ok as u8),
    ]
    .join(" ");
    println!("\nBENCH {bench}");
}
