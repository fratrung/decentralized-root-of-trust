//! Status list controlled by a t-of-N committee (leanVM).
//!  - one-time prover setup (measured: bytecode vs. extra)
//!  - N_UPDATES sequential updates, rotating the `t` signers over the `N`
//!    members at each update (each update = a new XMSS slot; the aggregated
//!    proof IS the signature of the update)
//!  - two final security tests that MUST be rejected:
//!      A) a tampered list carrying a valid proof of a DIFFERENT list
//!      B) a proof from signers OUTSIDE the committee

use std::time::{Duration, Instant};

use decentralized_root_of_trust::committee::{Committee, make_proof, verify_proof};
use decentralized_root_of_trust::status_list::{
    Algorithms, StatusList, hash_any, status_list_root_fe,
};
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, setup_prover, setup_verifier, xmss_key_gen,
    xmss_sign,
};
use rand::RngExt;
use rand::rngs::ThreadRng;

const SLOT: u32 = 43;
const N_MEMBERS: usize = 10;
const T: usize = 7;
const N_UPDATES: usize = 10;
const LOG_INV_RATE: usize = 2;

fn status_mb(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix(field)
                    .map(|v| v.trim().trim_end_matches(" kB").trim().to_string())
            })
        })
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}
fn rss_now_mb() -> u64 {
    status_mb("VmRSS:")
}
fn peak_rss_mb() -> u64 {
    status_mb("VmHWM:")
}

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
    committee: Committee,
    rng: &mut ThreadRng,
) -> (StatusList, Duration, Duration, Duration) {
    let message = status_list_root_fe(&list);

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

    let status_list = StatusList::new(Algorithms::WotsXmss, list, slot, zk_proof);

    let t_verify = Instant::now();
    let ok = verify_proof(committee, &status_list);
    let verify_time = t_verify.elapsed();
    assert!(ok, "a legitimate update failed to verify");

    (status_list, sign_time, prove_time, verify_time)
}

/// Signs `list` with `signers` at `slot` and returns just the proof bytes.
fn make_signed_proof(
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    list: &[[u8; 32]],
    slot: u32,
    rng: &mut ThreadRng,
) -> Vec<u8> {
    let message = status_list_root_fe(list);
    let mut raws = Vec::new();
    for &i in signers {
        let (sk, pk) = &keypairs[i];
        raws.push((
            pk.clone(),
            xmss_sign(rng, sk, &message, slot).expect("signing failed"),
        ));
    }
    make_proof(raws, message, slot, LOG_INV_RATE)
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
        keypairs.push(xmss_key_gen(seed, SLOT, SLOT + 64, false).expect("keygen failed"));
    }
    let members: Vec<XmssPublicKey> = keypairs.iter().map(|(_, pk)| pk.clone()).collect();
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
        let slot = SLOT + i as u32;
        let (sl, s, p, v) = run_flow(
            &keypairs,
            &signers,
            list.clone(),
            slot,
            Committee::new(members.clone(), T),
            &mut rng,
        );
        let rss = rss_now_mb();
        rss_updates_max = rss_updates_max.max(rss);
        let who: String = signers
            .iter()
            .map(|&j| char::from(b'A' + j as u8))
            .collect();
        println!(
            "  update {:2}/{}  signers {}  slot {}  prove={:>8.1?}  verify={:>8.1?}  RAM={} MB  OK",
            i + 1,
            N_UPDATES,
            who,
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

    // ---- SECURITY TESTS (both must be REJECTED) ----
    // A) tampered list carrying a valid proof of a DIFFERENT list.
    let honest_slot = SLOT + N_UPDATES as u32;
    let quorum: Vec<usize> = (0..T).collect();
    let good_proof = make_signed_proof(&keypairs, &quorum, &list, honest_slot, &mut rng);
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION")); // row not authorized by the committee
    let sl_tampered = StatusList::new(Algorithms::WotsXmss, tampered, honest_slot, good_proof);
    let tamper_rejected = !verify_proof(Committee::new(members.clone(), T), &sl_tampered);

    // B) proof from signers OUTSIDE the committee (keys not in it).
    let mut outsiders: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..T {
        let seed: [u8; 32] = rng.random();
        outsiders.push(xmss_key_gen(seed, SLOT, SLOT + 64, false).expect("outsider keygen"));
    }
    let out_list = vec![hash_any(rng.random::<[u8; 32]>())];
    let out_proof = make_signed_proof(&outsiders, &quorum, &out_list, SLOT, &mut rng);
    let sl_outsider = StatusList::new(Algorithms::WotsXmss, out_list, SLOT, out_proof);
    let outsider_rejected = !verify_proof(Committee::new(members.clone(), T), &sl_outsider);

    let sec_ok = tamper_rejected && outsider_rejected;

    // summary
    let rss_peak = peak_rss_mb();
    let (sg_min, sg_med, sg_max) = dur_stats(&sign_ts);
    let (pv_min, pv_med, pv_max) = dur_stats(&prove_ts);
    let (vf_min, vf_med, vf_max) = dur_stats(&verify_ts);
    let proof_med = usize_median(&proof_sizes);

    println!("\n Security (expected: both REJECTED)");
    println!("A) tampered list + valid proof : rejected = {tamper_rejected}");
    println!("B) proof from outside signers  : rejected = {outsider_rejected}");
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
