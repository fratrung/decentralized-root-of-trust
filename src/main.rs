//! Status list controlled by a t-of-N committee (leanVM).
//!
//! - one-time prover setup (measured: bytecode vs. extra)
//! - `N_UPDATES` sequential updates, rotating the `t` signers over the `N`
//!   members at each update (each update = a new XMSS slot; the aggregated
//!   proof IS the signature of the update)
//! - three final security tests, each of which MUST be rejected:
//!   - A) a tampered list carrying a valid proof of a DIFFERENT list
//!   - B) a proof from signers OUTSIDE the committee
//!   - C) a valid proof re-labelled with a spoofed version

use std::time::{Duration, Instant};

use decentralized_root_of_trust::committee::Committee;
use decentralized_root_of_trust::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::params::{
    KEY_SLOT_COUNT, KEY_SLOTS, LOG_INV_RATE, N_MEMBERS, N_UPDATES, SLOT, T,
};
use decentralized_root_of_trust::snark_prover_node::PQSNARKProverModule;
use decentralized_root_of_trust::snark_verifier_node::PQSNARKVerifierModule;
use decentralized_root_of_trust::status_list::{
    Algorithms, SnarkStatusList, hash_any, status_list_message,
};
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, setup_prover, setup_verifier, xmss_key_gen,
    xmss_sign,
};
use rand::RngExt;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// (min, median, max) in ms of a series of durations.
/// `(min, median, max)` in ms. Panics on an empty slice, deliberately and with a
/// message: an empty series here means the update loop never ran, and reporting
/// `0.0` for that — as `Series` does — makes a run that measured nothing
/// indistinguishable from an infinitely fast one.
fn dur_stats(v: &[Duration]) -> (f64, f64, f64) {
    assert!(
        !v.is_empty(),
        "no timings to summarise: the update loop produced no samples \
         (N_UPDATES = 0?). Refusing to report 0.0 as a measurement."
    );
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

/// One round: the `signers` sign the root of `list` at the slot the anchor assigns
/// to `version`, the signatures are aggregated into ONE proof, the SnarkStatusList
/// is built and verified. Returns (status_list, sign_time, prove_time, verify_time).
///
/// Both sides go through their module: `PQSNARKProverModule` derives the slot from
/// the anchor, `PQSNARKVerifierModule` performs all five checks. This is a
/// single-process demo, so there is one anchor and the prover borrows it from the
/// verifier module — in the split deployment (`prover` / `verifier`) each process
/// holds its own copy, which is the arrangement that actually matters.
fn run_flow(
    prover: &PQSNARKProverModule,
    verifier: &PQSNARKVerifierModule,
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    list: Vec<[u8; 32]>,
    version: u32,
) -> (SnarkStatusList, Duration, Duration, Duration) {
    let committee = verifier.committee_as_ref();
    // The signed message binds both the list and its version (Option B).
    let message = status_list_message(&list, version);
    let slot = committee.slot_for(version).expect("slot overflow");

    let t_sign = Instant::now();
    let mut raws: Vec<(XmssPublicKey, XmssSignature)> = Vec::new();
    for &i in signers {
        let (sk, pk) = &keypairs[i];
        let sig = xmss_sign(sk, slot, &message).expect("signing failed");
        raws.push((pk.clone(), sig));
    }
    let sign_time = t_sign.elapsed();

    let t_prove = Instant::now();
    let zk_proof = prover.make_proof(committee, raws, &list, version, LOG_INV_RATE);
    let prove_time = t_prove.elapsed();

    let status_list = SnarkStatusList::new(Algorithms::WotsXmss, list, version, zk_proof);

    let t_verify = Instant::now();
    let ok = verifier.verify(&status_list);
    let verify_time = t_verify.elapsed();
    assert!(ok, "a legitimate update failed to verify");

    (status_list, sign_time, prove_time, verify_time)
}

/// Signs `(list, version)` with `signers` at `slot` and returns just the proof
/// bytes. `version` is bound into the message, so a proof made here is only valid
/// for that exact version.
fn make_signed_proof(
    prover: &PQSNARKProverModule,
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    list: &[[u8; 32]],
    slot: u32,
    version: u32,
) -> Vec<u8> {
    prover.sign_and_prove(
        keypairs,
        signers,
        status_list_message(list, version),
        slot,
        LOG_INV_RATE,
    )
}

fn main() {
    let rss_baseline = rss_now_mb();

    // Setup is called directly here, not through the modules, because measuring the
    // two phases *apart* is the reason this binary exists: `setup_verifier` is the
    // bytecode alone, `setup_prover` adds the arena and the DFT twiddles. A module
    // constructor bundles setup with the object it builds, and the verifier module
    // cannot be built before the committee exists — which is after keygen, by which
    // point the RSS sample below would also be counting 200 keypairs.
    //
    // The modules are therefore constructed after keygen, and their setup calls land
    // as no-ops: `init_aggregation_bytecode` is a `OnceLock::get_or_init`,
    // `parallel::init` a `Once`, `enable_arena` two idempotent `mallopt`s, and
    // `precompute_dft_twiddles` returns early once the table is large enough
    // (`whir/src/dft.rs`: `if fft_len > curr_max_fft_len`).
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
    //
    // Timed apart from setup and reported as its own field: keygen is a fixed cost
    // *every* path pays, where `setup_*` is the leanVM circuit that only the SNARK
    // path pays. Folding them together — or, as before, measuring one and not the
    // other — makes `raw_agg`'s keygen column look like the SNARK's setup column
    // and inverts the comparison between the two.
    //
    // `xmss_key_gen` samples the seed from the RNG itself since v0.9 and returns
    // `(public, secret)`; this crate carries `(secret, public)` throughout, so the
    // pair is swapped here, at the boundary. The two types are distinct, so the
    // swap is compile-checked rather than a convention to remember.
    let t_keygen = Instant::now();
    let mut keypairs: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..N_MEMBERS {
        let (pk, sk) =
            xmss_key_gen(&mut rng, u64::from(SLOT), KEY_SLOT_COUNT).expect("keygen failed");
        keypairs.push((sk, pk));
    }
    let keygen_time = t_keygen.elapsed();
    let members: Vec<XmssPublicKey> = keypairs.iter().map(|(_, pk)| pk.clone()).collect();
    // The fixed trust anchor, built once and shared by every verification below.
    let committee = Committee::new(members, T, SLOT);

    // Both sides of the protocol, as the modules that own them. The second argument
    // feeds `PQSNARKVerifierModule::is_newer`, a stateless convenience this demo does
    // not use: freshness and anti-rollback live in `freshness::HighWaterMark`, which
    // the `verifier` binary exercises. Nothing here depends on the 0.
    let prover = PQSNARKProverModule::init_prover();
    let verifier = PQSNARKVerifierModule::new(committee, 0);
    let committee = verifier.committee_as_ref();

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
        //
        // The slot is derived through the anchor, never spelled out: `slot_for` is
        // the only place `genesis + version` is computed, and a second copy of that
        // expression is a second place to drift from the verifier.
        let version = i as u32;
        let slot = committee.slot_for(version).expect("slot overflow");
        let (sl, s, p, v) = run_flow(
            &prover,
            &verifier,
            &keypairs,
            &signers,
            list.clone(),
            version,
        );
        let rss = rss_now_mb();
        rss_updates_max = rss_updates_max.max(rss);
        // The signer window as a range rather than one character per member: at
        // N=200 the old `b'A' + index` mapping ran off the printable range into
        // Latin-1 and C1 control codes, and past N_UPDATES = 64 it would have
        // overflowed the u8 outright — a panic in debug, a silent wrap in release.
        println!(
            "  update {:2}/{}  signers {}..{} ({})  v{}  slot {}  prove={:>8.1?}  verify={:>8.1?}  RAM={} MB  OK",
            i + 1,
            N_UPDATES,
            signers[0],
            signers[signers.len() - 1],
            signers.len(),
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
    let honest_version = N_UPDATES as u32;
    let honest_slot = committee.slot_for(honest_version).expect("slot overflow");
    let quorum: Vec<usize> = (0..T).collect();

    // A) tampered list carrying a valid proof of a DIFFERENT list.
    let good_proof = make_signed_proof(
        &prover,
        &keypairs,
        &quorum,
        &list,
        honest_slot,
        honest_version,
    );
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION")); // row not authorized by the committee
    let sl_tampered =
        SnarkStatusList::new(Algorithms::WotsXmss, tampered, honest_version, good_proof);
    let tamper_rejected = !verifier.verify(&sl_tampered);

    // B) proof from signers OUTSIDE the committee (keys not in it).
    let mut outsiders: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..T {
        let (pk, sk) =
            xmss_key_gen(&mut rng, u64::from(SLOT), KEY_SLOT_COUNT).expect("outsider keygen");
        outsiders.push((sk, pk));
    }
    let out_list = vec![hash_any(rng.random::<[u8; 32]>())];
    let out_proof = make_signed_proof(&prover, &outsiders, &quorum, &out_list, SLOT, 0);
    let sl_outsider = SnarkStatusList::new(Algorithms::WotsXmss, out_list, 0, out_proof);
    let outsider_rejected = !verifier.verify(&sl_outsider);

    // C) version spoof: a VALID proof of (list, version) re-labelled with a
    //    different version. Defeated only by the version binding of check 2 —
    //    before Option B, when `version` was cleartext-only, this was ACCEPTED.
    //
    //    Built **slot-consistent** on purpose, mirroring `prover.rs`: signed at
    //    the slot the *inflated* version derives to, so check 3 (slot) passes and
    //    check 2 is the only thing standing between this record and acceptance.
    //    The previous version of this test signed at an unrelated slot, so check 2
    //    and check 3 both rejected it — the test still passed, but it no longer
    //    proved that check 2 was load-bearing, which is the single thing it exists
    //    to prove.
    //
    //    Note how far the inflation can reach: `slot = genesis + version` means the
    //    attacker needs a key covering that slot, so KEY_SLOTS is the largest lie
    //    available.
    let spoof_version = KEY_SLOTS;
    let spoof_slot = committee.slot_for(spoof_version).expect("slot overflow");
    let signed_version = (N_UPDATES - 1) as u32; // the true latest
    let versioned_proof = make_signed_proof(
        &prover,
        &keypairs,
        &quorum,
        &list,
        spoof_slot,
        signed_version,
    );
    let sl_spoofed = SnarkStatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        spoof_version,
        versioned_proof,
    );
    let version_rejected = !verifier.verify(&sl_spoofed);

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
    println!("keygen ({N_MEMBERS} keys, all paths) : {keygen_time:.2?}");

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
    //
    // `updates_total_ms` is the wall clock of the whole loop — sign, prove, verify,
    // the RSS reads and the printing. It is NOT comparable with the prover's
    // `prove_total_ms`, so the per-phase totals are emitted alongside it and those
    // are what the harness aggregates. Reporting the loop time under the same
    // heading as a phase sum makes this process look ~2.5x slower than it is.
    let sum_ms = |v: &[Duration]| -> f64 { v.iter().map(|d| ms(*d)).sum() };
    let bench = [
        format!("setup_verifier_ms={:.3}", ms(setup_verifier_time)),
        format!("setup_prover_extra_ms={:.3}", ms(setup_prover_extra)),
        format!("setup_total_ms={:.3}", ms(setup_prover_total)),
        format!("keygen_ms={:.3}", ms(keygen_time)),
        format!("n_updates={}", prove_ts.len()),
        format!("upd_sign_med_ms={sg_med:.3}"),
        format!("upd_sign_total_ms={:.3}", sum_ms(&sign_ts)),
        format!("upd_prove_med_ms={pv_med:.3}"),
        format!("upd_prove_min_ms={pv_min:.3}"),
        format!("upd_prove_max_ms={pv_max:.3}"),
        format!("upd_prove_total_ms={:.3}", sum_ms(&prove_ts)),
        format!("upd_verify_med_ms={vf_med:.3}"),
        format!("upd_verify_total_ms={:.3}", sum_ms(&verify_ts)),
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
