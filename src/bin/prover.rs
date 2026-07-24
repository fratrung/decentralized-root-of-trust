//! Prover side of the split deployment.
//!
//! Holds the committee secret keys, aggregates each update into one SNARK proof
//! and writes the publishable artifacts to disk (stand-in for the DHT). It
//! **never verifies**: that is `verifier`'s job, in a separate process whose
//! resident memory is ~36% smaller because it never calls `setup_prover()`.
//!
//! Artifacts written to `<outdir>`:
//!   anchor.bin          the committee (N public keys + threshold t)
//!   update-NN.bin       legitimate updates — the verifier MUST accept these
//!   attack-*.bin        forgeries — the verifier MUST reject these
//!
//! Usage: cargo run --release --bin prover -- [outdir]     (default ./artifacts)

use std::path::Path;
use std::time::{Duration, Instant};

use decentralized_root_of_trust::committee::{Committee, make_proof, sign_and_prove};
use decentralized_root_of_trust::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::params::{
    KEY_SLOTS, LOG_INV_RATE, N_MEMBERS, N_UPDATES, SLOT, T,
};
use decentralized_root_of_trust::stats::Series;
use decentralized_root_of_trust::status_list::{
    Algorithms, StatusList, hash_any, status_list_root_fe,
};
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, setup_prover, xmss_key_gen, xmss_sign,
};
use rand::RngExt;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

fn main() {
    let outdir = std::env::args().nth(1).unwrap_or_else(|| "artifacts".into());
    let outdir = Path::new(&outdir);
    std::fs::create_dir_all(outdir).expect("cannot create output directory");

    // Raw per-update records for the benchmark harness; off by default so
    // interactive runs stay readable.
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    let rss_baseline = rss_now_mb();
    println!("prover: setup...");
    let t_setup = Instant::now();
    setup_prover();
    let setup_time = t_setup.elapsed();
    let rss_after_setup = rss_now_mb();

    let mut rng = rand::rng();

    // The committee: N_MEMBERS XMSS keys, each valid over a KEY_SLOTS-wide window.
    let mut keypairs: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..N_MEMBERS {
        let seed: [u8; 32] = rng.random();
        keypairs.push(xmss_key_gen(seed, SLOT, SLOT + KEY_SLOTS, false).expect("keygen failed"));
    }
    let members: Vec<XmssPublicKey> = keypairs.iter().map(|(_, pk)| pk.clone()).collect();
    write(outdir, "anchor.bin", &Committee::new(members, T).to_bytes());

    println!("committee N={N_MEMBERS} t={T}; {N_UPDATES} updates rotating the signers");
    println!("writing artifacts to {}/\n", outdir.display());

    // ---- N_UPDATES updates, rotating the `t` signers over the `N` members ----
    // Each update consumes a fresh slot: XMSS is stateful, a (key, slot) pair
    // must never sign twice.
    let mut list: Vec<[u8; 32]> = Vec::new();
    let mut sign_ms = Vec::new();
    let mut prove_ms = Vec::new();
    let mut proof_bytes = Vec::new();
    let mut rss_updates_max = rss_after_setup;

    for i in 0..N_UPDATES {
        list.push(hash_any(rng.random::<[u8; 32]>()));
        let signers: Vec<usize> = (0..T).map(|j| (i + j) % N_MEMBERS).collect();
        // `slot` is the XMSS epoch (bounded by KEY_SLOTS); `version` is the
        // application counter, bound into the signed message so the cleartext
        // field cannot be forged. Independent by design.
        let slot = SLOT + i as u32;
        let version = i as u32;
        let message = status_list_root_fe(&list, version);

        // Signing and proving are timed apart: signing is `t` plain XMSS
        // signatures outside the circuit and scales linearly in `t`, proving is
        // the SNARK and scales with the padded trace. Conflating them would hide
        // which one a change actually moved.
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

        let t_prove = Instant::now();
        let proof = make_proof(raws, message, slot, LOG_INV_RATE);
        let prove_time = t_prove.elapsed();

        let sl = StatusList::new(Algorithms::WotsXmss, list.clone(), version, proof);
        let bytes = sl.to_bytes();
        write(outdir, &format!("update-{i:02}.bin"), &bytes);

        let rss = rss_now_mb();
        rss_updates_max = rss_updates_max.max(rss);
        let who: String = signers
            .iter()
            .map(|&j| char::from(b'A' + j as u8))
            .collect();
        println!(
            "  update {:2}/{}  signers {}  v{}  slot {}  sign={:>7.1?}  prove={:>8.1?}  {} B  RAM={} MB",
            i + 1,
            N_UPDATES,
            who,
            version,
            slot,
            sign_time,
            prove_time,
            bytes.len(),
            rss
        );
        if emit_samples {
            // Tidy per-sample record: one row per update, consumed by benchmark.sh.
            println!(
                "SAMPLE target=prover idx={i} sign_ms={:.3} prove_ms={:.3} bytes={} rss_mb={rss}",
                ms(sign_time),
                ms(prove_time),
                bytes.len()
            );
        }
        sign_ms.push(ms(sign_time));
        prove_ms.push(ms(prove_time));
        proof_bytes.push(bytes.len());
    }
    let sign = Series::new(sign_ms);
    let prove = Series::new(prove_ms);

    // ---- Forgeries the verifier must reject. Built here only because this is
    // the process that owns signing keys; conceptually these are the attacker's.
    let attack_slot = SLOT + N_UPDATES as u32;
    let attack_version = N_UPDATES as u32;
    let quorum: Vec<usize> = (0..T).collect();

    // A) a valid proof of the honest list, attached to a list with an extra row.
    //    Defeated by check 2 (message binds the list).
    let good_proof = sign_and_prove(
        &keypairs,
        &quorum,
        status_list_root_fe(&list, attack_version),
        attack_slot,
        LOG_INV_RATE,
        &mut rng,
    );
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION"));
    write(
        outdir,
        "attack-tampered.bin",
        &StatusList::new(Algorithms::WotsXmss, tampered, attack_version, good_proof).to_bytes(),
    );

    // B) a perfectly valid quorum of keys that are NOT in the committee.
    //    Defeated by check 1 (membership).
    let mut outsiders: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..T {
        let seed: [u8; 32] = rng.random();
        outsiders.push(xmss_key_gen(seed, SLOT, SLOT + KEY_SLOTS, false).expect("outsider keygen"));
    }
    let out_list = vec![hash_any(rng.random::<[u8; 32]>())];
    let out_proof = sign_and_prove(
        &outsiders,
        &quorum,
        status_list_root_fe(&out_list, 0),
        SLOT,
        LOG_INV_RATE,
        &mut rng,
    );
    write(
        outdir,
        "attack-outsider.bin",
        &StatusList::new(Algorithms::WotsXmss, out_list, 0, out_proof).to_bytes(),
    );

    // C) a valid proof of (list, version) re-labelled with an inflated version, as
    //    a hostile DHT peer would do to look freshest. Defeated by check 2 (message
    //    binds the version). It is also the decoy the verifier's freshness
    //    selection must try first and then skip.
    let spoof_slot = SLOT + N_UPDATES as u32 + 1;
    let signed_version = (N_UPDATES - 1) as u32; // the true latest
    let versioned_proof = sign_and_prove(
        &keypairs,
        &quorum,
        status_list_root_fe(&list, signed_version),
        spoof_slot,
        LOG_INV_RATE,
        &mut rng,
    );
    write(
        outdir,
        "attack-version.bin",
        &StatusList::new(Algorithms::WotsXmss, list.clone(), 999_999, versioned_proof).to_bytes(),
    );

    let (sg_min, sg_med, sg_max) = sign.min_med_max();
    let (pv_min, pv_med, pv_max) = prove.min_med_max();
    let proof_med = {
        let mut b = proof_bytes.clone();
        b.sort_unstable();
        b[b.len() / 2]
    };

    println!("\n{N_UPDATES} updates + 3 forgeries written");
    println!("setup_prover           : {setup_time:.2?}");
    println!("sign  min/med/max      : {sg_min:.1} / {sg_med:.1} / {sg_max:.1} ms");
    println!("prove min/med/max      : {pv_min:.1} / {pv_med:.1} / {pv_max:.1} ms");
    println!("proof size (median)    : {proof_med} bytes");
    println!("\nRAM (prover process)");
    println!("baseline (pre-setup)   : {rss_baseline} MB");
    println!("after setup (resident) : {rss_after_setup} MB");
    println!("max during updates     : {rss_updates_max} MB");
    println!("peak (VmHWM)           : {} MB", peak_rss_mb());

    // One-line machine-readable record, parsed by benchmark.sh.
    println!(
        "\nPROVER setup_ms={:.3} n_updates={} sign_med_ms={sg_med:.3} sign_mean_ms={:.3} \
         prove_med_ms={pv_med:.3} prove_mean_ms={:.3} prove_sd_ms={:.3} prove_min_ms={pv_min:.3} \
         prove_max_ms={pv_max:.3} prove_total_ms={:.3} proof_med_bytes={proof_med} \
         rss_setup_mb={rss_after_setup} rss_updates_max_mb={rss_updates_max} peak_rss_mb={}",
        ms(setup_time),
        prove.len(),
        sign.mean(),
        prove.mean(),
        prove.stddev(),
        prove.sum(),
        peak_rss_mb()
    );
}
