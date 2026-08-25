//! Prover side of the split deployment.
//!
//! Holds the committee secret keys, aggregates each update into one SNARK proof
//! and writes the publishable artifacts to disk (stand-in for the DHT). It
//! **never verifies**: that is `verifier`'s job, in a separate process whose
//! resident memory is ~36% smaller because it never calls `setup_prover()`.
//!
//! Artifacts written to `<outdir>`:
//!   anchor.bin          the committee (N public keys + threshold t)
//!   update-NN.bin       legitimate updates: the verifier MUST accept these
//!   attack-*.bin        forgeries: the verifier MUST reject these
//!
//! Usage: `cargo run --release --bin prover -- [outdir]` (default `./artifacts`)

use std::path::Path;
use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::{peak_rss_mb, rss_now_mb};
use decentralized_root_of_trust::bench::stats::Series;
use decentralized_root_of_trust::node::snark_prover::PQSNARKProverModule;
use decentralized_root_of_trust::params::{
    KEY_SLOT_COUNT, KEY_SLOTS, LOG_INV_RATE, N_MEMBERS, N_UPDATES, SLOT, T,
};
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{Algorithms, SnarkStatusList, hash_any};
use lean_multisig::{XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen, xmss_sign};
use rand::RngExt;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

fn main() {
    let outdir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "artifacts".into());
    let outdir = Path::new(&outdir);
    std::fs::create_dir_all(outdir).expect("cannot create output directory");

    // Clear artifacts from a previous run rather than writing over them. Each run
    // builds a fresh committee, so a shorter run leaving the tail of a longer one
    // behind produces files the verifier correctly rejects, which then reads as a
    // security regression rather than as the stale directory it is.
    for entry in std::fs::read_dir(outdir).expect("cannot read output directory") {
        let path = entry.expect("cannot read directory entry").path();
        let stale = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n == "anchor.bin" || n.starts_with("update-") || n.starts_with("attack-")
        });
        if stale {
            std::fs::remove_file(&path)
                .unwrap_or_else(|e| panic!("cannot remove stale {}: {e}", path.display()));
        }
    }

    // Raw per-update records for the benchmark harness; off by default so
    // interactive runs stay readable.
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    let rss_baseline = rss_now_mb();
    println!("prover: setup...");
    let t_setup = Instant::now();
    // `init_prover()` *is* the `setup_prover()` call: the module owns the pairing
    // of setup with proving, which is why the bare call is not made here as well.
    let prover = PQSNARKProverModule::init_prover();
    let setup_time = t_setup.elapsed();
    let rss_after_setup = rss_now_mb();

    let mut rng = rand::rng();

    // The committee: N_MEMBERS XMSS keys, each valid over a KEY_SLOTS-wide window.
    //
    // Timed, and reported separately from `setup_ms`, because the two fixed costs
    // are not the same cost. `setup_ms` is the leanVM circuit and is what the SNARK
    // path pays *extra*; keygen is paid by every path, `raw_agg` included. Leaving
    // it unmeasured made the summary table read as "SNARK setup 5.0 s vs raw 4.3 s",
    // i.e. as if the SNARK were the cheaper of the two: the comparison inverted,
    // because the raw column was keygen and the SNARK column was not.
    //
    // `xmss_key_gen` samples the seed from the RNG itself since leanVM v0.9 and
    // returns `(public, secret)`; this crate carries `(secret, public)`, so the
    // pair is swapped here, at the boundary. The types are distinct, so the swap
    // is compile-checked rather than a convention to remember.
    let t_keygen = Instant::now();
    let mut keypairs: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..N_MEMBERS {
        let (pk, sk) =
            xmss_key_gen(&mut rng, u64::from(SLOT), KEY_SLOT_COUNT).expect("keygen failed");
        keypairs.push((sk, pk));
    }
    let keygen_time = t_keygen.elapsed();
    let members: Vec<XmssPublicKey> = keypairs.iter().map(|(_, pk)| pk.clone()).collect();
    // Kept rather than built inline and dropped: every slot below is derived
    // through `slot_for`, so the anchor stays the only place `genesis + version`
    // is ever computed: signer and verifier cannot drift apart.
    let committee = Committee::new(members, T, SLOT);
    write(outdir, "anchor.bin", &committee.to_bytes());

    println!("committee N={N_MEMBERS} t={T}; {N_UPDATES} updates rotating the signers");
    println!("writing artifacts to {}/\n", outdir.display());

    // ---- N_UPDATES updates, rotating the `t` signers over the `N` members ----
    // Each update consumes a fresh slot: XMSS is stateful, a (key, slot) pair
    // must never sign twice.
    let mut list: Vec<[u8; 32]> = Vec::new();
    let mut prove_ms = Vec::new();
    let mut proof_bytes = Vec::new();
    let mut rss_updates_max = rss_after_setup;

    for i in 0..N_UPDATES {
        list.push(hash_any(rng.random::<[u8; 32]>()));
        let signers: Vec<usize> = (0..T).map(|j| (i + j) % N_MEMBERS).collect();
        // `slot` is the XMSS epoch (bounded by KEY_SLOTS); `version` is the
        // application counter, bound into the signed message so the cleartext
        // field cannot be forged. Independent by design, and the slot is derived
        // through the anchor rather than spelled out a second time.
        let version = i as u32;
        let slot = committee.slot_for(version).expect("slot overflow");
        let message = committee.message_for(Algorithms::WotsXmss, &list, version);

        // Signing happens here because an aggregator needs `t` signatures to have
        // something to aggregate, but it is deliberately NOT timed: in production
        // these `t` signatures come from `t` different machines, one each, and no
        // process ever produces them all. Timing the loop would sum the work of a
        // whole committee and attribute it to the aggregator. The cost of one
        // member's round is measured where it belongs, in `src/bin/signer.rs`.
        let mut raws: Vec<(XmssPublicKey, XmssSignature)> = Vec::with_capacity(signers.len());
        for &k in &signers {
            let (sk, pk) = &keypairs[k];
            raws.push((
                pk.clone(),
                xmss_sign(sk, slot, &message).expect("signing failed"),
            ));
        }

        // The module takes `version`, not `slot`: it derives the slot from the
        // anchor itself and computes the signed message the same way the verifier
        // does. Passing a slot here would be a second place for `genesis + version`
        // to live, which is exactly the drift check 3 exists to catch.
        let t_prove = Instant::now();
        let proof = prover.make_proof(
            &committee,
            Algorithms::WotsXmss,
            raws,
            &list,
            version,
            LOG_INV_RATE,
        );
        let prove_time = t_prove.elapsed();

        let sl = SnarkStatusList::new(Algorithms::WotsXmss, list.clone(), version, proof);
        let bytes = sl.to_bytes();
        write(outdir, &format!("update-{i:02}.bin"), &bytes);

        let rss = rss_now_mb();
        rss_updates_max = rss_updates_max.max(rss);
        println!(
            "  update {:2}/{}  signers {}..{} ({})  v{}  slot {}  prove={:>8.1?}  {} B  RAM={} MB",
            i + 1,
            N_UPDATES,
            signers[0],
            signers[signers.len() - 1],
            signers.len(),
            version,
            slot,
            prove_time,
            bytes.len(),
            rss
        );
        if emit_samples {
            // Tidy per-sample record: one row per update, consumed by benchmark.sh.
            println!(
                "SAMPLE target=prover idx={i} prove_ms={:.3} bytes={} rss_mb={rss}",
                ms(prove_time),
                bytes.len()
            );
        }
        prove_ms.push(ms(prove_time));
        proof_bytes.push(bytes.len());
    }
    let prove = Series::new(prove_ms);

    // ---- Forgeries the verifier must reject. Built here only because this is
    // the process that owns signing keys; conceptually these are the attacker's.
    //
    // These deliberately do NOT go through `PQSNARKProverModule::make_proof`, and
    // that is the method working as intended rather than a gap in it. Forgery C
    // signs one version's content at a *different* version's slot: `make_proof`
    // derives the slot from the anchor, so it structurally cannot express that. An
    // attacker is under no such constraint, so the attacker's code path is
    // `sign_and_prove`, which still takes an explicit slot.
    let attack_version = N_UPDATES as u32;
    let attack_slot = committee.slot_for(attack_version).expect("slot overflow");
    let quorum: Vec<usize> = (0..T).collect();

    // A) a valid proof of the honest list, attached to a list with an extra row.
    //    Defeated by check 2 (message binds the list).
    let good_proof = prover.sign_and_prove(
        &keypairs,
        &quorum,
        committee.message_for(Algorithms::WotsXmss, &list, attack_version),
        attack_slot,
        LOG_INV_RATE,
    );
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION"));
    write(
        outdir,
        "attack-tampered.bin",
        &SnarkStatusList::new(Algorithms::WotsXmss, tampered, attack_version, good_proof)
            .to_bytes(),
    );

    // B) a perfectly valid quorum of keys that are NOT in the committee.
    //    Defeated by check 1 (membership).
    let mut outsiders: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..T {
        let (pk, sk) =
            xmss_key_gen(&mut rng, u64::from(SLOT), KEY_SLOT_COUNT).expect("outsider keygen");
        outsiders.push((sk, pk));
    }
    let out_list = vec![hash_any(rng.random::<[u8; 32]>())];
    let out_proof = prover.sign_and_prove(
        &outsiders,
        &quorum,
        committee.message_for(Algorithms::WotsXmss, &out_list, 0),
        SLOT,
        LOG_INV_RATE,
    );
    write(
        outdir,
        "attack-outsider.bin",
        &SnarkStatusList::new(Algorithms::WotsXmss, out_list, 0, out_proof).to_bytes(),
    );

    // C) a valid proof of (list, version) re-labelled with an inflated version, as
    //    a hostile DHT peer would do to look freshest. Defeated by check 2 (message
    //    binds the version). It is also the decoy the verifier's freshness
    //    selection must try first and then skip.
    //
    //    The forgery is built slot-consistent on purpose: signed at the slot the
    //    inflated version derives to, so check 3 passes and check 2 is the one that
    //    fires. A sloppier forgery would be caught a step earlier and this artifact
    //    would silently stop testing the version binding it exists for.
    //
    //    Note how far the inflation can go: `slot = genesis + version` means an
    //    attacker needs a key covering that slot, so the reachable versions stop at
    //    the end of the key window. KEY_SLOTS is the largest lie available.
    let spoof_version = KEY_SLOTS;
    let spoof_slot = committee.slot_for(spoof_version).expect("slot overflow");
    let signed_version = (N_UPDATES - 1) as u32; // the true latest
    let versioned_proof = prover.sign_and_prove(
        &keypairs,
        &quorum,
        committee.message_for(Algorithms::WotsXmss, &list, signed_version),
        spoof_slot,
        LOG_INV_RATE,
    );
    write(
        outdir,
        "attack-version.bin",
        &SnarkStatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            spoof_version,
            versioned_proof,
        )
        .to_bytes(),
    );

    let (pv_min, pv_med, pv_max) = prove.min_med_max();
    // Same reasoning as `main.rs::dur_stats`: an empty series means no update was
    // ever produced, and a silent 0 would be reported as a measurement.
    assert!(
        !proof_bytes.is_empty(),
        "no proofs were produced (N_UPDATES = 0?); refusing to report a size"
    );
    let proof_med = {
        let mut b = proof_bytes.clone();
        b.sort_unstable();
        b[b.len() / 2]
    };

    println!("\n{N_UPDATES} updates + 3 forgeries written");
    println!("setup_prover           : {setup_time:.2?}");
    println!("keygen ({N_MEMBERS} keys)   : {keygen_time:.2?}");
    println!("prove min/med/max      : {pv_min:.1} / {pv_med:.1} / {pv_max:.1} ms");
    println!("proof size (median)    : {proof_med} bytes");
    println!("\nRAM (prover process)");
    println!("baseline (pre-setup)   : {rss_baseline} MB");
    println!("after setup (resident) : {rss_after_setup} MB");
    println!("max during updates     : {rss_updates_max} MB");
    println!("peak (VmHWM)           : {} MB", peak_rss_mb());

    // One-line machine-readable record, parsed by benchmark.sh.
    println!(
        "\nPROVER setup_ms={:.3} keygen_ms={:.3} n_updates={} \
         prove_med_ms={pv_med:.3} prove_mean_ms={:.3} prove_sd_ms={:.3} prove_min_ms={pv_min:.3} \
         prove_max_ms={pv_max:.3} prove_total_ms={:.3} proof_med_bytes={proof_med} \
         rss_setup_mb={rss_after_setup} rss_updates_max_mb={rss_updates_max} peak_rss_mb={}",
        ms(setup_time),
        ms(keygen_time),
        prove.len(),
        prove.mean(),
        prove.stddev(),
        prove.sum(),
        peak_rss_mb()
    );
}
