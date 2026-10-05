//! Prover side of the split deployment.
//!
//! Aggregates each update into one SNARK proof and writes the benchmark and
//! verification fixtures to disk. With `BENCH_INPUT_DIR`, signatures
//! come from a separate fixture process and this process holds no secret keys,
//! matching one deployed aggregator. Without it, the self-contained demo mode
//! generates the committee locally. It **never verifies**: that is `verifier`'s
//! job, in a separate process that never calls `setup_prover()`.
//!
//! Artifacts written to `<outdir>`:
//!   anchor.bin          the committee (N public keys + threshold t)
//!   update-NN.bin       legitimate updates: the verifier MUST accept these
//!   canonical.bin       the single current record supplied to the relying party
//!   attack-*.bin        forgeries: the verifier MUST reject these
//!
//! Usage: `cargo run --release --bin prover -- [outdir]` (default `./artifacts`)

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::{peak_rss_mib, rss_now_mib};
use decentralized_root_of_trust::bench::stats::{Series, median_usize};
use decentralized_root_of_trust::bench::timing::process_cpu_time;
use decentralized_root_of_trust::bench::workload::ListSizes;
use decentralized_root_of_trust::node::snark_prover::PQSNARKProverModule;
use decentralized_root_of_trust::params::{KEY_SLOTS, LOG_INV_RATE, N_MEMBERS, N_UPDATES, SLOT, T};
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{
    Algorithms, SnarkStatusList, StatusList, hash_any,
};
use leanvm::AggregateSignature;
use leanvm::xmss::{XmssPublicKey, XmssSecretKey, XmssSignature, key_gen, sign};
use rand::RngExt;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The check-5 control: `proof` with one proof-body bit changed. It must still
/// decode to the very same public claims, so checks 1 to 4 pass by construction
/// and only the SNARK itself can reject the record. The same construction as
/// `tests/snark_path.rs`; this binary never verifies, so it asserts only the
/// shape and leaves the rejection to the verifier.
fn corrupt_proof_body(proof: &[u8]) -> Vec<u8> {
    let honest = AggregateSignature::from_bytes(proof).expect("honest aggregate must decode");
    let mut bytes = proof.to_vec();
    *bytes.last_mut().expect("aggregate has proof bytes") ^= 1;
    let spliced = AggregateSignature::from_bytes(&bytes)
        .expect("changing a proof-body bit must preserve the aggregate shape");
    assert_eq!(spliced.xmss_signers(), honest.xmss_signers());
    assert_eq!(spliced.sphincs_signers(), honest.sphincs_signers());
    let spliced = spliced.to_bytes();
    assert_ne!(
        spliced, proof,
        "the proof-body control must differ from the honest proof"
    );
    spliced
}

/// The verifier corpus's below-quorum control needs `t - 1 >= 1` signatures:
/// leanVM cannot aggregate an empty signer set. Only corpus generation needs
/// it, so it is checked there, before any expensive work, and not at compile
/// time: a `t = 1` build must still produce every other binary, and this one
/// must still aggregate honest-only fixture updates.
fn require_corpus_quorum() {
    if T < 2 {
        panic!("the verifier corpus needs t >= 2 for its below-quorum control, got t={T}");
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

fn fixture_files(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read fixture directory {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .collect();
    paths.sort();
    paths
}

fn load_committee(path: &Path) -> Committee {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("cannot read fixture anchor {}: {e}", path.display()));
    Committee::from_bytes(&bytes)
        .unwrap_or_else(|e| panic!("malformed fixture anchor {}: {e}", path.display()))
}

fn load_raw(path: &Path) -> StatusList {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("cannot read raw fixture {}: {e}", path.display()));
    StatusList::from_bytes(&bytes)
        .unwrap_or_else(|e| panic!("malformed raw fixture {}: {e}", path.display()))
}

fn aggregation_inputs(
    committee: &Committee,
    record: &StatusList,
) -> Vec<(XmssPublicKey, XmssSignature)> {
    assert_eq!(
        record.signer_slots(),
        committee.members().len(),
        "fixture bitmap does not name this anchor"
    );
    assert_eq!(
        record.signer_count(),
        record.signatures().len(),
        "fixture signer bitmap/signature count mismatch"
    );
    record
        .signer_indices()
        .zip(record.signatures())
        .map(|(index, signature)| (committee.members()[index].clone(), signature.clone()))
        .collect()
}

/// Runs the measured aggregator role over signatures generated by the separate
/// `committee_fixture` process. No committee secret key enters this process.
fn run_fixture_prover(outdir: &Path, fixture_dir: &Path) {
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();
    let honest_only = std::env::var_os("BENCH_HONEST_ONLY").is_some();
    if !honest_only {
        require_corpus_quorum();
    }
    let rss_baseline = rss_now_mib();

    println!("prover: setup (pre-signed fixture input)...");
    let setup_cpu_start = process_cpu_time();
    let t_setup = Instant::now();
    let prover = PQSNARKProverModule::init_prover();
    let setup_time = t_setup.elapsed();
    let setup_cpu = ms(process_cpu_time().saturating_sub(setup_cpu_start));
    let rss_after_setup = rss_now_mib();

    let committee = load_committee(&fixture_dir.join("anchor.bin"));
    assert_eq!(
        committee.members().len(),
        N_MEMBERS,
        "fixture N/build N drift"
    );
    assert_eq!(committee.threshold(), T, "fixture t/build t drift");
    write(outdir, "anchor.bin", &committee.to_bytes());

    let updates = fixture_files(fixture_dir, "raw-update-");
    assert_eq!(
        updates.len(),
        N_UPDATES,
        "fixture must contain exactly N_UPDATES honest records"
    );
    let mut prove_ms = Vec::with_capacity(updates.len());
    let mut record_bytes = Vec::with_capacity(updates.len());
    let mut rss_updates_max = rss_after_setup;
    let mut prove_cpu_ms = Vec::with_capacity(updates.len());
    let mut list_sizes = ListSizes::default();

    for (index, path) in updates.iter().enumerate() {
        let raw = load_raw(path);
        list_sizes.record(raw.list().len());
        assert_eq!(
            raw.signer_count(),
            T,
            "fixture update must carry one quorum"
        );
        let inputs = aggregation_inputs(&committee, &raw);
        // Elapsed and CPU: the prover spreads its work over every core it is
        // given, so its CPU is a multiple of its elapsed time.
        let cpu_start = process_cpu_time();
        let t_prove = Instant::now();
        let proof = prover.make_proof(
            &committee,
            raw.alg,
            inputs,
            raw.list(),
            raw.version(),
            LOG_INV_RATE,
        );
        let prove_time = t_prove.elapsed();
        let prove_cpu = ms(process_cpu_time().saturating_sub(cpu_start));
        let record = SnarkStatusList::new(raw.alg, raw.list_cloned(), raw.version(), proof);
        let bytes = record.to_bytes();
        write(outdir, &format!("update-{index:02}.bin"), &bytes);
        if index + 1 == updates.len() {
            write(outdir, "canonical.bin", &bytes);
        }

        let rss = rss_now_mib();
        rss_updates_max = rss_updates_max.max(rss);
        println!(
            "  update {:2}/{}  t={}  prove={:>8.1?}  {} B  RAM={} MiB",
            index + 1,
            updates.len(),
            T,
            prove_time,
            bytes.len(),
            rss
        );
        if emit_samples {
            println!(
                "SAMPLE target=prover idx={index} prove_ms={:.3} bytes={} rss_mib={rss} cpu_ms={prove_cpu:.3}",
                ms(prove_time),
                bytes.len()
            );
        }
        prove_ms.push(ms(prove_time));
        prove_cpu_ms.push(prove_cpu);
        record_bytes.push(bytes.len());
    }

    if !honest_only {
        // Negative controls are generated from a slot that no honest update used.
        // They are needed only for the fixed verifier corpus. Measured prover
        // runs set BENCH_HONEST_ONLY: an aggregator publishes honest updates and
        // must not be charged for manufacturing adversarial fixtures.
        let honest_attack = load_raw(&fixture_dir.join("raw-attack-honest.bin"));
        let honest_inputs = aggregation_inputs(&committee, &honest_attack);
        let honest_proof = prover.make_proof(
            &committee,
            honest_attack.alg,
            honest_inputs.clone(),
            honest_attack.list(),
            honest_attack.version(),
            LOG_INV_RATE,
        );
        let mut tampered = honest_attack.list_cloned();
        tampered.push(hash_any(b"FAKE-REVOCATION"));
        write(
            outdir,
            "attack-tampered.bin",
            &SnarkStatusList::new(
                honest_attack.alg,
                tampered,
                honest_attack.version(),
                honest_proof.clone(),
            )
            .to_bytes(),
        );

        // Check 5 alone: honest claims over a proof body that no longer verifies.
        write(
            outdir,
            "attack-proofbody.bin",
            &SnarkStatusList::new(
                honest_attack.alg,
                honest_attack.list_cloned(),
                honest_attack.version(),
                corrupt_proof_body(&honest_proof),
            )
            .to_bytes(),
        );

        // Check 4 alone: a genuine proof of the right statement at the right
        // slot, but over t - 1 of the same signatures. Reusing signatures that
        // already exist asks no key to sign again.
        let short_proof = prover.make_proof(
            &committee,
            honest_attack.alg,
            honest_inputs.into_iter().take(T - 1).collect(),
            honest_attack.list(),
            honest_attack.version(),
            LOG_INV_RATE,
        );
        write(
            outdir,
            "attack-short.bin",
            &SnarkStatusList::new(
                honest_attack.alg,
                honest_attack.list_cloned(),
                honest_attack.version(),
                short_proof,
            )
            .to_bytes(),
        );

        // Check 3 alone: the attack version's genuine statement, signed by a full
        // quorum one slot after the one this version derives to.
        let slot_attack = load_raw(&fixture_dir.join("raw-attack-slot.bin"));
        let slot_inputs = aggregation_inputs(&committee, &slot_attack);
        let slot_message =
            committee.message_for(slot_attack.alg, slot_attack.list(), slot_attack.version());
        let wrong_slot = committee
            .slot_for(slot_attack.version() + 1)
            .expect("slot fixture slot overflow");
        let slot_proof = prover.aggregate(slot_inputs, slot_message, wrong_slot, LOG_INV_RATE);
        write(
            outdir,
            "attack-slot.bin",
            &SnarkStatusList::new(
                slot_attack.alg,
                slot_attack.list_cloned(),
                slot_attack.version(),
                slot_proof,
            )
            .to_bytes(),
        );

        // Slot-consistent, as in the self-contained mode below: the fixture
        // quorum signed the true latest version at the slot KEY_SLOTS derives
        // to, so check 3 passes and only check 2 rejects the relabelled record.
        // `make_proof` derives the slot from the record's own version and so
        // cannot express this; `aggregate` exists for exactly these fixtures.
        let version_attack = load_raw(&fixture_dir.join("raw-attack-version.bin"));
        let version_inputs = aggregation_inputs(&committee, &version_attack);
        let signed_message = committee.message_for(
            version_attack.alg,
            version_attack.list(),
            version_attack.version(),
        );
        let spoof_slot = committee
            .slot_for(KEY_SLOTS)
            .expect("version fixture slot overflow");
        let version_proof =
            prover.aggregate(version_inputs, signed_message, spoof_slot, LOG_INV_RATE);
        write(
            outdir,
            "attack-version.bin",
            &SnarkStatusList::new(
                version_attack.alg,
                version_attack.list_cloned(),
                KEY_SLOTS,
                version_proof,
            )
            .to_bytes(),
        );

        let outsider_committee = load_committee(&fixture_dir.join("outsider-anchor.bin"));
        let outsider_attack = load_raw(&fixture_dir.join("raw-attack-outsider.bin"));
        let outsider_inputs = aggregation_inputs(&outsider_committee, &outsider_attack);
        let message = committee.message_for(
            outsider_attack.alg,
            outsider_attack.list(),
            outsider_attack.version(),
        );
        let slot = committee
            .slot_for(outsider_attack.version())
            .expect("outsider fixture slot overflow");
        let outsider_proof = prover.aggregate(outsider_inputs, message, slot, LOG_INV_RATE);
        write(
            outdir,
            "attack-outsider.bin",
            &SnarkStatusList::new(
                outsider_attack.alg,
                outsider_attack.list_cloned(),
                outsider_attack.version(),
                outsider_proof,
            )
            .to_bytes(),
        );
    }

    let prove = Series::new(prove_ms);
    let (pv_min, pv_med, pv_max) = prove.min_med_max();
    let prove_cpu = Series::new(prove_cpu_ms);
    let (prove_cpu_med, prove_cpu_total) = (prove_cpu.median(), prove_cpu.sum());
    let record_med = median_usize(&record_bytes);

    if honest_only {
        println!("\n{} honest updates written", prove.len());
    } else {
        println!("\n{} updates + 6 forgeries written", prove.len());
    }
    println!("setup_prover           : {setup_time:.2?}");
    println!("prove min/med/max      : {pv_min:.1} / {pv_med:.1} / {pv_max:.1} ms");
    println!("published record size (median): {record_med:.1} bytes");
    println!("\nRAM (aggregator process; no secret keys)");
    println!("baseline (pre-setup)   : {rss_baseline} MiB");
    println!("after setup (resident) : {rss_after_setup} MiB");
    println!("max during updates     : {rss_updates_max} MiB");
    println!("peak (VmHWM)           : {} MiB", peak_rss_mib());
    println!(
        "\nPROVER setup_ms={:.3} n_members={N_MEMBERS} t={T} n_updates={} \
         prove_med_ms={pv_med:.3} prove_mean_ms={:.3} prove_sd_ms={:.3} prove_min_ms={pv_min:.3} \
         prove_max_ms={pv_max:.3} prove_total_ms={:.3} record_med_bytes={record_med:.3} \
         rss_setup_mib={rss_after_setup} rss_updates_max_mib={rss_updates_max} peak_rss_mib={} \
         fixture_input=1 {list_sizes} setup_cpu_ms={setup_cpu:.3} \
         prove_cpu_med_ms={prove_cpu_med:.3} prove_cpu_total_ms={prove_cpu_total:.3}",
        ms(setup_time),
        prove.len(),
        prove.mean(),
        prove.stddev(),
        prove.sum(),
        peak_rss_mib()
    );
}

/// Builds a deliberately malformed published record from fresh, process-local
/// keys at a slot unused by the honest loop. This helper is confined to the
/// attack-artifact binary; production member signing goes through `SignerNode`
/// and its durable burn-before-sign counter.
fn make_adversarial_proof(
    prover: &PQSNARKProverModule,
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    message: [u8; 32],
    slot: u32,
) -> Vec<u8> {
    let raws = sign_adversarial(keypairs, signers, message, slot);
    prover.aggregate(raws, message, slot, LOG_INV_RATE)
}

/// Signs once per listed key at `slot`. Split from aggregation so one set of
/// signatures can back several controls without any key signing twice there.
fn sign_adversarial(
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    signers: &[usize],
    message: [u8; 32],
    slot: u32,
) -> Vec<(XmssPublicKey, XmssSignature)> {
    let mut unique = signers.to_vec();
    unique.sort_unstable();
    assert!(
        unique.windows(2).all(|pair| pair[0] != pair[1]),
        "adversarial fixture must not reuse an XMSS key at one slot"
    );
    let mut rng = leanvm::rand::rng();
    signers
        .iter()
        .map(|&index| {
            let (secret, public) = &keypairs[index];
            (
                public.clone(),
                sign(&mut rng, secret, &message, slot).expect("signing failed"),
            )
        })
        .collect()
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
            n == "anchor.bin"
                || n == "canonical.bin"
                || n.starts_with("update-")
                || n.starts_with("attack-")
        });
        if stale {
            std::fs::remove_file(&path)
                .unwrap_or_else(|e| panic!("cannot remove stale {}: {e}", path.display()));
        }
    }

    if let Some(fixture_dir) = std::env::var_os("BENCH_INPUT_DIR") {
        run_fixture_prover(outdir, Path::new(&fixture_dir));
        return;
    }

    // Self-contained mode always writes the forgeries.
    require_corpus_quorum();

    // Raw per-update records for the benchmark harness; off by default so
    // interactive runs stay readable.
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    let rss_baseline = rss_now_mib();
    println!("prover: setup...");
    let t_setup = Instant::now();
    // `init_prover()` *is* the `setup_prover()` call: the module owns the pairing
    // of setup with proving, which is why the bare call is not made here as well.
    let prover = PQSNARKProverModule::init_prover();
    let setup_time = t_setup.elapsed();
    let rss_after_setup = rss_now_mib();

    let mut rng = rand::rng();
    let mut xmss_rng = leanvm::rand::rng();

    // The committee: N_MEMBERS XMSS keys, each valid over a KEY_SLOTS-wide window.
    //
    // Timed, and reported separately from `setup_ms`, because the two fixed costs
    // are not the same cost. `setup_ms` is the leanVM circuit and is what the SNARK
    // path pays *extra*; keygen is paid by every path, `raw_agg` included. Leaving
    // it unmeasured made the summary table read as "SNARK setup 5.0 s vs raw 4.3 s",
    // i.e. as if the SNARK were the cheaper of the two: the comparison inverted,
    // because the raw column was keygen and the SNARK column was not.
    //
    // leanVM's native v0.10 API takes an inclusive slot interval and returns
    // `(secret, public)`, the ordering used throughout this crate.
    let t_keygen = Instant::now();
    let mut keypairs: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..N_MEMBERS {
        let keypair = key_gen(&mut xmss_rng, SLOT, SLOT + KEY_SLOTS).expect("keygen failed");
        keypairs.push(keypair);
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
    let mut prove_cpu_ms = Vec::new();
    let mut record_bytes = Vec::new();
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
                sign(&mut xmss_rng, sk, &message, slot).expect("signing failed"),
            ));
        }

        // The module takes `version`, not `slot`: it derives the slot from the
        // anchor itself and computes the signed message the same way the verifier
        // does. Passing a slot here would be a second place for `genesis + version`
        // to live, which is exactly the drift check 3 exists to catch.
        let cpu_start = process_cpu_time();
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
        let prove_cpu = ms(process_cpu_time().saturating_sub(cpu_start));

        let sl = SnarkStatusList::new(Algorithms::WotsXmss, list.clone(), version, proof);
        let bytes = sl.to_bytes();
        write(outdir, &format!("update-{i:02}.bin"), &bytes);
        if i + 1 == N_UPDATES {
            write(outdir, "canonical.bin", &bytes);
        }

        let rss = rss_now_mib();
        rss_updates_max = rss_updates_max.max(rss);
        println!(
            "  update {:2}/{}  signers {}..{} ({})  v{}  slot {}  prove={:>8.1?}  {} B  RAM={} MiB",
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
                "SAMPLE target=prover idx={i} prove_ms={:.3} bytes={} rss_mib={rss} cpu_ms={prove_cpu:.3}",
                ms(prove_time),
                bytes.len()
            );
        }
        prove_ms.push(ms(prove_time));
        prove_cpu_ms.push(prove_cpu);
        record_bytes.push(bytes.len());
    }
    let prove = Series::new(prove_ms);
    let prove_cpu = Series::new(prove_cpu_ms);
    let (prove_cpu_med, prove_cpu_total) = (prove_cpu.median(), prove_cpu.sum());

    // ---- Forgeries the verifier must reject. Built here only because this is
    // the process that owns signing keys; conceptually these are the attacker's.
    //
    // These deliberately do NOT go through `PQSNARKProverModule::make_proof`, and
    // that is the method working as intended rather than a gap in it. Forgery C
    // signs one version's content at a *different* version's slot: `make_proof`
    // derives the slot from the anchor, so it structurally cannot express that. An
    // attacker is under no such constraint, so this binary's private fixture
    // helper signs at an explicit, otherwise unused slot.
    let attack_version = N_UPDATES as u32;
    let attack_slot = committee.slot_for(attack_version).expect("slot overflow");
    let quorum: Vec<usize> = (0..T).collect();

    // A) a valid proof of the honest list, attached to a list with an extra row.
    //    Defeated by check 2 (message binds the list). Its signatures also back
    //    controls D and E below, so no key signs twice at `attack_slot`.
    let attack_message = committee.message_for(Algorithms::WotsXmss, &list, attack_version);
    let attack_signatures = sign_adversarial(&keypairs, &quorum, attack_message, attack_slot);
    let good_proof = prover.aggregate(
        attack_signatures.clone(),
        attack_message,
        attack_slot,
        LOG_INV_RATE,
    );
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION"));
    write(
        outdir,
        "attack-tampered.bin",
        &SnarkStatusList::new(
            Algorithms::WotsXmss,
            tampered,
            attack_version,
            good_proof.clone(),
        )
        .to_bytes(),
    );

    // D) honest claims over a proof body that no longer verifies. Check 5 alone.
    write(
        outdir,
        "attack-proofbody.bin",
        &SnarkStatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            attack_version,
            corrupt_proof_body(&good_proof),
        )
        .to_bytes(),
    );

    // E) a genuine proof over t - 1 of A's signatures. Check 4 alone.
    let short_proof = prover.aggregate(
        attack_signatures.into_iter().take(T - 1).collect(),
        attack_message,
        attack_slot,
        LOG_INV_RATE,
    );
    write(
        outdir,
        "attack-short.bin",
        &SnarkStatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            attack_version,
            short_proof,
        )
        .to_bytes(),
    );

    // F) the attack version's genuine statement, signed by a full quorum one
    //    slot after the one it derives to. Check 3 alone. `attack_version + 1`
    //    is below KEY_SLOTS by the assertion in params.rs.
    let wrong_slot = committee
        .slot_for(attack_version + 1)
        .expect("slot overflow");
    let slot_proof =
        make_adversarial_proof(&prover, &keypairs, &quorum, attack_message, wrong_slot);
    write(
        outdir,
        "attack-slot.bin",
        &SnarkStatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            attack_version,
            slot_proof,
        )
        .to_bytes(),
    );

    // B) a perfectly valid quorum of keys that are NOT in the committee.
    //    Defeated by check 1 (membership).
    let mut outsiders: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();
    for _ in 0..T {
        let keypair = key_gen(&mut xmss_rng, SLOT, SLOT + KEY_SLOTS).expect("outsider keygen");
        outsiders.push(keypair);
    }
    let out_list = vec![hash_any(rng.random::<[u8; 32]>())];
    let out_proof = make_adversarial_proof(
        &prover,
        &outsiders,
        &quorum,
        committee.message_for(Algorithms::WotsXmss, &out_list, 0),
        SLOT,
    );
    write(
        outdir,
        "attack-outsider.bin",
        &SnarkStatusList::new(Algorithms::WotsXmss, out_list, 0, out_proof).to_bytes(),
    );

    // C) a valid proof of (list, version) re-labelled with an inflated version.
    //    Defeated by check 2 because the signed message binds the version.
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
    let versioned_proof = make_adversarial_proof(
        &prover,
        &keypairs,
        &quorum,
        committee.message_for(Algorithms::WotsXmss, &list, signed_version),
        spoof_slot,
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
        !record_bytes.is_empty(),
        "no records were produced (N_UPDATES = 0?); refusing to report a size"
    );
    let record_med = median_usize(&record_bytes);

    println!("\n{N_UPDATES} updates + 6 forgeries written");
    println!("setup_prover           : {setup_time:.2?}");
    println!("keygen ({N_MEMBERS} keys)   : {keygen_time:.2?}");
    println!("prove min/med/max      : {pv_min:.1} / {pv_med:.1} / {pv_max:.1} ms");
    println!("published record size (median): {record_med:.1} bytes");
    println!("\nRAM (prover process)");
    println!("baseline (pre-setup)   : {rss_baseline} MiB");
    println!("after setup (resident) : {rss_after_setup} MiB");
    println!("max during updates     : {rss_updates_max} MiB");
    println!("peak (VmHWM)           : {} MiB", peak_rss_mib());

    // One-line machine-readable record, parsed by benchmark.sh.
    println!(
        "\nPROVER setup_ms={:.3} keygen_ms={:.3} n_updates={} \
         prove_med_ms={pv_med:.3} prove_mean_ms={:.3} prove_sd_ms={:.3} prove_min_ms={pv_min:.3} \
         prove_max_ms={pv_max:.3} prove_total_ms={:.3} record_med_bytes={record_med:.3} \
         rss_setup_mib={rss_after_setup} rss_updates_max_mib={rss_updates_max} peak_rss_mib={} \
         prove_cpu_med_ms={prove_cpu_med:.3} prove_cpu_total_ms={prove_cpu_total:.3}",
        ms(setup_time),
        ms(keygen_time),
        prove.len(),
        prove.mean(),
        prove.stddev(),
        prove.sum(),
        peak_rss_mib()
    );
}
