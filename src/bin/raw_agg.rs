//! Baseline: the **crude** aggregate-signature path, with no SNARK at all.
//!
//! This is the yardstick the SNARK-aggregated prover/verifier are measured
//! against. Here an "aggregate" is nothing clever: it is the `t` individual XMSS
//! signatures a quorum produces for one update, published together with a bitmap
//! naming their signers. There is no proof to build and no proof to check.
//!
//! In self-contained mode this runs the **real node types**: every signer is a
//! `SignerNode` spending slots through its own durable `AtomicSlotCounter`, and
//! the verifier is a `VerifierNode` checking a `StatusList` against the anchor.
//! With `BENCH_INPUT_DIR`, signing has already happened in a separate fixture
//! process and this binary measures only the raw relying-party verifier.
//! In self-contained mode the `t` signatures are produced here only because a
//! record needs them; their cost is not timed, since in a deployment it is paid
//! once each by `t` separate machines. That role is measured in
//! `src/bin/signer.rs`.
//! What this binary measures is the relying party's side: verify and size.
//!
//! Note what this binary does **not** call: neither `setup_prover()` nor
//! `setup_verifier()`. Raw XMSS sign/verify use BLAKE2s directly: no circuit, no
//! arena, no FFT twiddles. That absence is itself a result: it is the fixed cost
//! the SNARK path pays and this one does not.
//!
//! The trade it quantifies: verification per signature is trivially cheap, but
//! both the payload and the verifier's work grow with `t`, where the SNARK
//! collapses both to a constant at the price of an expensive prover.
//!
//! Usage: cargo run --release --bin raw_agg          (always --release)

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::{peak_rss_mib, rss_now_mib};
use decentralized_root_of_trust::bench::state::signer_state_dir;
use decentralized_root_of_trust::bench::stats::{Series, median_usize};
use decentralized_root_of_trust::bench::timing::{
    DecodeVerify, decode_then_verify, process_cpu_time,
};
use decentralized_root_of_trust::bench::workload::ListSizes;
use decentralized_root_of_trust::node::raw_verifier::VerifierNode;
use decentralized_root_of_trust::node::signer::SignerNode;
use decentralized_root_of_trust::params::{KEY_SLOTS, N_MEMBERS, N_UPDATES, SLOT, T};
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{Algorithms, StatusList, hash_any};
use decentralized_root_of_trust::state::slot_counter::AtomicSlotCounter;
use leanvm::xmss::{XmssPublicKey, XmssSignature, key_gen};
use rand::RngExt;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Decode and verify one record under the boundary every relying-party target
/// shares (`bench::timing`): the returned value still owns the decoded record,
/// so its release is outside the timers and the caller reads RSS before
/// dropping it.
fn measure_verification(bytes: &[u8], verifier: &VerifierNode) -> DecodeVerify<StatusList, String> {
    decode_then_verify(
        || StatusList::from_bytes(bytes),
        |record| verifier.verify_status_list(record),
    )
}

/// The signature-validity control: `wire` with one bit of its last signature
/// changed. It must decode to the same list, version and signer set, so quorum,
/// bitmap and message are all in order and only verifying that signature can
/// reject it. SSZ puts the fixed-size signatures last, so the final byte of the
/// record is the final byte of the last one, and every XMSS byte string of the
/// right length decodes.
fn corrupt_last_signature(wire: &[u8]) -> StatusList {
    let honest = StatusList::from_bytes(wire).expect("honest control must decode");
    let mut bytes = wire.to_vec();
    *bytes.last_mut().expect("record has signature bytes") ^= 1;
    let corrupted = StatusList::from_bytes(&bytes)
        .expect("changing a signature bit must preserve the record shape");
    assert!(
        corrupted.list() == honest.list()
            && corrupted.version() == honest.version()
            && corrupted.signer_indices().eq(honest.signer_indices())
            && corrupted.to_bytes() != wire,
        "the signature control must differ from its honest record in a signature only"
    );
    corrupted
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

fn load_raw(path: &Path) -> StatusList {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("cannot read raw fixture {}: {e}", path.display()));
    StatusList::from_bytes(&bytes)
        .unwrap_or_else(|e| panic!("malformed raw fixture {}: {e}", path.display()))
}

fn indexed_signatures(record: &StatusList) -> Vec<(usize, XmssSignature)> {
    record
        .signer_indices()
        .zip(record.signatures())
        .map(|(index, signature)| (index, signature.clone()))
        .collect()
}

/// Measures only the raw relying-party role over records prepared by the
/// separate committee process. No secret key or slot counter is resident here.
fn run_fixture_verifier(fixture_dir: &Path) {
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();
    // `ready`: what a relying party pays once per process before it can verify
    // anything: read and decode the anchor, build the verifier. The three
    // verifier targets bracket the same steps, so a cold start can be compared
    // across them; this path has no circuit to set up.
    let ready_cpu_start = process_cpu_time();
    let t_ready = Instant::now();
    let anchor_bytes =
        std::fs::read(fixture_dir.join("anchor.bin")).expect("cannot read fixture anchor");
    let committee = Committee::from_bytes(&anchor_bytes).expect("malformed fixture anchor");
    assert_eq!(
        committee.members().len(),
        N_MEMBERS,
        "fixture N/build N drift"
    );
    assert_eq!(committee.threshold(), T, "fixture t/build t drift");
    let verifier = VerifierNode::new(committee);
    let ready = ms(t_ready.elapsed());
    let ready_cpu = ms(process_cpu_time().saturating_sub(ready_cpu_start));

    let rss_after_anchor = rss_now_mib();
    let updates = fixture_files(fixture_dir, "raw-update-");
    assert_eq!(
        updates.len(),
        N_UPDATES,
        "fixture must contain exactly N_UPDATES honest records"
    );
    let mut decode_ms = Vec::with_capacity(updates.len());
    let mut verify_only_ms = Vec::with_capacity(updates.len());
    let mut verify_ms = Vec::with_capacity(updates.len());
    let mut record_bytes = Vec::with_capacity(updates.len());
    let mut rss_updates_max = rss_after_anchor;

    let mut total_cpu_ms = Vec::with_capacity(updates.len());
    let mut list_sizes = ListSizes::default();

    for (index, path) in updates.iter().enumerate() {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("cannot read raw fixture {}: {e}", path.display()));
        let measured = measure_verification(&bytes, &verifier);
        assert!(
            measured.accepted,
            "an honest fixture failed raw verification"
        );
        if let Ok(record) = &measured.decoded {
            list_sizes.record(record.list().len());
        }
        let rss = rss_now_mib();
        rss_updates_max = rss_updates_max.max(rss);
        let (decode_time, verify_only_time, verify_time) =
            (measured.decode, measured.verify, measured.total);
        let cpu = ms(measured.cpu);
        drop(measured);
        println!(
            "  update {:2}/{}  t={}  verify={:>8.1?}  {} B  RAM={} MiB",
            index + 1,
            updates.len(),
            T,
            verify_time,
            bytes.len(),
            rss
        );
        if emit_samples {
            println!(
                "SAMPLE target=raw_agg idx={index} decode_ms={:.3} verify_ms={:.3} total_ms={:.3} bytes={} rss_mib={rss} cpu_ms={cpu:.3}",
                ms(decode_time),
                ms(verify_only_time),
                ms(verify_time),
                bytes.len()
            );
        }
        total_cpu_ms.push(cpu);
        decode_ms.push(ms(decode_time));
        verify_only_ms.push(ms(verify_only_time));
        verify_ms.push(ms(verify_time));
        record_bytes.push(bytes.len());
    }

    // Preserve the raw-path failure gate while keeping every negative control
    // outside the timed update series.
    let honest_bytes = std::fs::read(fixture_dir.join("raw-attack-honest.bin"))
        .expect("cannot read raw-attack-honest.bin");
    let honest = StatusList::from_bytes(&honest_bytes).expect("malformed raw-attack-honest.bin");
    let honest_pairs = indexed_signatures(&honest);
    let mut tampered_list = honest.list_cloned();
    tampered_list.push(hash_any(b"FAKE-REVOCATION"));
    let tampered = StatusList::new(
        honest.alg,
        tampered_list,
        honest.version(),
        N_MEMBERS,
        honest_pairs.clone(),
    )
    .expect("tampered control must be structurally valid");
    let tamper_rejected = !verifier.verify_status_list(&tampered);

    let relabelled = StatusList::new(
        honest.alg,
        honest.list_cloned(),
        honest.version() + 1,
        N_MEMBERS,
        honest_pairs.clone(),
    )
    .expect("relabelled control must be structurally valid");
    let relabel_rejected = !verifier.verify_status_list(&relabelled);

    let short = StatusList::new(
        honest.alg,
        honest.list_cloned(),
        honest.version(),
        N_MEMBERS,
        honest_pairs.into_iter().take(T - 1).collect(),
    )
    .expect("short control must be structurally valid");
    let short_rejected = !verifier.verify_status_list(&short);
    let outsider = load_raw(&fixture_dir.join("raw-attack-outsider.bin"));
    let outsider_rejected = !verifier.verify_status_list(&outsider);
    // A full quorum over the right statement, signed one slot late. The raw
    // record has no slot field, so this is rejected at signature verification.
    let slot_attack = load_raw(&fixture_dir.join("raw-attack-slot.bin"));
    let slot_rejected = !verifier.verify_status_list(&slot_attack);
    let signature_rejected = !verifier.verify_status_list(&corrupt_last_signature(&honest_bytes));
    let all_rejected = tamper_rejected
        && relabel_rejected
        && short_rejected
        && outsider_rejected
        && slot_rejected
        && signature_rejected;

    let decode = Series::new(decode_ms);
    let verify = Series::new(verify_only_ms);
    let total = Series::new(verify_ms);
    let (vf_min, vf_med, vf_max) = verify.min_med_max();
    let (total_min, total_med, total_max) = total.min_med_max();
    let total_cpu = Series::new(total_cpu_ms);
    let (total_cpu_med, total_cpu_total) = (total_cpu.median(), total_cpu.sum());
    let record_med = median_usize(&record_bytes);
    let per_signature_us = vf_med * 1000.0 / T as f64;

    println!("\n{} honest updates accepted", verify.len());
    println!(
        "forgeries rejected (tampered / relabelled / short / outsider / slot / signature): \
         {tamper_rejected} / {relabel_rejected} / {short_rejected} / {outsider_rejected} / \
         {slot_rejected} / {signature_rejected}"
    );
    println!("verify-only min/med/max : {vf_min:.1} / {vf_med:.1} / {vf_max:.1} ms");
    println!("decode+verify min/med/max: {total_min:.1} / {total_med:.1} / {total_max:.1} ms");
    println!("published record size (median): {record_med:.1} bytes");
    println!("\nRAM (raw verifier process; no secret keys)");
    println!("after anchor            : {rss_after_anchor} MiB");
    println!("max during updates      : {rss_updates_max} MiB");
    println!("peak (VmHWM)            : {} MiB", peak_rss_mib());
    println!(
        "\nRAW_AGG n_members={N_MEMBERS} t={T} n_updates={} \
         verify_med_ms={vf_med:.3} verify_mean_ms={:.3} verify_sd_ms={:.3} \
         verify_min_ms={vf_min:.3} verify_max_ms={vf_max:.3} verify_total_ms={:.3} \
         decode_med_ms={:.3} decode_mean_ms={:.3} decode_sd_ms={:.3} \
         decode_min_ms={:.3} decode_max_ms={:.3} decode_total_ms={:.3} \
         total_med_ms={total_med:.3} total_mean_ms={:.3} total_sd_ms={:.3} \
         total_min_ms={total_min:.3} total_max_ms={total_max:.3} total_total_ms={:.3} \
         per_sig_verify_us={per_signature_us:.3} record_med_bytes={record_med:.3} \
         rss_keygen_mib={rss_after_anchor} rss_updates_max_mib={rss_updates_max} \
         peak_rss_mib={} tamper_rejected={} fixture_input=1 {list_sizes} \
         total_cpu_med_ms={total_cpu_med:.3} total_cpu_total_ms={total_cpu_total:.3} \
         ready_ms={ready:.3} ready_cpu_ms={ready_cpu:.3}",
        verify.len(),
        verify.mean(),
        verify.stddev(),
        verify.sum(),
        decode.median(),
        decode.mean(),
        decode.stddev(),
        decode.min(),
        decode.max(),
        decode.sum(),
        total.mean(),
        total.stddev(),
        total.sum(),
        peak_rss_mib(),
        all_rejected as u8,
    );

    if !all_rejected {
        eprintln!("a raw-path negative control was accepted");
        std::process::exit(1);
    }
}

fn main() {
    if let Some(fixture_dir) = std::env::var_os("BENCH_INPUT_DIR") {
        run_fixture_verifier(Path::new(&fixture_dir));
        return;
    }

    // Off by default so interactive runs stay readable; the benchmark harness
    // sets it to collect one row per update.
    let emit_samples = std::env::var_os("EMIT_SAMPLES").is_some();

    // Slot state lives outside the repo and is wiped on the way out: these keys
    // are generated fresh every run, so their counters are meaningless the moment
    // the process exits. A real node does the opposite: its counter outlives it,
    // and deleting one while its key survives is how slots get reused.
    let state_dir = signer_state_dir().join(format!("raw-agg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).expect("cannot create slot state dir");

    let rss_baseline = rss_now_mib();

    // ---- One-time costs: the committee's N keys, and their durable slot state. ----
    //
    // Two numbers, not one. Keygen is not the counterpart of the SNARK path's
    // `setup_prover()`: every path pays it, and `prover` reports it too. What this
    // path uniquely does not pay is the circuit setup, which shows up as an empty
    // `setup` column. The slot state is separate again: N fsync'd
    // `AtomicSlotCounter`s, a cost of the safe *signer* rather than of the crypto.
    println!("raw_agg: keygen (no SNARK setup, no circuit)...");
    let mut rng = rand::rng();
    let mut xmss_rng = leanvm::rand::rng();
    let mut keygen_time = Duration::ZERO;
    let mut slot_state_time = Duration::ZERO;
    let mut signers: Vec<SignerNode> = Vec::with_capacity(N_MEMBERS);
    let mut members: Vec<XmssPublicKey> = Vec::with_capacity(N_MEMBERS);
    for i in 0..N_MEMBERS {
        let t_k = Instant::now();
        let (sk, pk) = key_gen(&mut xmss_rng, SLOT, SLOT + KEY_SLOTS).expect("keygen failed");
        keygen_time += t_k.elapsed();

        let path: PathBuf = state_dir.join(format!("member-{i:04}"));
        let t_s = Instant::now();
        let counter =
            AtomicSlotCounter::create(&path, &pk, SLOT, SLOT + KEY_SLOTS).expect("slot state");
        slot_state_time += t_s.elapsed();

        members.push(pk.clone());
        signers.push(SignerNode::new(pk, sk, counter));
    }
    let rss_after_keygen = rss_now_mib();

    // The fixed trust anchor. `SLOT` is the genesis: every round derives its slot
    // from it, so no signer ever chooses one.
    let committee = Committee::new(members, T, SLOT);
    let verifier = VerifierNode::new(committee.clone());

    println!("committee N={N_MEMBERS} t={T}; {N_UPDATES} updates rotating the signers");
    // `N + 1` bits: the SSZ BitList appends a sentinel bit after the last member,
    // which is what makes its length in bits recoverable on decode.
    println!(
        "aggregate = {T} raw XMSS signatures + a {}-byte signer bitmap (no proof)\n",
        (N_MEMBERS + 1).div_ceil(8)
    );

    // ---- N_UPDATES updates. For each: t signers sign the (list, version) root,
    //      the signatures plus their bitmap ARE the record, then it is verified. ----
    let mut list: Vec<[u8; 32]> = Vec::new();
    let mut decode_ms = Vec::new();
    let mut verify_only_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut total_cpu_ms = Vec::new();
    let mut record_bytes = Vec::new();
    let mut accepted = 0usize;
    let mut rss_updates_max = rss_after_keygen;

    for i in 0..N_UPDATES {
        list.push(hash_any(rng.random::<[u8; 32]>()));
        // t signers out of N, rotating the window at each update.
        let quorum: Vec<usize> = (0..T).map(|j| (i + j) % N_MEMBERS).collect();
        let version = i as u32;
        // Derived from the anchor, never negotiated, which is what lets members
        // that sat out earlier rounds rejoin without the committee losing
        // agreement on the slot.
        let slot = committee.slot_for(version).expect("slot overflow");
        let message = committee.message_for(Algorithms::WotsXmss, &list, version);

        // t plain XMSS signatures, each preceded by its signer's durable slot
        // burn. Untimed on purpose: see the note at the top of the file.
        let raws: Vec<(usize, XmssSignature)> = quorum
            .iter()
            .map(|&k| {
                let sig = signers[k].sign_at(&message, slot).expect("signing failed");
                (k, sig)
            })
            .collect();

        let record = StatusList::new(Algorithms::WotsXmss, list.clone(), version, N_MEMBERS, raws)
            .expect("well-formed quorum");
        // The wire payload: the honest analog of the SNARK's proof_bytes, and the
        // number that grows with t while the SNARK's stays constant.
        let wire = record.to_bytes();

        // Verify the way a peer would: decode off the wire, then check against the
        // anchor alone. Decoding is timed with verification because on an
        // untrusted transport it is part of the cost an attacker can force.
        let measured = measure_verification(&wire, &verifier);
        assert!(measured.accepted, "a legitimate update failed to verify");
        accepted += 1;

        let rss = rss_now_mib();
        rss_updates_max = rss_updates_max.max(rss);
        let (decode_time, verify_only_time, verify_time) =
            (measured.decode, measured.verify, measured.total);
        let cpu = ms(measured.cpu);
        drop(measured);
        println!(
            "  update {:2}/{}  v{}  slot {}  verify={:>8.1?}  {} B  RAM={} MiB",
            i + 1,
            N_UPDATES,
            version,
            slot,
            verify_time,
            wire.len(),
            rss
        );
        if emit_samples {
            println!(
                "SAMPLE target=raw_agg idx={i} decode_ms={:.3} verify_ms={:.3} total_ms={:.3} bytes={} rss_mib={rss} cpu_ms={cpu:.3}",
                ms(decode_time),
                ms(verify_only_time),
                ms(verify_time),
                wire.len()
            );
        }
        total_cpu_ms.push(cpu);
        decode_ms.push(ms(decode_time));
        verify_only_ms.push(ms(verify_only_time));
        verify_ms.push(ms(verify_time));
        record_bytes.push(wire.len());
    }

    // ---- Sanity checks: verification is not a no-op. ----
    // Each forgery is built from a *genuine* quorum, so what fails is the binding
    // under test and nothing else.
    let version = N_UPDATES as u32;
    let slot = committee.slot_for(version).expect("slot overflow");
    let message = committee.message_for(Algorithms::WotsXmss, &list, version);
    let honest: Vec<(usize, XmssSignature)> = (0..T)
        .map(|k| {
            (
                k,
                signers[k].sign_at(&message, slot).expect("signing failed"),
            )
        })
        .collect();

    // A) a row nobody authorized, appended to a list carrying a real quorum.
    let mut tampered = list.clone();
    tampered.push(hash_any(b"FAKE-REVOCATION"));
    let tamper_rejected = !verifier.verify_status_list(
        &StatusList::new(
            Algorithms::WotsXmss,
            tampered,
            version,
            N_MEMBERS,
            honest.clone(),
        )
        .expect("well-formed"),
    );

    // B) the same quorum re-labelled with a later version. The version is folded
    //    into the message AND fixes the slot, so both bindings break at once.
    let relabel_rejected = !verifier.verify_status_list(
        &StatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            version + 1,
            N_MEMBERS,
            honest.clone(),
        )
        .expect("well-formed"),
    );

    // C) below threshold: t - 1 signatures, every one of them valid.
    let short: Vec<(usize, XmssSignature)> = honest.iter().take(T - 1).cloned().collect();
    let short_rejected = !verifier.verify_status_list(
        &StatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            version,
            N_MEMBERS,
            short,
        )
        .expect("well-formed"),
    );

    // D) an outsider claiming a member's seat. There is no other way in: a record
    //    names signers by index, so a non-member is unnameable rather than merely
    //    rejected.
    let honest_wire = StatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        version,
        N_MEMBERS,
        honest.clone(),
    )
    .expect("well-formed")
    .to_bytes();
    let (out_sk, out_pk) = key_gen(&mut xmss_rng, SLOT, SLOT + KEY_SLOTS).expect("keygen");
    let out_counter =
        AtomicSlotCounter::create(state_dir.join("outsider"), &out_pk, SLOT, SLOT + KEY_SLOTS)
            .expect("slot state");
    let mut outsider = SignerNode::new(out_pk, out_sk, out_counter);
    let mut infiltrated = honest;
    infiltrated[0] = (0, outsider.sign_at(&message, slot).expect("signing failed"));
    let outsider_rejected = !verifier.verify_status_list(
        &StatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            version,
            N_MEMBERS,
            infiltrated,
        )
        .expect("well-formed"),
    );

    // E) the same statement signed by a full quorum one slot late. Each member's
    //    durable counter jumps forward to it, so no key signs twice at one slot.
    let late_slot = committee.slot_for(version + 1).expect("slot overflow");
    let late: Vec<(usize, XmssSignature)> = (0..T)
        .map(|k| {
            (
                k,
                signers[k]
                    .sign_at(&message, late_slot)
                    .expect("signing failed"),
            )
        })
        .collect();
    let slot_rejected = !verifier.verify_status_list(
        &StatusList::new(Algorithms::WotsXmss, list.clone(), version, N_MEMBERS, late)
            .expect("well-formed"),
    );

    // F) the honest record with one bit of one signature changed.
    let signature_rejected = !verifier.verify_status_list(&corrupt_last_signature(&honest_wire));

    let all_rejected = tamper_rejected
        && relabel_rejected
        && short_rejected
        && outsider_rejected
        && slot_rejected
        && signature_rejected;

    // ---- Summary ----
    let decode = Series::new(decode_ms);
    let verify = Series::new(verify_only_ms);
    let total = Series::new(verify_ms);
    let (vf_min, vf_med, vf_max) = verify.min_med_max();
    let (total_min, total_med, total_max) = total.min_med_max();
    let total_cpu = Series::new(total_cpu_ms);
    let (total_cpu_med, total_cpu_total) = (total_cpu.median(), total_cpu.sum());
    let record_med = median_usize(&record_bytes);
    // Per-signature figure, derived from the median: what checking one signature
    // costs, which is what makes the number projectable to other values of t.
    let per_sig_verify_us = vf_med * 1000.0 / T as f64;

    println!("\n{accepted}/{N_UPDATES} updates accepted by the verifier node");
    println!(
        "forgeries rejected (tampered / relabelled / short quorum / outsider / slot / signature): \
         {tamper_rejected} / {relabel_rejected} / {short_rejected} / {outsider_rejected} / \
         {slot_rejected} / {signature_rejected}"
    );

    println!("\nkeygen ({N_MEMBERS} keys)   : {keygen_time:.2?}");
    println!("slot state ({N_MEMBERS} counters) : {slot_state_time:.2?}   (durable, fsync'd)");
    println!("--- per update (t={T}): min / median / max ---");
    println!("verify-only: {vf_min:.1} / {vf_med:.1} / {vf_max:.1} ms");
    println!("decode+verify: {total_min:.1} / {total_med:.1} / {total_max:.1} ms");
    println!("per signature : verify {per_sig_verify_us:.1} us");
    println!("published record size (median): {record_med:.1} bytes  ({T} signatures + bitmap)");

    println!("\nRAM (raw-multisig process, no SNARK)");
    println!("baseline (pre-keygen)  : {rss_baseline} MiB");
    println!("after keygen (resident): {rss_after_keygen} MiB");
    println!("max during updates     : {rss_updates_max} MiB");
    println!("peak (VmHWM)           : {} MiB", peak_rss_mib());

    // One-line machine-readable record, same convention as prover.rs / verifier.rs.
    // Phases are carried into runs.csv under their own names (`verify_*`), never
    // under a positional "primary/secondary" slot: a shared column would have put
    // this target's numbers under the same heading as an unrelated phase of
    // another one.
    println!(
        "\nRAW_AGG keygen_ms={:.3} slot_state_ms={:.3} n_members={N_MEMBERS} t={T} n_updates={} \
         verify_med_ms={vf_med:.3} \
         verify_mean_ms={:.3} verify_sd_ms={:.3} verify_min_ms={vf_min:.3} \
         verify_max_ms={vf_max:.3} verify_total_ms={:.3} \
         decode_med_ms={:.3} decode_mean_ms={:.3} decode_sd_ms={:.3} \
         decode_min_ms={:.3} decode_max_ms={:.3} decode_total_ms={:.3} \
         total_med_ms={total_med:.3} total_mean_ms={:.3} total_sd_ms={:.3} \
         total_min_ms={total_min:.3} total_max_ms={total_max:.3} total_total_ms={:.3} \
         per_sig_verify_us={per_sig_verify_us:.3} \
         record_med_bytes={record_med:.3} rss_keygen_mib={rss_after_keygen} \
         rss_updates_max_mib={rss_updates_max} peak_rss_mib={} tamper_rejected={} \
         total_cpu_med_ms={total_cpu_med:.3} total_cpu_total_ms={total_cpu_total:.3}",
        ms(keygen_time),
        ms(slot_state_time),
        verify.len(),
        verify.mean(),
        verify.stddev(),
        verify.sum(),
        decode.median(),
        decode.mean(),
        decode.stddev(),
        decode.min(),
        decode.max(),
        decode.sum(),
        total.mean(),
        total.stddev(),
        total.sum(),
        peak_rss_mib(),
        // Must be an integer: benchmark.sh's failure gate tests this field against
        // "1", and a Rust bool would print "true" and score every run as a
        // security-expectation failure. Despite the field's name
        // (`tamper_rejected`), this is the AND of all six forgery checks.
        all_rejected as u8,
    );

    // Counters die with the keys they belong to; see the note at the top.
    drop(signers);
    drop(outsider);
    let _ = std::fs::remove_dir_all(&state_dir);

    if !all_rejected {
        eprintln!("\na forgery was accepted");
        std::process::exit(1);
    }
}
