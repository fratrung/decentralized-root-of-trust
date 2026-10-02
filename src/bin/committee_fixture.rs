//! Generates signed raw records consumed by the committee-scaling benchmark.
//!
//! This process models the committee members and is deliberately outside every
//! measured process. The measured prover receives ready-made signatures, just
//! as a deployed aggregator would; it never owns the committee secret keys.

use std::path::Path;

use decentralized_root_of_trust::bench::workload::{
    advance_list, list_entries_from_env, quorum_indices, workload_manifest,
};
use decentralized_root_of_trust::params::{KEY_SLOTS, N_MEMBERS, N_UPDATES, SLOT, T};
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{Algorithms, StatusList, hash_any};
use leanvm::xmss::{XmssPublicKey, XmssSecretKey, XmssSignature, key_gen, sign};
use rand::RngExt;

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

fn clear_known_files(dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("cannot read fixture directory") {
        let path = entry.expect("cannot read fixture entry").path();
        let known = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n == "anchor.bin"
                || n == "outsider-anchor.bin"
                || n == "workload.txt"
                || n.starts_with("raw-update-")
                || n.starts_with("raw-attack-")
        });
        if known {
            std::fs::remove_file(&path)
                .unwrap_or_else(|e| panic!("cannot remove stale {}: {e}", path.display()));
        }
    }
}

fn signatures_for(
    rng: &mut impl leanvm::rand::CryptoRng,
    keypairs: &[(XmssSecretKey, XmssPublicKey)],
    indices: impl Iterator<Item = usize>,
    message: &[u8; 32],
    slot: u32,
) -> Vec<(usize, XmssSignature)> {
    indices
        .map(|index| {
            let (secret, _) = &keypairs[index];
            let signature = sign(rng, secret, message, slot).expect("fixture signing failed");
            (index, signature)
        })
        .collect()
}

fn main() {
    let outdir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "committee-fixture".into());
    let outdir = Path::new(&outdir);
    std::fs::create_dir_all(outdir).expect("cannot create fixture directory");
    clear_known_files(outdir);

    println!("fixture: generating N={N_MEMBERS}, t={T}, updates={N_UPDATES}");
    let mut xmss_rng = leanvm::rand::rng();
    let mut app_rng = rand::rng();

    let mut keypairs = Vec::with_capacity(N_MEMBERS);
    for _ in 0..N_MEMBERS {
        keypairs
            .push(key_gen(&mut xmss_rng, SLOT, SLOT + KEY_SLOTS).expect("fixture keygen failed"));
    }
    let members = keypairs.iter().map(|(_, public)| public.clone()).collect();
    let committee = Committee::new(members, T, SLOT);
    write(outdir, "anchor.bin", &committee.to_bytes());

    // The workload is declared (`bench::workload`): the list size through
    // BENCH_LIST_ENTRIES, and a quorum spread over the whole committee.
    let list_entries = list_entries_from_env();
    println!(
        "fixture: list entries per version: {}",
        list_entries.map_or("growing 1..=updates".to_string(), |len| len.to_string())
    );
    let mut list = Vec::new();
    for version in 0..N_UPDATES {
        advance_list(&mut list, version, list_entries, || {
            hash_any(app_rng.random::<[u8; 32]>())
        });
        let version = version as u32;
        let slot = committee.slot_for(version).expect("fixture slot overflow");
        let message = committee.message_for(Algorithms::WotsXmss, &list, version);
        let indices = quorum_indices(N_MEMBERS, T, version).into_iter();
        let signatures = signatures_for(&mut xmss_rng, &keypairs, indices, &message, slot);
        let record = StatusList::new(
            Algorithms::WotsXmss,
            list.clone(),
            version,
            N_MEMBERS,
            signatures,
        )
        .expect("honest fixture must be canonical");
        write(
            outdir,
            &format!("raw-update-{version:02}.bin"),
            &record.to_bytes(),
        );
    }

    // One additional, unused slot supplies all negative controls without ever
    // asking an honest XMSS key to sign twice at the same slot.
    let attack_version = N_UPDATES as u32;
    let attack_slot = committee
        .slot_for(attack_version)
        .expect("fixture attack slot overflow");
    let attack_message = committee.message_for(Algorithms::WotsXmss, &list, attack_version);
    let honest = signatures_for(&mut xmss_rng, &keypairs, 0..T, &attack_message, attack_slot);
    let honest_attack = StatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        attack_version,
        N_MEMBERS,
        honest.clone(),
    )
    .expect("attack control must be canonical");
    write(outdir, "raw-attack-honest.bin", &honest_attack.to_bytes());

    // The wrong-slot control: the attack version's genuine statement, signed by
    // the same quorum one slot later. Every signature is valid at the slot it was
    // made at, so on the SNARK path only the derived-slot check can reject it;
    // the raw path, which has no slot field, rejects it at signature
    // verification. `SLOT + N_UPDATES + 1` is used by nothing else: params.rs
    // asserts it stays below `SLOT + KEY_SLOTS`.
    let wrong_slot = committee
        .slot_for(attack_version + 1)
        .expect("fixture wrong-slot overflow");
    let slot_signatures =
        signatures_for(&mut xmss_rng, &keypairs, 0..T, &attack_message, wrong_slot);
    let slot_attack = StatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        attack_version,
        N_MEMBERS,
        slot_signatures,
    )
    .expect("slot control must be canonical");
    write(outdir, "raw-attack-slot.bin", &slot_attack.to_bytes());

    // The version-relabelling control must isolate the message binding, exactly
    // as the self-contained prover's does: the quorum signs the true latest
    // version's statement at the slot the *spoofed* version derives to, so the
    // slot check passes and only the message check can reject the relabelled
    // record. `SLOT + KEY_SLOTS` is used by no honest update and differs from
    // both attack slots above, because params.rs asserts N_UPDATES + 1 < KEY_SLOTS.
    // The record carries the version actually signed; the prover relabels it.
    let signed_version = (N_UPDATES - 1) as u32;
    let spoof_slot = committee
        .slot_for(KEY_SLOTS)
        .expect("fixture spoof slot overflow");
    let spoof_message = committee.message_for(Algorithms::WotsXmss, &list, signed_version);
    let spoofed = signatures_for(&mut xmss_rng, &keypairs, 0..T, &spoof_message, spoof_slot);
    let version_attack = StatusList::new(
        Algorithms::WotsXmss,
        list.clone(),
        signed_version,
        N_MEMBERS,
        spoofed,
    )
    .expect("version control must be canonical");
    write(outdir, "raw-attack-version.bin", &version_attack.to_bytes());

    // Replace member zero with one outsider. The remaining t-1 signatures are
    // reused from the honest control: they sign the identical message and slot,
    // so no honest key is reused. The measured prover maps indices through this
    // alternate anchor but aggregates the main anchor's message, producing a
    // proof for which only membership is wrong.
    let (outsider_secret, outsider_public) =
        key_gen(&mut xmss_rng, SLOT, SLOT + KEY_SLOTS).expect("outsider keygen failed");
    let mut outsider_members = committee.members().to_vec();
    outsider_members[0] = outsider_public.clone();
    let outsider_committee = Committee::new(outsider_members, T, SLOT);
    write(
        outdir,
        "outsider-anchor.bin",
        &outsider_committee.to_bytes(),
    );
    let outsider_signature = sign(
        &mut xmss_rng,
        &outsider_secret,
        &attack_message,
        attack_slot,
    )
    .expect("outsider signing failed");
    let mut outsider = honest;
    outsider[0] = (0, outsider_signature);
    let outsider_attack = StatusList::new(
        Algorithms::WotsXmss,
        list,
        attack_version,
        N_MEMBERS,
        outsider,
    )
    .expect("outsider fixture must be canonical");
    write(
        outdir,
        "raw-attack-outsider.bin",
        &outsider_attack.to_bytes(),
    );

    // What this corpus is, for the harness that measures it: list size and
    // quorum selection. benchmark.sh compares it with the declared workload.
    write(
        outdir,
        "workload.txt",
        workload_manifest(list_entries).as_bytes(),
    );

    println!("FIXTURE n_members={N_MEMBERS} t={T} n_updates={N_UPDATES} status=ok");
}
