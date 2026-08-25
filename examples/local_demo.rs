//! Local, printable walkthrough of the library API.
//!
//! Usage:
//!
//! ```sh
//! cargo run --release --example local_demo -- raw
//! cargo run --release --example local_demo -- snark
//! ```
//!
//! The SNARK mode runs leanVM setup and should always be run in release mode.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use decentralized_root_of_trust::node::Outcome;
use decentralized_root_of_trust::node::raw_node::RawNode;
use decentralized_root_of_trust::node::signer::SignerNode;
use decentralized_root_of_trust::node::snark_node::SnarkNode;
use decentralized_root_of_trust::node::snark_prover::PQSNARKProverModule;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{
    Algorithms, SnarkStatusList, StatusList, hash_any,
};
use decentralized_root_of_trust::state::freshness::HighWaterMark;
use decentralized_root_of_trust::state::slot_counter::AtomicSlotCounter;
use decentralized_root_of_trust::state::status_list_head::{GENESIS_PREDECESSOR, SignedHead};
use lean_multisig::{XmssPublicKey, XmssSignature, xmss_key_gen_from_seed};
use ssz::Encode as _;

const N: usize = 5;
const T: usize = 3;
const GENESIS_SLOT: u32 = 43;
const KEY_SLOTS: u32 = 16;
const SLOT_COUNT: u64 = KEY_SLOTS as u64 + 1;
const LOG_INV_RATE: usize = 2;
const BATCHES: [usize; 3] = [2, 3, 1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Raw,
    Snark,
}

struct Member {
    signer: SignerNode,
    head: Option<SignedHead>,
}

struct EntryNote {
    label: String,
    digest: [u8; 32],
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mode = parse_mode()?;
    let scratch = scratch_dir();
    reset_scratch(&scratch)?;

    println!("decentralized-root-of-trust local example");
    println!("mode          : {}", mode.as_str());
    println!("committee     : {T}-of-{N}");
    println!("genesis slot  : {GENESIS_SLOT}");
    println!(
        "slot window   : {GENESIS_SLOT}..={}\n",
        GENESIS_SLOT + KEY_SLOTS
    );

    let started = Instant::now();
    let (committee, mut members) = bring_up_committee(&scratch)?;
    println!("anchor created in {}", fmt_duration(started.elapsed()));
    println!("anchor digest : 0x{}\n", short_hex(committee.fingerprint()));

    let anchor_bytes = committee.to_bytes();
    let mark_path = scratch.join("high-water.state");

    let mut raw_node = None;
    let mut snark_node = None;
    let mut prover = None;

    match mode {
        Mode::Raw => {
            let node = RawNode::new(
                committee.clone(),
                HighWaterMark::load(&mark_path, &anchor_bytes),
            );
            raw_node = Some(node);
            println!("raw verifier  : no circuit setup\n");
        }
        Mode::Snark => {
            println!("leanVM setup  : starting prover setup, this can take a few seconds");
            let setup_prover = Instant::now();
            prover = Some(PQSNARKProverModule::init_prover());
            println!(
                "leanVM setup  : prover ready in {}",
                fmt_duration(setup_prover.elapsed())
            );

            let setup_verifier = Instant::now();
            snark_node = Some(SnarkNode::new(
                committee.clone(),
                HighWaterMark::load(&mark_path, &anchor_bytes),
            ));
            println!(
                "leanVM setup  : verifier ready in {}\n",
                fmt_duration(setup_verifier.elapsed())
            );
        }
    }

    let domain = committee.domain(Algorithms::WotsXmss);
    let mut list = Vec::new();
    let mut latest_head = None;
    let mut first_record = None;

    for (round, batch_size) in BATCHES.into_iter().enumerate() {
        let version = round as u32;
        let slot = committee
            .slot_for(version)
            .ok_or_else(|| format!("version {version} has no slot under this anchor"))?;
        let predecessor = latest_head.map_or(GENESIS_PREDECESSOR, |head: SignedHead| head.digest());

        let added = append_batch(&mut list, round, batch_size);
        let signers = rotating_quorum(round);

        println!("round {}", round + 1);
        println!("  version     : {version}");
        println!("  slot        : {slot}");
        println!("  predecessor : 0x{}", short_hex(&predecessor));
        println!("  signers     : {:?}", signers);
        println!(
            "  appended    : {} entr{}",
            added.len(),
            plural_y(added.len())
        );
        for note in &added {
            println!("    - {} -> 0x{}", note.label, short_hex(&note.digest));
        }
        print_status_list(&list);

        let message = committee.message_for(Algorithms::WotsXmss, &list, version);
        let mut indexed_signatures = Vec::with_capacity(signers.len());

        for index in signers {
            sync_member_head(index, &mut members, latest_head);

            let next_head = SignedHead::successor(
                &domain,
                members[index].head.as_ref(),
                &predecessor,
                version,
                &list,
            )?;

            let t_sign = Instant::now();
            let signature = members[index]
                .signer
                .sign_at(&message, slot)
                .map_err(|e| format!("member {index} refused to sign v{version}: {e}"))?;
            members[index].head = Some(next_head);

            println!(
                "  member {index} signed in {} (next slot {}, {} left)",
                fmt_duration(t_sign.elapsed()),
                members[index].signer.next_slot(),
                members[index].signer.remaining_slots()
            );

            indexed_signatures.push((index, signature));
        }

        let (accepted, record_bytes) = match mode {
            Mode::Raw => publish_raw(
                raw_node.as_mut().expect("raw node exists"),
                &committee,
                &list,
                version,
                indexed_signatures,
            )?,
            Mode::Snark => publish_snark(
                snark_node.as_mut().expect("snark node exists"),
                prover.as_ref().expect("prover exists"),
                &committee,
                &list,
                version,
                indexed_signatures,
            )?,
        };

        if accepted != Some(version) {
            return Err(format!(
                "record v{version} was not accepted by the relying party: {accepted:?}"
            ));
        }

        if first_record.is_none() {
            first_record = Some(record_bytes);
        }

        latest_head = Some(SignedHead::from_authenticated(&domain, version, &list));
        println!();
    }

    replay_old_record(
        mode,
        first_record.as_deref().expect("at least one round ran"),
        raw_node.as_mut(),
        snark_node.as_mut(),
    )?;

    cleanup_scratch(&scratch);
    Ok(())
}

fn bring_up_committee(dir: &Path) -> Result<(Committee, Vec<Member>), String> {
    let mut pubkeys = Vec::with_capacity(N);
    let mut members = Vec::with_capacity(N);

    for index in 0..N {
        let (pk, sk) = xmss_key_gen_from_seed(seed(index), u64::from(GENESIS_SLOT), SLOT_COUNT)
            .map_err(|e| format!("keygen for member {index} failed: {e:?}"))?;
        let counter = AtomicSlotCounter::create(
            dir.join(format!("member-{index}.slot")),
            &pk,
            GENESIS_SLOT,
            GENESIS_SLOT + KEY_SLOTS,
        )
        .map_err(|e| format!("slot counter for member {index} failed: {e}"))?;

        println!("member {index} key : 0x{}", short_hex(&pk.as_ssz_bytes()));
        pubkeys.push(pk.clone());
        members.push(Member {
            signer: SignerNode::new(pk, sk, counter),
            head: None,
        });
    }

    Ok((Committee::new(pubkeys, T, GENESIS_SLOT), members))
}

fn publish_raw(
    node: &mut RawNode,
    committee: &Committee,
    list: &[[u8; 32]],
    version: u32,
    signatures: Vec<(usize, XmssSignature)>,
) -> Result<(Option<u32>, Vec<u8>), String> {
    let t_build = Instant::now();
    let record = StatusList::new(Algorithms::WotsXmss, list.to_vec(), version, N, signatures)?;
    let bytes = record.to_bytes();
    println!(
        "  raw record  : {} signatures, {} bytes, built in {}",
        record.signatures().len(),
        bytes.len(),
        fmt_duration(t_build.elapsed())
    );

    let t_verify = Instant::now();
    let outcome = node.accept(&bytes);
    println!(
        "  verify      : {:?} in {}",
        outcome,
        fmt_duration(t_verify.elapsed())
    );

    let expected_message = committee.message_for(Algorithms::WotsXmss, list, version);
    println!("  message     : 0x{}", short_hex(&expected_message));
    Ok((outcome.accepted(), bytes))
}

fn publish_snark(
    node: &mut SnarkNode,
    prover: &PQSNARKProverModule,
    committee: &Committee,
    list: &[[u8; 32]],
    version: u32,
    signatures: Vec<(usize, XmssSignature)>,
) -> Result<(Option<u32>, Vec<u8>), String> {
    let raws: Vec<(XmssPublicKey, XmssSignature)> = signatures
        .into_iter()
        .map(|(index, signature)| (committee.members()[index].clone(), signature))
        .collect();

    let t_prove = Instant::now();
    let proof = prover.make_proof(
        committee,
        Algorithms::WotsXmss,
        raws,
        list,
        version,
        LOG_INV_RATE,
    );
    println!(
        "  prove       : {} proof bytes in {}",
        proof.len(),
        fmt_duration(t_prove.elapsed())
    );

    let record = SnarkStatusList::new(Algorithms::WotsXmss, list.to_vec(), version, proof);
    let bytes = record.to_bytes();
    println!("  snark record: {} bytes", bytes.len());

    let t_verify = Instant::now();
    let outcome = node.accept(&bytes);
    println!(
        "  verify      : {:?} in {}",
        outcome,
        fmt_duration(t_verify.elapsed())
    );

    let expected_message = committee.message_for(Algorithms::WotsXmss, list, version);
    println!("  message     : 0x{}", short_hex(&expected_message));
    Ok((outcome.accepted(), bytes))
}

fn replay_old_record(
    mode: Mode,
    first_record: &[u8],
    raw_node: Option<&mut RawNode>,
    snark_node: Option<&mut SnarkNode>,
) -> Result<(), String> {
    let t_replay = Instant::now();
    let outcome = match mode {
        Mode::Raw => raw_node.expect("raw node exists").accept(first_record),
        Mode::Snark => snark_node.expect("snark node exists").accept(first_record),
    };
    println!(
        "replay check  : {:?} in {}",
        outcome,
        fmt_duration(t_replay.elapsed())
    );

    match outcome {
        Outcome::Stale { .. } => Ok(()),
        other => Err(format!("old record replay was not stale: {other:?}")),
    }
}

fn append_batch(list: &mut Vec<[u8; 32]>, round: usize, count: usize) -> Vec<EntryNote> {
    let mut notes = Vec::with_capacity(count);
    for offset in 0..count {
        let label = format!("did:iiot:device-{round}-{offset}");
        let digest = hash_any(label.as_bytes());
        list.push(digest);
        notes.push(EntryNote { label, digest });
    }
    notes
}

fn sync_member_head(index: usize, members: &mut [Member], latest: Option<SignedHead>) {
    if let Some(head) = latest {
        let current = members[index].head;
        if current != Some(head) {
            members[index].head = Some(head);
            println!(
                "  member {index} synced authenticated head v{} ({} entries)",
                head.version(),
                head.entries()
            );
        }
    }
}

fn rotating_quorum(round: usize) -> Vec<usize> {
    (0..T).map(|offset| (round + offset) % N).collect()
}

fn print_status_list(list: &[[u8; 32]]) {
    println!(
        "  status list : {} entr{}",
        list.len(),
        plural_y(list.len())
    );
    for (index, entry) in list.iter().enumerate() {
        println!("    [{index:02}] 0x{}", hex(entry));
    }
}

fn parse_mode() -> Result<Mode, String> {
    match std::env::args().nth(1).as_deref() {
        Some("raw") => Ok(Mode::Raw),
        Some("snark") => Ok(Mode::Snark),
        _ => Err("usage: cargo run --release --example local_demo -- raw|snark".into()),
    }
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Raw => "raw aggregation",
            Mode::Snark => "leanVM SNARK aggregation",
        }
    }
}

fn seed(member: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = 0xE1;
    seed[1] = member as u8;
    seed
}

fn scratch_dir() -> PathBuf {
    std::env::temp_dir().join(format!("drot-local-example-{}", std::process::id()))
}

fn reset_scratch(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("cannot reset {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))
}

fn cleanup_scratch(dir: &Path) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        eprintln!("warning: cannot remove {}: {e}", dir.display());
    }
}

fn fmt_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2} s", d.as_secs_f64())
    } else {
        format!("{:.2} ms", d.as_secs_f64() * 1000.0)
    }
}

fn plural_y(n: usize) -> &'static str {
    if n == 1 { "y" } else { "ies" }
}

fn short_hex(bytes: &[u8]) -> String {
    hex(bytes).chars().take(16).collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("writing into a String cannot fail");
    }
    out
}
