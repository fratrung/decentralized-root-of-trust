//! Asks one member to sign a version directly, with no aggregator involved.
//!
//! The demo's normal flow can never make a member sign twice at one slot,
//! because the aggregator derives the version from what is published and no
//! honest round repeats it. This probe is what an *aggregator that misbehaves*
//! would do: propose the same version twice, with a different entry each time,
//! and try to get two signatures out of one XMSS slot. That is the failure the
//! whole design exists to prevent, since two signatures at one slot recover the
//! secret key.
//!
//! Run it twice against a member with two different entry labels. The first call
//! is signed, the second is refused, and the refusal is durable: kill the
//! container between the two calls and restart it, and the answer does not
//! change, because the slot was burned on disk before the key ever touched it.
//!
//! Usage: `probe --member <index> --entry <label> [--version <n>]`
//!
//! Exit status: 0 signed, 3 abstained, 1 could not ask.

use std::time::Duration;

use decentralized_root_of_trust::protocol::status_list::{SnarkStatusList, StatusList, hash_any};
use drot_demo::config::{self, MEMBER_IPS, Mode};
use drot_demo::storage;
use drot_demo::wire::{self, Failure, Proposal, SignatureReply};
use ssz::{Decode as _, Encode as _};

fn main() {
    let mode = Mode::from_env(); // snark proof or raw aggretation 
    let mut member: usize = 0;
    let mut label = String::from("probe");
    let mut version: Option<u32> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--member" => member = value.parse().expect("--member takes an index"),
            "--entry" => label = value,
            "--version" => version = Some(value.parse().expect("--version takes a number")),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }

    // The proposal has to be one a member would accept on its merits: the
    // published list plus exactly one entry, at the next version. Otherwise the
    // extension check refuses it first and the slot counter is never reached,
    // which would prove nothing.
    let (published, mut list) = match storage::latest_record() {
        Some((_, bytes)) => decode(mode, &bytes),
        None => panic!("nothing is published yet; run a normal round first"),
    };
    let version = version.unwrap_or(published + 1);
    let entry = hash_any(label.as_bytes());
    list.push(entry);

    // The slot is not sent, and could not be: the member derives it. Reading the
    // anchor here only lets the probe name the slot it is about to compete for.
    let committee = storage::wait_for_committee(Duration::from_secs(60)).expect("no anchor");
    let slot = committee.slot_for(version).expect("version has no slot");

    println!(
        "probe: asking member {member} ({}) to sign v{version} (slot {slot}) with entry `{label}`",
        MEMBER_IPS[member]
    );
    let payload = Proposal { version, list }.as_ssz_bytes();
    let answer = wire::request(
        config::member_addr(member),
        config::request_timeout(),
        wire::MSG_PROPOSAL,
        &payload,
    );

    let (kind, reply) = match answer {
        Ok(frame) => frame,
        Err(e) => {
            println!("probe: member {member} is unreachable: {e}");
            std::process::exit(1);
        }
    };
    if kind != wire::MSG_SIGNATURE {
        println!(
            "probe: member {member} refused the request: {}",
            Failure::text(&reply)
        );
        std::process::exit(1);
    }

    let reply = SignatureReply::from_ssz_bytes(&reply).expect("malformed reply");
    match reply.signature.first() {
        Some(_) => {
            println!("probe: SIGNED. member {member} has now spent slot {slot}");
            std::process::exit(0);
        }
        None => {
            println!(
                "probe: ABSTAINED. member {member} says: {}",
                String::from_utf8_lossy(&reply.reason)
            );
            std::process::exit(3);
        }
    }
}

fn decode(mode: Mode, bytes: &[u8]) -> (u32, Vec<[u8; 32]>) {
    let decoded = match mode {
        Mode::Raw => StatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned())),
        Mode::Snark => SnarkStatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned())),
    };
    decoded.expect("the published record does not decode")
}
