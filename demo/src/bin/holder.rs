//! Node A: the relying party, and the only participant that holds no key.
//!
//! It knows the committee a priori, which in the demo means it loads the anchor
//! from the committee volume the way a real one would compile it in. Everything
//! else it learns from the network: which member it happens to dial, what
//! credential comes back, and which record the storage volume holds.
//!
//! The order matters and is the point of the whole exercise. The credential is
//! worth nothing on its own; what makes it meaningful is that its fingerprint
//! sits in a record which `t` members of a committee this node already trusted
//! signed. So the credential is received first and *verified afterwards*,
//! against bytes fetched from a volume nobody authenticates.
//!
//! That sequence is not spelled out here: it is [`RawNode`] and [`SnarkNode`],
//! which own the anchor and the anti-rollback mark together and will not let the
//! second move until the first has spoken. This binary is the transport around
//! one of them.
//!
//! It runs in three shapes, all from one image:
//!
//! * **resident** (`HOLDER_SERVE`): builds the node once, then serves round after
//!   round. This is what a relying party actually is, and on the SNARK path it is
//!   the only shape in which `setup_verifier()` is a startup cost rather than a
//!   per-check one.
//! * **trigger** (`HOLDER_TRIGGER=round|revoke|verify`): a throwaway container
//!   that asks the resident node A for one operation and prints its verdict.
//! * **one-shot** (neither): setup, one round, exit. Kept because it is the
//!   honest measurement of what a cold verifier costs.
//!
//! Configured by environment: `DEMO_MODE`, `SUBJECT`, `TARGET_MEMBER` (must be
//! one of the configured SNARK aggregators in SNARK mode),
//! `VERIFY_ONLY`, `HOLDER_SERVE`, `HOLDER_TRIGGER`.

use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::rss_now_mb;
use decentralized_root_of_trust::node::Outcome;
use decentralized_root_of_trust::node::raw_node::RawNode;
use decentralized_root_of_trust::node::snark_node::SnarkNode;
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{SnarkStatusList, StatusList};
use decentralized_root_of_trust::state::freshness::HighWaterMark;
use drot_demo::config::{self, MEMBER_IPS, Mode};
use drot_demo::wire::{
    self, ACTION_ISSUE, ACTION_REVOKE, ACTION_VERIFY, Failure, StatusRequest, StatusUpdated,
};
use drot_demo::{report, storage, vc};
use lean_multisig::SIGNATURE_SSZ_LEN;
use rand::RngExt;
use ssz::{Decode as _, Encode as _};

const ANCHOR_WAIT: Duration = Duration::from_secs(300);

enum Action {
    Issue(String),
    Revoke,
    Verify,
}

fn main() {
    let mode = Mode::from_env();
    let subject = std::env::var("SUBJECT").unwrap_or_else(|_| "did:demo:alice".into());

    // The trigger shares the resident node's image and environment, so this
    // check has to come first: a container started with both variables set is a
    // client, never a second server competing for the port.
    if let Ok(kind) = std::env::var("HOLDER_TRIGGER") {
        trigger(&kind, &subject);
        return;
    }

    let committee = storage::wait_for_committee(ANCHOR_WAIT).expect("no anchor to trust");
    println!(
        "node A: anchor loaded, {}-of-{} committee, genesis slot {}, {} B",
        committee.threshold(),
        committee.members().len(),
        committee.genesis_slot(),
        committee.to_bytes().len()
    );

    let mut node = Node::build(mode, committee);

    if std::env::var_os("HOLDER_SERVE").is_some() {
        serve(&mut node, &subject);
    }

    let action = if std::env::var_os("VERIFY_ONLY").is_some() {
        Action::Verify
    } else {
        Action::Issue(subject)
    };
    match run_round(&mut node, action) {
        Ok(summary) => println!("\nnode A: {summary}"),
        Err(reason) => {
            println!("\nnode A: {reason}");
            std::process::exit(1);
        }
    }
}

/// The relying party for one of the two published forms, built **once**.
///
/// Each variant owns its anchor, its verifier and its high-water mark, so the
/// only thing this binary decides is which form it is running. The split is also
/// where the cost of *existing* separates from the cost of *checking*: the raw
/// node has nothing to build, while `SnarkNode::new` runs `setup_verifier()`,
/// which loads the aggregation bytecode and has to have happened before a proof
/// can even be deserialised.
enum Node {
    Raw(RawNode),
    Snark(SnarkNode),
}

impl Node {
    /// Pays the fixed cost and reports it. Everything after this is per-record
    /// work, which is the number the two demos are being compared on.
    fn build(mode: Mode, committee: Committee) -> Self {
        let mark = HighWaterMark::load(
            storage::state_dir().join("highwater"),
            &committee.to_bytes(),
        );
        if let Some(version) = mark.current() {
            println!("node A: resuming, nothing below v{version} will be accepted again");
        }

        let before = rss_now_mb();
        let started = Instant::now();
        let built = match mode {
            Mode::Raw => Node::Raw(RawNode::new(committee, mark)),
            Mode::Snark => Node::Snark(SnarkNode::new(committee, mark)),
        };
        let setup = started.elapsed();
        let after = rss_now_mb();

        match mode {
            Mode::Raw => {
                report::rule("verifier startup, raw path");
                println!("  setup                 : none, there is no circuit to load");
                report::memory("anchor load", before, after);
            }
            Mode::Snark => {
                report::rule("verifier startup, SNARK path");
                println!("  setup_verifier()      : {setup:.2?}");
                println!("  paid                  : once per process, not once per check");
                report::memory("setup_verifier", before, after);
            }
        }
        built
    }

    fn mode(&self) -> Mode {
        match self {
            Node::Raw(_) => Mode::Raw,
            Node::Snark(_) => Mode::Snark,
        }
    }

    /// Decode, verify and gate, in that order and without a way to reorder them.
    fn accept(&mut self, bytes: &[u8]) -> Outcome {
        match self {
            Node::Raw(node) => node.accept(bytes),
            Node::Snark(node) => node.accept(bytes),
        }
    }

    /// What the record cost and what it is made of, plus the list the committee
    /// signed so the caller can look for its own credential in it.
    ///
    /// Everything here is a *description* of a record the node has already ruled
    /// on. None of it decides anything, which is why it can decode the bytes a
    /// second time without that being a second opinion.
    fn report(&self, bytes: &[u8], elapsed: Duration) -> Vec<[u8; 32]> {
        match self {
            Node::Raw(_) => {
                let Ok(record) = StatusList::from_bytes(bytes) else {
                    return Vec::new();
                };
                report::rule("verification, raw path");
                println!(
                    "  signers               : {} of {}",
                    record.signer_count(),
                    record.signer_slots()
                );
                println!(
                    "  indices               : {:?}",
                    record.signer_indices().collect::<Vec<_>>()
                );
                println!(
                    "  checked in            : {elapsed:.2?} (decode, {} signatures, and the durable gate)",
                    record.signatures().len()
                );
                println!(
                    "  per signature         : {:.2?}",
                    elapsed / record.signatures().len().max(1) as u32
                );
                report::raw_sizes(
                    bytes.len(),
                    record.list().len(),
                    record.signatures().len(),
                    SIGNATURE_SSZ_LEN,
                );
                report::memory_now();
                record.list_cloned()
            }
            Node::Snark(_) => {
                let Ok(record) = SnarkStatusList::from_bytes(bytes) else {
                    return Vec::new();
                };
                // Available only because `setup_verifier()` has run: the aggregate
                // cannot be deserialised without it.
                let quorum = record
                    .proof()
                    .map(|agg| agg.info.pubkeys.len())
                    .unwrap_or(0);
                report::rule("verification, SNARK path");
                println!("  quorum named in proof : {quorum}");
                println!(
                    "  checked in            : {elapsed:.2?} (decode, one proof, and the durable gate)"
                );
                println!("  setup                 : already paid at startup");
                report::snark_sizes(
                    bytes.len(),
                    record.list().len(),
                    record.proof_bytes().len(),
                    quorum,
                );
                report::memory_now();
                record.list_cloned()
            }
        }
    }
}

/// Serves rounds until the container is stopped, one at a time.
///
/// Sequential on purpose: node A is one relying party with one high-water mark,
/// and two rounds overlapping would race on it for no benefit the demo needs.
fn serve(node: &mut Node, subject: &str) -> ! {
    let listener = TcpListener::bind(("0.0.0.0", config::HOLDER_PORT))
        .expect("node A could not take its port");
    println!(
        "\nnode A: resident on {}. The setup above is paid; every trigger from here \
         on is verification only.",
        config::holder_addr()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => handle(node, subject, &mut stream),
            Err(e) => println!("node A: a trigger could not be accepted: {e}"),
        }
    }
    unreachable!("the listener never ends")
}

/// One trigger: run the round, then hand back the verdict as a single line.
///
/// The report itself stays in this node's own log rather than travelling back.
/// It belongs to the party that did the checking, and the driver tails it.
fn handle(node: &mut Node, subject: &str, stream: &mut TcpStream) {
    if stream
        .set_read_timeout(Some(config::request_timeout()))
        .is_err()
    {
        return;
    }
    let (kind, payload) = match wire::recv(stream) {
        Ok(frame) => frame,
        Err(e) => {
            println!("node A: unreadable trigger: {e}");
            return;
        }
    };
    if kind != wire::MSG_ROUND_REQUEST {
        let _ = wire::send(
            stream,
            wire::MSG_FAILURE,
            &Failure::of("not a round request"),
        );
        return;
    }

    let request = match StatusRequest::from_ssz_bytes(&payload) {
        Ok(request) => request,
        Err(e) => {
            let _ = wire::send(
                stream,
                wire::MSG_FAILURE,
                &Failure::of(format!("malformed status request: {e:?}")),
            );
            return;
        }
    };
    let action = match request.action {
        ACTION_VERIFY => Action::Verify,
        ACTION_REVOKE => Action::Revoke,
        ACTION_ISSUE => {
            let asked = match String::from_utf8(request.data) {
                Ok(asked) => asked,
                Err(_) => {
                    let _ = wire::send(
                        stream,
                        wire::MSG_FAILURE,
                        &Failure::of("credential subject is not UTF-8"),
                    );
                    return;
                }
            };
            Action::Issue(if asked == "default" {
                subject.to_string()
            } else {
                asked
            })
        }
        other => {
            let _ = wire::send(
                stream,
                wire::MSG_FAILURE,
                &Failure::of(format!("unknown status action {other}")),
            );
            return;
        }
    };

    let (kind, text) = match run_round(node, action) {
        Ok(summary) => (wire::MSG_ROUND_RESULT, summary),
        Err(reason) => (wire::MSG_FAILURE, reason),
    };
    println!("\nnode A: {text}");
    let _ = wire::send(stream, kind, &Failure::of(&text));
}

/// Asks the resident node A for one round and exits with its verdict.
fn trigger(kind: &str, subject: &str) {
    let (action, data) = match kind {
        "round" => (ACTION_ISSUE, subject.as_bytes().to_vec()),
        "revoke" => (ACTION_REVOKE, Vec::new()),
        "verify" => (ACTION_VERIFY, Vec::new()),
        other => {
            eprintln!("unknown holder trigger `{other}`; expected round, revoke, or verify");
            std::process::exit(2);
        }
    };
    let payload = StatusRequest { action, data }.as_ssz_bytes();

    let (kind, reply) = wire::request(
        config::holder_addr(),
        config::request_timeout(),
        wire::MSG_ROUND_REQUEST,
        &payload,
    )
    .expect("node A is not resident: start the network first");

    println!("node A: {}", Failure::text(&reply));
    if kind != wire::MSG_ROUND_RESULT {
        std::process::exit(1);
    }
}

/// One operation as node A performs it: request an update when needed, fetch the
/// resulting snapshot, authenticate it, and only then interpret membership.
fn run_round(node: &mut Node, action: Action) -> Result<String, String> {
    let (updated, expected_presence) = match action {
        Action::Issue(subject) => (
            Some(request_status_update(
                node.mode(),
                ACTION_ISSUE,
                subject.as_bytes(),
            )?),
            Some(true),
        ),
        Action::Revoke => {
            let credential = load_credential()?;
            (
                Some(request_status_update(
                    node.mode(),
                    ACTION_REVOKE,
                    &credential,
                )?),
                Some(false),
            )
        }
        Action::Verify => {
            println!("\nnode A: verify-only, checking whatever is published");
            (None, None)
        }
    };

    let (version, bytes) = storage::latest_record().ok_or("nothing is published")?;
    println!(
        "\nnode A: fetched the freshest published record, v{version}, {} B",
        bytes.len()
    );

    let started = Instant::now();
    let outcome = node.accept(&bytes);
    let elapsed = started.elapsed();

    let list = node.report(&bytes, elapsed);

    report::rule("freshness");
    let note = match outcome {
        Outcome::Accepted { version } => {
            println!("  accepted: the mark advanced to v{version}");
            format!("high-water now v{version}")
        }
        Outcome::Stale { version, mark } => {
            println!("  refused: v{version} is not newer than the mark at v{mark}");
            format!("already seen, high-water stays at v{mark}")
        }
        Outcome::Refused => {
            println!("  not reached: the record did not verify under this anchor");
            return Err(format!("v{version} did not verify, refusing it"));
        }
    };

    if let Some(updated) = &updated
        && updated.version != version
    {
        return Err(format!(
            "aggregator reported v{} but storage returned v{version}",
            updated.version
        ));
    }

    let credential = updated
        .as_ref()
        .map(|updated| updated.credential.clone())
        .or_else(load_credential_if_present);
    let membership = credential
        .as_deref()
        .map(|credential| report_credential(&list, credential));

    if let (Some(expected), Some(found)) = (expected_presence, membership)
        && expected != found
    {
        return Err(if expected {
            format!("v{version} verified, but the issued credential is absent")
        } else {
            format!("v{version} verified, but the revoked credential is still present")
        });
    }

    let operation = match expected_presence {
        Some(true) => {
            let credential = credential.expect("an issuance response carries a credential");
            storage::write_atomic(&credential_path(), &credential)
                .map_err(|e| format!("cannot persist the issued credential: {e}"))?;
            "credential issued and present: valid"
        }
        Some(false) => "credential removed: revoked",
        None => match membership {
            Some(true) => "saved credential is present: valid",
            Some(false) => "saved credential is absent: revoked",
            None => "no saved credential to query",
        },
    };
    Ok(format!("v{version} verified, {operation}, {note}"))
}

/// Asks one allowed aggregator, chosen at random unless `TARGET_MEMBER` is set,
/// to publish one validity-snapshot update.
///
/// Raw mode keeps the original rule: every member may coordinate the round. In
/// SNARK mode, only the configured prover subset is eligible, because those are
/// the nodes that paid `setup_prover()` at startup.
fn request_status_update(mode: Mode, action: u8, data: &[u8]) -> Result<StatusUpdated, String> {
    let candidates = config::aggregator_indices(mode);
    let role = match mode {
        Mode::Raw => "member",
        Mode::Snark => "SNARK aggregator",
    };
    let target = match std::env::var("TARGET_MEMBER") {
        Ok(raw) => {
            let target = raw
                .parse::<usize>()
                .map_err(|_| format!("TARGET_MEMBER must be a committee index, got `{raw}`"))?;
            if !candidates.contains(&target) {
                return Err(format!(
                    "member {target} cannot aggregate in {} mode; allowed targets: [{}]",
                    mode.as_str(),
                    config::format_indices(candidates)
                ));
            }
            target
        }
        Err(_) => candidates[(rand::rng().random::<u64>() % candidates.len() as u64) as usize],
    };

    match action {
        ACTION_ISSUE => println!(
            "\nnode A: asking {role} {target} ({}) to issue a credential for {}",
            MEMBER_IPS[target],
            String::from_utf8_lossy(data)
        ),
        ACTION_REVOKE => println!(
            "\nnode A: asking {role} {target} ({}) to revoke fingerprint {}",
            MEMBER_IPS[target],
            &vc::hex(&vc::fingerprint(data))[..16]
        ),
        _ => return Err(format!("unsupported status action {action}")),
    }
    if mode == Mode::Snark {
        println!(
            "node A: SNARK aggregator subset: [{}]",
            config::format_indices(candidates)
        );
    }
    let payload = StatusRequest {
        action,
        data: data.to_vec(),
    }
    .as_ssz_bytes();

    let started = Instant::now();
    let (kind, reply) = wire::request(
        config::member_addr(target),
        config::request_timeout(),
        wire::MSG_STATUS_REQUEST,
        &payload,
    )
    .map_err(|e| format!("{role} {target} did not answer: {e}"))?;

    match kind {
        wire::MSG_STATUS_UPDATED => {
            let updated = StatusUpdated::from_ssz_bytes(&reply)
                .map_err(|_| "malformed status-update response".to_string())?;
            println!("node A: status updated after {:.2?}\n", started.elapsed());
            if action == ACTION_ISSUE {
                println!("{}", vc::pretty(&updated.credential));
            }
            Ok(updated)
        }
        _ => Err(format!(
            "{role} {target} failed the round: {}",
            Failure::text(&reply)
        )),
    }
}
/// The last question, and the one the holder actually came for: is this exact
/// credential currently valid?
///
/// The fingerprint is recomputed from the credential as received, so this
/// answers "these bytes are valid" rather than "some credential is".
fn report_credential(list: &[[u8; 32]], credential: &[u8]) -> bool {
    let entry = vc::fingerprint(credential);
    let found = vc::is_valid(list, credential);
    report::rule("credential");
    println!("  fingerprint           : {}", vc::hex(&entry));
    println!("  present in the signed list: {found}");
    println!(
        "  status                : {}",
        if found { "VALID" } else { "REVOKED" }
    );
    found
}

fn credential_path() -> std::path::PathBuf {
    storage::state_dir().join("credential.bin")
}

fn load_credential() -> Result<Vec<u8>, String> {
    std::fs::read(credential_path())
        .map_err(|e| format!("no issued credential is available to revoke: {e}"))
}

fn load_credential_if_present() -> Option<Vec<u8>> {
    std::fs::read(credential_path()).ok()
}
