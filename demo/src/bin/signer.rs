//! A committee member, and, for selected nodes, an aggregator.
//!
//! Every node in the demo runs this same binary. In raw mode any member can
//! coordinate a round. In SNARK mode only the configured prover subset can do
//! that: those nodes run `setup_prover()` before they start listening, and node A
//! requests credentials only from them. They are not more trusted than the other
//! members; they just pay the memory and time cost needed to produce the proof.
//! In particular an aggregator cannot name the XMSS slot. It proposes a
//! *version*, and every member derives the slot from the anchor itself.
//!
//! A member's cryptographic defence is its durable slot counter: signing a
//! second snapshot under one slot is unreachable rather than merely discouraged.
//! The status list itself is a complete validity snapshot and may grow, shrink,
//! or become empty; one version may add and remove any number of fingerprints at
//! once. Which changes a member approves is application policy; this demo has
//! every member approve the requested update.
//!
//! Configured entirely by environment: `MEMBER_INDEX`, `MEMBER_SECRET`,
//! `DEMO_MODE`.

use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::rss_now_mb;
use decentralized_root_of_trust::node::raw_verifier::VerifierNode;
use decentralized_root_of_trust::node::signer::SignerNode;
use decentralized_root_of_trust::node::snark_prover::PQSNARKProverModule;
use decentralized_root_of_trust::params::{KEY_SLOT_COUNT, KEY_SLOTS, LOG_INV_RATE, SLOT};
use decentralized_root_of_trust::protocol::committee::Committee;
use decentralized_root_of_trust::protocol::status_list::{Algorithms, SnarkStatusList, StatusList};
use decentralized_root_of_trust::state::slot_counter::AtomicSlotCounter;
use drot_demo::config::{self, MEMBER_IPS, MEMBER_PORT, Mode, N_MEMBERS, THRESHOLD};
use drot_demo::storage;
use drot_demo::vc;
use drot_demo::wire::{
    self, ACTION_ISSUE, ACTION_REVOKE, Failure, Proposal, SignatureReply, StatusRequest,
    StatusUpdated,
};
use lean_multisig::{XmssPublicKey, XmssSignature, xmss_key_gen_from_seed};
use ssz::{Decode as _, Encode as _};

/// How long a node waits at startup for the bootstrap step.
const BOOTSTRAP_WAIT: Duration = Duration::from_secs(300);

struct Node {
    index: usize,
    mode: Mode,
    committee: Committee,
    /// The one place a slot is spent. Behind a mutex because proposals arrive on
    /// their own threads, and two concurrent signatures would race the counter
    /// that exists precisely to keep them apart.
    signer: Mutex<SignerNode>,
    /// Serialises the rounds *this* node coordinates. Two holders arriving at
    /// once would otherwise propose the same version twice, and the second round
    /// would collect nothing but abstentions.
    round: Mutex<()>,
    /// True for every raw member and for the configured SNARK prover subset.
    can_aggregate: bool,
    /// Present only on SNARK aggregators. Signer-only nodes leave it empty and
    /// can still answer proposals like every other committee member.
    prover: OnceLock<PQSNARKProverModule>,
    rounds_served: AtomicUsize,
}

fn main() {
    let index: usize = env("MEMBER_INDEX")
        .parse()
        .expect("MEMBER_INDEX must be a number");
    assert!(
        index < N_MEMBERS,
        "MEMBER_INDEX {index} outside a committee of {N_MEMBERS}"
    );
    let secret = env("MEMBER_SECRET");
    let mode = Mode::from_env();

    // The address map is what the aggregator uses to turn a peer into a
    // committee index, so a container whose address does not match its index
    // would have its signatures filed under someone else. Checking it here turns
    // a compose typo into a startup failure instead of a verification failure.
    let own = own_ip();
    assert_eq!(
        own.to_string(),
        MEMBER_IPS[index],
        "member {index} is configured for {} but is running at {own}",
        MEMBER_IPS[index]
    );

    println!(
        "member {index} ({own}), mode {}: waiting for the run identifier",
        mode.as_str()
    );
    let run_id = storage::wait_for_run_id(BOOTSTRAP_WAIT).expect("bootstrap never started");

    // Same seed on a restart, therefore the same key, therefore a counter file
    // that still belongs to its key. See `storage::member_seed`.
    let seed = storage::member_seed(&secret, &run_id, index);
    let (pk, sk) = xmss_key_gen_from_seed(seed, u64::from(SLOT), KEY_SLOT_COUNT).expect("keygen");

    let key_file = storage::member_key_file(index);
    if !key_file.exists() {
        storage::write_atomic(&key_file, &pk.as_ssz_bytes()).expect("cannot publish the key");
    }

    // `create` on a first start, `open` on a restart. The distinction is not a
    // convenience: `create` refuses to overwrite live state, and `open` refuses a
    // file written for a different key, so neither can silently rewind the
    // counter to the bottom of the window.
    let state = storage::state_dir().join("slot-counter");
    let counter = if state.exists() {
        let c = AtomicSlotCounter::open(&state, &pk, SLOT + KEY_SLOTS).expect("counter state");
        println!(
            "member {index}: counter resumed, next slot {}, {} left",
            c.next_slot(),
            c.remaining()
        );
        c
    } else {
        let c =
            AtomicSlotCounter::create(&state, &pk, SLOT, SLOT + KEY_SLOTS).expect("counter state");
        println!("member {index}: counter created at slot {}", c.next_slot());
        c
    };

    let committee = storage::wait_for_committee(BOOTSTRAP_WAIT).expect("no anchor");
    assert_eq!(
        committee.index_of(&pk),
        Some(index),
        "the anchor does not name this key at index {index}"
    );

    let can_aggregate = config::can_aggregate(mode, index);
    let role = match (mode, can_aggregate) {
        (Mode::Raw, _) => "signer + raw aggregator",
        (Mode::Snark, true) => "signer + SNARK aggregator",
        (Mode::Snark, false) => "signer only",
    };
    let prover = OnceLock::new();
    match (mode, can_aggregate) {
        (Mode::Snark, true) => {
            let before = rss_now_mb();
            let started = Instant::now();
            println!(
                "member {index}: SNARK aggregator role enabled; running setup_prover() before listening"
            );
            let module = PQSNARKProverModule::init_prover();
            assert!(prover.set(module).is_ok(), "fresh prover slot");
            println!(
                "member {index}: setup_prover() ready in {:.2?}, RSS {before} MB -> {} MB",
                started.elapsed(),
                rss_now_mb()
            );
        }
        (Mode::Snark, false) => println!(
            "member {index}: signer-only in SNARK mode; aggregator subset is [{}]",
            config::format_indices(config::aggregator_indices(mode))
        ),
        (Mode::Raw, _) => {
            println!("member {index}: raw mode; this member can aggregate if node A dials it")
        }
    }

    let node = Arc::new(Node {
        index,
        mode,
        committee,
        signer: Mutex::new(SignerNode::new(pk, sk, counter)),
        round: Mutex::new(()),
        can_aggregate,
        prover,
        rounds_served: AtomicUsize::new(0),
    });

    let listener = TcpListener::bind(("0.0.0.0", MEMBER_PORT)).expect("cannot bind");
    println!(
        "member {index}: ready on {MEMBER_PORT} as {role}, {}-of-{} committee, RSS {} MB\n",
        THRESHOLD,
        N_MEMBERS,
        rss_now_mb()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let node = Arc::clone(&node);
                // One thread per connection, which is also what lets the
                // aggregator send itself a proposal over the network like
                // everybody else instead of taking a shortcut in memory.
                std::thread::spawn(move || node.serve(stream));
            }
            Err(e) => eprintln!("member {index}: accept failed: {e}"),
        }
    }
}

impl Node {
    fn serve(self: &Arc<Self>, mut stream: TcpStream) {
        let peer = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        if let Err(e) = stream.set_read_timeout(Some(config::request_timeout())) {
            eprintln!("member {}: cannot set a read timeout: {e}", self.index);
            return;
        }
        let (kind, payload) = match wire::recv(&mut stream) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("member {}: unreadable request from {peer}: {e}", self.index);
                return;
            }
        };

        let (kind, reply) = match kind {
            wire::MSG_PROPOSAL => self.on_proposal(&payload, &peer),
            wire::MSG_STATUS_REQUEST => self.on_status_request(&payload, &peer),
            other => (
                wire::MSG_FAILURE,
                Failure::of(format!("unknown message type {other}")),
            ),
        };
        if let Err(e) = wire::send(&mut stream, kind, &reply) {
            eprintln!("member {}: cannot answer {peer}: {e}", self.index);
        }
    }

    /// The member's side of a round: derive the slot, sign, or abstain.
    fn on_proposal(&self, payload: &[u8], peer: &str) -> (u8, Vec<u8>) {
        let proposal = match Proposal::from_ssz_bytes(payload) {
            Ok(p) => p,
            Err(e) => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("malformed proposal: {e:?}")),
                );
            }
        };

        // Derived, never taken from the proposal. An aggregator that could pick
        // the slot could have one version signed at the slot of another.
        let Some(slot) = self.committee.slot_for(proposal.version) else {
            return (
                wire::MSG_SIGNATURE,
                abstain("version has no slot under this anchor"),
            );
        };
        let message =
            self.committee
                .message_for(Algorithms::WotsXmss, &proposal.list, proposal.version);

        let started = Instant::now();
        let signed = self
            .signer
            .lock()
            .expect("signer poisoned")
            .sign_at(&message, slot);
        match signed {
            Ok(signature) => {
                println!(
                    "member {}: signed v{} at slot {slot} in {:.1?} ({} entries, asked by {peer})",
                    self.index,
                    proposal.version,
                    started.elapsed(),
                    proposal.list.len()
                );
                let reply = SignatureReply {
                    signature: vec![signature],
                    reason: Vec::new(),
                };
                (wire::MSG_SIGNATURE, reply.as_ssz_bytes())
            }
            Err(e) => {
                // The interesting case is `AlreadySpent`: this member is past
                // that round and abstains rather than signing a second message
                // under a slot it has already used. It is a normal outcome, and
                // it is exactly what a restarted node reports for the rounds it
                // slept through.
                println!(
                    "member {}: abstains on v{}, {e}",
                    self.index, proposal.version
                );
                (wire::MSG_SIGNATURE, abstain(format!("{e}")))
            }
        }
    }

    /// The `(version, list)` carried by a published record, in whichever form
    /// this demo publishes.
    fn decode_list(&self, bytes: &[u8]) -> Result<(u32, Vec<[u8; 32]>), String> {
        match self.mode {
            Mode::Raw => StatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned())),
            Mode::Snark => {
                SnarkStatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned()))
            }
        }
    }

    /// The aggregator's side of one validity-snapshot update.
    fn on_status_request(self: &Arc<Self>, payload: &[u8], peer: &str) -> (u8, Vec<u8>) {
        if !self.can_aggregate {
            let why = format!(
                "member {} is signer-only in {} mode; ask one of [{}]",
                self.index,
                self.mode.as_str(),
                config::format_indices(config::aggregator_indices(self.mode))
            );
            println!(
                "member {}: status request from {peer} refused, {why}",
                self.index
            );
            return (wire::MSG_FAILURE, Failure::of(why));
        }

        let request = match StatusRequest::from_ssz_bytes(payload) {
            Ok(r) => r,
            Err(e) => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("malformed request: {e:?}")),
                );
            }
        };
        let _round = self.round.lock().expect("round lock poisoned");
        let round_started = Instant::now();

        println!(
            "\n--- member {} is the aggregator for this round ---",
            self.index
        );
        // Start from the current validity snapshot. `Proposal` accepts the whole
        // replacement snapshot: neither this member nor the wire format imposes
        // a one-entry delta, a minimum size, or an append-only prefix rule.
        let (version, mut list) = match storage::latest_record() {
            Some((_, bytes)) => match self.decode_list(&bytes) {
                Ok((v, list)) => match v.checked_add(1) {
                    Some(next) => (next, list),
                    None => {
                        return (
                            wire::MSG_FAILURE,
                            Failure::of("the status-list version is exhausted"),
                        );
                    }
                },
                Err(e) => {
                    return (
                        wire::MSG_FAILURE,
                        Failure::of(format!("published record is unreadable: {e}")),
                    );
                }
            },
            None => (0, Vec::new()),
        };

        let credential = match request.action {
            ACTION_ISSUE => {
                let subject = String::from_utf8(request.data)
                    .map_err(|_| "credential subject is not UTF-8")
                    .and_then(|subject| {
                        (!subject.is_empty())
                            .then_some(subject)
                            .ok_or("credential subject is empty")
                    });
                let subject = match subject {
                    Ok(subject) => subject,
                    Err(why) => return (wire::MSG_FAILURE, Failure::of(why)),
                };
                println!("    {peer} asks to issue a credential for {subject}");
                let credential = vc::issue(&subject, version, self.index);
                assert!(
                    vc::add_valid(&mut list, &credential),
                    "a newly random credential cannot already be in the valid set"
                );
                credential
            }
            ACTION_REVOKE => {
                if request.data.is_empty() {
                    return (
                        wire::MSG_FAILURE,
                        Failure::of("revocation requires the canonical credential bytes"),
                    );
                }
                println!(
                    "    {peer} asks to revoke fingerprint {}",
                    &vc::hex(&vc::fingerprint(&request.data))[..16]
                );
                if !vc::revoke(&mut list, &request.data) {
                    return (
                        wire::MSG_FAILURE,
                        Failure::of("credential is not valid in the current snapshot"),
                    );
                }
                request.data
            }
            other => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("unknown status action {other}")),
                );
            }
        };
        let entry = vc::fingerprint(&credential);
        println!(
            "    v{version}: {} valid fingerprint(s), target {} is {}",
            list.len(),
            &vc::hex(&entry)[..16],
            if request.action == ACTION_ISSUE {
                "present"
            } else {
                "absent"
            }
        );

        let proposal = Proposal {
            version,
            list: list.clone(),
        };
        let quorum = self.collect_signatures(&proposal);
        if quorum.len() < THRESHOLD {
            let why = format!(
                "only {} of {THRESHOLD} signatures arrived within {:?}",
                quorum.len(),
                config::sign_window()
            );
            println!("    round abandoned: {why}");
            return (wire::MSG_FAILURE, Failure::of(why));
        }

        let record = match self.build_record(&list, version, quorum) {
            Ok(bytes) => bytes,
            Err(e) => return (wire::MSG_FAILURE, Failure::of(e)),
        };
        let path = match storage::publish(version, &record) {
            Ok(p) => p,
            Err(e) => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("cannot publish: {e}")),
                );
            }
        };
        println!(
            "    published {} ({} B) in {:.2?}",
            path.display(),
            record.len(),
            round_started.elapsed()
        );

        // Only now is the result returned: the holder authenticates the published
        // snapshot independently and checks presence for issuance or absence for
        // revocation.
        let served = self.rounds_served.fetch_add(1, Ordering::Relaxed) + 1;
        println!("    update returned to {peer}; this node has aggregated {served} round(s)");
        let updated = StatusUpdated {
            version,
            credential,
        };
        (wire::MSG_STATUS_UPDATED, updated.as_ssz_bytes())
    }

    /// Broadcasts the proposal and collects signatures until the threshold is
    /// reached or the window closes.
    ///
    /// The round ends on the `t`-th signature, so the three slowest members of a
    /// healthy ten-node committee simply do not appear in the record. Their slot
    /// is spent all the same, which is what makes the next round derive a fresh
    /// one for everybody.
    fn collect_signatures(self: &Arc<Self>, proposal: &Proposal) -> Vec<(usize, XmssSignature)> {
        let bytes = Arc::new(proposal.as_ssz_bytes());
        let message =
            self.committee
                .message_for(Algorithms::WotsXmss, &proposal.list, proposal.version);
        let slot = self
            .committee
            .slot_for(proposal.version)
            .expect("checked by the caller");
        let window = config::sign_window();
        let (tx, rx) = std::sync::mpsc::channel();

        for index in 0..N_MEMBERS {
            let (bytes, tx) = (Arc::clone(&bytes), tx.clone());
            std::thread::spawn(move || {
                let answer = wire::request(
                    config::member_addr(index),
                    window,
                    wire::MSG_PROPOSAL,
                    &bytes,
                );
                let signature = match answer {
                    Ok((wire::MSG_SIGNATURE, payload)) => {
                        match SignatureReply::from_ssz_bytes(&payload) {
                            Ok(reply) => reply.signature.into_iter().next(),
                            Err(e) => {
                                eprintln!("    member {index}: malformed reply, {e:?}");
                                None
                            }
                        }
                    }
                    Ok((_, payload)) => {
                        eprintln!("    member {index}: {}", Failure::text(&payload));
                        None
                    }
                    Err(e) => {
                        eprintln!("    member {index}: unreachable, {e}");
                        None
                    }
                };
                if let Some(signature) = signature {
                    let _ = tx.send((index, signature));
                }
            });
        }
        drop(tx);

        // Every signature is checked against the key the anchor holds at that
        // index before it is counted. The address map decides *where* to look, it
        // never decides whether the signature is good, so a mislabelled peer
        // costs one rejected contribution rather than a broken record.
        let verifier = VerifierNode::new(self.committee.clone());
        let members = self.committee.members();
        let deadline = Instant::now() + window;
        let mut quorum: Vec<(usize, XmssSignature)> = Vec::with_capacity(THRESHOLD);

        while quorum.len() < THRESHOLD {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok((index, signature)) = rx.recv_timeout(remaining) else {
                break;
            };
            if verifier
                .verify(&members[index], &signature, &message, slot)
                .is_err()
            {
                eprintln!("    member {index}: signature rejected, not counted");
                continue;
            }
            println!(
                "    signature {}/{THRESHOLD} from member {index}",
                quorum.len() + 1
            );
            quorum.push((index, signature));
        }
        quorum
    }

    /// Turns the quorum into whichever form this demo publishes.
    ///
    /// This is the *only* place the two demos differ. Same committee, same
    /// message, same slot, same list: what changes is how the quorum is evidenced
    /// and, therefore, what a relying party has to do about it.
    fn build_record(
        &self,
        list: &[[u8; 32]],
        version: u32,
        quorum: Vec<(usize, XmssSignature)>,
    ) -> Result<Vec<u8>, String> {
        match self.mode {
            Mode::Raw => {
                // The bitmap is built here, from the indices the address map
                // yielded: `StatusList::new` sets one bit per pair and refuses a
                // repeated signer, so the record is canonical the moment it
                // exists.
                let record = StatusList::new(
                    Algorithms::WotsXmss,
                    list.to_vec(),
                    version,
                    N_MEMBERS,
                    quorum,
                )?;
                println!(
                    "    raw form: {} signatures, bitmap of {} members",
                    record.signatures().len(),
                    record.signer_slots()
                );
                Ok(record.to_bytes())
            }
            Mode::Snark => {
                let members = self.committee.members();
                let raws: Vec<(XmssPublicKey, XmssSignature)> = quorum
                    .into_iter()
                    .map(|(i, sig)| (members[i].clone(), sig))
                    .collect();
                let signers = raws.len();

                let prover = self.prover.get().ok_or_else(|| {
                    format!("member {} is not a configured SNARK aggregator", self.index)
                })?;
                let before = rss_now_mb();

                let proving = Instant::now();
                let proof = prover.make_proof(
                    &self.committee,
                    Algorithms::WotsXmss,
                    raws,
                    list,
                    version,
                    LOG_INV_RATE,
                );
                println!(
                    "    SNARK form: {signers} signatures aggregated into {} B",
                    proof.len()
                );
                println!(
                    "    prove {:.2?}, RSS {} MB -> {} MB (setup_prover() paid at startup)",
                    proving.elapsed(),
                    before,
                    rss_now_mb()
                );
                Ok(
                    SnarkStatusList::new(Algorithms::WotsXmss, list.to_vec(), version, proof)
                        .to_bytes(),
                )
            }
        }
    }
}

fn abstain(reason: impl AsRef<str>) -> Vec<u8> {
    SignatureReply {
        signature: Vec::new(),
        reason: reason.as_ref().as_bytes().to_vec(),
    }
    .as_ssz_bytes()
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

/// This container's address on the demo network.
///
/// A connected UDP socket sends nothing; it only makes the kernel pick the
/// source address it *would* use to reach a peer, which is the address the other
/// members will see.
fn own_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("cannot open a probe socket");
    socket
        .connect(config::member_addr(0))
        .expect("the demo network is unreachable");
    socket.local_addr().expect("no local address").ip()
}
