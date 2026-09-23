//! ML-DSA-65 committee member and raw-record aggregator for the container demo.
//!
//! ML-DSA is stateless: there is no XMSS leaf counter. The stable per-container
//! secret and run identifier still derive a stable identity across restarts.

use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use drot_demo::config::{self, MEMBER_IPS, MEMBER_PORT, N_MEMBERS, THRESHOLD};
use drot_demo::storage;
use drot_demo::vc;
use drot_demo::wire::{
    self, ACTION_ISSUE, ACTION_REVOKE, Failure, MlDsaSignatureReply, Proposal, StatusRequest,
    StatusUpdated,
};
use drot_mldsa::status_list::MlDsaStatusList;
use drot_mldsa::{Committee, MlDsa65Signer, Seed, Signature, encode_public_key, verify};
use sha3::{Digest, Sha3_256};
use ssz::{Decode as _, Encode as _};

const BOOTSTRAP_WAIT: Duration = Duration::from_secs(300);

struct Node {
    index: usize,
    committee: Committee,
    signer: Mutex<MlDsa65Signer>,
    round: Mutex<()>,
    rounds_served: AtomicUsize,
}

fn main() {
    let index: usize = env("MEMBER_INDEX")
        .parse()
        .expect("MEMBER_INDEX must be a number");
    assert!(index < N_MEMBERS, "member index outside committee");
    let own = own_ip();
    assert_eq!(
        own.to_string(),
        MEMBER_IPS[index],
        "member address/index mismatch"
    );

    let run_id = storage::wait_for_run_id(BOOTSTRAP_WAIT).expect("bootstrap never started");
    let raw_seed = storage::member_seed(&env("MEMBER_SECRET"), &run_id, index);
    let mut hasher = Sha3_256::new();
    hasher.update(b"drot-demo/ml-dsa-65/member-seed/v1\0");
    hasher.update(raw_seed);
    let mut scheme_seed = [0u8; 32];
    scheme_seed.copy_from_slice(&hasher.finalize());
    let seed = Seed::from(scheme_seed);
    let signer = MlDsa65Signer::from_seed(&seed);
    let public_key = signer.public_key();

    let key_file = storage::member_key_file(index);
    if !key_file.exists() {
        storage::write_atomic(&key_file, &encode_public_key(&public_key))
            .expect("cannot publish ML-DSA key");
    }

    let anchor_bytes = storage::wait_for(
        &storage::committee_dir().join(storage::ANCHOR),
        BOOTSTRAP_WAIT,
    )
    .expect("no anchor");
    let committee = Committee::from_bytes(&anchor_bytes).expect("invalid ML-DSA anchor");
    assert_eq!(
        committee.index_of(&public_key),
        Some(index),
        "anchor does not name this key at the configured index"
    );

    let node = Arc::new(Node {
        index,
        committee,
        signer: Mutex::new(signer),
        round: Mutex::new(()),
        rounds_served: AtomicUsize::new(0),
    });
    let listener = TcpListener::bind(("0.0.0.0", MEMBER_PORT)).expect("cannot bind");
    println!(
        "member {index}: ready on {MEMBER_PORT} as ML-DSA signer + raw aggregator, {THRESHOLD}-of-{N_MEMBERS}"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let node = Arc::clone(&node);
                std::thread::spawn(move || node.serve(stream));
            }
            Err(error) => eprintln!("member {index}: accept failed: {error}"),
        }
    }
}

impl Node {
    fn serve(self: &Arc<Self>, mut stream: TcpStream) {
        let peer = stream
            .peer_addr()
            .map(|address| address.ip().to_string())
            .unwrap_or_default();
        if stream
            .set_read_timeout(Some(config::request_timeout()))
            .is_err()
        {
            return;
        }
        let (kind, payload) = match wire::recv(&mut stream) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!(
                    "member {}: unreadable request from {peer}: {error}",
                    self.index
                );
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
        if let Err(error) = wire::send(&mut stream, kind, &reply) {
            eprintln!("member {}: cannot answer {peer}: {error}", self.index);
        }
    }

    fn on_proposal(&self, payload: &[u8], peer: &str) -> (u8, Vec<u8>) {
        let proposal = match Proposal::from_ssz_bytes(payload) {
            Ok(proposal) => proposal,
            Err(error) => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("malformed proposal: {error:?}")),
                );
            }
        };
        let statement = self
            .committee
            .statement_for(&proposal.list, proposal.version);
        let started = Instant::now();
        let signature = match self
            .signer
            .lock()
            .expect("signer poisoned")
            .sign(&statement)
        {
            Ok(signature) => signature,
            Err(error) => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("ML-DSA signing failed: {error}")),
                );
            }
        };
        println!(
            "member {}: signed v{} in {:.1?} ({} entries, asked by {peer})",
            self.index,
            proposal.version,
            started.elapsed(),
            proposal.list.len()
        );
        let encoded = signature.encode();
        let encoded_bytes: &[u8] = encoded.as_ref();
        let reply = MlDsaSignatureReply {
            signature: vec![encoded_bytes.to_vec()],
            reason: Vec::new(),
        };
        (wire::MSG_SIGNATURE, reply.as_ssz_bytes())
    }

    fn on_status_request(self: &Arc<Self>, payload: &[u8], peer: &str) -> (u8, Vec<u8>) {
        let request = match StatusRequest::from_ssz_bytes(payload) {
            Ok(request) => request,
            Err(error) => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("malformed request: {error:?}")),
                );
            }
        };
        let _round = self.round.lock().expect("round lock poisoned");
        let started = Instant::now();
        println!("\n--- member {} aggregates an ML-DSA round ---", self.index);

        let (version, mut list) = match storage::current_record() {
            Some(bytes) => match MlDsaStatusList::from_bytes(&bytes) {
                Ok(record) => match record.version().checked_add(1) {
                    Some(version) => (version, record.list().to_vec()),
                    None => {
                        return (
                            wire::MSG_FAILURE,
                            Failure::of("status-list version exhausted"),
                        );
                    }
                },
                Err(error) => {
                    return (
                        wire::MSG_FAILURE,
                        Failure::of(format!("published record is unreadable: {error}")),
                    );
                }
            },
            None => (0, Vec::new()),
        };

        let credential = match request.action {
            ACTION_ISSUE => {
                let subject = match String::from_utf8(request.data) {
                    Ok(subject) if !subject.is_empty() => subject,
                    _ => {
                        return (
                            wire::MSG_FAILURE,
                            Failure::of("credential subject is empty or not UTF-8"),
                        );
                    }
                };
                println!("    {peer} asks to issue a credential for {subject}");
                let credential = vc::issue(&subject, version, self.index);
                if !vc::add_valid(&mut list, &credential) {
                    return (
                        wire::MSG_FAILURE,
                        Failure::of("new credential fingerprint already exists"),
                    );
                }
                credential
            }
            ACTION_REVOKE => {
                if request.data.is_empty() || !vc::revoke(&mut list, &request.data) {
                    return (
                        wire::MSG_FAILURE,
                        Failure::of("credential is absent from the current snapshot"),
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

        let proposal = Proposal {
            version,
            list: list.clone(),
        };
        let quorum = self.collect_signatures(&proposal);
        if quorum.len() < THRESHOLD {
            return (
                wire::MSG_FAILURE,
                Failure::of(format!(
                    "only {} of {THRESHOLD} signatures arrived",
                    quorum.len()
                )),
            );
        }
        let record = match MlDsaStatusList::new(list, version, N_MEMBERS, quorum) {
            Ok(record) => record.to_bytes(),
            Err(error) => return (wire::MSG_FAILURE, Failure::of(error)),
        };
        let path = match storage::publish(&record) {
            Ok(path) => path,
            Err(error) => {
                return (
                    wire::MSG_FAILURE,
                    Failure::of(format!("cannot publish: {error}")),
                );
            }
        };
        println!(
            "    published {} ({} B) in {:.2?}",
            path.display(),
            record.len(),
            started.elapsed()
        );
        let served = self.rounds_served.fetch_add(1, Ordering::Relaxed) + 1;
        println!("    this member has aggregated {served} round(s)");
        (
            wire::MSG_STATUS_UPDATED,
            StatusUpdated {
                version,
                credential,
            }
            .as_ssz_bytes(),
        )
    }

    fn collect_signatures(&self, proposal: &Proposal) -> Vec<(usize, Signature)> {
        let bytes = Arc::new(proposal.as_ssz_bytes());
        let window = config::sign_window();
        let (tx, rx) = std::sync::mpsc::channel();
        for index in 0..N_MEMBERS {
            let bytes = Arc::clone(&bytes);
            let tx = tx.clone();
            std::thread::spawn(move || {
                let answer = wire::request(
                    config::member_addr(index),
                    window,
                    wire::MSG_PROPOSAL,
                    &bytes,
                );
                let signature = match answer {
                    Ok((wire::MSG_SIGNATURE, payload)) => {
                        MlDsaSignatureReply::from_ssz_bytes(&payload)
                            .ok()
                            .and_then(|reply| {
                                let [raw]: [Vec<u8>; 1] = reply.signature.try_into().ok()?;
                                Signature::try_from(raw.as_slice()).ok()
                            })
                    }
                    Ok((_, payload)) => {
                        eprintln!("    member {index}: {}", Failure::text(&payload));
                        None
                    }
                    Err(error) => {
                        eprintln!("    member {index}: unreachable, {error}");
                        None
                    }
                };
                if let Some(signature) = signature {
                    let _ = tx.send((index, signature));
                }
            });
        }
        drop(tx);

        let statement = self
            .committee
            .statement_for(&proposal.list, proposal.version);
        let deadline = Instant::now() + window;
        let mut quorum = Vec::with_capacity(THRESHOLD);
        while quorum.len() < THRESHOLD {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok((index, signature)) = rx.recv_timeout(remaining) else {
                break;
            };
            if !verify(&self.committee.members()[index], &statement, &signature) {
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
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn own_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("cannot open probe socket");
    socket
        .connect(config::member_addr(0))
        .expect("demo network unavailable");
    socket.local_addr().expect("no local address").ip()
}
