//! ML-DSA relying party for the container demo.

use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::mem::rss_now_mb;
use decentralized_root_of_trust::node::Outcome;
use decentralized_root_of_trust::state::freshness::{Decision, HighWaterMark};
use drot_demo::config::{self, ALL_MEMBER_INDICES, MEMBER_IPS};
use drot_demo::wire::{
    self, ACTION_ISSUE, ACTION_REVOKE, ACTION_VERIFY, Failure, StatusRequest, StatusUpdated,
};
use drot_demo::{report, storage, vc};
use drot_mldsa::status_list::{MlDsaStatusList, SIGNATURE_BYTES};
use drot_mldsa::{Committee, RawVerifier};
use rand::RngExt;
use ssz::{Decode as _, Encode as _};

const ANCHOR_WAIT: Duration = Duration::from_secs(300);

enum Action {
    Issue(String),
    Revoke,
    Verify,
}

struct Node {
    verifier: RawVerifier,
    mark: HighWaterMark,
}

fn main() {
    let subject = std::env::var("SUBJECT").unwrap_or_else(|_| "did:demo:alice".into());
    if let Ok(kind) = std::env::var("HOLDER_TRIGGER") {
        trigger(&kind, &subject);
        return;
    }

    let anchor = storage::wait_for(&storage::committee_dir().join(storage::ANCHOR), ANCHOR_WAIT)
        .expect("no ML-DSA anchor");
    let committee = Committee::from_bytes(&anchor).expect("invalid ML-DSA anchor");
    println!(
        "node A: ML-DSA anchor loaded, {}-of-{} committee, {} B",
        committee.threshold(),
        committee.member_count(),
        anchor.len()
    );
    let mut node = Node::build(committee, &anchor);
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
            eprintln!("\nnode A: {reason}");
            std::process::exit(1);
        }
    }
}

impl Node {
    fn build(committee: Committee, anchor: &[u8]) -> Self {
        let path = storage::state_dir().join("highwater");
        let state_mode = std::env::var("HOLDER_STATE_MODE").unwrap_or_else(|_| "open".into());
        let mark = match state_mode.as_str() {
            "create" => HighWaterMark::create(&path, anchor),
            "open" => HighWaterMark::open(&path, anchor),
            other => panic!("invalid HOLDER_STATE_MODE={other:?}"),
        }
        .unwrap_or_else(|error| panic!("cannot {state_mode} {}: {error}", path.display()));
        if let Some(version) = mark.current() {
            println!("node A: resuming; versions through v{version} are stale");
        }
        let before = rss_now_mb();
        let node = Self {
            verifier: RawVerifier::new(committee),
            mark,
        };
        report::rule("verifier startup, ML-DSA raw path");
        println!("  setup                 : none, there is no circuit to load");
        report::memory("anchor load", before, rss_now_mb());
        node
    }

    fn accept(&mut self, bytes: &[u8]) -> Outcome {
        let Ok(record) = MlDsaStatusList::from_bytes(bytes) else {
            return Outcome::Refused;
        };
        if !self.verifier.verify_status_list(&record) {
            return Outcome::Refused;
        }
        match self.mark.try_advance(record.version()) {
            Ok(Decision::Accepted) => Outcome::Accepted {
                version: record.version(),
            },
            Ok(Decision::Stale(mark)) => Outcome::Stale {
                version: record.version(),
                mark,
            },
            Err(_) => Outcome::Refused,
        }
    }

    fn report(&self, bytes: &[u8], elapsed: Duration) -> Vec<[u8; 32]> {
        let Ok(record) = MlDsaStatusList::from_bytes(bytes) else {
            return Vec::new();
        };
        report::rule("verification, ML-DSA raw path");
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
            "  checked in            : {elapsed:.2?} (decode, {} signatures, durable gate)",
            record.signatures().len()
        );
        report::raw_sizes(
            bytes.len(),
            record.list().len(),
            record.signatures().len(),
            SIGNATURE_BYTES,
        );
        report::memory_now();
        record.list().to_vec()
    }
}

fn serve(node: &mut Node, subject: &str) -> ! {
    let listener = TcpListener::bind(("0.0.0.0", config::HOLDER_PORT))
        .expect("node A could not bind its port");
    println!(
        "\nnode A: resident on {}; ML-DSA verification is ready.",
        config::holder_addr()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => handle(node, subject, &mut stream),
            Err(error) => eprintln!("node A: trigger accept failed: {error}"),
        }
    }
    unreachable!()
}

fn handle(node: &mut Node, subject: &str, stream: &mut TcpStream) {
    if stream
        .set_read_timeout(Some(config::request_timeout()))
        .is_err()
    {
        return;
    }
    let (kind, payload) = match wire::recv(stream) {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("node A: unreadable trigger: {error}");
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
        Err(error) => {
            let _ = wire::send(
                stream,
                wire::MSG_FAILURE,
                &Failure::of(format!("malformed request: {error:?}")),
            );
            return;
        }
    };
    let action = match request.action {
        ACTION_VERIFY => Action::Verify,
        ACTION_REVOKE => Action::Revoke,
        ACTION_ISSUE => match String::from_utf8(request.data) {
            Ok(value) if value == "default" => Action::Issue(subject.to_string()),
            Ok(value) => Action::Issue(value),
            Err(_) => {
                let _ = wire::send(
                    stream,
                    wire::MSG_FAILURE,
                    &Failure::of("credential subject is not UTF-8"),
                );
                return;
            }
        },
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
        Ok(text) => (wire::MSG_ROUND_RESULT, text),
        Err(text) => (wire::MSG_FAILURE, text),
    };
    println!("\nnode A: {text}");
    let _ = wire::send(stream, kind, &Failure::of(text));
}

fn trigger(kind: &str, subject: &str) {
    let (action, data) = match kind {
        "round" => (ACTION_ISSUE, subject.as_bytes().to_vec()),
        "revoke" => (ACTION_REVOKE, Vec::new()),
        "verify" => (ACTION_VERIFY, Vec::new()),
        other => {
            eprintln!("unknown trigger {other:?}");
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
    .expect("node A is not resident");
    println!("node A: {}", Failure::text(&reply));
    if kind != wire::MSG_ROUND_RESULT {
        std::process::exit(1);
    }
}

fn run_round(node: &mut Node, action: Action) -> Result<String, String> {
    let (updated, expected) = match action {
        Action::Issue(subject) => (
            Some(request_status_update(ACTION_ISSUE, subject.as_bytes())?),
            Some(true),
        ),
        Action::Revoke => {
            let credential = load_credential()?;
            (
                Some(request_status_update(ACTION_REVOKE, &credential)?),
                Some(false),
            )
        }
        Action::Verify => {
            println!("\nnode A: verify-only, checking the published record");
            (None, None)
        }
    };

    let bytes = storage::current_record().ok_or("nothing is published")?;
    println!("\nnode A: fetched canonical record, {} B", bytes.len());
    let started = Instant::now();
    let outcome = node.accept(&bytes);
    let elapsed = started.elapsed();
    let list = node.report(&bytes, elapsed);

    report::rule("freshness");
    let (version, note) = match outcome {
        Outcome::Accepted { version } => (version, format!("high-water now v{version}")),
        Outcome::Stale { version, mark } => {
            (version, format!("already seen, high-water remains v{mark}"))
        }
        Outcome::Refused => {
            return Err("record failed ML-DSA quorum verification; freshness unchanged".into());
        }
    };
    if updated
        .as_ref()
        .is_some_and(|value| value.version != version)
    {
        return Err("aggregator version differs from stored record".into());
    }

    let credential = updated
        .as_ref()
        .map(|value| value.credential.clone())
        .or_else(load_credential_if_present);
    let membership = credential
        .as_deref()
        .map(|credential| report_credential(&list, credential));
    if let (Some(expected), Some(actual)) = (expected, membership)
        && expected != actual
    {
        return Err("authenticated snapshot has the wrong credential state".into());
    }

    let operation = match expected {
        Some(true) => {
            let credential = credential.expect("issuance returns a credential");
            storage::write_atomic(&credential_path(), &credential)
                .map_err(|error| format!("cannot save credential: {error}"))?;
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

fn request_status_update(action: u8, data: &[u8]) -> Result<StatusUpdated, String> {
    let candidates = &ALL_MEMBER_INDICES;
    let target = match std::env::var("TARGET_MEMBER") {
        Ok(value) => {
            let target = value
                .parse::<usize>()
                .map_err(|_| format!("invalid TARGET_MEMBER {value:?}"))?;
            if !candidates.contains(&target) {
                return Err(format!("member {target} is outside the committee"));
            }
            target
        }
        Err(_) => candidates[(rand::rng().random::<u64>() % candidates.len() as u64) as usize],
    };
    println!(
        "\nnode A: asking ML-DSA aggregator {target} ({}) for an update",
        MEMBER_IPS[target]
    );
    let payload = StatusRequest {
        action,
        data: data.to_vec(),
    }
    .as_ssz_bytes();
    let (kind, reply) = wire::request(
        config::member_addr(target),
        config::request_timeout(),
        wire::MSG_STATUS_REQUEST,
        &payload,
    )
    .map_err(|error| format!("aggregator {target} did not answer: {error}"))?;
    if kind != wire::MSG_STATUS_UPDATED {
        return Err(format!(
            "aggregator {target} failed: {}",
            Failure::text(&reply)
        ));
    }
    StatusUpdated::from_ssz_bytes(&reply)
        .map_err(|error| format!("malformed update response: {error:?}"))
}

fn report_credential(list: &[[u8; 32]], credential: &[u8]) -> bool {
    let fingerprint = vc::fingerprint(credential);
    let found = vc::is_valid(list, credential);
    report::rule("credential");
    println!("  fingerprint           : {}", vc::hex(&fingerprint));
    println!("  present in signed list: {found}");
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
        .map_err(|error| format!("no issued credential is available: {error}"))
}

fn load_credential_if_present() -> Option<Vec<u8>> {
    std::fs::read(credential_path()).ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    use drot_mldsa::MlDsa65Signer;

    #[test]
    fn invalid_record_cannot_advance_freshness() {
        let signers: Vec<_> = (0..3)
            .map(|_| MlDsa65Signer::generate().expect("signer"))
            .collect();
        let committee = Committee::new(signers.iter().map(MlDsa65Signer::public_key).collect(), 2)
            .expect("committee");
        let anchor = committee.to_bytes();
        let path = std::env::temp_dir().join(format!(
            "drot-demo-mldsa-holder-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("test directory");
        let mark = HighWaterMark::create(path.join("highwater"), &anchor).expect("mark");
        let mut node = Node {
            verifier: RawVerifier::new(committee.clone()),
            mark,
        };

        let list = vec![[0x42; 32]];
        let statement = committee.statement_for(&list, 0);
        let signatures = vec![
            (0, signers[0].sign(&statement).expect("signature")),
            (2, signers[2].sign(&statement).expect("signature")),
        ];
        let honest = MlDsaStatusList::new(list.clone(), 0, 3, signatures.clone())
            .expect("record")
            .to_bytes();
        let forged = MlDsaStatusList::new(list, 100, 3, signatures)
            .expect("forged record")
            .to_bytes();

        assert_eq!(node.accept(&forged), Outcome::Refused);
        assert_eq!(node.mark.current(), None);
        assert_eq!(node.accept(&honest), Outcome::Accepted { version: 0 });
        assert_eq!(
            node.accept(&honest),
            Outcome::Stale {
                version: 0,
                mark: 0
            }
        );
        assert_eq!(node.mark.current(), Some(0));

        drop(node);
        std::fs::remove_dir_all(path).expect("remove test directory");
    }
}
