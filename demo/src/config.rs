//! The fixed network layout every node is born knowing.
//!
//! A real deployment discovers peers and authenticates them by key. The demo
//! pins addresses instead, because the aggregator has to answer one question
//! that would otherwise need a whole membership protocol: *which committee index
//! is this signature from?* With a fixed map the answer is the peer's address,
//! and the interesting part of the system, the quorum and the two verification
//! paths, stays in focus.
//!
//! The map is a demo shortcut and not a security boundary. The aggregator never
//! trusts it on its own: every signature it counts is verified against
//! `members[index]` from the anchor before it is accepted, so a wrong entry
//! costs a rejected signature rather than a forged record.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Committee size `N`.
pub const N_MEMBERS: usize = 10;

/// Threshold `t`: how many distinct members must sign an update.
pub const THRESHOLD: usize = 7;

/// Member `i` lives at `MEMBER_IPS[i]`. Position in this table *is* the
/// committee index, the same index the anchor orders public keys by and the
/// same one a record's bitmap names.
pub const MEMBER_IPS: [&str; N_MEMBERS] = [
    "172.28.0.11",
    "172.28.0.12",
    "172.28.0.13",
    "172.28.0.14",
    "172.28.0.15",
    "172.28.0.16",
    "172.28.0.17",
    "172.28.0.18",
    "172.28.0.19",
    "172.28.0.20",
];

/// The port every member listens on, for both proposals and credential requests.
pub const MEMBER_PORT: u16 = 9000;

/// Node A's address, fixed for the same reason the members' are: the driver has
/// to reach the relying party without discovering anything.
///
/// It is a *resident* address because the SNARK verifier's `setup_verifier()` is
/// a per-process cost. A relying party that exits after every check pays it
/// every time, which measures process startup rather than verification.
pub const HOLDER_IP: &str = "172.28.0.30";

/// The port node A takes triggers on.
pub const HOLDER_PORT: u16 = 9100;

/// Which form the aggregator publishes, and therefore which verifier the holder
/// runs. The one difference between the two demos.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `t` raw signatures plus the bitmap naming their signers.
    Raw,
    /// One aggregated SNARK proof.
    Snark,
}

impl Mode {
    /// Reads `DEMO_MODE`, defaulting to the raw path.
    ///
    /// # Panics
    ///
    /// On any other value. A typo that silently selected the other demo would
    /// invalidate the comparison the two runs exist to make.
    pub fn from_env() -> Self {
        match std::env::var("DEMO_MODE").as_deref() {
            Ok("snark") => Mode::Snark,
            Ok("raw") | Err(_) => Mode::Raw,
            Ok(other) => panic!("DEMO_MODE must be `raw` or `snark`, got `{other}`"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Raw => "raw",
            Mode::Snark => "snark",
        }
    }
}

/// The committee index of the member at `ip`, or `None` for a stranger.
///
/// This is the aggregator's whole membership lookup: an address that is not in
/// the table cannot contribute a signature, because there is no index to record
/// it under and therefore no bit to set.
pub fn index_of_ip(ip: IpAddr) -> Option<usize> {
    let ip = ip.to_string();
    MEMBER_IPS.iter().position(|m| *m == ip)
}

/// Where member `i` listens.
pub fn member_addr(index: usize) -> SocketAddr {
    format!("{}:{}", MEMBER_IPS[index], MEMBER_PORT)
        .parse()
        .expect("member address table is malformed")
}

/// Where node A listens for round triggers.
pub fn holder_addr() -> SocketAddr {
    format!("{HOLDER_IP}:{HOLDER_PORT}")
        .parse()
        .expect("holder address is malformed")
}

/// How long the aggregator waits for signatures before giving up on the round.
///
/// The round ends as soon as the `t`-th signature arrives, so this bounds the
/// *failure* case: members that are down, unreachable, or refusing to sign.
pub fn sign_window() -> Duration {
    Duration::from_millis(env_u64("SIGN_WINDOW_MS", 5_000))
}

/// How long a holder waits for its credential.
///
/// Generous, because on the SNARK path this covers the aggregator's one-time
/// `setup_prover()` and the proof itself, which are seconds and not
/// milliseconds. That asymmetry is the point of the comparison, so the timeout
/// must not be what ends the run.
pub fn request_timeout() -> Duration {
    Duration::from_secs(env_u64("VC_TIMEOUT_S", 900))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
