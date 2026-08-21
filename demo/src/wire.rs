//! The four messages the demo network exchanges, and their framing.
//!
//! SSZ again, for the same reason the protocol objects use it: one encoding per
//! value, decoders that refuse everything else, and no length varint whose
//! spelling a peer gets to choose. A demo could have used JSON, but then the
//! network would be the one place in the system where bytes are ambiguous.
//!
//! Every exchange is one request and one response on one connection. The
//! aggregator therefore learns which member it is talking to from the address it
//! dialled, which is exactly what the fixed map in [`crate::config`] provides,
//! and a member that never answers costs the round nothing but its read timeout.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use lean_multisig::XmssSignature;
use ssz::{Decode, Encode};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

pub const MSG_VC_REQUEST: u8 = 1;
pub const MSG_PROPOSAL: u8 = 2;
pub const MSG_SIGNATURE: u8 = 3;
pub const MSG_VC_ISSUED: u8 = 4;
pub const MSG_FAILURE: u8 = 5;

/// Frames larger than this are refused before a single byte is allocated. The
/// biggest legitimate message is a proposal carrying the whole status list, so
/// the ceiling is generous by three orders of magnitude and still bounds what an
/// unauthenticated peer can make a node allocate.
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// A holder asking a committee member for a credential.
#[derive(SszEncode, SszDecode)]
pub struct VcRequest {
    pub subject: Vec<u8>,
}

/// The aggregator asking the committee to sign the next version of the list.
///
/// It carries the list and the version, and deliberately **not** the slot: every
/// member derives that itself through `Committee::slot_for`. An aggregator that
/// could name the slot could ask two different versions to be signed at one, and
/// a reused XMSS slot is a recovered secret key.
#[derive(SszEncode, SszDecode)]
pub struct Proposal {
    pub version: u32,
    pub list: Vec<[u8; 32]>,
}

/// A member's answer to a proposal.
///
/// Abstaining is a normal outcome and not an error: a member that has already
/// spent the slot this version derives to refuses rather than signing a second
/// message under it, and the quorum proceeds without it. That is what `t < N`
/// buys, and the reason the reason string is carried back.
#[derive(SszEncode, SszDecode)]
pub struct SignatureReply {
    /// One signature when the member signed, empty when it abstained. SSZ has no
    /// optional, and a one-element list is the encoding that cannot disagree
    /// with itself: a `signed` flag plus a separate signature field would admit
    /// records claiming both.
    pub signature: Vec<XmssSignature>,
    pub reason: Vec<u8>,
}

/// The credential, handed over only once its fingerprint is in a published,
/// committee-signed record.
#[derive(SszEncode, SszDecode)]
pub struct VcIssued {
    pub version: u32,
    pub credential: Vec<u8>,
}

/// Why a request could not be served.
#[derive(SszEncode, SszDecode)]
pub struct Failure {
    pub reason: Vec<u8>,
}

impl Failure {
    pub fn of(reason: impl AsRef<str>) -> Vec<u8> {
        Failure {
            reason: reason.as_ref().as_bytes().to_vec(),
        }
        .as_ssz_bytes()
    }

    pub fn text(bytes: &[u8]) -> String {
        Failure::from_ssz_bytes(bytes)
            .map(|f| String::from_utf8_lossy(&f.reason).into_owned())
            .unwrap_or_else(|_| "undecodable failure message".into())
    }
}

/// Writes one framed message: a type byte, a length, and the SSZ payload.
pub fn send(stream: &mut TcpStream, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::other(format!(
            "outbound frame of {} bytes exceeds the {MAX_FRAME}-byte ceiling",
            payload.len()
        )));
    }
    let mut framed = Vec::with_capacity(5 + payload.len());
    framed.push(kind);
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(payload);
    stream.write_all(&framed)?;
    stream.flush()
}

/// Reads one framed message. The length is checked against the ceiling *before*
/// the buffer is allocated, so a peer cannot ask a node to reserve gigabytes by
/// announcing a frame it never sends.
pub fn recv(stream: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header[1..].try_into().expect("four bytes")) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other(format!(
            "inbound frame announces {len} bytes, over the {MAX_FRAME}-byte ceiling"
        )));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((header[0], payload))
}

/// One round trip to `addr`, with the same timeout on connect, write and read.
///
/// A single deadline for the whole exchange is what makes the aggregator's
/// signing window meaningful: an unreachable member and a silent one cost the
/// round the same bounded amount of time.
pub fn request(
    addr: SocketAddr,
    timeout: Duration,
    kind: u8,
    payload: &[u8],
) -> io::Result<(u8, Vec<u8>)> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    send(&mut stream, kind, payload)?;
    recv(&mut stream)
}
