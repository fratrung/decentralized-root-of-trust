//! Shared plumbing for the two container demos.
//!
//! Both demos run the same network of ten committee members and differ in one
//! decision only: what the aggregator publishes once it has a quorum. The raw
//! demo publishes the `t` signatures themselves, the SNARK demo publishes one
//! proof that such a quorum existed. Everything else, the fixed address map, the
//! proposal round, the shared storage volume and the credential format, is
//! identical, so the two runs are comparable by construction.
//!
//! Nothing here is part of the protocol. The security-relevant code lives in the
//! parent crate and is used unmodified.

pub mod config;
pub mod report;
pub mod storage;
pub mod vc;
pub mod wire;
