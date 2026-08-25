//! Shared plumbing for the two container demos.
//!
//! Both demos run the same network of ten committee members. The raw demo lets
//! any member aggregate and publishes the `t` signatures themselves; the SNARK
//! demo asks only a configured prover subset to aggregate and publishes one proof
//! that such a quorum existed. The proposal round, shared storage volume and
//! credential format stay the same, so the comparison remains focused on the two
//! publication and verification paths.
//!
//! Nothing here is part of the protocol. The security-relevant code lives in the
//! parent crate and is used unmodified.

pub mod config;
pub mod report;
pub mod storage;
pub mod vc;
pub mod wire;
