//! Durable local state a participant keeps outside the protocol objects.
//!
//! [`slot_counter`] keeps stateful XMSS honest; [`freshness`] is the
//! relying party's anti-rollback gate.

pub mod freshness;
pub mod slot_counter;
