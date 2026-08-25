//! Local state a participant keeps outside the protocol objects themselves.
//!
//! Two of these are durable and survive a restart: [`slot_counter`], which is
//! what keeps stateful XMSS honest, and [`freshness`], the anti-rollback gate.
//! [`status_list_head`] is **not** — it is rebuilt on every start from a record
//! the caller has authenticated, and what makes that safe is the slot counter
//! underneath it, not the head itself.

pub mod freshness;
pub mod slot_counter;
pub mod status_list_head;
