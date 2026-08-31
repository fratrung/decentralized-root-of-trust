//! Protocol objects exchanged between participants.

/// Maximum committee size any published protocol object can name.
///
/// The raw form stores signers in an SSZ `BitList`, whose maximum is a
/// compile-time type parameter. The anchor must enforce the same ceiling so the
/// raw and SNARK forms do not accept different committee universes.
pub const MAX_COMMITTEE_SIZE: usize = 2048;

pub mod committee;
pub mod status_list;
