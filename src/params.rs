//! Demo parameters, shared by the combined demo (`main.rs`) and the split
//! `prover` binary. The `verifier` binary deliberately uses **none** of these:
//! everything it needs comes from the committee anchor it loads.

/// First XMSS slot. XMSS is stateful: each update must consume a fresh slot.
pub const SLOT: u32 = 43;

/// Committee size `N`.
pub const N_MEMBERS: usize = 10;

/// Threshold `t`: minimum number of distinct committee members per update.
///
/// The proving trace is padded to a power of two, so `t = 5..=8` all cost the
/// same (measured: `t=7` and `t=8` are indistinguishable in prove time, proof
/// size and RAM; `t=4` is the next step down).
pub const T: usize = 7;

/// Number of sequential updates the demo performs.
///
/// Bounded by the keygen window below: keys are generated for
/// `SLOT..=SLOT + KEY_SLOTS`, and the security tests consume one extra slot.
pub const N_UPDATES: usize = 10;

/// Width of the XMSS slot window each committee key is generated for.
pub const KEY_SLOTS: u32 = 64;

/// WHIR inverse rate. Trades prover memory against proof size and soundness
/// margin — changing it changes the security level, so measure before touching.
pub const LOG_INV_RATE: usize = 2;
