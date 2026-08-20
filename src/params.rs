//! Demo parameters, shared by the combined demo (`main.rs`) and the split
//! `prover` binary. The `verifier` binary deliberately uses **none** of these:
//! everything it needs comes from the committee anchor it loads.

/// Genesis slot: the one round 0 is signed at. Later rounds derive theirs as
/// `SLOT + version`, so the committee agrees without coordinating. It lives in the
/// anchor, which makes the derivation authenticated rather than a convention every
/// node has to be trusted to follow.
pub const SLOT: u32 = 43;

/// Committee size `N`.
pub const N_MEMBERS: usize = 200;

/// Threshold `t`: minimum number of distinct committee members per update.
///
/// The proving trace pads to a power of two, so `t = 5..=8` all cost the same.
/// Prove cost is a step function at small `t`, linear from a few dozen upward.
pub const T: usize = 128;

/// Number of sequential updates the demo performs.
///
/// Bounded by the key window: updates take slots `SLOT..SLOT + N_UPDATES` and the
/// two security-test forgeries take `SLOT + N_UPDATES` and `SLOT + KEY_SLOTS`.
/// Hence `N_UPDATES < KEY_SLOTS`, strictly; see the assertion below.
pub const N_UPDATES: usize = 20;

/// Width of the XMSS slot window each committee key is generated for: the last
/// usable slot is `SLOT + KEY_SLOTS`, **inclusive**.
pub const KEY_SLOTS: u32 = 64;

/// The same window as the slot *count* `xmss_key_gen` takes since leanVM v0.9.
///
/// The `+ 1` lives here and nowhere else: a copy at each keygen call site is a
/// second place to get it wrong, and a window one slot short surfaces only when
/// the last security test fails to sign.
pub const KEY_SLOT_COUNT: u64 = KEY_SLOTS as u64 + 1;

// `N_UPDATES == KEY_SLOTS` destroys the committee keys *silently*: both forgeries
// then derive slot `SLOT + KEY_SLOTS`, still inside the key window, so `t` members
// sign two different messages at one XMSS slot while the demo prints
// `security OK: true`. `main.rs` and `prover.rs` sign by plain arithmetic on these
// constants rather than through `AtomicSlotCounter`, so nothing at runtime would
// catch it. Derandomized signing does not help: the two messages differ.
const _: () = assert!(
    N_UPDATES < KEY_SLOTS as usize,
    "N_UPDATES must be < KEY_SLOTS: the two security-test forgeries consume the \
     slots above the update range, and at N_UPDATES == KEY_SLOTS they collide, \
     making the committee sign twice at one XMSS slot"
);

/// WHIR inverse rate. Trades prover memory against proof size and soundness
/// margin: changing it changes the security level, so measure before touching.
pub const LOG_INV_RATE: usize = 2;
