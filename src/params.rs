//! Demo parameters, shared by the combined demo (`main.rs`) and the split
//! `prover` binary. The `verifier` binary deliberately uses **none** of these:
//! everything it needs comes from the committee anchor it loads.

/// Genesis slot: the one round 0 is signed at. Every later round derives its slot
/// as `SLOT + version`, so the whole committee agrees without coordinating.
///
/// It goes into the anchor (`Committee::genesis_slot`), which is what makes the
/// derivation authenticated rather than a convention each node has to be trusted
/// to follow.
pub const SLOT: u32 = 43;

/// Committee size `N`.
pub const N_MEMBERS: usize = 200;

/// Threshold `t`: minimum number of distinct committee members per update.
///
/// The proving trace is padded to a power of two, so `t = 5..=8` all cost the
/// same (measured: `t=7` and `t=8` are indistinguishable in prove time, proof
/// size and RAM; `t=4` is the next step down).
pub const T: usize = 128;

/// Number of sequential updates the demo performs.
///
/// Bounded by the keygen window below: keys are generated for
/// `SLOT..=SLOT + KEY_SLOTS` (**both bounds inclusive**), the updates consume
/// slots `SLOT..SLOT + N_UPDATES`, and the security tests consume **two** more —
/// `SLOT + N_UPDATES` for the tampered-list forgery and `SLOT + KEY_SLOTS`, the
/// last slot of the window, for the slot-consistent version forgery. So the real
/// bound is `N_UPDATES < KEY_SLOTS`, not `N_UPDATES <= KEY_SLOTS`.
pub const N_UPDATES: usize = 20;

/// Width of the XMSS slot window each committee key is generated for: the last
/// usable slot is `SLOT + KEY_SLOTS`, **inclusive**.
pub const KEY_SLOTS: u32 = 64;

/// The same window as the slot *count* `xmss_key_gen` takes since leanVM v0.9,
/// where the old API took an inclusive `(slot_start, slot_end)` pair.
///
/// The `+ 1` lives here and nowhere else. It is exactly the off-by-one the
/// assertion below is about, and a second copy of it in each keygen call site is
/// a second place to get it wrong — silently, since a window one slot short only
/// shows up when the last security test fails to sign.
pub const KEY_SLOT_COUNT: u64 = KEY_SLOTS as u64 + 1;

// The bound above, enforced rather than described. `main.rs` and `prover.rs` hold
// the committee secret keys and sign by plain arithmetic on these two constants —
// they do not go through `AtomicSlotCounter`, so nothing at runtime would notice a
// collision.
//
// `N_UPDATES == KEY_SLOTS` is the dangerous value, and it fails silently: the
// updates end at `SLOT + KEY_SLOTS - 1`, then the tampered-list forgery derives
// `SLOT + N_UPDATES` and the version forgery derives `SLOT + KEY_SLOTS` — the same
// slot, still inside the key window (`KEY_SLOT_COUNT` covers `SLOT + KEY_SLOTS`),
// so `t` members sign two *different* messages there and the demo prints
// `security OK: true` while the secret keys are being destroyed.
//
// leanVM v0.9's derandomized signing does not save this: it makes a repeated
// (slot, message) pair bit-identical, and the two forgeries deliberately sign
// different messages.
//
// One past that (`N_UPDATES == KEY_SLOTS + 1`) is loud instead — the forgery slot
// falls outside the window and `xmss_sign` fails — but relying on that is relying
// on the *second* mistake to catch the first.
const _: () = assert!(
    N_UPDATES < KEY_SLOTS as usize,
    "N_UPDATES must be < KEY_SLOTS: the two security-test forgeries consume the \
     slots above the update range, and at N_UPDATES == KEY_SLOTS they collide, \
     making the committee sign twice at one XMSS slot"
);

/// WHIR inverse rate. Trades prover memory against proof size and soundness
/// margin — changing it changes the security level, so measure before touching.
pub const LOG_INV_RATE: usize = 2;
