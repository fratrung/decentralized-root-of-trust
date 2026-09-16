//! Demo parameters, shared by the combined demo (`main.rs`) and the split
//! `prover` binary. The `verifier` binary deliberately uses **none** of these:
//! everything it needs comes from the committee anchor it loads.

/// Genesis slot: the one round 0 is signed at. Later rounds derive theirs as
/// `SLOT + version`, so the committee agrees without coordinating. It lives in the
/// anchor, which makes the derivation authenticated rather than a convention every
/// node has to be trusted to follow.
pub const SLOT: u32 = 43;

/// Default committee size `N` used outside controlled benchmark sweeps.
pub const DEFAULT_N_MEMBERS: usize = 200;

/// Default threshold `t` used outside controlled benchmark sweeps.
pub const DEFAULT_T: usize = 128;

/// Parses a positive decimal build-time benchmark parameter.
///
/// Keeping this parser here lets Cargo's `option_env!` dependency tracking
/// rebuild only this crate when a scaling point changes; the pinned leanVM
/// dependency remains compiled. Invalid values fail the build instead of
/// silently falling back to the production/demo defaults.
const fn benchmark_usize(value: Option<&str>, default: usize) -> usize {
    let Some(value) = value else {
        return default;
    };
    let bytes = value.as_bytes();
    assert!(!bytes.is_empty(), "benchmark parameter must not be empty");
    let mut result = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let digit = bytes[i];
        assert!(
            digit >= b'0' && digit <= b'9',
            "benchmark parameter must be decimal"
        );
        result = match result.checked_mul(10) {
            Some(value) => value,
            None => panic!("benchmark parameter overflow"),
        };
        result = match result.checked_add((digit - b'0') as usize) {
            Some(value) => value,
            None => panic!("benchmark parameter overflow"),
        };
        i += 1;
    }
    result
}

/// Committee size `N`.
///
/// `DROT_BENCH_N` is a compile-time override reserved for
/// `committee-scaling-benchmark.sh`. Ordinary builds use
/// [`DEFAULT_N_MEMBERS`].
pub const N_MEMBERS: usize = benchmark_usize(option_env!("DROT_BENCH_N"), DEFAULT_N_MEMBERS);

/// Threshold `t`: minimum number of distinct committee members per update.
///
/// `DROT_BENCH_T` is paired with `DROT_BENCH_N`; the compile-time assertion
/// below rejects an invalid scaling point before key generation starts.
pub const T: usize = benchmark_usize(option_env!("DROT_BENCH_T"), DEFAULT_T);

/// Number of sequential updates the demo performs.
///
/// Bounded by the key window: updates take slots `SLOT..SLOT + N_UPDATES` and the
/// two security-test forgeries take `SLOT + N_UPDATES` and `SLOT + KEY_SLOTS`.
/// Hence `N_UPDATES < KEY_SLOTS`, strictly; see the assertion below.
pub const N_UPDATES: usize = 20;

/// Width of the XMSS slot window each committee key is generated for: the last
/// usable slot is `SLOT + KEY_SLOTS`, **inclusive**.
pub const KEY_SLOTS: u32 = 64;

// `N_UPDATES == KEY_SLOTS` destroys the committee keys *silently*: both forgeries
// then derive slot `SLOT + KEY_SLOTS`, still inside the key window, so `t` members
// sign two different messages at one XMSS slot while the demo prints
// `security OK: true`. `main.rs` and `prover.rs` sign by plain arithmetic on these
// constants rather than through `AtomicSlotCounter`, so nothing at runtime would
// catch it. Signing randomness does not help: any reuse of an XMSS slot is unsafe.
const _: () = assert!(
    N_UPDATES < KEY_SLOTS as usize,
    "N_UPDATES must be < KEY_SLOTS: the two security-test forgeries consume the \
     slots above the update range, and at N_UPDATES == KEY_SLOTS they collide, \
     making the committee sign twice at one XMSS slot"
);

// `Committee::new` already refuses `t` outside `1..=N`, but it refuses at
// runtime, after keygen: at `N_MEMBERS = 200, T = 201` every binary spends
// minutes generating 200 keys and then panics on the line that builds the anchor.
// These constants are known at compile time, so the answer is too. It is the same
// invariant, asserted where it costs nothing to be wrong.
const _: () = assert!(
    T >= 1 && T <= N_MEMBERS,
    "T must lie in 1..=N_MEMBERS: t = 0 lets a record nobody signed reach quorum, \
     and t > N is unsatisfiable, so no update could ever be published"
);

/// WHIR inverse rate. Trades prover memory against proof size and soundness
/// margin: changing it changes the security level, so measure before touching.
pub const LOG_INV_RATE: usize = 2;
