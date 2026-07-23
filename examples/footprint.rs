//! Measures the fixed RAM cost of setup_prover() vs. setup_verifier().
//! Usage: cargo run --release --example footprint -- prover|verifier|none
//!
//! Both figures are printed: `VmRSS` is what the process retains, `VmHWM` the
//! peak. For the verifier the two are close, which means the aggregation
//! bytecode is *retained*, not a transient compilation cost — there is no
//! fork-and-drop trick available. For the prover they coincide because
//! `enable_arena()` disables malloc trimming.
use decentralized_root_of_trust::mem::{peak_rss_mb, rss_now_mb};
use lean_multisig::{setup_prover, setup_verifier};

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "none".into());
    let t = std::time::Instant::now();
    match mode.as_str() {
        "prover" => setup_prover(),
        "verifier" => setup_verifier(),
        _ => {}
    }
    println!(
        "mode '{mode}' in {:?}: resident = {} MB, peak = {} MB",
        t.elapsed(),
        rss_now_mb(),
        peak_rss_mb()
    );
}
