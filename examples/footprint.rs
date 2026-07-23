//! Measures the fixed RAM cost of setup_prover() vs. setup_verifier().
//! Usage: cargo run --release --example footprint -- prover|verifier|none
use lean_multisig::{setup_prover, setup_verifier};

fn rss_mb(tag: &str) {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    for l in s.lines() {
        if let Some(v) = l.strip_prefix("VmHWM:") {
            let kb: u64 = v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
            println!("{tag}: peak RSS = {} MB", kb / 1024);
        }
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "none".into());
    let t = std::time::Instant::now();
    match mode.as_str() {
        "prover" => setup_prover(),
        "verifier" => setup_verifier(),
        _ => {}
    }
    println!("mode '{mode}' in {:?}", t.elapsed());
    rss_mb(&mode);
}
