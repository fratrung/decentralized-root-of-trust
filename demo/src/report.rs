//! What the holder prints once it has verified a record.
//!
//! Two things are worth reporting and neither is a wall-clock number on its own:
//! how large the evidence of a quorum is, and how much memory checking it cost.
//! The raw and SNARK demos publish the same list under the same committee, so
//! putting those two figures side by side is the whole comparison.

use decentralized_root_of_trust::bench::mem::{peak_rss_mb, rss_now_mb};

pub fn rule(title: &str) {
    println!("\n=== {title} ===");
}

/// Byte sizes of the raw form, broken down by what actually occupies them.
///
/// The signatures dominate so completely that the breakdown is the point: the
/// record is `t` signatures and a rounding error, which is what makes its size
/// linear in the threshold.
pub fn raw_sizes(record_bytes: usize, entries: usize, signatures: usize, sig_len: usize) {
    let sig_total = signatures * sig_len;
    let list_total = entries * 32;
    rule("record size, raw form");
    println!("  record (SSZ)          : {record_bytes:>9} B");
    println!(
        "  {signatures} signatures x {sig_len} B  : {sig_total:>9} B   ({:.1}% of the record)",
        percent(sig_total, record_bytes)
    );
    println!("  {entries} list entries x 32 B : {list_total:>9} B");
    println!(
        "  bitmap + framing      : {:>9} B",
        record_bytes.saturating_sub(sig_total + list_total)
    );
    println!("  cost per extra signer : {sig_len:>9} B");
}

/// Byte sizes of the SNARK form, with the raw record it replaces for scale.
pub fn snark_sizes(record_bytes: usize, entries: usize, proof_bytes: usize, quorum: usize) {
    const SIG_LEN: usize = lean_multisig::SIGNATURE_SSZ_LEN;
    let list_total = entries * 32;
    rule("record size, SNARK form");
    println!("  record (SSZ)          : {record_bytes:>9} B");
    println!(
        "  aggregated proof      : {proof_bytes:>9} B   ({:.1}% of the record)",
        percent(proof_bytes, record_bytes)
    );
    println!("  {entries} list entries x 32 B : {list_total:>9} B");
    println!("  cost per extra signer :         0 B   (the proof size does not move)");
    println!(
        "  the same quorum raw   : {:>9} B   ({quorum} x {SIG_LEN} B)",
        quorum * SIG_LEN
    );
}

/// Resident memory around the verifier's one-time setup.
///
/// The SNARK path pays for the aggregation bytecode before it can check
/// anything; the raw path has no setup at all. Printing the same three numbers
/// in both demos is what makes that visible rather than asserted.
pub fn memory(stage: &str, before: u64, after: u64) {
    rule("verifier memory");
    println!("  RSS before {stage:<11}: {before:>5} MB");
    println!("  RSS after  {stage:<11}: {after:>5} MB");
    println!("  RSS now               : {:>5} MB", rss_now_mb());
    println!("  peak (VmHWM)          : {:>5} MB", peak_rss_mb());
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    100.0 * part as f64 / whole as f64
}
