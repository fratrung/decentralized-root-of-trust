//! Resident-memory probes (Linux `/proc/self/status`), shared by every binary.
//!
//! `VmRSS` is what the process holds right now; `VmHWM` is the high-water mark.
//! The distinction matters here: `setup_prover()` calls `zk_alloc::enable_arena()`,
//! which sets `M_TRIM_THRESHOLD = -1` and `M_MMAP_MAX = 0`, so a *prover* process
//! never returns freed memory to the OS and its RSS is monotonically
//! non-decreasing. A verify-only process keeps the normal malloc policy.

fn status_mb(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix(field)
                    .map(|v| v.trim().trim_end_matches(" kB").trim().to_string())
            })
        })
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Currently resident memory, in MB.
pub fn rss_now_mb() -> u64 {
    status_mb("VmRSS:")
}

/// Peak resident memory since process start, in MB.
pub fn peak_rss_mb() -> u64 {
    status_mb("VmHWM:")
}
