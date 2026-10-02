//! Resident-memory probes (Linux `/proc/self/status`), shared by every binary.
//!
//! `VmRSS` is what the process holds right now; `VmHWM` is the high-water mark.
//! The distinction matters here: `setup_prover()` calls `zk_alloc::enable_arena()`,
//! which sets `M_TRIM_THRESHOLD = -1` and `M_MMAP_MAX = 0`, so a *prover* process
//! never returns freed memory to the OS and its RSS is monotonically
//! non-decreasing. A verify-only process keeps the normal malloc policy.
//!
//! The values are KiB divided by 1024 and truncated: whole **MiB**, whatever a
//! field name ending in `_mb` suggests.
//!
//! A reading that cannot be taken is never reported as 0. On Linux, where the
//! benchmarks run, an unreadable or malformed `/proc/self/status` stops the
//! process with a message: a silent 0 would enter `runs.csv` as "this
//! process used no memory". Elsewhere there is no such file and the probes
//! return 0 so the demos still run; `benchmark.sh` refuses to start there.

/// The value of `field` (for example `"VmHWM:"`) in a `/proc/<pid>/status`
/// text, in KiB. `None` when the field is absent or not a `<number> kB` line.
fn status_kib(status: &str, field: &str) -> Option<u64> {
    let value = status.lines().find_map(|line| line.strip_prefix(field))?;
    value.trim().strip_suffix("kB")?.trim().parse().ok()
}

fn status_mb(field: &str) -> u64 {
    let reading = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| status_kib(&status, field));
    match reading {
        Some(kib) => kib / 1024,
        None if cfg!(target_os = "linux") => {
            panic!("cannot read {field} from /proc/self/status; refusing to report 0 MiB")
        }
        None => 0,
    }
}

/// Currently resident memory, in whole MiB.
pub fn rss_now_mb() -> u64 {
    status_mb("VmRSS:")
}

/// Peak resident memory since process start, in whole MiB.
pub fn peak_rss_mb() -> u64 {
    status_mb("VmHWM:")
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tverifier\nVmPeak:\t  204800 kB\nVmHWM:\t   10240 kB\nVmRSS:\t    2047 kB\nThreads:\t8\n";

    #[test]
    fn reads_the_named_field_in_kib() {
        assert_eq!(status_kib(STATUS, "VmHWM:"), Some(10240));
        assert_eq!(status_kib(STATUS, "VmRSS:"), Some(2047));
    }

    #[test]
    fn a_missing_or_malformed_field_is_not_zero() {
        assert_eq!(status_kib(STATUS, "VmSwap:"), None);
        assert_eq!(status_kib("VmHWM:\t\n", "VmHWM:"), None);
        assert_eq!(status_kib("VmHWM:\t12 MB\n", "VmHWM:"), None);
        assert_eq!(status_kib("VmHWM:\tlots kB\n", "VmHWM:"), None);
        assert_eq!(status_kib("", "VmHWM:"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_has_a_positive_peak_not_below_its_current_rss() {
        let now = rss_now_mb();
        let peak = peak_rss_mb();
        assert!(peak >= now, "peak {peak} MiB below current {now} MiB");
        assert!(peak > 0);
    }
}
