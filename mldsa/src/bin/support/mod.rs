//! Shared, dependency-light helpers for the ML-DSA measurement binaries.

// Each binary uses a different subset of these helpers.
#![allow(dead_code)]

use sha3::{Digest, Sha3_256};

pub const MAX_UPDATES: usize = 64;

pub fn milliseconds(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

pub fn fingerprint(index: u32) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"decentralized-root-of-trust/ml-dsa-benchmark-entry/v1\0");
    hasher.update(index.to_le_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    bytes
}

pub fn parse_count(text: &str, name: &str, max: usize) -> usize {
    let value = text
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{name} must be a positive decimal integer"));
    assert!((1..=max).contains(&value), "{name} must lie in 1..={max}");
    value
}

pub fn rss_mb(field: &str) -> usize {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("benchmark requires Linux /proc/self/status");
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .unwrap_or_else(|| panic!("missing {field} in /proc/self/status"));
    let kb: usize = line
        .split_whitespace()
        .nth(1)
        .expect("missing RSS value")
        .parse()
        .expect("invalid RSS value");
    kb / 1024
}

pub struct Summary {
    pub count: usize,
    pub min: f64,
    pub median: f64,
    pub max: f64,
    pub mean: f64,
    pub sd: f64,
    pub total: f64,
}

pub fn summary(values: &[f64]) -> Summary {
    assert!(
        !values.is_empty(),
        "cannot summarize an empty measurement series"
    );
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let count = sorted.len();
    let middle = count / 2;
    let median = if count.is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    };
    let total: f64 = sorted.iter().sum();
    let mean = total / count as f64;
    let sd = if count < 2 {
        0.0
    } else {
        (sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (count - 1) as f64).sqrt()
    };
    Summary {
        count,
        min: sorted[0],
        median,
        max: sorted[count - 1],
        mean,
        sd,
        total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn even_median_and_sample_deviation() {
        let result = summary(&[4.0, 1.0, 3.0, 2.0]);
        assert_eq!(result.median, 2.5);
        assert_eq!(result.mean, 2.5);
        assert!((result.sd - (5.0_f64 / 3.0).sqrt()).abs() < 1e-12);
    }
}
