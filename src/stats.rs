//! Minimal descriptive statistics for the benchmark records the binaries emit.
//!
//! Deliberately reports the whole shape (min / median / max) rather than a lone
//! mean: prove and verify times are right-skewed by scheduler and allocator
//! effects, so a mean alone misrepresents them. `benchmark.sh` consumes the raw
//! per-sample records anyway — these aggregates are for the human-readable run.

/// A series of millisecond measurements.
pub struct Series(Vec<f64>);

impl Series {
    pub fn new(samples: impl IntoIterator<Item = f64>) -> Self {
        let mut v: Vec<f64> = samples.into_iter().collect();
        v.sort_by(|a, b| a.partial_cmp(b).expect("NaN in measurement series"));
        Series(v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn min(&self) -> f64 {
        self.0.first().copied().unwrap_or(0.0)
    }

    pub fn max(&self) -> f64 {
        self.0.last().copied().unwrap_or(0.0)
    }

    pub fn median(&self) -> f64 {
        let n = self.0.len();
        if n == 0 {
            return 0.0;
        }
        if n % 2 == 1 {
            self.0[n / 2]
        } else {
            (self.0[n / 2 - 1] + self.0[n / 2]) / 2.0
        }
    }

    pub fn sum(&self) -> f64 {
        self.0.iter().sum()
    }

    pub fn mean(&self) -> f64 {
        if self.0.is_empty() {
            0.0
        } else {
            self.sum() / self.0.len() as f64
        }
    }

    /// Sample standard deviation (Bessel-corrected); 0 for n < 2.
    pub fn stddev(&self) -> f64 {
        let n = self.0.len();
        if n < 2 {
            return 0.0;
        }
        let m = self.mean();
        (self.0.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt()
    }

    /// `min / median / max`, the compact form used in the console summaries.
    pub fn min_med_max(&self) -> (f64, f64, f64) {
        (self.min(), self.median(), self.max())
    }
}
