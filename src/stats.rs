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

#[cfg(test)]
mod tests {
    use super::*;

    /// Millisecond timings, so ~1e-9 is far below anything that could be a real
    /// difference. Exact equality would be testing IEEE rounding, not arithmetic.
    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// The constructor sorts, so every order statistic below is a claim about the
    /// *multiset*. If this stopped holding, `median` would silently start
    /// reporting "whatever landed in the middle of the input" — which for a
    /// benchmark is a number that looks plausible and means nothing.
    #[test]
    fn the_order_of_the_samples_does_not_change_any_statistic() {
        let ascending = Series::new([1.0, 2.0, 3.0, 4.0, 5.0]);
        let shuffled = Series::new([4.0, 1.0, 5.0, 2.0, 3.0]);
        let descending = Series::new([5.0, 4.0, 3.0, 2.0, 1.0]);

        for s in [&shuffled, &descending] {
            assert!(close(s.median(), ascending.median()));
            assert!(close(s.min(), ascending.min()));
            assert!(close(s.max(), ascending.max()));
            assert!(close(s.mean(), ascending.mean()));
            assert!(close(s.stddev(), ascending.stddev()));
        }
        assert!(close(ascending.median(), 3.0));
    }

    /// Both parities, because the even case is the one with an arithmetic step in
    /// it — and an off-by-one in the index would still return a plausible sample.
    #[test]
    fn the_median_handles_both_parities_and_the_degenerate_sizes() {
        // Odd: the middle sample itself.
        assert!(close(Series::new([10.0, 20.0, 30.0]).median(), 20.0));
        // Even: the mean of the two middle samples, not either one of them.
        assert!(close(Series::new([10.0, 20.0, 30.0, 40.0]).median(), 25.0));
        // A single sample is its own median, and n = 2 must not index out of range.
        assert!(close(Series::new([7.5]).median(), 7.5));
        assert!(close(Series::new([1.0, 2.0]).median(), 1.5));
    }

    /// The reason this module reports the median at all. Prove the two statistics
    /// really do disagree on the shape these measurements have, so a future
    /// "simplification" to a lone mean cannot pass silently.
    #[test]
    fn the_median_resists_the_outlier_that_moves_the_mean() {
        // One run descheduled: 19 samples at 1 ms and a single 100 ms straggler.
        let mut samples = vec![1.0; 19];
        samples.push(100.0);
        let s = Series::new(samples);

        assert!(
            close(s.median(), 1.0),
            "the median must ignore the straggler"
        );
        assert!(s.mean() > 5.0, "the mean must not");
        assert!(close(s.max(), 100.0), "and max must still expose it");
    }

    /// Bessel-corrected (`n - 1`), which is the right choice here: these are
    /// samples from a host's behaviour, not an enumeration of a population. The
    /// population formula would understate the spread, and `benchmark.sh` builds
    /// its confidence interval on top of this number.
    #[test]
    fn the_standard_deviation_is_the_sample_one() {
        // [1, 3]: mean 2, squared deviations 1 + 1 = 2. Sample: 2/1 = 2 -> sqrt 2.
        // Population would be 2/2 = 1 -> 1.0, so the two are distinguishable.
        let s = Series::new([1.0, 3.0]);
        assert!(close(s.stddev(), std::f64::consts::SQRT_2));

        // [2,4,4,4,5,5,7,9]: mean 5, squared deviations sum to 32.
        // Sample: 32/7 -> 2.138..., population: 32/8 -> 2.0.
        let s = Series::new([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert!(close(s.mean(), 5.0));
        assert!(close(s.stddev(), (32.0f64 / 7.0).sqrt()));

        // No spread is zero spread, not a rounding artefact.
        assert!(close(Series::new([3.0, 3.0, 3.0]).stddev(), 0.0));
    }

    /// `n - 1` is a division by zero at `n = 1`. It must be 0, not NaN or inf: a
    /// NaN would propagate into every downstream figure, and `benchmark.sh` prints
    /// what it is given.
    #[test]
    fn a_single_sample_has_no_spread_rather_than_a_nan() {
        let s = Series::new([42.0]);
        assert_eq!(s.len(), 1);
        assert!(close(s.stddev(), 0.0));
        assert!(s.stddev().is_finite());
        assert!(close(s.mean(), 42.0));
    }

    /// An empty series returns 0.0 from every accessor rather than panicking or
    /// producing `0/0 = NaN`. That is a *sentinel*, not a measurement — "0.0 ms"
    /// is indistinguishable from a real zero — so the binaries assert non-emptiness
    /// before they format anything. This test pins the behaviour so the assertion
    /// upstream stays the thing that catches it.
    #[test]
    fn an_empty_series_is_all_zeros_and_never_a_nan() {
        let s = Series::new([]);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        for v in [s.min(), s.max(), s.median(), s.mean(), s.stddev(), s.sum()] {
            assert!(v.is_finite(), "empty series produced a non-finite value");
            assert!(close(v, 0.0));
        }
    }

    #[test]
    fn sum_and_mean_agree_and_min_med_max_matches_its_parts() {
        let s = Series::new([2.0, 8.0, 5.0, 1.0]);
        assert!(close(s.sum(), 16.0));
        assert!(close(s.mean(), 4.0));
        assert!(close(s.mean() * s.len() as f64, s.sum()));

        let (lo, med, hi) = s.min_med_max();
        assert!(close(lo, s.min()) && close(med, s.median()) && close(hi, s.max()));
        assert!(close(lo, 1.0) && close(med, 3.5) && close(hi, 8.0));
    }

    /// A NaN has no place in an ordering, and silently sorting it to one end would
    /// corrupt every order statistic downstream. Failing loudly is the only honest
    /// option for a number that will be published.
    #[test]
    #[should_panic(expected = "NaN in measurement series")]
    fn a_nan_sample_is_refused_rather_than_ordered() {
        let _ = Series::new([1.0, f64::NAN, 2.0]);
    }

    /// Infinities are not NaN, so they sort — and must land at the ends rather
    /// than anywhere in the middle. This is not expected to occur; it is here so
    /// that if it ever does, the median stays a real sample.
    #[test]
    fn infinities_sort_to_the_ends() {
        let s = Series::new([1.0, f64::INFINITY, 2.0, f64::NEG_INFINITY, 3.0]);
        assert_eq!(s.min(), f64::NEG_INFINITY);
        assert_eq!(s.max(), f64::INFINITY);
        assert!(close(s.median(), 2.0));
    }
}
