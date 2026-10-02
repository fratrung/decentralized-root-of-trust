# Descriptive statistics shared by benchmark.sh and committee-scaling-benchmark.sh.
#
#   sort -g | awk -f tools/stats.awk
#
# Reads one number per line, already sorted ascending, and prints one line:
#   n min q1 median q3 max mean sd cv_pct mean_ci95_halfwidth
# Quantiles use linear interpolation (type 7, the R/numpy default). sd is the
# Bessel-corrected (n-1) sample standard deviation. The interval is the 95%
# Student-t confidence interval of the MEAN of the inputs (for benchmark.sh,
# the mean of per-run values), not of their median.
#
# A value that cannot be estimated is printed as NA, never as 0:
#   n = 0   every statistic is NA;
#   n = 1   sd, cv and the interval are NA (one observation has no spread);
#   mean 0  cv is NA.
# A 0 in their place would make a single run read as perfect precision and
# could "confirm" a difference. The quantile below is exact for every integer
# df: the normal 1.960 is too narrow for a Student interval at the run counts
# used here (df=47: 2.0117).

# P(|T| <= x) for Student's t with integer df (Abramowitz & Stegun 26.7.3/4).
# Finite sums of powers of cos(theta), theta = atan(x / sqrt(df)): exact, with
# no gamma function or series truncation.
function t_central(x, df,    theta, c, s, term, sum, k) {
    theta = atan2(x, sqrt(df)); c = cos(theta); s = sin(theta)
    if (df % 2 == 1) {
        if (df == 1) return 2 * theta / 3.14159265358979323846
        term = c; sum = c
        for (k = 2; k <= df - 3; k += 2) {
            term *= c * c * k / (k + 1)
            sum += term
        }
        return 2 / 3.14159265358979323846 * (theta + s * sum)
    }
    term = 1; sum = 1
    for (k = 1; k <= df - 3; k += 2) {
        term *= c * c * k / (k + 1)
        sum += term
    }
    return s * sum
}
# Two-sided 95% quantile: the x with P(|T| <= x) = 0.95, by bisection. The
# distribution function is monotone in x, so 200 halvings of [0, 1000] reach
# double precision.
function t975(df,    lo, hi, mid, i) {
    lo = 0; hi = 1000
    for (i = 0; i < 200; i++) {
        mid = (lo + hi) / 2
        if (t_central(mid, df) < 0.95) lo = mid; else hi = mid
    }
    return (lo + hi) / 2
}
function q(p,    h, lo, fr) {
    h = (n - 1) * p + 1; lo = int(h); fr = h - lo
    return (lo >= n) ? a[n] : a[lo] + fr * (a[lo + 1] - a[lo])
}
{ a[++n] = $1; s += $1 }
END {
    if (n == 0) { print "0 NA NA NA NA NA NA NA NA NA"; exit }
    m = s / n
    if (n < 2) {
        sd = "NA"; cv = "NA"; ci = "NA"
    } else {
        for (i = 1; i <= n; i++) { d = a[i] - m; ss += d * d }
        sd = sqrt(ss / (n - 1))
        cv = (m != 0) ? sprintf("%.3f", 100 * sd / m) : "NA"
        ci = sprintf("%.6f", t975(n - 1) * sd / sqrt(n))
        sd = sprintf("%.6f", sd)
    }
    printf "%d %.6f %.6f %.6f %.6f %.6f %.6f %s %s %s\n",
           n, a[1], q(0.25), q(0.50), q(0.75), a[n], m, sd, cv, ci
}
