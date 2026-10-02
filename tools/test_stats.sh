#!/usr/bin/env bash
# Regression tests for tools/stats.awk, the statistics both harnesses share.
# The expected Student quantiles come from an independent computation (numerical
# integration of the t density), not from the module under test:
#   df=1 12.706205  df=30 2.042272  df=31 2.039513  df=47 2.011741
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C

stats() { sort -g | awk -f tools/stats.awk; }
fail() { echo "stats.awk: $1" >&2; exit 1; }
# field N of the stats line equals an exact token
expect_token() { # label line field token
  [ "$(awk -v f="$3" '{print $f}' <<<"$2")" = "$4" ] || fail "$1: field $3 is '$(awk -v f="$3" '{print $f}' <<<"$2")', expected '$4'"
}
# field N of the stats line is within 1e-5 of a number
expect_near() { # label line field number
  awk -v f="$3" -v want="$4" '{d = $f - want; if (d < 0) d = -d; exit !($f != "NA" && d < 1e-5)}' <<<"$2" ||
    fail "$1: field $3 is '$(awk -v f="$3" '{print $f}' <<<"$2")', expected $4"
}
seq_lines() { awk -v n="$1" 'BEGIN { for (i = 1; i <= n; i++) print i }'; }

# n=0: nothing can be estimated, and nothing is reported as zero.
line="$(printf '' | stats)"
[ "$line" = "0 NA NA NA NA NA NA NA NA NA" ] || fail "n=0 gave '$line'"

# n=1: a location exists, a spread does not. Never sd=0 and a zero-width
# interval, which would read as perfect precision.
line="$(printf '3\n' | stats)"
expect_near "n=1" "$line" 7 3
for field in 8 9 10; do expect_token "n=1" "$line" "$field" NA; done

# n=2: df=1.
line="$(printf '1\n3\n' | stats)"
expect_near "n=2 sd" "$line" 8 1.414214
expect_near "n=2 ci" "$line" 10 12.706205

# n=31 (df=30) and n=32 (df=31): the exact Student quantile on both sides of
# the point where a t table usually ends. 1..n has sd = sqrt(n(n+1)/12).
line="$(seq_lines 31 | stats)"
expect_near "n=31 ci" "$line" 10 "$(awk 'BEGIN { printf "%.6f", 2.042272 * sqrt(31*32/12) / sqrt(31) }')"
line="$(seq_lines 32 | stats)"
expect_near "n=32 ci" "$line" 10 "$(awk 'BEGIN { printf "%.6f", 2.039513 * sqrt(32*33/12) / sqrt(32) }')"

# n=48 at the boundary of zero: mean 1.98 and a standard error of exactly 1.
# With the normal 1.960 the lower bound would be +0.020 and the difference
# "confirmed"; the Student df=47 bound is -0.031741.
line="$(awk 'BEGIN { for (i = 0; i < 24; i++) { printf "%.12f\n%.12f\n", 1.98 - sqrt(47), 1.98 + sqrt(47) } }' | stats)"
expect_near "n=48 mean" "$line" 7 1.98
expect_near "n=48 ci" "$line" 10 2.011741
awk '{ exit !($7 - $10 < 0) }' <<<"$line" || fail "n=48: lower bound $(awk '{print $7 - $10}' <<<"$line") must be below zero"

# A zero mean has no coefficient of variation.
line="$(printf -- '-1\n1\n' | stats)"
expect_token "zero mean" "$line" 9 NA

# Quantiles (type 7) on an even count.
line="$(printf '4\n1\n3\n2\n' | stats)"
expect_near "q1" "$line" 3 1.75
expect_near "median" "$line" 4 2.5
expect_near "q3" "$line" 5 3.25

echo 'shared statistics: OK'
