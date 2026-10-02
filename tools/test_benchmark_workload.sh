#!/usr/bin/env bash
# Workload checks of benchmark.sh that need no build: a list size the campaign
# could not honour is refused before OUTDIR exists, i.e. before any build,
# fixture or measurement.
#   - LIST_ENTRIES must be a positive integer within the binaries' limit;
#   - the self-contained shape and the combined target build their own growing
#     lists and ignore the list size, so a campaign labelled L would have
#     measured something else.
# Not covered here, because they need built binaries: benchmark.sh refuses a
# fixture built for another list size before anything is measured, and stops
# the campaign when a process reports list sizes other than the declared ones.
set -euo pipefail
cd "$(dirname "$0")/.."
scratch="$(mktemp -d /tmp/drot-benchmark-workload.XXXXXX)"
trap 'rm -rf "$scratch"' EXIT

refused() { # label expected-message env...
  local label="$1" message="$2" out="$scratch/refused-$RANDOM"
  shift 2
  if env "$@" OUTDIR="$out" ./benchmark.sh >"$scratch/log" 2>&1; then
    echo "benchmark workload: accepted $label" >&2; exit 1
  fi
  grep -qF "$message" "$scratch/log" || {
    echo "benchmark workload: $label refused for another reason:" >&2; tail -3 "$scratch/log" >&2; exit 1
  }
  [ ! -e "$out" ] || { echo "benchmark workload: $label created OUTDIR before refusing" >&2; exit 1; }
}
refused "a non-numeric list size" "LIST_ENTRIES must be a positive integer" LIST_ENTRIES=many
refused "an empty list" "LIST_ENTRIES must be a positive integer" LIST_ENTRIES=0
refused "a list size with a leading zero" "LIST_ENTRIES must be a positive integer" LIST_ENTRIES=0100
refused "a list above the limit" "exceeds the limit" LIST_ENTRIES=1048577
refused "a list size in the self-contained shape" "conflicts with BENCH_SELF_CONTAINED=1" \
  LIST_ENTRIES=1000 BENCH_SELF_CONTAINED=1
refused "a list size with the combined target" "conflicts with the combined target" \
  LIST_ENTRIES=1000 TARGETS="signer combined"
# The variable the binaries read is accepted as a synonym, so a caller that
# exports it cannot end up with an undeclared workload.
refused "a list size given only as BENCH_LIST_ENTRIES" "conflicts with BENCH_SELF_CONTAINED=1" \
  BENCH_LIST_ENTRIES=1000 BENCH_SELF_CONTAINED=1
echo 'benchmark workload: OK'
