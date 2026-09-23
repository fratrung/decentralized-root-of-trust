#!/usr/bin/env bash
# Small, prover-free regression tests for the fail-closed CSV validator.
set -euo pipefail
cd "$(dirname "$0")/.."
scratch="$(mktemp -d /tmp/drot-csv-validation.XXXXXX)"
trap 'rm -f "$scratch/runs.csv" "$scratch/samples.csv"; rmdir "$scratch"' EXIT

write_valid() {
  printf '%s\n' \
    'target,run,n_items,failures,peak_rss_mb,keygen_ms,sign_med_ms,artifact_med_bytes' \
    'mldsa_signer,1,2,0,3,1.000,0.500,3309' > "$scratch/runs.csv"
  printf '%s\n' \
    'target,run,idx,phase,ms,bytes,rss_mb' \
    'mldsa_signer,1,0,sign_crypto,0.500,3309,3' \
    'mldsa_signer,1,1,sign_crypto,0.600,3309,3' > "$scratch/samples.csv"
}
validate() {
  awk -F, -v targets=mldsa_signer -v expected_runs=1 -v expected_items=2 \
    -f tools/validate_benchmark_csv.awk "$scratch/runs.csv" "$scratch/samples.csv"
}
expect_invalid() {
  if validate >/dev/null 2>&1; then
    echo "validator accepted malformed $1" >&2
    exit 1
  fi
}
write_valid
validate
printf '%s\n' \
  'target,run,n_items,failures,peak_rss_mb,keygen_ms,sign_med_ms,artifact_med_bytes' \
  'mldsa_signer,1,2,0,3,1.000,,3309' > "$scratch/runs.csv"
expect_invalid 'missing timing'
write_valid
printf '%s\n' 'mldsa_signer,1,2,0,3,1.000,0.500,3309' >> "$scratch/runs.csv"
expect_invalid 'duplicate run'
write_valid
printf '%s\n' \
  'target,run,idx,phase,ms,bytes,rss_mb' \
  'mldsa_signer,1,0,sign_crypto,0.500,3309,3' > "$scratch/samples.csv"
expect_invalid 'missing sample'
write_valid
printf '%s\n' \
  'target,run,n_items,failures,peak_rss_mb,keygen_ms,sign_med_ms,artifact_med_bytes' \
  'mldsa_signer,1,1,0,3,1.000,0.500,3309' > "$scratch/runs.csv"
expect_invalid 'wrong item count'
echo 'benchmark CSV validator: OK'
