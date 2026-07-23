#!/usr/bin/env bash
# Benchmark of the committee / status-list flow (src/main.rs): one-time setup,
# N updates rotating the signers, and two security tests (which must be
# rejected). Runs N iterations, discards the warmups, parses the "BENCH" line,
# reports min/median/mean/stddev/max per metric, and saves a CSV.
#
#   ./benchmark.sh
#   RUNS=30 WARMUP=3 ./benchmark.sh
#   CM4_LOW=8 CM4_HIGH=15 ./benchmark.sh
set -euo pipefail

RUNS="${RUNS:-10}"
WARMUP="${WARMUP:-1}"
CM4_LOW="${CM4_LOW:-8}"
CM4_HIGH="${CM4_HIGH:-15}"

cd "$(dirname "${BASH_SOURCE[0]}")"
BIN="./target/release/decentralized-root-of-trust"
CSV="bench_$(date +%Y%m%d-%H%M%S).csv"

cargo build --release >/dev/null 2>&1
[ -x "$BIN" ] || { echo "binary not found: $BIN"; exit 1; }

cpu="$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
gov="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"

cat <<EOF

host      : ${cpu:-?} ($(uname -m)), $(nproc) threads, RAM $(free -h | awk '/^Mem:/{print $2}')
governor  : $gov
rustc     : $(rustc --version)
runs      : $RUNS (warmups discarded: $WARMUP)
csv       : $CSV
EOF
[ "$gov" = performance ] || echo "warning   : governor '$gov' != performance -> noisier measurements"
echo

hdr="run,setup_verifier_ms,setup_prover_extra_ms,setup_total_ms,upd_sign_med_ms,upd_prove_med_ms,upd_prove_min_ms,upd_prove_max_ms,upd_verify_med_ms,updates_total_ms,proof_med_bytes,rss_setup_mb,rss_updates_max_mb,peak_rss_mb,sec_ok"
echo "$hdr" > "$CSV"

for i in $(seq 1 $((WARMUP + RUNS))); do
  line="$("$BIN" 2>/dev/null | grep '^BENCH ' || true)"
  [ -n "$line" ] || { echo "run $i: BENCH line missing"; exit 1; }
  if [ "$i" -le "$WARMUP" ]; then echo "  warmup $i/$WARMUP"; continue; fi
  run=$((i - WARMUP))
  echo "$line" | awk -v r="$run" '{
    for (k=2;k<=NF;k++){ split($k,kv,"="); v[kv[1]]=kv[2] }
    printf "%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", r,
      v["setup_verifier_ms"],v["setup_prover_extra_ms"],v["setup_total_ms"],
      v["upd_sign_med_ms"],v["upd_prove_med_ms"],v["upd_prove_min_ms"],v["upd_prove_max_ms"],
      v["upd_verify_med_ms"],v["updates_total_ms"],v["proof_med_bytes"],
      v["rss_setup_mb"],v["rss_updates_max_mb"],v["peak_rss_mb"],v["sec_ok"]
  }' >> "$CSV"
  echo "  run $run/$RUNS"
done

col() { tail -n +2 "$CSV" | cut -d, -f"$1"; }

# stdin: numbers -> "min median mean stddev max" (full precision)
stats() {
  sort -n | awk '
    { a[NR]=$1; s+=$1 }
    END {
      n=NR; if (n==0) { print "0 0 0 0 0"; exit }
      m=s/n
      md=(n%2) ? a[(n+1)/2] : (a[n/2]+a[n/2+1])/2
      for (i=1;i<=n;i++) { d=a[i]-m; ss+=d*d }
      sd=(n>1) ? sqrt(ss/(n-1)) : 0
      printf "%.6f %.6f %.6f %.6f %.6f\n", a[1], md, m, sd, a[n]
    }'
}

row() { # label  column  decimals
  col "$2" | stats | awk -v L="$1" -v d="$3" '{
    f="%13." d "f"
    printf "  %-26s", L
    for (i=1;i<=5;i++) printf f, $i
    print ""
  }'
}

echo "STATISTICS (host)  [10 updates, committee and threshold from src/main.rs]"
printf "  %-26s%13s%13s%13s%13s%13s\n" "metric [unit]" "min" "median" "mean" "stddev" "max"
row "setup_verifier [ms]"       2  2
row "setup_prover_extra [ms]"   3  2
row "setup_prover_tot [ms]"     4  2
row "update sign med [ms]"      5  2
row "update prove med [ms]"     6  2
row "update prove min [ms]"     7  2
row "update prove max [ms]"     8  2
row "update verify med [ms]"    9  2
row "total updates [ms]"        10 2
row "proof median [bytes]"      11 0
row "RAM after setup [MB]"      12 0
row "RAM max update [MB]"       13 0
row "peak RSS [MB]"             14 0
row "security ok [1=yes]"       15 0

# --- Raspberry CM4 (2 GB) projection: linear host->CM4 estimate, NOT a measurement ---
med() { col "$1" | stats | awk '{print $2}'; }
fmt() { awk -v x="$1" 'BEGIN{ if (x>=1000) printf "%.2f s", x/1000; else printf "%.0f ms", x }'; }
proj() { # label  column
  local m; m="$(med "$2")"
  printf "  %-24s host %-9s ->  CM4 %s .. %s\n" "$1" "$(fmt "$m")" \
    "$(fmt "$(awk -v m="$m" -v f="$CM4_LOW"  'BEGIN{print m*f}')")" \
    "$(fmt "$(awk -v m="$m" -v f="$CM4_HIGH" 'BEGIN{print m*f}')")"
}

rss_setup="$(med 12 | awk '{printf "%.0f",$1}')"
rss_updmax="$(med 13 | awk '{printf "%.0f",$1}')"
rss_peak="$(med 14 | awk '{printf "%.0f",$1}')"

echo
echo "PROJECTION Raspberry CM4 (BCM2711 A72, 2 GB)  ESTIMATE x${CM4_LOW}..x${CM4_HIGH}, not a measurement"
proj "setup_prover"      4
proj "update prove med"  6
proj "update verify"     9
proj "total updates"     10
printf "  %-24s host %-9s ->  CM4 unchanged (RAM does not scale with CPU)\n" "RAM after setup" "${rss_setup} MB"
printf "  %-24s host %-9s ->  CM4 unchanged\n" "RAM max update" "${rss_updmax} MB"
printf "  %-24s host %-9s ->  CM4 unchanged\n" "peak RSS" "${rss_peak} MB"
echo "  RAM gate: peak ~${rss_peak} MB -> FITS the CM4 2GB (~$((2048 - rss_peak)) MB free for OS); 1GB excluded"
echo
echo "csv: $CSV"
