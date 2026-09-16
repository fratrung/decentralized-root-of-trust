#!/usr/bin/env bash
# Committee-size scaling study built on top of benchmark.sh.
#
# This file deliberately does not reimplement measurement or statistics.
# It first invokes benchmark.sh once for the single-member signer role. Then,
# for every admitted (N,t) point, it:
#   1. builds this crate with compile-time benchmark-only N/t overrides;
#   2. generates committee signatures in an unmeasured fixture process;
#   3. invokes benchmark.sh for one aggregator, one SNARK verifier and the raw
#      verifier baseline;
#   4. enforces one host-wide RAM/swap/time budget around every stage;
#   5. combines benchmark.sh's summary.csv files into a scaling report.
#
# Default quorum policy: t = floor(2N/3) + 1, a strict two-thirds
# supermajority. The benchmark evaluates performance under that policy; it does
# not claim to implement a consensus protocol.
set -euo pipefail
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO="$PWD"

RUNS="${RUNS:-3}"
WARMUP="${WARMUP:-1}"
STRICT_ENV="${STRICT_ENV:-0}"
PLAN_ONLY="${PLAN_ONLY:-0}"
PIN_CPUS="${PIN_CPUS:-}"
INTERLEAVE="${INTERLEAVE:-1}"
POINT_TIMEOUT_MINUTES="${POINT_TIMEOUT_MINUTES:-90}"
MONITOR_INTERVAL_SECONDS="${MONITOR_INTERVAL_SECONDS:-2}"
PROGRESS_INTERVAL_SECONDS="${PROGRESS_INTERVAL_SECONDS:-15}"
MAX_SWAP_GROWTH_MB="${MAX_SWAP_GROWTH_MB:-64}"
OUTDIR="${OUTDIR:-$REPO/committee-scaling-$(date +%Y%m%d-%H%M%S)}"

# These are conservative admission thresholds for the usable benchmark budget,
# not claims about leanVM's exact memory curve. The live guard below remains the
# authority and can stop any admitted point, including N=500.
RAM_FOR_N1000_MB="${RAM_FOR_N1000_MB:-12288}"
RAM_FOR_N1500_MB="${RAM_FOR_N1500_MB:-20480}"

required_commands=(awk cargo date grep kill lscpu mkdir nproc ps sed setsid sort tail)
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "missing required command: $command_name" >&2
    exit 1
  }
done
[ -r /proc/meminfo ] || {
  echo "committee scaling requires Linux /proc/meminfo" >&2
  exit 1
}

positive_integer() {
  case "$2" in
    ''|*[!0-9]*|0) echo "$1 must be a positive integer, got '$2'" >&2; exit 1 ;;
  esac
}
positive_integer RUNS "$RUNS"
case "$WARMUP" in ''|*[!0-9]*) echo "WARMUP must be a non-negative integer" >&2; exit 1 ;; esac
case "$PLAN_ONLY" in 0|1) ;; *) echo "PLAN_ONLY must be 0 or 1" >&2; exit 1 ;; esac
positive_integer POINT_TIMEOUT_MINUTES "$POINT_TIMEOUT_MINUTES"
positive_integer MONITOR_INTERVAL_SECONDS "$MONITOR_INTERVAL_SECONDS"
positive_integer PROGRESS_INTERVAL_SECONDS "$PROGRESS_INTERVAL_SECONDS"
positive_integer RAM_FOR_N1000_MB "$RAM_FOR_N1000_MB"
positive_integer RAM_FOR_N1500_MB "$RAM_FOR_N1500_MB"

meminfo_mb() {
  awk -v key="$1" '$1 == key ":" { print int($2 / 1024); exit }' /proc/meminfo
}

TOTAL_MB="$(meminfo_mb MemTotal)"
AVAILABLE_MB="$(meminfo_mb MemAvailable)"
SWAP_FREE_AT_START_MB="$(meminfo_mb SwapFree)"
RESERVE_MB="${RESERVE_MB:-$((TOTAL_MB / 8))}"
[ "$RESERVE_MB" -lt 2048 ] && RESERVE_MB=2048
positive_integer RESERVE_MB "$RESERVE_MB"

CAP_FROM_TOTAL_MB=$((TOTAL_MB * 70 / 100))
CAP_FROM_AVAILABLE_MB=$((AVAILABLE_MB - RESERVE_MB))
if [ "$CAP_FROM_AVAILABLE_MB" -le 0 ]; then
  echo "insufficient available RAM: ${AVAILABLE_MB} MB available, ${RESERVE_MB} MB reserved" >&2
  exit 1
fi
SAFE_MEMORY_LIMIT_MB="$CAP_FROM_TOTAL_MB"
[ "$CAP_FROM_AVAILABLE_MB" -lt "$SAFE_MEMORY_LIMIT_MB" ] &&
  SAFE_MEMORY_LIMIT_MB="$CAP_FROM_AVAILABLE_MB"

if [ -n "${MAX_RSS_MB:-}" ]; then
  positive_integer MAX_RSS_MB "$MAX_RSS_MB"
  MEMORY_LIMIT_MB="$MAX_RSS_MB"
  if [ "$MEMORY_LIMIT_MB" -gt "$SAFE_MEMORY_LIMIT_MB" ]; then
    echo "NOTE: requested MAX_RSS_MB=$MEMORY_LIMIT_MB exceeds the safe host budget; clamping to $SAFE_MEMORY_LIMIT_MB MB"
    MEMORY_LIMIT_MB="$SAFE_MEMORY_LIMIT_MB"
  fi
else
  MEMORY_LIMIT_MB="$SAFE_MEMORY_LIMIT_MB"
fi

REQUESTED_SIZES=(5 10 100 500 1000 1500)
SELECTED_SIZES=(5 10 100 500)
MAX_SELECTED_N=500
N1000_REASON="usable budget ${MEMORY_LIMIT_MB} MB is below ${RAM_FOR_N1000_MB} MB"
N1500_REASON="N=1000 was not admitted"
if [ "$MEMORY_LIMIT_MB" -ge "$RAM_FOR_N1000_MB" ]; then
  SELECTED_SIZES+=(1000)
  MAX_SELECTED_N=1000
  N1000_REASON="admitted"
  N1500_REASON="usable budget ${MEMORY_LIMIT_MB} MB is below ${RAM_FOR_N1500_MB} MB"
  if [ "$MEMORY_LIMIT_MB" -ge "$RAM_FOR_N1500_MB" ]; then
    SELECTED_SIZES+=(1500)
    MAX_SELECTED_N=1500
    N1500_REASON="admitted"
  fi
fi

mkdir -p "$OUTDIR"
DECISION_FILE="$OUTDIR/memory-decision.txt"
MANIFEST="$OUTDIR/manifest.csv"
SCALING_CSV="$OUTDIR/scaling.csv"
REPORT="$OUTDIR/report.txt"
SIGNER_DIR="$OUTDIR/signer"
SIGNER_BENCHMARK_DIR="$SIGNER_DIR/benchmark"
SIGNER_CSV="$OUTDIR/signer.csv"

{
  echo "COMMITTEE SCALING — MEMORY ADMISSION DECISION"
  echo "timestamp                 : $(date -Is)"
  echo "host                      : $(hostname)"
  echo "physical RAM              : $TOTAL_MB MB"
  echo "available RAM at start    : $AVAILABLE_MB MB"
  echo "RAM reserved for host     : $RESERVE_MB MB"
  echo "70% physical-RAM ceiling : $CAP_FROM_TOTAL_MB MB"
  echo "enforced process-group cap: $MEMORY_LIMIT_MB MB"
  echo "allowed swap growth       : $MAX_SWAP_GROWTH_MB MB"
  echo "timeout per stage         : $POINT_TIMEOUT_MINUTES minutes"
  echo "N=1000 admission threshold: $RAM_FOR_N1000_MB MB -> $N1000_REASON"
  echo "N=1500 admission threshold: $RAM_FOR_N1500_MB MB -> $N1500_REASON"
  echo "selected committee sizes  : ${SELECTED_SIZES[*]}"
  echo "selected maximum          : N=$MAX_SELECTED_N"
  echo
  echo "The selected maximum is fixed for this run. During execution the guard"
  echo "also stops a stage if its process group exceeds the cap, available RAM"
  echo "falls below the reserve, swap grows, or the timeout expires."
} | tee "$DECISION_FILE"
echo

if [ "$PLAN_ONLY" = 1 ]; then
  echo "PLAN_ONLY=1: admission decision recorded; no build or benchmark was started."
  exit 0
fi

threshold_for() {
  echo $((2 * $1 / 3 + 1))
}

group_rss_mb() {
  ps -eo pgid=,rss= | awk -v group="$1" '$1 + 0 == group { sum += $2 } END { print int((sum + 1023) / 1024) }'
}

ACTIVE_PGID=""
terminate_active_group() {
  [ -n "$ACTIVE_PGID" ] || return 0
  kill -TERM -- "-$ACTIVE_PGID" 2>/dev/null || true
  local attempt
  for attempt in 1 2 3 4 5; do
    ps -eo pgid= | awk -v group="$ACTIVE_PGID" '$1 + 0 == group { found=1 } END { exit !found }' || break
    sleep 1
  done
  kill -KILL -- "-$ACTIVE_PGID" 2>/dev/null || true
  ACTIVE_PGID=""
}
trap 'terminate_active_group; exit 130' INT TERM
trap 'terminate_active_group' EXIT

GUARD_REASON=""
GUARD_PEAK_MB=0
run_guarded() {
  local label="$1" log="$2"
  shift 2
  local available_before start now last_report pid pgid rss available swap_free swap_growth rc
  available_before="$(meminfo_mb MemAvailable)"
  if [ "$available_before" -lt "$RESERVE_MB" ]; then
    GUARD_REASON="available RAM ${available_before} MB is already below reserve ${RESERVE_MB} MB"
    return 70
  fi

  echo "[$(date +%H:%M:%S)] START $label"
  setsid "$@" >"$log" 2>&1 &
  pid=$!
  pgid="$pid"
  ACTIVE_PGID="$pgid"
  GUARD_REASON=""
  GUARD_PEAK_MB=0
  start="$(date +%s)"
  last_report="$start"

  while kill -0 "$pid" 2>/dev/null; do
    rss="$(group_rss_mb "$pgid")"
    available="$(meminfo_mb MemAvailable)"
    swap_free="$(meminfo_mb SwapFree)"
    swap_growth=$((SWAP_FREE_AT_START_MB - swap_free))
    [ "$swap_growth" -lt 0 ] && swap_growth=0
    [ "$rss" -gt "$GUARD_PEAK_MB" ] && GUARD_PEAK_MB="$rss"
    now="$(date +%s)"

    if [ "$rss" -gt "$MEMORY_LIMIT_MB" ]; then
      GUARD_REASON="process-group RSS ${rss} MB exceeded cap ${MEMORY_LIMIT_MB} MB"
    elif [ "$available" -lt "$RESERVE_MB" ]; then
      GUARD_REASON="available RAM ${available} MB fell below reserve ${RESERVE_MB} MB"
    elif [ "$swap_growth" -gt "$MAX_SWAP_GROWTH_MB" ]; then
      GUARD_REASON="swap use grew by ${swap_growth} MB (limit ${MAX_SWAP_GROWTH_MB} MB)"
    elif [ $((now - start)) -ge $((POINT_TIMEOUT_MINUTES * 60)) ]; then
      GUARD_REASON="stage exceeded ${POINT_TIMEOUT_MINUTES}-minute timeout"
    fi

    if [ -n "$GUARD_REASON" ]; then
      echo "[$(date +%H:%M:%S)] STOP  $label: $GUARD_REASON"
      terminate_active_group
      wait "$pid" 2>/dev/null || true
      return 70
    fi
    if [ $((now - last_report)) -ge "$PROGRESS_INTERVAL_SECONDS" ]; then
      printf '[%s] GUARD %-24s RSS=%d/%d MB available=%d MB swap_delta=%d MB\n' \
        "$(date +%H:%M:%S)" "$label" "$rss" "$MEMORY_LIMIT_MB" "$available" "$swap_growth"
      last_report="$now"
    fi
    sleep "$MONITOR_INTERVAL_SECONDS"
  done

  set +e
  wait "$pid"
  rc=$?
  set -e
  ACTIVE_PGID=""
  if [ "$rc" -ne 0 ]; then
    GUARD_REASON="command exited with status $rc"
    echo "[$(date +%H:%M:%S)] FAIL  $label: $GUARD_REASON"
    tail -20 "$log" >&2 || true
    return "$rc"
  fi
  echo "[$(date +%H:%M:%S)] DONE  $label (observed group peak ${GUARD_PEAK_MB} MB)"
}

write_status() {
  local point_dir="$1" status="$2" reason="$3"
  printf '%s\n%s\n' "$status" "$reason" > "$point_dir/status.txt"
}

summary_value() {
  local file="$1" target="$2" metric="$3"
  awk -F, -v target="$target" -v metric="$metric" '
    NR > 1 && $1 == target && $2 == metric { print $7; exit }
  ' "$file"
}

summary_rss() {
  local file="$1" target="$2" value
  value="$(summary_value "$file" "$target" peak_rss_kernel)"
  [ -n "$value" ] || value="$(summary_value "$file" "$target" peak_rss_vmhwm)"
  echo "$value"
}

STOP_FURTHER=0
STOP_REASON=""
OVERALL_STATUS=0

# Signing is independent of committee size: each member produces one signature
# for the same message and slot regardless of N or t. Measure that role once as
# a complete benchmark.sh campaign, preserving repeated runs and confidence
# intervals without redundantly charging it to every scaling point. N=5,t=4 is
# only the compile-time anchor for this invocation; the signer binary uses
# neither parameter.
mkdir -p "$SIGNER_BENCHMARK_DIR"
if [ -f "$SIGNER_DIR/status.txt" ] &&
   [ "$(sed -n '1p' "$SIGNER_DIR/status.txt")" = complete ] &&
   [ -s "$SIGNER_BENCHMARK_DIR/summary.csv" ]; then
  echo "RESUME: single-member signer benchmark already complete"
elif run_guarded "single-member signer benchmark" "$SIGNER_DIR/benchmark.log" \
    env DROT_BENCH_N=5 DROT_BENCH_T=4 \
    RUNS="$RUNS" WARMUP="$WARMUP" TARGETS="signer" \
    STRICT_ENV="$STRICT_ENV" PIN_CPUS="$PIN_CPUS" INTERLEAVE="$INTERLEAVE" \
    OUTDIR="$SIGNER_BENCHMARK_DIR" "$REPO/benchmark.sh"; then
  if [ -s "$SIGNER_BENCHMARK_DIR/summary.csv" ]; then
    write_status "$SIGNER_DIR" "complete" "single-member benchmark.sh failure gates passed"
  else
    write_status "$SIGNER_DIR" "benchmark_failed" "benchmark.sh produced no summary.csv"
    STOP_FURTHER=1
    STOP_REASON="single-member signer benchmark produced no summary"
    OVERALL_STATUS=1
  fi
else
  write_status "$SIGNER_DIR" "benchmark_failed" "$GUARD_REASON"
  STOP_FURTHER=1
  STOP_REASON="single-member signer benchmark did not complete safely"
  OVERALL_STATUS=2
fi

for n in "${SELECTED_SIZES[@]}"; do
  t="$(threshold_for "$n")"
  point_name="N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
  point_dir="$OUTDIR/$point_name"
  fixture_dir="$point_dir/fixture"
  benchmark_dir="$point_dir/benchmark"
  mkdir -p "$fixture_dir" "$benchmark_dir"

  if [ "$STOP_FURTHER" -ne 0 ]; then
    write_status "$point_dir" "not_run_after_guard" "${STOP_REASON:-a previous selected point did not complete safely}"
    continue
  fi
  if [ -f "$point_dir/status.txt" ] && [ "$(sed -n '1p' "$point_dir/status.txt")" = complete ] &&
     [ -s "$benchmark_dir/summary.csv" ]; then
    echo "RESUME: $point_name already complete; keeping its recorded results"
    continue
  fi

  echo
  echo "======================================================================"
  echo "POINT $point_name: one aggregator, one SNARK verifier, one raw verifier"
  echo "quorum policy: t=floor(2N/3)+1 -> t=$t"
  echo "guard: RSS <= $MEMORY_LIMIT_MB MB, available >= $RESERVE_MB MB, swap growth <= $MAX_SWAP_GROWTH_MB MB"
  echo "======================================================================"

  if ! run_guarded "$point_name build" "$point_dir/build.log" \
      env DROT_BENCH_N="$n" DROT_BENCH_T="$t" cargo build --release --locked; then
    write_status "$point_dir" "build_failed" "$GUARD_REASON"
    STOP_FURTHER=1
    STOP_REASON="$point_name build did not complete safely"
    OVERALL_STATUS=1
    continue
  fi

  if ! run_guarded "$point_name fixture" "$point_dir/fixture.log" \
      env DROT_BENCH_N="$n" DROT_BENCH_T="$t" \
      "$REPO/target/release/committee_fixture" "$fixture_dir"; then
    write_status "$point_dir" "fixture_failed" "$GUARD_REASON"
    STOP_FURTHER=1
    STOP_REASON="$point_name fixture did not complete safely"
    OVERALL_STATUS=2
    continue
  fi

  if ! run_guarded "$point_name benchmark" "$point_dir/benchmark.log" \
      env DROT_BENCH_N="$n" DROT_BENCH_T="$t" BENCH_INPUT_DIR="$fixture_dir" \
      RUNS="$RUNS" WARMUP="$WARMUP" TARGETS="prover verifier raw_agg" \
      STRICT_ENV="$STRICT_ENV" PIN_CPUS="$PIN_CPUS" INTERLEAVE="$INTERLEAVE" \
      OUTDIR="$benchmark_dir" "$REPO/benchmark.sh"; then
    write_status "$point_dir" "benchmark_failed" "$GUARD_REASON"
    STOP_FURTHER=1
    STOP_REASON="$point_name benchmark did not complete safely"
    OVERALL_STATUS=2
    continue
  fi

  [ -s "$benchmark_dir/summary.csv" ] || {
    write_status "$point_dir" "benchmark_failed" "benchmark.sh produced no summary.csv"
    STOP_FURTHER=1
    STOP_REASON="$point_name benchmark produced no summary"
    OVERALL_STATUS=1
    continue
  }
  write_status "$point_dir" "complete" "all benchmark.sh failure gates passed"
  sed -n '1,18p' "$benchmark_dir/summary.txt"
done

# Lift the signer rows to the campaign root. They deliberately remain separate
# from scaling.csv, whose rows each describe one (N,t) point.
if [ -f "$SIGNER_DIR/status.txt" ] &&
   [ "$(sed -n '1p' "$SIGNER_DIR/status.txt")" = complete ] &&
   [ -s "$SIGNER_BENCHMARK_DIR/summary.csv" ]; then
  awk -F, 'NR == 1 || $1 == "signer"' "$SIGNER_BENCHMARK_DIR/summary.csv" > "$SIGNER_CSV"
else
  echo 'target,metric,unit,n,min,q1,median,q3,max,mean,sd,cv_pct,ci95_halfwidth' > "$SIGNER_CSV"
fi

# Build a complete manifest, including the large points rejected by the initial
# host-memory decision and selected points not reached after a live guard stop.
echo 'n,t,selected,status,reason,point_dir' > "$MANIFEST"
for n in "${REQUESTED_SIZES[@]}"; do
  t="$(threshold_for "$n")"
  selected=0
  for admitted in "${SELECTED_SIZES[@]}"; do
    [ "$n" -eq "$admitted" ] && selected=1
  done
  point_name="N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
  point_dir="$OUTDIR/$point_name"
  if [ "$selected" -eq 1 ]; then
    status="not_run"
    reason="selected but no status was recorded"
    if [ -f "$point_dir/status.txt" ]; then
      status="$(sed -n '1p' "$point_dir/status.txt")"
      reason="$(sed -n '2p' "$point_dir/status.txt")"
    fi
  elif [ "$n" -eq 1000 ]; then
    status="not_selected_ram"; reason="$N1000_REASON"
  else
    status="not_selected_ram"; reason="$N1500_REASON"
  fi
  reason="${reason//,/;}"
  printf '%d,%d,%d,%s,%s,%s\n' "$n" "$t" "$selected" "$status" "$reason" "$point_dir" >> "$MANIFEST"
done

echo 'n,t,prover_setup_ms,prove_ms,snark_verify_ms,raw_verify_ms,snark_record_bytes,raw_record_bytes,verify_speedup,wire_reduction_pct,break_even_verifiers,prover_peak_mb,snark_verifier_peak_mb,raw_verifier_peak_mb,benchmark_dir' > "$SCALING_CSV"
for n in "${SELECTED_SIZES[@]}"; do
  t="$(threshold_for "$n")"
  point_name="N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
  benchmark_dir="$OUTDIR/$point_name/benchmark"
  [ -f "$OUTDIR/$point_name/status.txt" ] || continue
  [ "$(sed -n '1p' "$OUTDIR/$point_name/status.txt")" = complete ] || continue
  summary="$benchmark_dir/summary.csv"
  prover_setup="$(summary_value "$summary" prover setup)"
  prove="$(summary_value "$summary" prover prove_per_item)"
  snark_verify="$(summary_value "$summary" verifier verify_per_item)"
  raw_verify="$(summary_value "$summary" raw_agg verify_per_item)"
  snark_bytes="$(summary_value "$summary" prover proof_size)"
  raw_bytes="$(summary_value "$summary" raw_agg proof_size)"
  prover_rss="$(summary_rss "$summary" prover)"
  snark_verifier_rss="$(summary_rss "$summary" verifier)"
  raw_verifier_rss="$(summary_rss "$summary" raw_agg)"
  derived="$(awk -v p="$prove" -v sv="$snark_verify" -v rv="$raw_verify" -v sb="$snark_bytes" -v rb="$raw_bytes" 'BEGIN {
    speed=(sv>0)?rv/sv:0; reduction=(rb>0)?100*(rb-sb)/rb:0; be=""
    if (rv>sv) { be=int(p/(rv-sv)); if (be*(rv-sv)<p) be++ }
    printf "%.6f,%.3f,%s", speed, reduction, be
  }')"
  printf '%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$n" "$t" "$prover_setup" "$prove" "$snark_verify" "$raw_verify" \
    "$snark_bytes" "$raw_bytes" "$derived" "$prover_rss" "$snark_verifier_rss" \
    "$raw_verifier_rss" "$benchmark_dir" >> "$SCALING_CSV"
done

{
  echo "COMMITTEE SCALING REPORT"
  echo "generated : $(date -Is)"
  echo "host      : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "policy    : t=floor(2N/3)+1 (strict two-thirds supermajority)"
  echo "runs      : $RUNS measured + $WARMUP warmup per target campaign"
  echo "roles     : one signer campaign; per point, one aggregator, one SNARK verifier and one raw verifier"
  echo "RAM plan  : ${AVAILABLE_MB} MB initially available; ${MEMORY_LIMIT_MB} MB process cap; selected N<=${MAX_SELECTED_N}"
  echo
  echo "SINGLE-MEMBER SIGNER — MEASURED ONCE FOR THE WHOLE SWEEP"
  if [ -s "$SIGNER_CSV" ] && [ "$(awk 'END { print NR }' "$SIGNER_CSV")" -gt 1 ]; then
    signer_n="$(awk -F, 'NR > 1 && $2 == "sign_per_item" { print $4; exit }' "$SIGNER_CSV")"
    signer_keygen="$(summary_value "$SIGNER_CSV" signer keygen)"
    signer_slot_state="$(summary_value "$SIGNER_CSV" signer slot_state)"
    signer_sign="$(summary_value "$SIGNER_CSV" signer sign_per_item)"
    signer_bytes="$(summary_value "$SIGNER_CSV" signer proof_size)"
    signer_rss="$(summary_rss "$SIGNER_CSV" signer)"
    printf "  key generation (one key) : %.2f ms\n" "$signer_keygen"
    printf "  durable slot state       : %.2f ms\n" "$signer_slot_state"
    printf "  sign / round             : %.2f ms (median of %s run medians)\n" "$signer_sign" "$signer_n"
    printf "  signature size           : %.0f bytes\n" "$signer_bytes"
    printf "  signer peak RSS          : %.1f MB\n" "$signer_rss"
    echo "  applies unchanged to every (N,t) point and to both publication forms"
    echo "  N=5,t=4 is only this invocation's compilation anchor; signer uses neither"
  else
    echo "  unavailable: see signer/status.txt and signer/benchmark.log"
  fi
  echo
  printf '%6s %6s %11s %11s %11s %9s %12s %12s %11s\n' \
    N t prove_ms snark_v_ms raw_v_ms speedup snark_bytes raw_bytes break_even
  if [ -s "$SCALING_CSV" ]; then
    tail -n +2 "$SCALING_CSV" | while IFS=, read -r n t setup prove sv rv sb rb speed reduction be pr sr rr dir; do
      printf '%6d %6d %11.2f %11.2f %11.2f %8.2fx %12.0f %12.0f %11s\n' \
        "$n" "$t" "$prove" "$sv" "$rv" "$speed" "$sb" "$rb" "${be:--}"
    done
  fi
  echo
  size_cross="$(awk -F, 'NR>1 && $8+0>$7+0 {print $1; exit}' "$SCALING_CSV")"
  verify_cross="$(awk -F, 'NR>1 && $6+0>$5+0 {print $1; exit}' "$SCALING_CSV")"
  joint_cross="$(awk -F, 'NR>1 && $8+0>$7+0 && $6+0>$5+0 {print $1; exit}' "$SCALING_CSV")"
  echo "CROSSOVERS WITHIN THE COMPLETED GRID"
  echo "  smaller published record : ${size_cross:-not observed}"
  echo "  faster relying-party verify: ${verify_cross:-not observed}"
  echo "  both conditions           : ${joint_cross:-not observed}"
  echo
  echo "break_even is the number of independent relying-party verifications needed"
  echo "for saved verification time to repay one proof:"
  echo "  ceil(prove_ms / (raw_verify_ms - snark_verify_ms))."
  echo "It excludes one-time setup, signing (identical for both forms), network cost"
  echo "and fixture generation. A blank value means SNARK verification was not faster."
  echo
  echo "RESOURCE OUTCOME"
  awk -F, 'NR>1 {printf "  N=%-4s t=%-4s %-22s %s\n", $1, $2, $4, $5}' "$MANIFEST"
  echo
  echo "See each point's benchmark/summary.txt for confidence intervals and caveats."
  echo "The scaling table uses benchmark.sh's per-run-median aggregates; it does not"
  echo "pool within-run observations or extrapolate unmeasured committee sizes."
} | tee "$REPORT"

echo
echo "written:"
echo "  $DECISION_FILE"
echo "  $SIGNER_CSV"
echo "  $MANIFEST"
echo "  $SCALING_CSV"
echo "  $REPORT"

trap - INT TERM EXIT
exit "$OVERALL_STATUS"
