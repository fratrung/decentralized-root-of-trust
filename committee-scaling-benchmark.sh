#!/usr/bin/env bash
# Committee-size scaling study built on top of benchmark.sh.
#
# This file deliberately does not reimplement measurement or statistics.
# It first invokes benchmark.sh once for the XMSS and ML-DSA signer roles. Then,
# for every admitted (N,t) point, it:
#   1. builds both crates, with benchmark-only N/t overrides for XMSS;
#   2. generates XMSS and ML-DSA signatures in unmeasured fixture processes;
#   3. invokes benchmark.sh for one aggregator, one SNARK verifier and raw XMSS
#      and ML-DSA verifier alternatives;
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

STUDY_MODE="${STUDY_MODE:-pilot}"
case "$STUDY_MODE" in
  pilot)
    RUNS="${RUNS:-3}"
    WARMUP="${WARMUP:-1}"
    SWEEP_REPEATS="${SWEEP_REPEATS:-1}"
    STRICT_ENV="${STRICT_ENV:-0}"
    COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-2}"
    ;;
  publication)
    RUNS="${RUNS:-24}"
    WARMUP="${WARMUP:-2}"
    SWEEP_REPEATS="${SWEEP_REPEATS:-2}"
    STRICT_ENV="${STRICT_ENV:-1}"
    COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-10}"
    ;;
  *) echo "STUDY_MODE must be pilot or publication" >&2; exit 1 ;;
esac
PLAN_ONLY="${PLAN_ONLY:-0}"
RESUME="${RESUME:-0}"
PIN_CPUS="${PIN_CPUS:-}"
INTERLEAVE="${INTERLEAVE:-1}"
POINT_TIMEOUT_MINUTES="${POINT_TIMEOUT_MINUTES:-90}"
MONITOR_INTERVAL_SECONDS="${MONITOR_INTERVAL_SECONDS:-2}"
PROGRESS_INTERVAL_SECONDS="${PROGRESS_INTERVAL_SECONDS:-15}"
MAX_SWAP_GROWTH_MB="${MAX_SWAP_GROWTH_MB:-64}"
HARD_MEMORY_LIMIT="${HARD_MEMORY_LIMIT:-required}"
MIN_FREE_DISK_MB="${MIN_FREE_DISK_MB:-8192}"
OUTDIR="${OUTDIR:-$REPO/committee-scaling-$(date +%Y%m%d-%H%M%S)}"
BENCH_UPDATES="$(sed -n 's/^pub const N_UPDATES: usize = \([0-9][0-9]*\).*/\1/p' src/params.rs)"

# These are conservative admission thresholds for the usable benchmark budget,
# not claims about leanVM's exact memory curve. The live guard below remains the
# authority and can stop any admitted point, including N=500.
RAM_FOR_N500_MB="${RAM_FOR_N500_MB:-8192}"
RAM_FOR_N1000_MB="${RAM_FOR_N1000_MB:-12288}"
RAM_FOR_N1500_MB="${RAM_FOR_N1500_MB:-20480}"

required_commands=(awk cargo cmp cp date df diff find grep kill lscpu mkdir nproc ps sed setsid sha256sum sort tail)
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
for target in signer mldsa_signer prover verifier raw_agg mldsa_raw_agg; do
  for prefix in RUNS WARMUP; do
    override="${prefix}_${target}"
    if [ "${!override+x}" ]; then
      echo "scaling requires one balanced run count; unset $override and use $prefix instead" >&2
      exit 1
    fi
  done
done

positive_integer BENCH_UPDATES "$BENCH_UPDATES"
[ "$BENCH_UPDATES" -le 64 ] || { echo "N_UPDATES=$BENCH_UPDATES exceeds the ML-DSA fixture limit 64" >&2; exit 1; }
positive_integer RUNS "$RUNS"
positive_integer SWEEP_REPEATS "$SWEEP_REPEATS"
case "$WARMUP" in ''|*[!0-9]*) echo "WARMUP must be a non-negative integer" >&2; exit 1 ;; esac
case "$COOLDOWN_SECONDS" in ''|*[!0-9]*) echo "COOLDOWN_SECONDS must be a non-negative integer" >&2; exit 1 ;; esac
case "$PLAN_ONLY" in 0|1) ;; *) echo "PLAN_ONLY must be 0 or 1" >&2; exit 1 ;; esac
case "$RESUME" in 0|1) ;; *) echo "RESUME must be 0 or 1" >&2; exit 1 ;; esac
case "$STRICT_ENV" in 0|1) ;; *) echo "STRICT_ENV must be 0 or 1" >&2; exit 1 ;; esac
case "$HARD_MEMORY_LIMIT" in required|auto|off) ;; *) echo "HARD_MEMORY_LIMIT must be required, auto or off" >&2; exit 1 ;; esac
positive_integer POINT_TIMEOUT_MINUTES "$POINT_TIMEOUT_MINUTES"
positive_integer MONITOR_INTERVAL_SECONDS "$MONITOR_INTERVAL_SECONDS"
positive_integer PROGRESS_INTERVAL_SECONDS "$PROGRESS_INTERVAL_SECONDS"
positive_integer MAX_SWAP_GROWTH_MB "$MAX_SWAP_GROWTH_MB"
positive_integer MIN_FREE_DISK_MB "$MIN_FREE_DISK_MB"
positive_integer RAM_FOR_N500_MB "$RAM_FOR_N500_MB"
positive_integer RAM_FOR_N1000_MB "$RAM_FOR_N1000_MB"
positive_integer RAM_FOR_N1500_MB "$RAM_FOR_N1500_MB"

if [ "$STUDY_MODE" = publication ]; then
  [ "$RUNS" -ge 10 ] || { echo "publication mode requires RUNS >= 10" >&2; exit 1; }
  [ $((RUNS % 4)) -eq 0 ] || {
    echo "publication mode requires RUNS to be a multiple of 4 for the complete four-target Williams design" >&2
    exit 1
  }
  [ "$SWEEP_REPEATS" -ge 2 ] || { echo "publication mode requires SWEEP_REPEATS >= 2" >&2; exit 1; }
  [ "$STRICT_ENV" = 1 ] || { echo "publication mode requires STRICT_ENV=1" >&2; exit 1; }
  [ -n "$PIN_CPUS" ] || { echo "publication mode requires an explicit PIN_CPUS mask" >&2; exit 1; }
  [ -z "$(git status --porcelain 2>/dev/null)" ] || {
    echo "publication mode requires a clean committed working tree" >&2
    exit 1
  }
fi

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

REQUESTED_MAX_RSS_MB="${MAX_RSS_MB:-auto}"
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
SELECTED_SIZES=(5 10 100)
MAX_SELECTED_N=100
N500_REASON="usable budget ${MEMORY_LIMIT_MB} MB is below ${RAM_FOR_N500_MB} MB"
N1000_REASON="usable budget ${MEMORY_LIMIT_MB} MB is below ${RAM_FOR_N1000_MB} MB"
N1500_REASON="N=1000 was not admitted"
if [ "$MEMORY_LIMIT_MB" -ge "$RAM_FOR_N500_MB" ]; then
  SELECTED_SIZES+=(500)
  MAX_SELECTED_N=500
  N500_REASON="admitted"
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
fi

HARD_LIMIT_BACKEND=unavailable
if [ "$HARD_MEMORY_LIMIT" != off ] && command -v systemd-run >/dev/null 2>&1; then
  if systemd-run --user --scope --quiet -p MemoryMax=64M -p MemorySwapMax=0 true >/dev/null 2>&1; then
    HARD_LIMIT_BACKEND=systemd-user-scope
  fi
fi
if [ "$PLAN_ONLY" = 0 ] && [ "$HARD_MEMORY_LIMIT" = required ] && [ "$HARD_LIMIT_BACKEND" = unavailable ]; then
  echo "a kernel-enforced memory limit is required, but systemd --user scopes are unavailable" >&2
  echo "use PLAN_ONLY=1 to inspect the plan; HARD_MEMORY_LIMIT=auto permits the polling fallback" >&2
  exit 1
fi
if [ "$PLAN_ONLY" = 0 ] && [ "$STUDY_MODE" = publication ] && [ "$HARD_LIMIT_BACKEND" = unavailable ]; then
  echo "publication mode requires a kernel-enforced memory limit; systemd --user scopes are unavailable" >&2
  echo "PLAN_ONLY=1 may still be used to inspect the host-derived plan" >&2
  exit 1
fi

if [ -d "$OUTDIR" ] && [ -n "$(find "$OUTDIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ] && [ "$RESUME" != 1 ]; then
  echo "OUTDIR already contains data; use a new directory or RESUME=1: $OUTDIR" >&2
  exit 1
fi
mkdir -p "$OUTDIR"
DECISION_FILE="$OUTDIR/memory-decision.txt"
CONFIG_FILE="$OUTDIR/campaign-config.txt"
MANIFEST="$OUTDIR/manifest.csv"
SCALING_CSV="$OUTDIR/scaling.csv"
REPORT="$OUTDIR/report.txt"
SIGNER_DIR="$OUTDIR/signer"
SIGNER_BENCHMARK_DIR="$SIGNER_DIR/benchmark"
SIGNER_CSV="$OUTDIR/signer.csv"

# Resume the original N decision. The hard cap is recalculated from current
# availability because it is a safety ceiling, not a treatment variable. A
# lower cap is acceptable until hit; what must remain true is the admission
# threshold for the largest N already selected. Extra RAM must not add points.
if [ "$RESUME" = 1 ] && [ -f "$CONFIG_FILE" ]; then
  stored_sizes="$(sed -n 's/^selected_sizes=//p' "$CONFIG_FILE")"
  [ -n "$stored_sizes" ] || {
    echo "resume refused: stored campaign plan is incomplete" >&2
    exit 1
  }
  read -r -a SELECTED_SIZES <<<"$stored_sizes"
  MAX_SELECTED_N="${SELECTED_SIZES[${#SELECTED_SIZES[@]}-1]}"
  required_resume_mb=0
  [ "$MAX_SELECTED_N" -ge 500 ] && required_resume_mb="$RAM_FOR_N500_MB"
  [ "$MAX_SELECTED_N" -ge 1000 ] && required_resume_mb="$RAM_FOR_N1000_MB"
  [ "$MAX_SELECTED_N" -ge 1500 ] && required_resume_mb="$RAM_FOR_N1500_MB"
  if [ "$MEMORY_LIMIT_MB" -lt "$required_resume_mb" ]; then
    echo "resume refused: current usable RAM cap ${MEMORY_LIMIT_MB} MB is below the ${required_resume_mb} MB admission threshold for N=$MAX_SELECTED_N" >&2
    exit 1
  fi
  N500_REASON="not admitted in the recorded campaign"
  N1000_REASON="not admitted in the recorded campaign"
  N1500_REASON="not admitted in the recorded campaign"
  for stored_n in "${SELECTED_SIZES[@]}"; do
    [ "$stored_n" -eq 500 ] && N500_REASON=admitted
    [ "$stored_n" -eq 1000 ] && N1000_REASON=admitted
    [ "$stored_n" -eq 1500 ] && N1500_REASON=admitted
  done
fi

current_config() {
  echo "schema=5"
  echo "study_mode=$STUDY_MODE"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo n/a)"
  echo "git_dirty=$(test -n "$(git status --porcelain 2>/dev/null)" && echo yes || echo no)"
  echo "source_patch_sha=$(git diff --binary HEAD 2>/dev/null | sha256sum | awk '{print $1}')"
  echo "cargo_lock_sha=$(sha256sum Cargo.lock 2>/dev/null | awk '{print $1}')"
  echo "mldsa_cargo_lock_sha=$(sha256sum mldsa/Cargo.lock 2>/dev/null | awk '{print $1}')"
  echo "benchmark_sha=$(sha256sum benchmark.sh | awk '{print $1}')"
  echo "scaling_sha=$(sha256sum committee-scaling-benchmark.sh | awk '{print $1}')"
  echo "validator_sha=$(sha256sum tools/validate_benchmark_csv.awk | awk '{print $1}')"
  echo "untracked_sha=$(git ls-files -z --others --exclude-standard | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}')"
  echo "host=$(hostname)"
  echo "cpu=$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "updates=$BENCH_UPDATES"
  echo "runs=$RUNS"
  echo "warmup=$WARMUP"
  echo "sweep_repeats=$SWEEP_REPEATS"
  echo "strict_env=$STRICT_ENV"
  echo "pin_cpus=$PIN_CPUS"
  echo "interleave=$INTERLEAVE"
  echo "cooldown_seconds=$COOLDOWN_SECONDS"
  echo "selected_sizes=${SELECTED_SIZES[*]}"
  echo "hard_limit_backend=$HARD_LIMIT_BACKEND"
  echo "hard_memory_policy=$HARD_MEMORY_LIMIT"
  echo "requested_max_rss_mb=$REQUESTED_MAX_RSS_MB"
  echo "reserve_mb=$RESERVE_MB"
  echo "ram_for_n500_mb=$RAM_FOR_N500_MB"
  echo "ram_for_n1000_mb=$RAM_FOR_N1000_MB"
  echo "ram_for_n1500_mb=$RAM_FOR_N1500_MB"
  echo "max_swap_growth_mb=$MAX_SWAP_GROWTH_MB"
  echo "point_timeout_minutes=$POINT_TIMEOUT_MINUTES"
  echo "monitor_interval_seconds=$MONITOR_INTERVAL_SECONDS"
  echo "progress_interval_seconds=$PROGRESS_INTERVAL_SECONDS"
  echo "min_free_disk_mb=$MIN_FREE_DISK_MB"
}
CONFIG_TMP="$(mktemp)"
current_config > "$CONFIG_TMP"
if [ "$RESUME" = 1 ]; then
  [ -f "$CONFIG_FILE" ] || { echo "RESUME=1 but $CONFIG_FILE is missing" >&2; exit 1; }
  cmp -s "$CONFIG_TMP" "$CONFIG_FILE" || {
    echo "resume refused: campaign configuration or source fingerprint changed" >&2
    diff -u "$CONFIG_FILE" "$CONFIG_TMP" >&2 || true
    exit 1
  }
else
  cp "$CONFIG_TMP" "$CONFIG_FILE"
fi
rm -f "$CONFIG_TMP"

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
  echo "cooldown per target       : $COOLDOWN_SECONDS seconds"
  echo "study mode                : $STUDY_MODE"
  echo "complete sweep repeats    : $SWEEP_REPEATS"
  echo "hard memory backend        : $HARD_LIMIT_BACKEND ($HARD_MEMORY_LIMIT policy)"
  echo "minimum free disk          : $MIN_FREE_DISK_MB MB"
  echo "N=500 admission threshold : $RAM_FOR_N500_MB MB -> $N500_REASON"
  echo "N=1000 admission threshold: $RAM_FOR_N1000_MB MB -> $N1000_REASON"
  echo "N=1500 admission threshold: $RAM_FOR_N1500_MB MB -> $N1500_REASON"
  echo "selected committee sizes  : ${SELECTED_SIZES[*]}"
  echo "selected maximum          : N=$MAX_SELECTED_N"
  echo
  echo "The selected maximum is fixed for this run. During execution the guard"
  echo "also stops a stage if its process group exceeds the cap, available RAM"
  echo "or disk falls below reserve, swap grows, or the timeout expires."
  if [ "$HARD_LIMIT_BACKEND" = unavailable ]; then
    echo "WARNING: RAM protection is polling-only in this plan; a fast spike can outrun it."
  fi
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

disk_available_mb() {
  df -Pk "$1" | awk 'NR==2 {print int($4/1024)}'
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
  local available_before disk_before start now last_report pid pgid rss available disk_free swap_free swap_growth rc
  local -a guarded_cmd
  available_before="$(meminfo_mb MemAvailable)"
  if [ "$available_before" -lt "$RESERVE_MB" ]; then
    GUARD_REASON="available RAM ${available_before} MB is already below reserve ${RESERVE_MB} MB"
    return 70
  fi
  disk_before="$(disk_available_mb "$OUTDIR")"
  if [ "$disk_before" -lt "$MIN_FREE_DISK_MB" ]; then
    GUARD_REASON="free disk ${disk_before} MB is below reserve ${MIN_FREE_DISK_MB} MB"
    return 70
  fi

  if [ "$HARD_LIMIT_BACKEND" = systemd-user-scope ]; then
    guarded_cmd=(systemd-run --user --scope --quiet
      -p "MemoryMax=${MEMORY_LIMIT_MB}M"
      -p "MemorySwapMax=${MAX_SWAP_GROWTH_MB}M" -- "$@")
  else
    guarded_cmd=("$@")
  fi

  echo "[$(date +%H:%M:%S)] START $label"
  setsid "${guarded_cmd[@]}" >"$log" 2>&1 &
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
    disk_free="$(disk_available_mb "$OUTDIR")"
    swap_free="$(meminfo_mb SwapFree)"
    swap_growth=$((SWAP_FREE_AT_START_MB - swap_free))
    [ "$swap_growth" -lt 0 ] && swap_growth=0
    [ "$rss" -gt "$GUARD_PEAK_MB" ] && GUARD_PEAK_MB="$rss"
    now="$(date +%s)"

    if [ "$rss" -gt "$MEMORY_LIMIT_MB" ]; then
      GUARD_REASON="process-group RSS ${rss} MB exceeded cap ${MEMORY_LIMIT_MB} MB"
    elif [ "$available" -lt "$RESERVE_MB" ]; then
      GUARD_REASON="available RAM ${available} MB fell below reserve ${RESERVE_MB} MB"
    elif [ "$disk_free" -lt "$MIN_FREE_DISK_MB" ]; then
      GUARD_REASON="free disk ${disk_free} MB fell below reserve ${MIN_FREE_DISK_MB} MB"
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
      printf '[%s] GUARD %-24s RSS=%d/%d MB available=%d MB disk=%d MB swap_delta=%d MB\n' \
        "$(date +%H:%M:%S)" "$label" "$rss" "$MEMORY_LIMIT_MB" "$available" "$disk_free" "$swap_growth"
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

validate_campaign() { # directory, space-separated targets
  local dir="$1" targets="$2"
  [ -s "$dir/runs.csv" ] && [ -s "$dir/samples.csv" ] || return 1
  awk -F, -v targets="$targets" -v expected_runs="$RUNS" \
      -v expected_items="$BENCH_UPDATES" \
      -f "$REPO/tools/validate_benchmark_csv.awk" \
      "$dir/runs.csv" "$dir/samples.csv"
}

STOP_FURTHER=0
STOP_REASON=""
OVERALL_STATUS=0

# Signing is independent of committee size: each member produces one signature
# per update regardless of N or t. Measure XMSS and ML-DSA once each as
# a complete benchmark.sh campaign, preserving repeated runs and confidence
# intervals without redundantly charging it to every scaling point. N=5,t=4 is
# only the compile-time anchor for this invocation; neither signer binary uses
# those committee parameters.
mkdir -p "$SIGNER_BENCHMARK_DIR"
if [ -f "$SIGNER_DIR/status.txt" ] &&
   [ "$(sed -n '1p' "$SIGNER_DIR/status.txt")" = complete ] &&
   [ -s "$SIGNER_BENCHMARK_DIR/summary.csv" ]; then
  if validate_campaign "$SIGNER_BENCHMARK_DIR" "signer mldsa_signer"; then
    echo "RESUME: single-member signer benchmark already complete"
  else
    write_status "$SIGNER_DIR" benchmark_failed "stored signer measurements are incomplete or malformed"
    STOP_FURTHER=1; STOP_REASON="stored signer measurements failed validation"; OVERALL_STATUS=1
  fi
elif run_guarded "single-member signer benchmarks" "$SIGNER_DIR/benchmark.log" \
    env DROT_BENCH_N=5 DROT_BENCH_T=4 \
    RUNS="$RUNS" WARMUP="$WARMUP" TARGETS="signer mldsa_signer" \
    STRICT_ENV="$STRICT_ENV" PIN_CPUS="$PIN_CPUS" INTERLEAVE="$INTERLEAVE" \
    COOLDOWN_SECONDS="$COOLDOWN_SECONDS" \
    OUTDIR="$SIGNER_BENCHMARK_DIR" "$REPO/benchmark.sh"; then
  if [ -s "$SIGNER_BENCHMARK_DIR/summary.csv" ]; then
    if ! validate_campaign "$SIGNER_BENCHMARK_DIR" "signer mldsa_signer"; then
      write_status "$SIGNER_DIR" benchmark_failed "signer measurements are incomplete or malformed"
      STOP_FURTHER=1; STOP_REASON="signer measurements failed validation"; OVERALL_STATUS=1
    elif [ "$STUDY_MODE" = publication ] && [ ! -s "$SIGNER_BENCHMARK_DIR/drift.csv" ]; then
      write_status "$SIGNER_DIR" "benchmark_failed" "benchmark.sh produced no drift.csv"
      STOP_FURTHER=1; STOP_REASON="single-member signer benchmark produced no drift diagnostic"; OVERALL_STATUS=1
    elif [ "$STUDY_MODE" = publication ] &&
       awk -F, 'NR>1 && $8=="warning" {bad=1} END{exit !bad}' "$SIGNER_BENCHMARK_DIR/drift.csv"; then
      write_status "$SIGNER_DIR" unstable "early/late drift exceeded 15%"
      STOP_FURTHER=1; STOP_REASON="signer campaign was not stationary"; OVERALL_STATUS=2
    else
      write_status "$SIGNER_DIR" "complete" "single-member benchmark.sh failure gates passed"
    fi
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

ordered_sizes() { # alternating complete sweeps break the N/time confound
  local sweep="$1" i
  if [ $((sweep % 2)) -eq 1 ]; then
    printf '%s\n' "${SELECTED_SIZES[@]}"
  else
    for ((i=${#SELECTED_SIZES[@]}-1; i>=0; i--)); do
      printf '%s\n' "${SELECTED_SIZES[$i]}"
    done
  fi
}

for ((sweep=1; sweep<=SWEEP_REPEATS; sweep++)); do
  echo
  echo "######################## COMPLETE SWEEP $sweep/$SWEEP_REPEATS ########################"
  while IFS= read -r n; do
    t="$(threshold_for "$n")"
    point_name="N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
    point_dir="$OUTDIR/$point_name"
    fixture_dir="$point_dir/fixture"
    mldsa_fixture_dir="$point_dir/mldsa-fixture"
    session_dir="$point_dir/session-$(printf '%02d' "$sweep")"
    benchmark_dir="$session_dir/benchmark"
    mkdir -p "$fixture_dir" "$benchmark_dir"

    if [ "$STOP_FURTHER" -ne 0 ]; then
      write_status "$session_dir" "not_run_after_guard" "${STOP_REASON:-a previous stage did not complete safely}"
      continue
    fi
    if [ -f "$session_dir/status.txt" ] && [ "$(sed -n '1p' "$session_dir/status.txt")" = complete ] &&
       [ -s "$benchmark_dir/summary.csv" ]; then
      if validate_campaign "$benchmark_dir" "prover verifier raw_agg mldsa_raw_agg"; then
        echo "RESUME: $point_name session $sweep already complete"
      else
        write_status "$session_dir" benchmark_failed "stored measurements are incomplete or malformed"
        STOP_FURTHER=1; STOP_REASON="$point_name stored measurements failed validation"; OVERALL_STATUS=1
      fi
      continue
    fi

    echo
    echo "======================================================================"
    echo "POINT $point_name, sweep $sweep/$SWEEP_REPEATS"
    echo "one aggregator, one SNARK verifier, one raw XMSS verifier, one raw ML-DSA verifier"
    echo "quorum policy: t=floor(2N/3)+1 -> t=$t"
    echo "guard: cgroup/poll RSS <= $MEMORY_LIMIT_MB MB, available >= $RESERVE_MB MB, disk >= $MIN_FREE_DISK_MB MB"
    echo "======================================================================"

    if ! run_guarded "$point_name/s$sweep build" "$session_dir/build.log" \
        env DROT_BENCH_N="$n" DROT_BENCH_T="$t" cargo build --release --locked; then
      write_status "$session_dir" "build_failed" "$GUARD_REASON"
      STOP_FURTHER=1; STOP_REASON="$point_name build did not complete safely"; OVERALL_STATUS=1
      continue
    fi

    if ! run_guarded "$point_name/s$sweep ML-DSA build" "$session_dir/mldsa-build.log" \
        cargo build --manifest-path "$REPO/mldsa/Cargo.toml" --release --locked; then
      write_status "$session_dir" "build_failed" "$GUARD_REASON"
      STOP_FURTHER=1; STOP_REASON="$point_name ML-DSA build did not complete safely"; OVERALL_STATUS=1
      continue
    fi

    if [ ! -f "$point_dir/fixture.complete" ]; then
      if ! run_guarded "$point_name fixture" "$point_dir/fixture.log" \
          env DROT_BENCH_N="$n" DROT_BENCH_T="$t" \
          "$REPO/target/release/committee_fixture" "$fixture_dir"; then
        write_status "$session_dir" "fixture_failed" "$GUARD_REASON"
        STOP_FURTHER=1; STOP_REASON="$point_name fixture did not complete safely"; OVERALL_STATUS=2
        continue
      fi
      printf 'complete\n' > "$point_dir/fixture.complete"
    fi

    if [ ! -f "$point_dir/mldsa-fixture.complete" ]; then
      if [ -e "$mldsa_fixture_dir" ]; then
        write_status "$session_dir" "fixture_failed" "incomplete ML-DSA fixture exists at $mldsa_fixture_dir; use a new OUTDIR or inspect and remove it explicitly"
        STOP_FURTHER=1; STOP_REASON="$point_name has an incomplete ML-DSA fixture"; OVERALL_STATUS=2
        continue
      fi
      if ! run_guarded "$point_name ML-DSA fixture" "$point_dir/mldsa-fixture.log" \
          "$REPO/mldsa/target/release/mldsa_fixture" \
          "$mldsa_fixture_dir" "$n" "$t" "$BENCH_UPDATES"; then
        write_status "$session_dir" "fixture_failed" "$GUARD_REASON"
        STOP_FURTHER=1; STOP_REASON="$point_name ML-DSA fixture did not complete safely"; OVERALL_STATUS=2
        continue
      fi
      printf 'complete\n' > "$point_dir/mldsa-fixture.complete"
    fi

    if ! run_guarded "$point_name/s$sweep benchmark" "$session_dir/benchmark.log" \
        env DROT_BENCH_N="$n" DROT_BENCH_T="$t" BENCH_INPUT_DIR="$fixture_dir" MLDSA_INPUT_DIR="$mldsa_fixture_dir" \
        BENCH_SELF_CONTAINED=0 RUNS="$RUNS" WARMUP="$WARMUP" \
        TARGETS="prover verifier raw_agg mldsa_raw_agg" STRICT_ENV="$STRICT_ENV" \
        REQUIRE_CLEAN_TREE="$STRICT_ENV" PIN_CPUS="$PIN_CPUS" INTERLEAVE="$INTERLEAVE" \
        COOLDOWN_SECONDS="$COOLDOWN_SECONDS" \
        OUTDIR="$benchmark_dir" "$REPO/benchmark.sh"; then
      write_status "$session_dir" "benchmark_failed" "$GUARD_REASON"
      STOP_FURTHER=1; STOP_REASON="$point_name benchmark did not complete safely"; OVERALL_STATUS=2
      continue
    fi

    if [ ! -s "$benchmark_dir/summary.csv" ]; then
      write_status "$session_dir" "benchmark_failed" "benchmark.sh produced no summary.csv"
      STOP_FURTHER=1; STOP_REASON="$point_name benchmark produced no summary"; OVERALL_STATUS=1
      continue
    fi
    if ! validate_campaign "$benchmark_dir" "prover verifier raw_agg mldsa_raw_agg"; then
      write_status "$session_dir" benchmark_failed "measurements are incomplete or malformed"
      STOP_FURTHER=1; STOP_REASON="$point_name measurements failed validation"; OVERALL_STATUS=1
      continue
    fi
    if [ "$STUDY_MODE" = publication ] && [ ! -s "$benchmark_dir/drift.csv" ]; then
      write_status "$session_dir" "benchmark_failed" "benchmark.sh produced no drift.csv"
      STOP_FURTHER=1; STOP_REASON="$point_name benchmark produced no drift diagnostic"; OVERALL_STATUS=1
      continue
    fi
    if [ "$STUDY_MODE" = publication ] &&
       awk -F, 'NR>1 && $8=="warning" {bad=1} END{exit !bad}' "$benchmark_dir/drift.csv"; then
      write_status "$session_dir" unstable "early/late drift exceeded 15%; no observations removed"
      STOP_FURTHER=1; STOP_REASON="$point_name session $sweep was not stationary"; OVERALL_STATUS=2
      continue
    fi
    write_status "$session_dir" "complete" "benchmark.sh failure gates passed"
    sed -n '1,18p' "$benchmark_dir/summary.txt"
  done < <(ordered_sizes "$sweep")
done

# A point is complete only when every counterbalanced sweep completed. This root
# status is what the manifest and aggregate report consume.
for n in "${SELECTED_SIZES[@]}"; do
  t="$(threshold_for "$n")"
  point_name="N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
  point_dir="$OUTDIR/$point_name"
  mkdir -p "$point_dir"
  complete=0
  for ((sweep=1; sweep<=SWEEP_REPEATS; sweep++)); do
    session_dir="$point_dir/session-$(printf '%02d' "$sweep")"
    if [ -f "$session_dir/status.txt" ] && [ "$(sed -n '1p' "$session_dir/status.txt")" = complete ]; then
      if validate_campaign "$session_dir/benchmark" "prover verifier raw_agg mldsa_raw_agg"; then
        complete=$((complete + 1))
      else
        write_status "$session_dir" benchmark_failed "measurements failed final validation"
        OVERALL_STATUS=1
      fi
    fi
  done
  if [ "$complete" -eq "$SWEEP_REPEATS" ]; then
    write_status "$point_dir" complete "$complete/$SWEEP_REPEATS sweeps complete"
  else
    root_status=incomplete
    root_reason="$complete/$SWEEP_REPEATS sweeps complete"
    for ((sweep=1; sweep<=SWEEP_REPEATS; sweep++)); do
      session_dir="$point_dir/session-$(printf '%02d' "$sweep")"
      if [ -f "$session_dir/status.txt" ] && [ "$(sed -n '1p' "$session_dir/status.txt")" != complete ]; then
        root_status="$(sed -n '1p' "$session_dir/status.txt")"
        root_reason="session $sweep: $(sed -n '2p' "$session_dir/status.txt")"
        break
      fi
    done
    write_status "$point_dir" "$root_status" "$root_reason"
  fi
done

# Lift the signer rows to the campaign root. They deliberately remain separate
# from scaling.csv, whose rows each describe one (N,t) point.
if [ -f "$SIGNER_DIR/status.txt" ] &&
   [ "$(sed -n '1p' "$SIGNER_DIR/status.txt")" = complete ] &&
   [ -s "$SIGNER_BENCHMARK_DIR/summary.csv" ]; then
  awk -F, 'NR == 1 || $1 == "signer" || $1 == "mldsa_signer"' "$SIGNER_BENCHMARK_DIR/summary.csv" > "$SIGNER_CSV"
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
  elif [ "$n" -eq 500 ]; then
    status="not_selected_ram"; reason="$N500_REASON"
  elif [ "$n" -eq 1000 ]; then
    status="not_selected_ram"; reason="$N1000_REASON"
  else
    status="not_selected_ram"; reason="$N1500_REASON"
  fi
  reason="${reason//,/;}"
  printf '%d,%d,%d,%s,%s,%s\n' "$n" "$t" "$selected" "$status" "$reason" "$point_dir" >> "$MANIFEST"
done

stats() {
  sort -g | awk '
    BEGIN { split("12.706 4.303 3.182 2.776 2.571 2.447 2.365 2.306 2.262 2.228 2.201 2.179 2.160 2.145 2.131 2.120 2.110 2.101 2.093 2.086 2.080 2.074 2.069 2.064 2.060 2.056 2.052 2.048 2.045 2.042",tt," ") }
    {a[++n]=$1;s+=$1}
    function q(p, h,lo,fr){h=(n-1)*p+1;lo=int(h);fr=h-lo;return(lo>=n)?a[n]:a[lo]+fr*(a[lo+1]-a[lo])}
    END {if(!n){print "0 0 0 0 0 0 0 0 0 0";exit} m=s/n;for(i=1;i<=n;i++){d=a[i]-m;ss+=d*d}
      sd=(n>1)?sqrt(ss/(n-1)):0;df=n-1;tc=(df<=0)?0:(df<=30?tt[df]:1.960);ci=(n>1)?tc*sd/sqrt(n):0
      printf "%d %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.3f %.6f\n",n,a[1],q(.25),q(.5),q(.75),a[n],m,sd,(m?100*sd/m:0),ci}'
}

point_values() { # point_dir target column
  local point_dir="$1" target="$2" column="$3" file
  for file in "$point_dir"/session-*/benchmark/runs.csv; do
    [ -f "$file" ] || continue
    awk -F, -v t="$target" -v c="$column" 'NR>1 && $1==t && $c!="" {print $c}' "$file"
  done
}

paired_values() { # point_dir delta|speedup|break_even|nonpositive
  local point_dir="$1" mode="$2" file
  for file in "$point_dir"/session-*/benchmark/runs.csv; do
    [ -f "$file" ] || continue
    awk -F, -v mode="$mode" '
      NR>1 && $1=="prover"   {p[$2]=$14}
      NR>1 && $1=="verifier" {v[$2]=$44}
      NR>1 && $1=="raw_agg"  {r[$2]=$44}
      END {for(i in p) if((i in v)&&(i in r)) {
        d=r[i]-v[i]
        if(mode=="delta") print d
        else if(mode=="speedup" && v[i]>0) print r[i]/v[i]
        else if(mode=="break_even" && d>0) {
          x=p[i]/d; ceiling=int(x); if(ceiling<x) ceiling++
          print ceiling
        }
        else if(mode=="nonpositive" && d<=0) print 1
      }}' "$file"
  done
}

echo 'n,t,observations,prover_setup_ms,prove_ms,snark_decode_verify_ms,raw_decode_verify_ms,verify_delta_mean_ms,verify_delta_ci95_low,verify_delta_ci95_high,verify_advantage_confirmed,verify_speedup_median,verify_speedup_q1,verify_speedup_q3,snark_record_bytes,raw_record_bytes,wire_reduction_pct,break_even_median,break_even_q1,break_even_q3,prover_peak_mb,snark_verifier_peak_mb,raw_verifier_peak_mb,point_dir,mldsa_decode_ms,mldsa_verify_ms,mldsa_decode_verify_ms,mldsa_record_bytes,mldsa_verifier_peak_mb,snark_decode_ms,snark_verify_only_ms,raw_decode_ms,raw_verify_only_ms' > "$SCALING_CSV"
for n in "${SELECTED_SIZES[@]}"; do
  t="$(threshold_for "$n")"
  point_name="N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
  point_dir="$OUTDIR/$point_name"
  [ -f "$point_dir/status.txt" ] || continue
  [ "$(sed -n '1p' "$point_dir/status.txt")" = complete ] || continue

  setup_stats="$(point_values "$point_dir" prover 4 | stats)"
  prove_stats="$(point_values "$point_dir" prover 14 | stats)"
  sv_stats="$(point_values "$point_dir" verifier 44 | stats)"
  rv_stats="$(point_values "$point_dir" raw_agg 44 | stats)"
  sd_stats="$(point_values "$point_dir" verifier 38 | stats)"
  so_stats="$(point_values "$point_dir" verifier 20 | stats)"
  rd_stats="$(point_values "$point_dir" raw_agg 38 | stats)"
  ro_stats="$(point_values "$point_dir" raw_agg 20 | stats)"
  sb_stats="$(point_values "$point_dir" prover 26 | stats)"
  rb_stats="$(point_values "$point_dir" raw_agg 26 | stats)"
  pr_stats="$(point_values "$point_dir" prover 30 | stats)"
  sr_stats="$(point_values "$point_dir" verifier 30 | stats)"
  rr_stats="$(point_values "$point_dir" raw_agg 30 | stats)"
  md_stats="$(point_values "$point_dir" mldsa_raw_agg 38 | stats)"
  mv_stats="$(point_values "$point_dir" mldsa_raw_agg 20 | stats)"
  mt_stats="$(point_values "$point_dir" mldsa_raw_agg 44 | stats)"
  mb_stats="$(point_values "$point_dir" mldsa_raw_agg 26 | stats)"
  mr_stats="$(point_values "$point_dir" mldsa_raw_agg 30 | stats)"
  delta_stats="$(paired_values "$point_dir" delta | stats)"
  speed_stats="$(paired_values "$point_dir" speedup | stats)"
  be_stats="$(paired_values "$point_dir" break_even | stats)"
  nonpositive_deltas="$(paired_values "$point_dir" nonpositive | awk 'END{print NR+0}')"

  observations="$(awk '{print $1}' <<<"$prove_stats")"
  delta_count="$(awk '{print $1}' <<<"$delta_stats")"
  speed_count="$(awk '{print $1}' <<<"$speed_stats")"
  expected_observations=$((RUNS * SWEEP_REPEATS))
  if [ "$observations" -ne "$expected_observations" ] ||
     [ "$delta_count" -ne "$expected_observations" ] ||
     [ "$speed_count" -ne "$expected_observations" ]; then
    echo "incomplete paired observations for $point_name: prove=$observations delta=$delta_count speedup=$speed_count expected=$expected_observations" >&2
    exit 1
  fi
  prover_setup="$(awk '{print $4}' <<<"$setup_stats")"
  prove="$(awk '{print $4}' <<<"$prove_stats")"
  snark_verify="$(awk '{print $4}' <<<"$sv_stats")"
  raw_verify="$(awk '{print $4}' <<<"$rv_stats")"
  snark_bytes="$(awk '{print $4}' <<<"$sb_stats")"
  raw_bytes="$(awk '{print $4}' <<<"$rb_stats")"
  delta_mean="$(awk '{print $7}' <<<"$delta_stats")"
  delta_ci="$(awk '{print $10}' <<<"$delta_stats")"
  delta_low="$(awk -v m="$delta_mean" -v c="$delta_ci" 'BEGIN{printf "%.6f",m-c}')"
  delta_high="$(awk -v m="$delta_mean" -v c="$delta_ci" 'BEGIN{printf "%.6f",m+c}')"
  advantage="$(awk -v lo="$delta_low" 'BEGIN{print(lo>0)?1:0}')"
  speed="$(awk '{print $4}' <<<"$speed_stats")"
  speed_q1="$(awk '{print $3}' <<<"$speed_stats")"
  speed_q3="$(awk '{print $5}' <<<"$speed_stats")"
  break_even=""; break_even_q1=""; break_even_q3=""
  if [ "$advantage" = 1 ] && [ "$nonpositive_deltas" -eq 0 ]; then
    break_even="$(awk '{print $4}' <<<"$be_stats")"
    break_even_q1="$(awk '{print $3}' <<<"$be_stats")"
    break_even_q3="$(awk '{print $5}' <<<"$be_stats")"
  fi
  wire_reduction="$(awk -v sb="$snark_bytes" -v rb="$raw_bytes" 'BEGIN{printf "%.3f",(rb>0)?100*(rb-sb)/rb:0}')"
  prover_rss="$(awk '{print $4}' <<<"$pr_stats")"
  snark_verifier_rss="$(awk '{print $4}' <<<"$sr_stats")"
  raw_verifier_rss="$(awk '{print $4}' <<<"$rr_stats")"
  mldsa_decode="$(awk '{print $4}' <<<"$md_stats")"
  mldsa_verify="$(awk '{print $4}' <<<"$mv_stats")"
  mldsa_total="$(awk '{print $4}' <<<"$mt_stats")"
  mldsa_bytes="$(awk '{print $4}' <<<"$mb_stats")"
  mldsa_rss="$(awk '{print $4}' <<<"$mr_stats")"
  snark_decode="$(awk '{print $4}' <<<"$sd_stats")"
  snark_verify_only="$(awk '{print $4}' <<<"$so_stats")"
  raw_decode="$(awk '{print $4}' <<<"$rd_stats")"
  raw_verify_only="$(awk '{print $4}' <<<"$ro_stats")"

  printf '%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$n" "$t" "$observations" "$prover_setup" "$prove" "$snark_verify" "$raw_verify" \
    "$delta_mean" "$delta_low" "$delta_high" "$advantage" "$speed" "$speed_q1" "$speed_q3" \
    "$snark_bytes" "$raw_bytes" "$wire_reduction" "$break_even" "$break_even_q1" "$break_even_q3" \
    "$prover_rss" "$snark_verifier_rss" "$raw_verifier_rss" "$point_dir" \
    "$mldsa_decode" "$mldsa_verify" "$mldsa_total" "$mldsa_bytes" "$mldsa_rss" \
    "$snark_decode" "$snark_verify_only" "$raw_decode" "$raw_verify_only" >> "$SCALING_CSV"
done
awk -F, '
  NR == 1 { expected = NF; next }
  NF != expected {
    printf "scaling.csv row %d has %d columns; expected %d\n", NR, NF, expected > "/dev/stderr"
    bad = 1
  }
  END { exit bad }
' "$SCALING_CSV"

{
  echo "COMMITTEE SCALING REPORT"
  echo "generated : $(date -Is)"
  echo "host      : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "mode      : $STUDY_MODE"
  echo "policy    : t=floor(2N/3)+1 (strict two-thirds supermajority)"
  echo "runs      : $RUNS measured + $WARMUP warmup per target, across $SWEEP_REPEATS complete sweep(s)"
  echo "cooldown  : $COOLDOWN_SECONDS seconds before every measured process"
  echo "roles     : two single-member signers; per point, one aggregator and three relying-party verifiers"
  echo "RAM plan  : ${AVAILABLE_MB} MB initially available; ${MEMORY_LIMIT_MB} MB process cap; selected N<=${MAX_SELECTED_N}"
  echo "hard cap  : $HARD_LIMIT_BACKEND"
  [ "$STUDY_MODE" = pilot ] && echo "status    : EXPLORATORY PILOT — do not publish as a final measurement campaign"
  echo
  echo "SINGLE-MEMBER SIGNERS — MEASURED ONCE FOR THE WHOLE SWEEP"
  if [ -s "$SIGNER_CSV" ] && [ "$(awk 'END { print NR }' "$SIGNER_CSV")" -gt 1 ]; then
    signer_n="$(awk -F, 'NR > 1 && $1 == "signer" && $2 == "sign_protocol_per_item" { print $4; exit }' "$SIGNER_CSV")"
    signer_keygen="$(summary_value "$SIGNER_CSV" signer keygen)"
    signer_slot_state="$(summary_value "$SIGNER_CSV" signer slot_state)"
    signer_sign="$(summary_value "$SIGNER_CSV" signer sign_protocol_per_item)"
    signer_burn="$(summary_value "$SIGNER_CSV" signer slot_burn_per_item)"
    signer_crypto="$(summary_value "$SIGNER_CSV" signer sign_crypto_per_item)"
    signer_bytes="$(summary_value "$SIGNER_CSV" signer signature_size)"
    signer_rss="$(summary_rss "$SIGNER_CSV" signer)"
    mldsa_n="$(awk -F, 'NR > 1 && $1 == "mldsa_signer" && $2 == "sign_crypto_per_item" { print $4; exit }' "$SIGNER_CSV")"
    mldsa_keygen="$(summary_value "$SIGNER_CSV" mldsa_signer keygen)"
    mldsa_sign="$(summary_value "$SIGNER_CSV" mldsa_signer sign_crypto_per_item)"
    mldsa_bytes="$(summary_value "$SIGNER_CSV" mldsa_signer signature_size)"
    mldsa_signer_rss="$(summary_rss "$SIGNER_CSV" mldsa_signer)"
    printf "  XMSS keygen (one key)    : %.2f ms\n" "$signer_keygen"
    printf "  XMSS durable slot state  : %.2f ms\n" "$signer_slot_state"
    printf "  XMSS protocol sign       : %.2f ms (median of %s run medians)\n" "$signer_sign" "$signer_n"
    printf "    durable slot burn      : %.2f ms; cryptographic sign %.2f ms\n" "$signer_burn" "$signer_crypto"
    printf "  XMSS signature size      : %.0f bytes; peak RSS %.1f MB\n" "$signer_bytes" "$signer_rss"
    printf "  ML-DSA keygen (one key)  : %.2f ms\n" "$mldsa_keygen"
    printf "  ML-DSA crypto sign only  : %.2f ms (median of %s run medians)\n" "$mldsa_sign" "$mldsa_n"
    printf "  ML-DSA signature size    : %.0f bytes; peak RSS %.1f MB\n" "$mldsa_bytes" "$mldsa_signer_rss"
    echo "  XMSS protocol cost includes durable burn; ML-DSA has no"
    echo "  one-statement-per-version state and is NOT a comparable protocol cost"
    echo "  both per-member measurements are independent of N and t"
    echo "  N=5,t=4 is only this invocation's compilation anchor; neither signer uses it"
  else
    echo "  unavailable: see signer/status.txt and signer/benchmark.log"
  fi
  echo
  printf '%6s %6s %5s %11s %11s %11s %9s %12s %12s %10s %11s\n' \
    N t obs prove_ms snark_e2e raw_e2e speedup snark_bytes raw_bytes confirmed break_even
  if [ -s "$SCALING_CSV" ]; then
    awk -F, 'NR>1 {printf "%6d %6d %5d %11.2f %11.2f %11.2f %8.2fx %12.0f %12.0f %10s %11s\n",$1,$2,$3,$5,$6,$7,$12,$15,$16,($11==1?"yes":"no"),($18==""?"-":sprintf("%.1f",$18))}' "$SCALING_CSV"
  fi
  echo
  echo "RAW VERIFIER PHASES — E2E IS ONE CONTIGUOUS DECODE + VERIFY TIMER"
  printf '%6s %6s %10s %10s %10s %10s %10s %10s %12s %12s\n' \
    N t xmss_dec xmss_ver xmss_e2e mldsa_dec mldsa_ver mldsa_e2e xmss_bytes mldsa_bytes
  if [ -s "$SCALING_CSV" ]; then
    awk -F, 'NR>1 {printf "%6d %6d %10.2f %10.2f %10.2f %10.2f %10.2f %10.2f %12.0f %12.0f\n",$1,$2,$32,$33,$7,$25,$26,$27,$16,$28}' "$SCALING_CSV"
  fi
  echo
  size_cross="$(awk -F, 'NR>1 && $16+0>$15+0 {print $1; exit}' "$SCALING_CSV")"
  verify_cross="$(awk -F, 'NR>1 && $11==1 {print $1; exit}' "$SCALING_CSV")"
  joint_cross="$(awk -F, 'NR>1 && $16+0>$15+0 && $11==1 {print $1; exit}' "$SCALING_CSV")"
  echo "CROSSOVERS WITHIN THE COMPLETED GRID"
  echo "  smaller published record : ${size_cross:-not observed}"
  echo "  faster relying-party verify (95% paired CI above zero): ${verify_cross:-not observed}"
  echo "  both conditions           : ${joint_cross:-not observed}"
  echo
  echo "break_even is the number of independent relying-party verifications needed"
  echo "for saved verification time to repay one proof:"
  echo "  ceil(prove_ms / (raw_decode_verify_ms - snark_decode_verify_ms))."
  echo "It excludes one-time setup, signing (identical for both forms), network cost"
  echo "and fixture generation. The table reports break-even only when the paired"
  echo "95% CI for raw_verify - snark_verify is wholly above zero and every paired"
  echo "run saved end-to-end verification time. The paired CI treats repeated runs"
  echo "as independent within this host/session; it does not establish an effect"
  echo "across days or machines. scaling.csv contains Q1/Q3 for speedup"
  echo "and break-even. No timing samples are discarded."
  echo
  echo "RESOURCE OUTCOME"
  awk -F, 'NR>1 {printf "  N=%-4s t=%-4s %-22s %s\n", $1, $2, $4, $5}' "$MANIFEST"
  echo
  echo "See each point's session-XX/benchmark/summary.txt and drift.csv artifacts."
  echo "The scaling table aggregates per-run medians across complete sweeps; it does"
  echo "not pool within-run observations or extrapolate unmeasured committee sizes."
  echo "Ascending and descending sweeps counterbalance N against experiment time."
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
