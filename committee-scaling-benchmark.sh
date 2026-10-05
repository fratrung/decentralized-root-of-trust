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
case "$INTERLEAVE" in 0|1) ;; *) echo "INTERLEAVE must be 0 or 1" >&2; exit 1 ;; esac
case "$HARD_MEMORY_LIMIT" in required|auto|off) ;; *) echo "HARD_MEMORY_LIMIT must be required, auto or off" >&2; exit 1 ;; esac
positive_integer POINT_TIMEOUT_MINUTES "$POINT_TIMEOUT_MINUTES"
positive_integer MONITOR_INTERVAL_SECONDS "$MONITOR_INTERVAL_SECONDS"
positive_integer PROGRESS_INTERVAL_SECONDS "$PROGRESS_INTERVAL_SECONDS"
positive_integer MAX_SWAP_GROWTH_MB "$MAX_SWAP_GROWTH_MB"
positive_integer MIN_FREE_DISK_MB "$MIN_FREE_DISK_MB"
positive_integer RAM_FOR_N500_MB "$RAM_FOR_N500_MB"
positive_integer RAM_FOR_N1000_MB "$RAM_FOR_N1000_MB"
positive_integer RAM_FOR_N1500_MB "$RAM_FOR_N1500_MB"

# The status-list size of this campaign: one value for every point, so a sweep
# varies the committee and not the list. Unset keeps the default growing
# list (1..=N_UPDATES entries). It is exported under both names: benchmark.sh
# reads LIST_ENTRIES and checks every process against it, the fixture binaries
# read BENCH_LIST_ENTRIES. Compare list sizes by running one campaign per size.
LIST_ENTRIES="${LIST_ENTRIES:-${BENCH_LIST_ENTRIES:-}}"
case "$LIST_ENTRIES" in
  '') ;;
  *[!0-9]*|0*) echo "LIST_ENTRIES must be a positive integer without leading zeros (unset: the default growing list)" >&2; exit 1 ;;
esac
if [ -n "$LIST_ENTRIES" ]; then
  [ "$LIST_ENTRIES" -le 1048576 ] || { echo "LIST_ENTRIES=$LIST_ENTRIES exceeds the limit 1048576" >&2; exit 1; }
  export LIST_ENTRIES BENCH_LIST_ENTRIES="$LIST_ENTRIES"
  WORKLOAD_LIST="$LIST_ENTRIES"
  WORKLOAD_L="L=$LIST_ENTRIES"
  WORKLOAD_DESC="$LIST_ENTRIES entries in every version, one entry replaced per version"
else
  unset LIST_ENTRIES BENCH_LIST_ENTRIES
  WORKLOAD_LIST=growing
  WORKLOAD_L="L=1..$BENCH_UPDATES"
  WORKLOAD_DESC="growing, one entry added per version: 1..=$BENCH_UPDATES entries (default workload)"
fi

SIGNER_STATE_DIR="${SIGNER_STATE_DIR:-${TMPDIR:-/tmp}}"
export SIGNER_STATE_DIR
SIGNER_STORAGE="$("$REPO/tools/storage_class.sh" "$SIGNER_STATE_DIR")" || exit 1

if [ "$STUDY_MODE" = publication ]; then
  [ "$RUNS" -ge 10 ] || { echo "publication mode requires RUNS >= 10" >&2; exit 1; }
  [ $((RUNS % 4)) -eq 0 ] || {
    echo "publication mode requires RUNS to be a multiple of 4 for the complete four-target Williams design" >&2
    exit 1
  }
  [ "$SWEEP_REPEATS" -ge 2 ] || { echo "publication mode requires SWEEP_REPEATS >= 2" >&2; exit 1; }
  # The report describes a counterbalanced design: every point as often early as
  # late in the campaign, and the four roles interleaved within each session.
  # Three sweeps are two ascending and one descending, and INTERLEAVE=0 runs the
  # roles in contiguous blocks; both confound the comparison with time.
  [ $((SWEEP_REPEATS % 2)) -eq 0 ] || {
    echo "publication mode requires an even SWEEP_REPEATS (ascending and descending sweeps in equal number)" >&2
    exit 1
  }
  [ "$INTERLEAVE" = 1 ] || {
    echo "publication mode requires INTERLEAVE=1 (the balanced four-target order)" >&2
    exit 1
  }
  # The XMSS signer's durable burn is one sync per signature on this storage.
  if [ "$(sed -n 's/^class=\([a-z]*\) .*/\1/p' <<<"$SIGNER_STORAGE")" = ram ] &&
     [ "${ALLOW_RAM_SIGNER_STATE:-0}" != 1 ]; then
    echo "publication mode refuses signer state on RAM-backed storage ($SIGNER_STORAGE); set SIGNER_STATE_DIR, or ALLOW_RAM_SIGNER_STATE=1 to measure that scenario by name" >&2
    exit 1
  fi
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
  echo "insufficient available RAM: ${AVAILABLE_MB} MiB available, ${RESERVE_MB} MiB reserved" >&2
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
    echo "NOTE: requested MAX_RSS_MB=$MEMORY_LIMIT_MB exceeds the safe host budget; clamping to $SAFE_MEMORY_LIMIT_MB MiB"
    MEMORY_LIMIT_MB="$SAFE_MEMORY_LIMIT_MB"
  fi
else
  MEMORY_LIMIT_MB="$SAFE_MEMORY_LIMIT_MB"
fi

REQUESTED_SIZES=(5 10 100 500 1000 1500)
SELECTED_SIZES=(5 10 100)
MAX_SELECTED_N=100
N500_REASON="usable budget ${MEMORY_LIMIT_MB} MiB is below ${RAM_FOR_N500_MB} MiB"
N1000_REASON="usable budget ${MEMORY_LIMIT_MB} MiB is below ${RAM_FOR_N1000_MB} MiB"
N1500_REASON="N=1000 was not admitted"
if [ "$MEMORY_LIMIT_MB" -ge "$RAM_FOR_N500_MB" ]; then
  SELECTED_SIZES+=(500)
  MAX_SELECTED_N=500
  N500_REASON="admitted"
  if [ "$MEMORY_LIMIT_MB" -ge "$RAM_FOR_N1000_MB" ]; then
    SELECTED_SIZES+=(1000)
    MAX_SELECTED_N=1000
    N1000_REASON="admitted"
    N1500_REASON="usable budget ${MEMORY_LIMIT_MB} MiB is below ${RAM_FOR_N1500_MB} MiB"
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
# Tidy companions of scaling.csv (see the aggregation section):
#   costs.csv        elapsed and CPU cost of every role, per update and once per process
#   comparisons.csv  paired differences between the three verifiers, on both clocks
#   all-runs.csv     every measured run of every session, with its place in the campaign
COSTS_CSV="$OUTDIR/costs.csv"
COMPARISONS_CSV="$OUTDIR/comparisons.csv"
ALL_RUNS_CSV="$OUTDIR/all-runs.csv"
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
    echo "resume refused: current usable RAM cap ${MEMORY_LIMIT_MB} MiB is below the ${required_resume_mb} MiB admission threshold for N=$MAX_SELECTED_N" >&2
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
  echo "schema=10"
  echo "study_mode=$STUDY_MODE"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo n/a)"
  echo "git_dirty=$(test -n "$(git status --porcelain 2>/dev/null)" && echo yes || echo no)"
  echo "source_patch_sha=$(git diff --binary HEAD 2>/dev/null | sha256sum | awk '{print $1}')"
  echo "cargo_lock_sha=$(sha256sum Cargo.lock 2>/dev/null | awk '{print $1}')"
  echo "mldsa_cargo_lock_sha=$(sha256sum mldsa/Cargo.lock 2>/dev/null | awk '{print $1}')"
  echo "benchmark_sha=$(sha256sum benchmark.sh | awk '{print $1}')"
  echo "scaling_sha=$(sha256sum committee-scaling-benchmark.sh | awk '{print $1}')"
  echo "validator_sha=$(sha256sum tools/validate_benchmark_csv.awk | awk '{print $1}')"
  echo "stats_sha=$(sha256sum tools/stats.awk | awk '{print $1}')"
  echo "untracked_sha=$(git ls-files -z --others --exclude-standard | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}')"
  # Build and runtime conditions a commit does not pin: toolchain, every Cargo
  # config and rustflags override, the stack variable the targets inherit, and
  # where temporary and signer state lives. Sessions differing in any of these
  # are different experiments and must not be merged by a resume.
  echo "cargo_env_sha=$("$REPO/tools/cargo_env_fingerprint.sh" | sha256sum | awk '{print $1}')"
  echo "rust_min_stack=${RUST_MIN_STACK-<unset>}"
  echo "signer_state=$SIGNER_STORAGE"
  echo "allow_ram_signer_state=${ALLOW_RAM_SIGNER_STATE:-0}"
  echo "tmpdir=${TMPDIR:-/tmp} fstype=$(df -PT "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2 {print $2}')"
  echo "host=$(hostname)"
  echo "cpu=$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "updates=$BENCH_UPDATES"
  echo "list_entries=$WORKLOAD_LIST"
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

# A resume appends its own block under the original decision instead of
# replacing it: the conditions the campaign started under stay on record.
decision_tee=(tee "$DECISION_FILE")
[ "$RESUME" = 1 ] && decision_tee=(tee -a "$DECISION_FILE")
{
  if [ "$RESUME" = 1 ]; then
    echo
    echo "=== RESUME: original N selection reused, cap recalculated ==="
  fi
  echo "COMMITTEE SCALING — MEMORY ADMISSION DECISION"
  echo "timestamp                 : $(date -Is)"
  echo "host                      : $(hostname)"
  echo "physical RAM              : $TOTAL_MB MiB"
  echo "available RAM at start    : $AVAILABLE_MB MiB"
  echo "RAM reserved for host     : $RESERVE_MB MiB"
  echo "70% physical-RAM ceiling : $CAP_FROM_TOTAL_MB MiB"
  echo "enforced process-group cap: $MEMORY_LIMIT_MB MiB"
  echo "allowed swap growth       : $MAX_SWAP_GROWTH_MB MiB"
  echo "timeout per stage         : $POINT_TIMEOUT_MINUTES minutes"
  echo "cooldown per target       : $COOLDOWN_SECONDS seconds"
  echo "study mode                : $STUDY_MODE"
  echo "status list               : $WORKLOAD_DESC"
  echo "complete sweep repeats    : $SWEEP_REPEATS"
  echo "hard memory backend        : $HARD_LIMIT_BACKEND ($HARD_MEMORY_LIMIT policy)"
  echo "minimum free disk          : $MIN_FREE_DISK_MB MiB on every filesystem used:"
  for guarded in "$OUTDIR" "${TMPDIR:-/tmp}" "$SIGNER_STATE_DIR" "${CARGO_TARGET_DIR:-$REPO/target}"; do
    [ -e "$guarded" ] || continue
    echo "    $(df -Pk "$guarded" | awk 'NR == 2 { printf "%s (%d MiB free)", $6, $4 / 1024 }') <- $guarded"
  done
  echo "N=500 admission threshold : $RAM_FOR_N500_MB MiB -> $N500_REASON"
  echo "N=1000 admission threshold: $RAM_FOR_N1000_MB MiB -> $N1000_REASON"
  echo "N=1500 admission threshold: $RAM_FOR_N1500_MB MiB -> $N1500_REASON"
  echo "selected committee sizes  : ${SELECTED_SIZES[*]}"
  echo "selected maximum          : N=$MAX_SELECTED_N"
  echo
  echo "The selected maximum is fixed for this run. During execution the guard"
  echo "also stops a stage if its process group exceeds the cap, available RAM"
  echo "or disk falls below reserve, swap grows, or the timeout expires."
  if [ "$HARD_LIMIT_BACKEND" = unavailable ]; then
    echo "WARNING: RAM protection is polling-only in this plan; a fast spike can outrun it."
  fi
} | "${decision_tee[@]}"
echo

threshold_for() {
  echo $((2 * $1 / 3 + 1))
}

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

# The planned sequence of complete sweeps, written once per campaign. Together
# with schedule.csv (what actually ran, appended as it happens) it lets the
# design be audited instead of inferred from the report's description.
PLAN_CSV="$OUTDIR/plan.csv"
SCHEDULE_CSV="$OUTDIR/schedule.csv"
if [ ! -f "$PLAN_CSV" ]; then
  {
    echo 'sweep,direction,position,n,t'
    for ((sweep=1; sweep<=SWEEP_REPEATS; sweep++)); do
      direction=ascending; [ $((sweep % 2)) -eq 0 ] && direction=descending
      position=0
      while IFS= read -r n; do
        position=$((position + 1))
        printf '%d,%s,%d,%d,%d\n' "$sweep" "$direction" "$position" "$n" "$(threshold_for "$n")"
      done < <(ordered_sizes "$sweep")
    done
  } > "$PLAN_CSV"
fi

if [ "$PLAN_ONLY" = 1 ]; then
  echo "PLAN_ONLY=1: admission decision recorded; no build or benchmark was started."
  exit 0
fi

group_rss_mib() {
  ps -eo pgid=,rss= | awk -v group="$1" '$1 + 0 == group { sum += $2 } END { print int((sum + 1023) / 1024) }'
}

# Every filesystem the campaign writes to, not only OUTDIR: the build goes to
# Cargo's target directory, fixtures and scratch data to TMPDIR, the signer's
# journal to SIGNER_STATE_DIR.
GUARD_PATHS=("$OUTDIR" "${TMPDIR:-/tmp}" "$SIGNER_STATE_DIR")
if [ -d "${CARGO_TARGET_DIR:-$REPO/target}" ]; then
  GUARD_PATHS+=("${CARGO_TARGET_DIR:-$REPO/target}")
else
  GUARD_PATHS+=("$REPO")
fi
disk_available_mb() { # the smallest free space among the guarded filesystems
  df -Pk "${GUARD_PATHS[@]}" | awk 'NR > 1 { mb = int($4 / 1024); if (min == "" || mb < min) min = mb } END { print min + 0 }'
}
disk_tightest_mount() {
  df -Pk "${GUARD_PATHS[@]}" | awk 'NR > 1 { mb = int($4 / 1024); if (min == "" || mb < min) { min = mb; mount = $6 } } END { print mount }'
}
# pswpin pswpout mem_pressure_some_total_us oom_kill, each NA when unreadable.
memory_events_now() {
  local swapin=NA swapout=NA oom=NA pressure=NA
  if [ -r /proc/vmstat ]; then
    read -r swapin swapout oom < <(awk '
      $1 == "pswpin" { i = $2 } $1 == "pswpout" { o = $2 } $1 == "oom_kill" { k = $2 }
      END { print (i == "" ? "NA" : i), (o == "" ? "NA" : o), (k == "" ? "NA" : k) }' /proc/vmstat)
  fi
  if [ -r /proc/pressure/memory ]; then
    pressure="$(sed -n 's/^some .*total=\([0-9][0-9]*\).*/\1/p' /proc/pressure/memory)"
    [ -n "$pressure" ] || pressure=NA
  fi
  echo "$swapin $swapout $pressure $oom"
}
# Preflight: a filesystem already below the reserve stops the campaign here,
# before anything is built, and is named.
if [ "$(disk_available_mb)" -lt "$MIN_FREE_DISK_MB" ]; then
  echo "preflight: free disk $(disk_available_mb) MiB on $(disk_tightest_mount) is below the ${MIN_FREE_DISK_MB} MiB reserve; nothing was built" >&2
  exit 1
fi
PRESSURE_CSV="$OUTDIR/pressure.csv"
# One line per guarded stage: host-wide paging, memory-stall time and OOM kills
# while it ran. A stage can finish under pressure; its timings then include
# paging, and this is where that shows.
record_pressure() { # label events_before events_after outcome
  [ -f "$PRESSURE_CSV" ] || echo 'time,stage,swap_in_pages,swap_out_pages,mem_pressure_us,oom_kills,peak_group_rss_mib,outcome' > "$PRESSURE_CSV"
  awk -v now="$(date -Is)" -v label="$1" -v a="$2" -v b="$3" -v peak="$GUARD_PEAK_MB" -v outcome="$4" 'BEGIN {
    split(a, s, " "); split(b, e, " "); gsub(/,/, ";", label)
    printf "%s,%s", now, label
    for (i = 1; i <= 4; i++) printf ",%s", (s[i] == "NA" || e[i] == "NA") ? "" : e[i] - s[i]
    printf ",%s,%s\n", peak, outcome
  }' >> "$PRESSURE_CSV"
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
  local events_before
  local -a guarded_cmd
  available_before="$(meminfo_mb MemAvailable)"
  if [ "$available_before" -lt "$RESERVE_MB" ]; then
    GUARD_REASON="available RAM ${available_before} MiB is already below reserve ${RESERVE_MB} MiB"
    return 70
  fi
  disk_before="$(disk_available_mb)"
  if [ "$disk_before" -lt "$MIN_FREE_DISK_MB" ]; then
    GUARD_REASON="free disk ${disk_before} MiB on $(disk_tightest_mount) is below reserve ${MIN_FREE_DISK_MB} MiB"
    return 70
  fi
  events_before="$(memory_events_now)"

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
    rss="$(group_rss_mib "$pgid")"
    available="$(meminfo_mb MemAvailable)"
    disk_free="$(disk_available_mb)"
    swap_free="$(meminfo_mb SwapFree)"
    swap_growth=$((SWAP_FREE_AT_START_MB - swap_free))
    [ "$swap_growth" -lt 0 ] && swap_growth=0
    [ "$rss" -gt "$GUARD_PEAK_MB" ] && GUARD_PEAK_MB="$rss"
    now="$(date +%s)"

    if [ "$rss" -gt "$MEMORY_LIMIT_MB" ]; then
      GUARD_REASON="process-group RSS ${rss} MiB exceeded cap ${MEMORY_LIMIT_MB} MiB"
    elif [ "$available" -lt "$RESERVE_MB" ]; then
      GUARD_REASON="available RAM ${available} MiB fell below reserve ${RESERVE_MB} MiB"
    elif [ "$disk_free" -lt "$MIN_FREE_DISK_MB" ]; then
      GUARD_REASON="free disk ${disk_free} MiB on $(disk_tightest_mount) fell below reserve ${MIN_FREE_DISK_MB} MiB"
    elif [ "$swap_growth" -gt "$MAX_SWAP_GROWTH_MB" ]; then
      GUARD_REASON="swap use grew by ${swap_growth} MiB (limit ${MAX_SWAP_GROWTH_MB} MiB)"
    elif [ $((now - start)) -ge $((POINT_TIMEOUT_MINUTES * 60)) ]; then
      GUARD_REASON="stage exceeded ${POINT_TIMEOUT_MINUTES}-minute timeout"
    fi

    if [ -n "$GUARD_REASON" ]; then
      echo "[$(date +%H:%M:%S)] STOP  $label: $GUARD_REASON"
      terminate_active_group
      wait "$pid" 2>/dev/null || true
      record_pressure "$label" "$events_before" "$(memory_events_now)" stopped
      return 70
    fi
    if [ $((now - last_report)) -ge "$PROGRESS_INTERVAL_SECONDS" ]; then
      printf '[%s] GUARD %-24s RSS=%d/%d MiB available=%d MiB disk=%d MiB swap_delta=%d MiB\n' \
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
  record_pressure "$label" "$events_before" "$(memory_events_now)" "exit=$rc"
  if [ "$rc" -ne 0 ]; then
    GUARD_REASON="command exited with status $rc"
    echo "[$(date +%H:%M:%S)] FAIL  $label: $GUARD_REASON"
    tail -20 "$log" >&2 || true
    return "$rc"
  fi
  echo "[$(date +%H:%M:%S)] DONE  $label (observed group peak ${GUARD_PEAK_MB} MiB)"
}

# status.txt holds the current outcome; status-history.txt keeps every outcome
# ever written there, so a resume that fails again does not erase why an
# earlier attempt stopped.
write_status() {
  local point_dir="$1" status="$2" reason="$3"
  printf '%s\n%s\n' "$status" "$reason" > "$point_dir/status.txt"
  printf '%s %s %s\n' "$(date -Is)" "$status" "$reason" >> "$point_dir/status-history.txt"
  log_event "$point_dir" "$status" "$reason"
}
# schedule.csv: one line per event, in the order they happened, across resumes.
# A `started` session with no later outcome is an interruption.
log_event() { # directory event detail
  [ -f "$SCHEDULE_CSV" ] || echo 'time,stage,event,detail' > "$SCHEDULE_CSV"
  printf '%s,%s,%s,%s\n' "$(date -Is)" "${1#"$OUTDIR"/}" "$2" "${3//,/;}" >> "$SCHEDULE_CSV"
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
  # Only a campaign benchmark.sh itself declared complete, with every file it
  # bound in outputs.sha256 unchanged since, may contribute.
  [ "$(sed -n '1p' "$dir/status.txt" 2>/dev/null)" = complete ] || return 1
  (cd "$dir" && sha256sum --quiet --strict -c outputs.sha256) >/dev/null 2>&1 || return 1
  # ... and only one that measured this campaign's list size (benchmark.sh
  # checked every process against the workload.txt it wrote).
  grep -qx "list_entries=$WORKLOAD_LIST" "$dir/workload.txt" 2>/dev/null || return 1
  awk -F, -v targets="$targets" -v expected_runs="$RUNS" \
      -v expected_items="$BENCH_UPDATES" \
      -f "$REPO/tools/validate_benchmark_csv.awk" \
      "$dir/runs.csv" "$dir/samples.csv"
}

# benchmark.sh requires a new or empty OUTDIR. A retried stage keeps its
# previous attempt under a new name instead of overwriting it; the aggregation
# globs (session-*/benchmark/) never read those.
set_aside_attempt() { # directory
  local dir="$1" kept
  [ -n "$(find "$dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ] || return 0
  kept="$dir.attempt-$(date +%Y%m%dT%H%M%S)-$RANDOM"
  mv -- "$dir" "$kept"
  mkdir -p "$dir"
  echo "previous attempt kept in $kept"
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
    log_event "$SIGNER_DIR" kept_complete "earlier invocation; stored data revalidated"
  else
    write_status "$SIGNER_DIR" benchmark_failed "stored signer measurements are incomplete or malformed"
    STOP_FURTHER=1; STOP_REASON="stored signer measurements failed validation"; OVERALL_STATUS=1
  fi
elif set_aside_attempt "$SIGNER_BENCHMARK_DIR" &&
     log_event "$SIGNER_DIR" started "single-member signers" &&
     run_guarded "single-member signer benchmarks" "$SIGNER_DIR/benchmark.log" \
    env DROT_BENCH_N=5 DROT_BENCH_T=4 \
    RUNS="$RUNS" WARMUP="$WARMUP" TARGETS="signer mldsa_signer" \
    STRICT_ENV="$STRICT_ENV" PIN_CPUS="$PIN_CPUS" INTERLEAVE="$INTERLEAVE" \
    COOLDOWN_SECONDS="$COOLDOWN_SECONDS" PLOT=0 \
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
      # A session completed by an earlier invocation keeps that outcome: a later
      # failure stops new work but says nothing about measurements already
      # taken. The final validation below still rechecks them and marks only
      # the session whose data is actually damaged.
      if [ -f "$session_dir/status.txt" ] && [ "$(sed -n '1p' "$session_dir/status.txt")" = complete ]; then
        echo "RESUME: $point_name session $sweep already complete; kept, no new work after the stop"
        log_event "$session_dir" kept_complete "earlier invocation; no new work after the stop"
      else
        write_status "$session_dir" "not_run_after_guard" "${STOP_REASON:-a previous stage did not complete safely}"
      fi
      continue
    fi
    if [ -f "$session_dir/status.txt" ] && [ "$(sed -n '1p' "$session_dir/status.txt")" = complete ] &&
       [ -s "$benchmark_dir/summary.csv" ]; then
      if validate_campaign "$benchmark_dir" "prover verifier raw_agg mldsa_raw_agg"; then
        echo "RESUME: $point_name session $sweep already complete"
        log_event "$session_dir" kept_complete "earlier invocation; stored data revalidated"
      else
        write_status "$session_dir" benchmark_failed "stored measurements are incomplete or malformed"
        STOP_FURTHER=1; STOP_REASON="$point_name stored measurements failed validation"; OVERALL_STATUS=1
      fi
      continue
    fi

    echo
    echo "======================================================================"
    log_event "$session_dir" started "sweep $sweep/$SWEEP_REPEATS"
    echo "POINT $point_name, sweep $sweep/$SWEEP_REPEATS"
    echo "one aggregator, one SNARK verifier, one raw XMSS verifier, one raw ML-DSA verifier"
    echo "quorum policy: t=floor(2N/3)+1 -> t=$t"
    echo "guard: cgroup/poll RSS <= $MEMORY_LIMIT_MB MiB, available >= $RESERVE_MB MiB, disk >= $MIN_FREE_DISK_MB MiB"
    echo "======================================================================"

    # One frozen, hashed set of binaries per session: the fixtures and every
    # measured process of this session run from it, never from target/release,
    # which Cargo may not have written and a later build would overwrite. A
    # retried session replaces its own set. See tools/freeze_bins.sh.
    session_bin="$session_dir/bin"
    rm -rf "$session_bin"
    if ! run_guarded "$point_name/s$sweep build" "$session_dir/build.log" \
        env DROT_BENCH_N="$n" DROT_BENCH_T="$t" "$REPO/tools/freeze_bins.sh" "$session_bin" \
        "$REPO/Cargo.toml" prover verifier raw_agg committee_fixture check_prover_output; then
      write_status "$session_dir" "build_failed" "$GUARD_REASON"
      STOP_FURTHER=1; STOP_REASON="$point_name build did not complete safely"; OVERALL_STATUS=1
      continue
    fi

    if ! run_guarded "$point_name/s$sweep ML-DSA build" "$session_dir/mldsa-build.log" \
        "$REPO/tools/freeze_bins.sh" "$session_bin" "$REPO/mldsa/Cargo.toml" mldsa_raw_agg mldsa_fixture; then
      write_status "$session_dir" "build_failed" "$GUARD_REASON"
      STOP_FURTHER=1; STOP_REASON="$point_name ML-DSA build did not complete safely"; OVERALL_STATUS=1
      continue
    fi

    if [ ! -f "$point_dir/fixture.complete" ]; then
      if ! run_guarded "$point_name fixture" "$point_dir/fixture.log" \
          env DROT_BENCH_N="$n" DROT_BENCH_T="$t" \
          "$session_bin/committee_fixture" "$fixture_dir"; then
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
          "$session_bin/mldsa_fixture" \
          "$mldsa_fixture_dir" "$n" "$t" "$BENCH_UPDATES"; then
        write_status "$session_dir" "fixture_failed" "$GUARD_REASON"
        STOP_FURTHER=1; STOP_REASON="$point_name ML-DSA fixture did not complete safely"; OVERALL_STATUS=2
        continue
      fi
      printf 'complete\n' > "$point_dir/mldsa-fixture.complete"
    fi

    set_aside_attempt "$benchmark_dir"
    if ! run_guarded "$point_name/s$sweep benchmark" "$session_dir/benchmark.log" \
        env DROT_BENCH_N="$n" DROT_BENCH_T="$t" BENCH_BIN_DIR="$session_bin" \
        BENCH_INPUT_DIR="$fixture_dir" MLDSA_INPUT_DIR="$mldsa_fixture_dir" \
        BENCH_SELF_CONTAINED=0 RUNS="$RUNS" WARMUP="$WARMUP" \
        TARGETS="prover verifier raw_agg mldsa_raw_agg" STRICT_ENV="$STRICT_ENV" \
        REQUIRE_CLEAN_TREE="$STRICT_ENV" PIN_CPUS="$PIN_CPUS" INTERLEAVE="$INTERLEAVE" \
        COOLDOWN_SECONDS="$COOLDOWN_SECONDS" PLOT=0 \
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
  echo 'target,metric,unit,n,min,q1,median,q3,max,mean,sd,cv_pct,mean_ci95_halfwidth' > "$SIGNER_CSV"
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

# The same descriptive statistics as benchmark.sh, from the shared module:
# n min q1 median q3 max mean sd cv% mean_ci95_halfwidth, NA where a value
# cannot be estimated (see tools/stats.awk).
stats() { sort -g | awk -f "$REPO/tools/stats.awk"; }

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

echo 'n,t,observations,prover_setup_ms,prove_ms,snark_decode_verify_ms,raw_decode_verify_ms,verify_delta_mean_ms,verify_delta_ci95_low,verify_delta_ci95_high,verify_advantage_confirmed,verify_speedup_median,verify_speedup_q1,verify_speedup_q3,snark_record_bytes,raw_record_bytes,wire_reduction_pct,break_even_elapsed_median,break_even_elapsed_q1,break_even_elapsed_q3,prover_peak_mib,snark_verifier_peak_mib,raw_verifier_peak_mib,point_dir,mldsa_decode_ms,mldsa_verify_ms,mldsa_decode_verify_ms,mldsa_record_bytes,mldsa_verifier_peak_mib,snark_decode_ms,snark_verify_only_ms,raw_decode_ms,raw_verify_only_ms,peak_rss_source,prover_peak_max_mib,snark_verifier_peak_max_mib,raw_verifier_peak_max_mib,mldsa_verifier_peak_max_mib,prover_work_rss_mib,snark_verifier_work_rss_mib,raw_verifier_work_rss_mib,mldsa_verifier_work_rss_mib,list_entries' > "$SCALING_CSV"
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
  # Peak RSS comes from the kernel's ru_maxrss (runs.csv column 30) when every
  # run of every role has that reading, and otherwise from the processes' own
  # VmHWM (column 29) for all four roles, so one point never mixes sources. The
  # source is recorded: without /usr/bin/time the kernel column is empty, and an
  # empty series must not be published as a peak of 0.
  expected_observations=$((RUNS * SWEEP_REPEATS))
  peak_column=30; peak_source=kernel
  for role in prover verifier raw_agg mldsa_raw_agg; do
    if [ "$(point_values "$point_dir" "$role" 30 | awk 'END { print NR + 0 }')" -ne "$expected_observations" ]; then
      peak_column=29; peak_source=vmhwm
    fi
  done
  pr_stats="$(point_values "$point_dir" prover "$peak_column" | stats)"
  sr_stats="$(point_values "$point_dir" verifier "$peak_column" | stats)"
  rr_stats="$(point_values "$point_dir" raw_agg "$peak_column" | stats)"
  # Largest RSS sampled after each honest update (column 28): unlike a peak, it
  # excludes whatever the process does after its measured loop.
  pw_stats="$(point_values "$point_dir" prover 28 | stats)"
  sw_stats="$(point_values "$point_dir" verifier 28 | stats)"
  rw_stats="$(point_values "$point_dir" raw_agg 28 | stats)"
  mw_stats="$(point_values "$point_dir" mldsa_raw_agg 28 | stats)"
  md_stats="$(point_values "$point_dir" mldsa_raw_agg 38 | stats)"
  mv_stats="$(point_values "$point_dir" mldsa_raw_agg 20 | stats)"
  mt_stats="$(point_values "$point_dir" mldsa_raw_agg 44 | stats)"
  mb_stats="$(point_values "$point_dir" mldsa_raw_agg 26 | stats)"
  mr_stats="$(point_values "$point_dir" mldsa_raw_agg "$peak_column" | stats)"
  delta_stats="$(paired_values "$point_dir" delta | stats)"
  speed_stats="$(paired_values "$point_dir" speedup | stats)"
  be_stats="$(paired_values "$point_dir" break_even | stats)"
  nonpositive_deltas="$(paired_values "$point_dir" nonpositive | awk 'END{print NR+0}')"

  observations="$(awk '{print $1}' <<<"$prove_stats")"
  delta_count="$(awk '{print $1}' <<<"$delta_stats")"
  speed_count="$(awk '{print $1}' <<<"$speed_stats")"
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
  if [ "$delta_ci" = NA ]; then
    # Fewer than two paired runs: there is no interval, so no advantage can be
    # confirmed.
    delta_low=""; delta_high=""; advantage=0
  else
    delta_low="$(awk -v m="$delta_mean" -v c="$delta_ci" 'BEGIN{printf "%.6f",m-c}')"
    delta_high="$(awk -v m="$delta_mean" -v c="$delta_ci" 'BEGIN{printf "%.6f",m+c}')"
    advantage="$(awk -v lo="$delta_low" 'BEGIN{print(lo>0)?1:0}')"
  fi
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
  prover_rss_max="$(awk '{print $6}' <<<"$pr_stats")"
  snark_verifier_rss_max="$(awk '{print $6}' <<<"$sr_stats")"
  raw_verifier_rss_max="$(awk '{print $6}' <<<"$rr_stats")"
  mldsa_rss_max="$(awk '{print $6}' <<<"$mr_stats")"
  prover_work_rss="$(awk '{print $4}' <<<"$pw_stats")"
  snark_verifier_work_rss="$(awk '{print $4}' <<<"$sw_stats")"
  raw_verifier_work_rss="$(awk '{print $4}' <<<"$rw_stats")"
  mldsa_work_rss="$(awk '{print $4}' <<<"$mw_stats")"
  snark_decode="$(awk '{print $4}' <<<"$sd_stats")"
  snark_verify_only="$(awk '{print $4}' <<<"$so_stats")"
  raw_decode="$(awk '{print $4}' <<<"$rd_stats")"
  raw_verify_only="$(awk '{print $4}' <<<"$ro_stats")"

  # Every reported location must exist; a missing one would otherwise reach
  # the report as 0. Only the delta interval may be absent (fewer than two runs).
  for reported in "$prover_setup" "$prove" "$snark_verify" "$raw_verify" "$delta_mean" \
      "$speed" "$speed_q1" "$speed_q3" "$snark_bytes" "$raw_bytes" "$prover_rss" \
      "$snark_verifier_rss" "$raw_verifier_rss" "$mldsa_decode" "$mldsa_verify" \
      "$mldsa_total" "$mldsa_bytes" "$mldsa_rss" "$snark_decode" "$snark_verify_only" \
      "$raw_decode" "$raw_verify_only" "$prover_rss_max" "$snark_verifier_rss_max" \
      "$raw_verifier_rss_max" "$mldsa_rss_max" "$prover_work_rss" "$snark_verifier_work_rss" \
      "$raw_verifier_work_rss" "$mldsa_work_rss"; do
    if [ -z "$reported" ] || [ "$reported" = NA ]; then
      echo "missing measurement for $point_name; refusing to report it as zero" >&2
      exit 1
    fi
  done
  printf '%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$n" "$t" "$observations" "$prover_setup" "$prove" "$snark_verify" "$raw_verify" \
    "$delta_mean" "$delta_low" "$delta_high" "$advantage" "$speed" "$speed_q1" "$speed_q3" \
    "$snark_bytes" "$raw_bytes" "$wire_reduction" "$break_even" "$break_even_q1" "$break_even_q3" \
    "$prover_rss" "$snark_verifier_rss" "$raw_verifier_rss" "$point_dir" \
    "$mldsa_decode" "$mldsa_verify" "$mldsa_total" "$mldsa_bytes" "$mldsa_rss" \
    "$snark_decode" "$snark_verify_only" "$raw_decode" "$raw_verify_only" \
    "$peak_source" "$prover_rss_max" "$snark_verifier_rss_max" "$raw_verifier_rss_max" "$mldsa_rss_max" \
    "$prover_work_rss" "$snark_verifier_work_rss" "$raw_verifier_work_rss" "$mldsa_work_rss" \
    "$WORKLOAD_LIST" >> "$SCALING_CSV"
done
awk -F, '
  NR == 1 { expected = NF; next }
  NF != expected {
    printf "scaling.csv row %d has %d columns; expected %d\n", NR, NF, expected > "/dev/stderr"
    bad = 1
  }
  END { exit bad }
' "$SCALING_CSV"

# ---------------------------------------------------------------- costs ----
# What each role costs, on both clocks, for every completed point: one row per
# (point, role, quantity, clock, per-run statistic), summarized across runs.
#   quantity  per_update  one proof, or one decode + verify of one record
#             setup       the leanVM circuit, once per process (SNARK roles)
#             ready       everything a verifier does once per process before
#                         its first verification (contains setup)
#   clock     elapsed     how long the caller waits
#             cpu         user + system CPU over every thread of the process
#   per_run_statistic     median: each run contributes the median of its
#                         updates (the typical update); mean: each run
#                         contributes the mean of its updates (what a total or
#                         a budget is made of; a median hides the tail);
#                         value: one reading per process
# These are the inputs of any cost model a reader wants to apply; the report
# does not choose one.
echo 'n,t,list_entries,role,quantity,clock,per_run_statistic,unit,observations,min,q1,median,q3,max,mean,sd,cv_pct,mean_ci95_halfwidth' > "$COSTS_CSV"
ratio_values() { # point_dir target numerator_column denominator_column
  local file
  for file in "$1"/session-*/benchmark/runs.csv; do
    [ -f "$file" ] || continue
    awk -F, -v t="$2" -v a="$3" -v b="$4" 'NR>1 && $1==t && $a!="" && $b+0>0 { printf "%.6f\n", $a / $b }' "$file"
  done
}
cost_row() { # n t point_dir role quantity clock per_run_statistic  then the values on stdin
  local st count
  st="$(stats)"
  count="$(awk '{print $1}' <<<"$st")"
  if [ "$count" != "$((RUNS * SWEEP_REPEATS))" ]; then
    echo "costs.csv: $4 $5 $6 ($7) of N=$1 has ${count:-0} observations; expected $((RUNS * SWEEP_REPEATS))" >&2
    exit 1
  fi
  printf '%d,%d,%s,%s,%s,%s,%s,ms,%s\n' "$1" "$2" "$WORKLOAD_LIST" "$4" "$5" "$6" "$7" \
    "$(awk -v OFS=, '{ $1 = $1; for (i = 1; i <= NF; i++) if ($i == "NA") $i = ""; print }' <<<"$st")" >> "$COSTS_CSV"
}
# runs.csv columns: 4 setup, 7 n_items, 14/15 prove median/mean, 44/45
# decode+verify median/mean, 68/69 prove CPU median/total, 70/71 decode+verify
# CPU median/total, 72 setup CPU, 73/74 ready elapsed/CPU.
for n in "${SELECTED_SIZES[@]}"; do
  t="$(threshold_for "$n")"
  point_dir="$OUTDIR/N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
  [ "$(sed -n '1p' "$point_dir/status.txt" 2>/dev/null)" = complete ] || continue
  point_values "$point_dir" prover 14 | cost_row "$n" "$t" "$point_dir" prover per_update elapsed median
  point_values "$point_dir" prover 15 | cost_row "$n" "$t" "$point_dir" prover per_update elapsed mean
  point_values "$point_dir" prover 68 | cost_row "$n" "$t" "$point_dir" prover per_update cpu median
  ratio_values "$point_dir" prover 69 7 | cost_row "$n" "$t" "$point_dir" prover per_update cpu mean
  point_values "$point_dir" prover 4 | cost_row "$n" "$t" "$point_dir" prover setup elapsed value
  point_values "$point_dir" prover 72 | cost_row "$n" "$t" "$point_dir" prover setup cpu value
  for pair in verifier:snark_verifier raw_agg:xmss_raw_verifier mldsa_raw_agg:mldsa_raw_verifier; do
    target="${pair%%:*}"; role="${pair#*:}"
    point_values "$point_dir" "$target" 44 | cost_row "$n" "$t" "$point_dir" "$role" per_update elapsed median
    point_values "$point_dir" "$target" 45 | cost_row "$n" "$t" "$point_dir" "$role" per_update elapsed mean
    point_values "$point_dir" "$target" 70 | cost_row "$n" "$t" "$point_dir" "$role" per_update cpu median
    ratio_values "$point_dir" "$target" 71 7 | cost_row "$n" "$t" "$point_dir" "$role" per_update cpu mean
    point_values "$point_dir" "$target" 73 | cost_row "$n" "$t" "$point_dir" "$role" ready elapsed value
    point_values "$point_dir" "$target" 74 | cost_row "$n" "$t" "$point_dir" "$role" ready cpu value
  done
  point_values "$point_dir" verifier 4 | cost_row "$n" "$t" "$point_dir" snark_verifier setup elapsed value
  point_values "$point_dir" verifier 72 | cost_row "$n" "$t" "$point_dir" snark_verifier setup cpu value
done

# ---------------------------------------------------------- comparisons ----
# The three verifiers compared two at a time, on both clocks. Each run of
# verifier a is paired with the same-numbered run of verifier b in the same
# session (the same balanced row of benchmark.sh), and `delta = a - b` per
# pair, on the per-run medians of decode + verify.
#   sign  a_slower | b_slower when the 95% CI of the mean delta excludes zero,
#         not_confirmed when it contains zero, no_interval with one pair.
#   break_even_medians  only against the SNARK verifier: ceil(prove / delta)
#         per pair, prove on the same clock; reported under the same rule as
#         scaling.csv (CI wholly above zero, every pair with a positive delta).
#         It is a ratio of typical per-update costs on one clock. It leaves out
#         setup and ready costs, signing, network and storage, and it does not
#         say that more verifiers shorten any single request.
echo 'n,t,list_entries,a,b,clock,observations,a_median_ms,b_median_ms,delta_mean_ms,delta_ci95_low,delta_ci95_high,sign,ratio_median,ratio_q1,ratio_q3,nonpositive_pairs,prove_median_ms,break_even_medians,break_even_q1,break_even_q3' > "$COMPARISONS_CSV"
pair_values() { # point_dir a_target b_target column prove_column mode
  local file
  for file in "$1"/session-*/benchmark/runs.csv; do
    [ -f "$file" ] || continue
    awk -F, -v ta="$2" -v tb="$3" -v c="$4" -v pc="$5" -v mode="$6" '
      NR>1 && $1=="prover" { p[$2]=$pc }
      NR>1 && $1==ta { a[$2]=$c }
      NR>1 && $1==tb { b[$2]=$c }
      END { for (i in a) if ((i in b) && a[i] != "" && b[i] != "") {
        d = a[i] - b[i]
        if (mode == "delta") printf "%.6f\n", d
        else if (mode == "ratio" && b[i] > 0) printf "%.6f\n", a[i] / b[i]
        else if (mode == "nonpositive" && d <= 0) print 1
        else if (mode == "break_even" && d > 0 && p[i] != "") {
          x = p[i] / d; ceiling = int(x); if (ceiling < x) ceiling++
          print ceiling
        }
      }}' "$file"
  done
}
role_name() { case "$1" in verifier) echo snark ;; raw_agg) echo xmss_raw ;; mldsa_raw_agg) echo mldsa_raw ;; esac; }
for n in "${SELECTED_SIZES[@]}"; do
  t="$(threshold_for "$n")"
  point_dir="$OUTDIR/N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
  [ "$(sed -n '1p' "$point_dir/status.txt" 2>/dev/null)" = complete ] || continue
  for comparison in raw_agg:verifier mldsa_raw_agg:verifier raw_agg:mldsa_raw_agg; do
    ta="${comparison%%:*}"; tb="${comparison#*:}"
    for clock in elapsed cpu; do
      if [ "$clock" = elapsed ]; then column=44; prove_column=14; else column=70; prove_column=68; fi
      d_stats="$(pair_values "$point_dir" "$ta" "$tb" "$column" "$prove_column" delta | stats)"
      r_stats="$(pair_values "$point_dir" "$ta" "$tb" "$column" "$prove_column" ratio | stats)"
      pairs="$(awk '{print $1}' <<<"$d_stats")"
      if [ "$pairs" != "$((RUNS * SWEEP_REPEATS))" ]; then
        echo "comparisons.csv: $ta against $tb ($clock) of N=$n has ${pairs:-0} pairs; expected $((RUNS * SWEEP_REPEATS))" >&2
        exit 1
      fi
      nonpositive="$(pair_values "$point_dir" "$ta" "$tb" "$column" "$prove_column" nonpositive | awk 'END{print NR+0}')"
      d_mean="$(awk '{print $7}' <<<"$d_stats")"; d_ci="$(awk '{print $10}' <<<"$d_stats")"
      if [ "$d_ci" = NA ]; then
        d_low=""; d_high=""; sign=no_interval
      else
        d_low="$(awk -v m="$d_mean" -v c="$d_ci" 'BEGIN{printf "%.6f",m-c}')"
        d_high="$(awk -v m="$d_mean" -v c="$d_ci" 'BEGIN{printf "%.6f",m+c}')"
        sign="$(awk -v lo="$d_low" -v hi="$d_high" 'BEGIN{print (lo>0)?"a_slower":(hi<0)?"b_slower":"not_confirmed"}')"
      fi
      prove_median=""; be=""; be_q1=""; be_q3=""
      if [ "$tb" = verifier ]; then
        prove_median="$(point_values "$point_dir" prover "$prove_column" | stats | awk '{print $4}')"
        if [ "$sign" = a_slower ] && [ "$nonpositive" -eq 0 ]; then
          b_stats="$(pair_values "$point_dir" "$ta" "$tb" "$column" "$prove_column" break_even | stats)"
          be="$(awk '{print $4}' <<<"$b_stats")"; be_q1="$(awk '{print $3}' <<<"$b_stats")"; be_q3="$(awk '{print $5}' <<<"$b_stats")"
        fi
      fi
      printf '%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$n" "$t" "$WORKLOAD_LIST" \
        "$(role_name "$ta")" "$(role_name "$tb")" "$clock" "$pairs" \
        "$(point_values "$point_dir" "$ta" "$column" | stats | awk '{print $4}')" \
        "$(point_values "$point_dir" "$tb" "$column" | stats | awk '{print $4}')" \
        "$d_mean" "$d_low" "$d_high" "$sign" \
        "$(awk '{print $4}' <<<"$r_stats")" "$(awk '{print $3}' <<<"$r_stats")" "$(awk '{print $5}' <<<"$r_stats")" \
        "$nonpositive" "$prove_median" "$be" "$be_q1" "$be_q3" >> "$COMPARISONS_CSV"
    done
  done
done

# -------------------------------------------------------------- all runs ----
# Every measured run of every complete session in one file, with where it sat
# in the campaign: committee, list size, sweep, the sweep's direction and the
# point's position in it (plan.csv), then the session's own runs.csv row, whose
# t_start is the time the process started. An analysis that needs the time
# order, the sessions as blocks, or sweep-to-sweep differences starts here;
# scaling.csv keeps only the aggregate across sweeps.
{
  header=""
  for n in "${SELECTED_SIZES[@]}"; do
    t="$(threshold_for "$n")"
    point_dir="$OUTDIR/N$(printf '%04d' "$n")-t$(printf '%04d' "$t")"
    [ "$(sed -n '1p' "$point_dir/status.txt" 2>/dev/null)" = complete ] || continue
    for sweep in $(seq 1 "$SWEEP_REPEATS"); do
      file="$point_dir/session-$(printf '%02d' "$sweep")/benchmark/runs.csv"
      [ -f "$file" ] || continue
      if [ -z "$header" ]; then
        header="n,t,list_entries,sweep,sweep_direction,sweep_position,$(sed -n '1p' "$file")"
        echo "$header"
      fi
      place="$(awk -F, -v s="$sweep" -v n="$n" 'NR>1 && $1==s && $4==n { print $2 "," $3; exit }' "$PLAN_CSV")"
      awk -v prefix="$n,$t,$WORKLOAD_LIST,$sweep,${place:-,}" 'NR>1 { print prefix "," $0 }' "$file"
    done
  done
} > "$ALL_RUNS_CSV"

# Describe the design that actually ran; publication mode admits only the
# counterbalanced one, but a pilot may not be.
ascending=$(((SWEEP_REPEATS + 1) / 2)); descending=$((SWEEP_REPEATS / 2))
if [ "$ascending" -eq "$descending" ]; then
  SWEEP_DESIGN="$ascending ascending and $descending descending sweeps; N counterbalanced against experiment time"
else
  SWEEP_DESIGN="$ascending ascending and $descending descending sweep(s); NOT counterbalanced, N is confounded with experiment time"
fi
if [ "$INTERLEAVE" = 1 ] && [ $((RUNS % 4)) -eq 0 ]; then
  ROLE_ORDER="Williams-balanced within each session, complete four-target designs"
elif [ "$INTERLEAVE" = 1 ]; then
  ROLE_ORDER="Williams order within each session, but RUNS=$RUNS is not a multiple of 4; only partly balanced"
else
  ROLE_ORDER="contiguous blocks per role (INTERLEAVE=0); NOT balanced, roles are confounded with time"
fi

{
  echo "COMMITTEE SCALING REPORT"
  echo "generated : $(date -Is)"
  echo "host      : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "mode      : $STUDY_MODE"
  echo "policy    : t=floor(2N/3)+1 (strict two-thirds supermajority)"
  echo "workload  : every row below is (N, t, $WORKLOAD_L): status list $WORKLOAD_DESC;"
  echo "            $BENCH_UPDATES versions per process; fixture quorums are t distinct members spread over"
  echo "            the whole committee (spread-splitmix64-v1). N and t move together under the"
  echo "            policy, so this sweep does not separate the effect of N from that of t."
  echo "runs      : $RUNS measured + $WARMUP warmup per target, across $SWEEP_REPEATS complete sweep(s)"
  echo "design    : $SWEEP_DESIGN"
  echo "order     : $ROLE_ORDER (plan.csv, schedule.csv and each session's schedule.csv record it)"
  echo "cooldown  : $COOLDOWN_SECONDS seconds before every measured process"
  echo "roles     : two single-member signers; per point, one aggregator and three relying-party verifiers"
  echo "RAM plan  : ${AVAILABLE_MB} MiB initially available; ${MEMORY_LIMIT_MB} MiB process cap; selected N<=${MAX_SELECTED_N}"
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
    echo "  XMSS slot-journal storage: $SIGNER_STORAGE"
    case "$SIGNER_STORAGE" in class=ram\ *)
      echo "  WARNING: RAM-backed storage; the protocol-sign and slot-burn figures below"
      echo "           do not describe durable signing on a device" ;;
    esac
    printf "  XMSS keygen (one key)    : %.2f ms\n" "$signer_keygen"
    printf "  XMSS durable slot state  : %.2f ms\n" "$signer_slot_state"
    printf "  XMSS protocol sign       : %.2f ms (median of %s run medians)\n" "$signer_sign" "$signer_n"
    printf "    durable slot burn      : %.2f ms; cryptographic sign %.2f ms\n" "$signer_burn" "$signer_crypto"
    printf "  XMSS signature size      : %.0f bytes; peak RSS %.1f MiB\n" "$signer_bytes" "$signer_rss"
    printf "  ML-DSA keygen (one key)  : %.2f ms\n" "$mldsa_keygen"
    printf "  ML-DSA crypto sign only  : %.2f ms (median of %s run medians)\n" "$mldsa_sign" "$mldsa_n"
    printf "  ML-DSA signature size    : %.0f bytes; peak RSS %.1f MiB\n" "$mldsa_bytes" "$mldsa_signer_rss"
    echo "  XMSS protocol cost includes durable burn; ML-DSA has no"
    echo "  one-statement-per-version state and is NOT a comparable protocol cost"
    echo "  both per-member measurements are independent of N and t"
    echo "  N=5,t=4 is only this invocation's compilation anchor; neither signer uses it"
  else
    echo "  unavailable: see signer/status.txt and signer/benchmark.log"
  fi
  echo
  printf '%6s %6s %5s %11s %11s %11s %9s %12s %12s %10s %11s\n' \
    N t obs prove_ms snark_e2e raw_e2e speedup snark_bytes raw_bytes confirmed be_elapsed
  if [ -s "$SCALING_CSV" ]; then
    awk -F, 'NR>1 {printf "%6d %6d %5d %11.2f %11.2f %11.2f %8.4fx %12.0f %12.0f %10s %11s\n",$1,$2,$3,$5,$6,$7,$12,$15,$16,($11==1?"yes":"no"),($18==""?"-":sprintf("%.1f",$18))}' "$SCALING_CSV"
  fi
  echo
  echo "RAW VERIFIER PHASES — E2E IS ONE CONTIGUOUS DECODE + VERIFY TIMER"
  printf '%6s %6s %10s %10s %10s %10s %10s %10s %12s %12s\n' \
    N t xmss_dec xmss_ver xmss_e2e mldsa_dec mldsa_ver mldsa_e2e xmss_bytes mldsa_bytes
  if [ -s "$SCALING_CSV" ]; then
    awk -F, 'NR>1 {printf "%6d %6d %10.2f %10.2f %10.2f %10.2f %10.2f %10.2f %12.0f %12.0f\n",$1,$2,$32,$33,$7,$25,$26,$27,$16,$28}' "$SCALING_CSV"
  fi
  echo
  # Lookups into the tidy files written above.
  cost() { # n role quantity clock per_run_statistic  -> median across runs, or -
    awk -F, -v n="$1" -v r="$2" -v q="$3" -v c="$4" -v s="$5" '
      NR>1 && $1==n && $4==r && $5==q && $6==c && $7==s { printf "%.2f", $12; found=1; exit }
      END { if (!found) printf "-" }' "$COSTS_CSV"
  }
  completed_sizes="$(awk -F, 'NR>1 {print $1}' "$SCALING_CSV" 2>/dev/null || true)"
  echo "ELAPSED AND CPU PER UPDATE, ms — median across runs of the per-run median"
  echo "  elapsed = how long the caller waits; cpu = user + system over every thread."
  echo "  One proof for the prover; one decode + verify of one record for a verifier."
  printf '%6s %6s | %10s %10s | %10s %10s | %10s %10s | %10s %10s\n' \
    N t prove cpu snark_e2e cpu xmss_e2e cpu mldsa_e2e cpu
  for n in $completed_sizes; do
    printf '%6d %6d | %10s %10s | %10s %10s | %10s %10s | %10s %10s\n' "$n" "$(threshold_for "$n")" \
      "$(cost "$n" prover per_update elapsed median)" "$(cost "$n" prover per_update cpu median)" \
      "$(cost "$n" snark_verifier per_update elapsed median)" "$(cost "$n" snark_verifier per_update cpu median)" \
      "$(cost "$n" xmss_raw_verifier per_update elapsed median)" "$(cost "$n" xmss_raw_verifier per_update cpu median)" \
      "$(cost "$n" mldsa_raw_verifier per_update elapsed median)" "$(cost "$n" mldsa_raw_verifier per_update cpu median)"
  done
  echo "  costs.csv also has the mean per update (what a total is made of; a median"
  echo "  hides the tail) with quartiles and the 95% CI of the mean, for every cell."
  echo
  echo "ONCE PER PROCESS, ms — elapsed / cpu, median across runs"
  echo "  setup = the leanVM circuit. ready = everything a verifier does before its first"
  echo "  verification: read and decode the anchor, build the verifier, and setup where"
  echo "  there is one. A resident verifier pays ready once; a verifier started for one"
  echo "  request pays ready plus one decode + verify every time."
  printf '%6s %6s | %22s | %22s %22s | %18s | %18s\n' \
    N t prover_setup snark_ready of_which_setup xmss_ready mldsa_ready
  for n in $completed_sizes; do
    printf '%6d %6d | %22s | %22s %22s | %18s | %18s\n' "$n" "$(threshold_for "$n")" \
      "$(cost "$n" prover setup elapsed value) / $(cost "$n" prover setup cpu value)" \
      "$(cost "$n" snark_verifier ready elapsed value) / $(cost "$n" snark_verifier ready cpu value)" \
      "$(cost "$n" snark_verifier setup elapsed value) / $(cost "$n" snark_verifier setup cpu value)" \
      "$(cost "$n" xmss_raw_verifier ready elapsed value) / $(cost "$n" xmss_raw_verifier ready cpu value)" \
      "$(cost "$n" mldsa_raw_verifier ready elapsed value) / $(cost "$n" mldsa_raw_verifier ready cpu value)"
  done
  echo
  echo "PAIRED COMPARISONS OF THE THREE VERIFIERS (comparisons.csv)"
  echo "  delta = a - b on the per-run medians of decode + verify, paired run by run;"
  echo "  mean and 95% CI of the mean in ms. sign: which one is slower when the CI"
  echo "  excludes zero. be = descriptive break-even against the SNARK verifier, see below."
  printf '%6s %6s %-22s %-8s %12s %26s %-14s %9s %8s\n' N t 'a - b' clock delta_mean 'ci95' sign ratio be
  awk -F, 'NR>1 {
    ci = ($11 == "" ? "n/a" : sprintf("[%.3f, %.3f]", $11, $12))
    printf "%6d %6d %-22s %-8s %12.3f %26s %-14s %8.4fx %8s\n", $1, $2, $4 " - " $5, $6, $10, ci, $13, $14, ($19 == "" ? "-" : sprintf("%.0f", $19))
  }' "$COMPARISONS_CSV"
  echo
  echo "PROCESS RSS IN MiB — typical peak / largest peak / during honest updates"
  printf '%6s %6s %7s %22s %22s %22s %22s\n' N t source prover snark_verifier xmss_raw_verifier mldsa_raw_verifier
  if [ -s "$SCALING_CSV" ]; then
    awk -F, 'NR>1 {
      printf "%6d %6d %7s %22s %22s %22s %22s\n", $1, $2, $34,
        sprintf("%.1f/%.1f/%.0f", $21, $35, $39), sprintf("%.1f/%.1f/%.0f", $22, $36, $40),
        sprintf("%.1f/%.1f/%.0f", $23, $37, $41), sprintf("%.1f/%.1f/%.0f", $29, $38, $42)
    }' "$SCALING_CSV"
  fi
  echo "  source: kernel = ru_maxrss from time -v; vmhwm = the process's own VmHWM,"
  echo "  whole MiB, used for a point when a kernel reading is missing."
  echo "  A peak covers the whole process: setup, the measured updates and, for the"
  echo "  verifiers, the negative controls run after them. The third figure is the"
  echo "  largest RSS sampled after each honest update. These are medians and maxima"
  echo "  of observed process peaks on this host, not bounds for sizing a machine."
  echo
  size_cross="$(awk -F, 'NR>1 && $16+0>$15+0 {print $1; exit}' "$SCALING_CSV")"
  verify_cross="$(awk -F, 'NR>1 && $11==1 {print $1; exit}' "$SCALING_CSV")"
  joint_cross="$(awk -F, 'NR>1 && $16+0>$15+0 && $11==1 {print $1; exit}' "$SCALING_CSV")"
  first_point() { # a b clock -> first completed N at which a is confirmed slower than b
    awk -F, -v a="$1" -v b="$2" -v c="$3" 'NR>1 && $4==a && $5==b && $6==c && $13=="a_slower" {print $1; exit}' "$COMPARISONS_CSV"
  }
  echo "FIRST OBSERVED POINTS, AMONG THE COMMITTEE SIZES THIS CAMPAIGN COMPLETED"
  echo "  SnarkStatusList smaller than the raw XMSS record        : ${size_cross:-not observed}"
  echo "  SNARK verify faster than raw XMSS, elapsed (CI above 0) : ${verify_cross:-not observed}"
  echo "  SNARK verify cheaper than raw XMSS, CPU (CI above 0)    : $(v="$(first_point xmss_raw snark cpu)"; echo "${v:-not observed}")"
  echo "  SNARK verify faster than raw ML-DSA, elapsed            : $(v="$(first_point mldsa_raw snark elapsed)"; echo "${v:-not observed}")"
  echo "  SNARK verify cheaper than raw ML-DSA, CPU               : $(v="$(first_point mldsa_raw snark cpu)"; echo "${v:-not observed}")"
  echo "  both: smaller record and faster elapsed verify than XMSS: ${joint_cross:-not observed}"
  if awk -F, 'NR>1 && $9=="" {found=1} END{exit !found}' "$SCALING_CSV"; then
    echo "  (some points have fewer than two paired runs: no interval, nothing confirmed)"
  fi
  echo "  A first observed point is the smallest N of this grid at which the condition"
  echo "  held, for this list size, host and session. It is not the exact N at which"
  echo "  the regime changes (the grid is coarse), not a statement about every larger"
  echo "  N, and not about points this campaign did not complete. Each line is one of"
  echo "  several comparisons read off the same grid, each with its own 95% interval:"
  echo "  the intervals are not simultaneous. Confirm a candidate with an independent"
  echo "  campaign around it before relying on it."
  echo
  echo "be_elapsed (scaling.csv: break_even_elapsed_*) and be in the comparison table"
  echo "are one descriptive ratio, per paired run:"
  echo "  ceil(prove / (raw decode+verify - SNARK decode+verify)), all on one clock,"
  echo "from per-run medians. Read it as: with typical per-update costs on that clock,"
  echo "this many verifications of one record cost as much as the proof saved. It is"
  echo "reported only when the paired 95% CI of the difference is wholly above zero and"
  echo "every paired run had a positive difference. What it is not:"
  echo "  - not a cost: elapsed milliseconds of processes with different parallelism"
  echo "    do not add up to CPU, energy or money (compare the two clocks above);"
  echo "  - not a budget: it uses medians, and totals are made of means (costs.csv);"
  echo "  - not an interval: its Q1/Q3 are the spread of the ratio across runs;"
  echo "  - not end-to-end: it leaves out setup and ready costs, signing, network and"
  echo "    storage, and more verifiers do not make one request faster, since the"
  echo "    proof must exist before anyone verifies it."
  echo "The quantities for a fuller model are in costs.csv: P (prover per_update), R and"
  echo "S (verifier per_update), Sp (prover setup), Sv (snark_verifier ready), each on"
  echo "both clocks. With U updates per prover process, K verifications per verifier"
  echo "process and M verifications per update, the SNARK form costs less when"
  echo "  P + Sp/U + M x (S + Sv/K) < M x R,"
  echo "all in one unit. This report does not choose U, K, M or the unit."
  echo "The paired CIs treat repeated runs as independent within this host and"
  echo "session, one comparison at a time; they do not establish an effect across"
  echo "days or machines. tools/analyze_scaling.py reads all-runs.csv (every run with"
  echo "its sweep, position and start time) and reports the session effect, the drift"
  echo "inside sessions, intervals with sessions as blocks and as the unit, and"
  echo "simultaneous intervals for the whole family. No timing samples are discarded."
  echo
  echo "MEMORY PRESSURE DURING THE CAMPAIGN (pressure.csv; runs.csv has it per run)"
  if [ -s "$PRESSURE_CSV" ]; then
    awk -F, 'NR > 1 {
      stages++
      if ($3 == "" || $4 == "") unknown++
      if ($3 + $4 > 0 || $6 + 0 > 0) { hit++; printf "  %s: %d pages swapped, %d OOM kill(s)\n", $2, $3 + $4, $6 }
    }
    END {
      if (!hit && unknown == stages) print "  swap counters unavailable on this kernel; not checked"
      else if (!hit) printf "  none: no paging and no OOM kill in %d guarded stage(s)\n", stages
      else print "  timings of the stages above include paging and are not comparable with the rest"
    }' "$PRESSURE_CSV"
  else
    echo "  no stage recorded"
  fi
  echo
  echo "RESOURCE OUTCOME"
  awk -F, 'NR>1 {printf "  N=%-4s t=%-4s %-22s %s\n", $1, $2, $4, $5}' "$MANIFEST"
  echo
  echo "See each point's session-XX/benchmark/summary.txt and drift.csv artifacts."
  echo "The scaling table aggregates per-run medians across complete sweeps; it does"
  echo "not pool within-run observations or extrapolate unmeasured committee sizes."
  echo "Sweep design: $SWEEP_DESIGN."
} | tee "$REPORT"

echo
echo "written:"
echo "  $DECISION_FILE"
echo "  $SIGNER_CSV"
echo "  $MANIFEST"
echo "  $SCALING_CSV"
echo "  $COSTS_CSV"
echo "  $COMPARISONS_CSV"
echo "  $ALL_RUNS_CSV"
echo "  $REPORT"

trap - INT TERM EXIT
exit "$OVERALL_STATUS"
