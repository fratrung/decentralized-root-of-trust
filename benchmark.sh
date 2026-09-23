#!/usr/bin/env bash
# Reproducible benchmark of the committee status list, split-deployment aware.
#
# The deployment has three ROLES, and each is measured on the process that would
# actually run it. No target is ever charged for another role's work:
#   signer    ONE committee member, one signature + one durable slot burn per
#             round                                 (src/bin/signer.rs)
#   mldsa_signer
#             ONE ML-DSA member, one randomized stateless signature per round
#                                                   (mldsa/src/bin/mldsa_signer.rs)
#   prover    the aggregator: N updates, prove only (src/bin/prover.rs)
#   verifier  a relying party: verifies a FIXED artifact corpus
#                                                   (src/bin/verifier.rs)
# plus the raw alternatives:
#   mldsa_raw_agg
#             decode + verify an ML-DSA StatusList (mldsa/src/bin/mldsa_raw_agg.rs)
#   raw_agg   crude multisig, NO SNARK              (src/bin/raw_agg.rs)
#             verify scales with t, unlike the constant-time SNARK verify, and
#             record_size is the complete StatusList on the wire
#
# `combined` (src/main.rs, the single-process demo) is NOT in the defaults. It
# measures a process that proves and verifies at once, which is not a role anyone
# deploys. It stays available as `TARGETS="... combined"` when an independent
# second reading of prove time is wanted — that is what it is for.
#
# Only the two signer targets report a `sign` row. In production nobody produces
# t signatures: each member signs ONCE per round on its own machine and broadcasts,
# and the aggregator receives t signatures and produces none. A `sign`
# figure taken from a process that signs t times is the summed work of t machines
# billed to one, and describes no process that exists. By default a separate,
# unmeasured fixture process creates the signed inputs once; the measured prover
# is then strictly one aggregator with no secret keys and raw_agg is strictly one
# relying-party verifier. BENCH_SELF_CONTAINED=1 retains the older all-in-one
# process shape for diagnostic back-comparison.
#
# Produces, in $OUTDIR:
#   env.txt      full environment capture (reproducibility appendix)
#   samples.csv  tidy raw data, one row per individual update/verification
#   runs.csv     one row per process run
#   summary.csv  aggregate statistics, machine-readable
#   summary.txt  the same table, human-readable
#   drift.csv    early/late regime diagnostic; observations are never removed
#   source.patch / source-status.txt  tracked diff and dirty paths; untracked contents omitted
#
# The unit of analysis for per-update metrics is the PER-RUN MEDIAN (n = RUNS),
# not the pooled sample: updates within one process share allocator and cache
# state and are not independent. samples.csv keeps every raw observation so the
# pooled distribution can be re-analysed if that is what you want to report.
#
# Targets use a balanced Williams-style order by default and cool down before
# each process. Odd designs use rotations plus reversals; warm-ups are scheduled
# separately from measured runs. Across a complete design, each target occupies
# each position and precedes every other target equally often. runs.csv records
# time, load, frequency and temperature so residual drift can be inspected.
#
#   ./benchmark.sh
#   RUNS=30 WARMUP=3 ./benchmark.sh
#   TARGETS="prover verifier" RUNS=50 ./benchmark.sh
#   STRICT_ENV=1 PIN_CPUS=0-7 RUNS=30 ./benchmark.sh   # publication settings
#   INTERLEAVE=0 ./benchmark.sh           # old block order, for back-comparison
#
# Everything this script prints is MEASURED on the host it ran on. It does not
# extrapolate to other hardware, and it should not be made to: `target-cpu=native`
# already makes the binaries host-specific, so the way to get numbers for another
# machine is to run this script there.
set -euo pipefail

# Every number here passes through `sort -g` and awk. Both honour LC_NUMERIC, and
# in a comma-decimal locale `sort -g` truncates "5.10" at the separator: the
# series silently mis-sorts, and since stats() reads min, max and every quantile
# off the sorted array, the whole summary is quietly wrong with no error. Pin C.
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO="$PWD"

RUNS="${RUNS:-24}"
WARMUP="${WARMUP:-2}"
TARGETS="${TARGETS:-signer mldsa_signer prover verifier raw_agg mldsa_raw_agg}"
OUTDIR="${OUTDIR:-bench-$(date +%Y%m%d-%H%M%S)}"
BENCH_INPUT_DIR="${BENCH_INPUT_DIR:-}"
MLDSA_INPUT_DIR="${MLDSA_INPUT_DIR:-}"
BENCH_SELF_CONTAINED="${BENCH_SELF_CONTAINED:-0}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-2}"

# Scaling sweeps override the compile-time demo parameters without editing the
# source tree. Both values must travel together: changing only N or only t would
# benchmark a policy the caller did not ask for. Cargo tracks option_env! and
# recompiles this crate (not the pinned leanVM tree) when either value changes.
DEFAULT_N="$(sed -n 's/^pub const DEFAULT_N_MEMBERS: usize = \([0-9][0-9]*\).*/\1/p' src/params.rs)"
DEFAULT_T="$(sed -n 's/^pub const DEFAULT_T: usize = \([0-9][0-9]*\).*/\1/p' src/params.rs)"
BENCH_UPDATES="$(sed -n 's/^pub const N_UPDATES: usize = \([0-9][0-9]*\).*/\1/p' src/params.rs)"
if { [ -n "${DROT_BENCH_N:-}" ] && [ -z "${DROT_BENCH_T:-}" ]; } ||
   { [ -z "${DROT_BENCH_N:-}" ] && [ -n "${DROT_BENCH_T:-}" ]; }; then
  echo "DROT_BENCH_N and DROT_BENCH_T must be set together" >&2
  exit 1
fi
BENCH_N="${DROT_BENCH_N:-$DEFAULT_N}"
BENCH_T="${DROT_BENCH_T:-$DEFAULT_T}"
case "$BENCH_N" in ''|*[!0-9]*) echo "benchmark N must be a decimal integer" >&2; exit 1 ;; esac
case "$BENCH_T" in ''|*[!0-9]*) echo "benchmark t must be a decimal integer" >&2; exit 1 ;; esac
if [ "$BENCH_N" -lt 1 ] || [ "$BENCH_T" -lt 1 ] || [ "$BENCH_T" -gt "$BENCH_N" ]; then
  echo "invalid committee parameters: require N >= t >= 1, got N=$BENCH_N t=$BENCH_T" >&2
  exit 1
fi
if [ "$BENCH_N" -gt 2048 ]; then
  echo "invalid committee size: N=$BENCH_N exceeds MAX_COMMITTEE_SIZE=2048" >&2
  exit 1
fi
if [ -n "$BENCH_INPUT_DIR" ] && [ ! -d "$BENCH_INPUT_DIR" ]; then
  echo "BENCH_INPUT_DIR is not a directory: $BENCH_INPUT_DIR" >&2
  exit 1
fi
if [ -n "$MLDSA_INPUT_DIR" ] && [ ! -d "$MLDSA_INPUT_DIR" ]; then
  echo "MLDSA_INPUT_DIR is not a directory: $MLDSA_INPUT_DIR" >&2
  exit 1
fi

case "$RUNS" in ''|*[!0-9]*|0) echo "RUNS must be a positive integer" >&2; exit 1 ;; esac
case "$WARMUP" in ''|*[!0-9]*) echo "WARMUP must be a non-negative integer" >&2; exit 1 ;; esac
case "$COOLDOWN_SECONDS" in ''|*[!0-9]*) echo "COOLDOWN_SECONDS must be a non-negative integer" >&2; exit 1 ;; esac
case "$BENCH_SELF_CONTAINED" in 0|1) ;; *) echo "BENCH_SELF_CONTAINED must be 0 or 1" >&2; exit 1 ;; esac
if [ "$BENCH_SELF_CONTAINED" = 1 ] && [ -n "$BENCH_INPUT_DIR" ]; then
  echo "BENCH_SELF_CONTAINED=1 conflicts with BENCH_INPUT_DIR" >&2
  exit 1
fi

# Run targets in balanced blocks instead of target-sized contiguous blocks.
#
# Blocks confound target identity with time: a thermal ramp or a background job
# that lands during the prover block is indistinguishable, in the data, from the
# prover being slow. Interleaving spreads any time-varying disturbance across all
# targets, so it inflates variance instead of biasing one mean. Set 0 to restore
# block order (only useful when comparing against an older block-ordered run).
INTERLEAVE="${INTERLEAVE:-1}"
case "$INTERLEAVE" in 0|1) ;; *) echo "INTERLEAVE must be 0 or 1" >&2; exit 1 ;; esac

# Refuse to measure unless the governor is 'performance'. Off by default because
# it needs root to fix, on for anything whose numbers get published.
STRICT_ENV="${STRICT_ENV:-0}"
case "$STRICT_ENV" in 0|1) ;; *) echo "STRICT_ENV must be 0 or 1" >&2; exit 1 ;; esac
REQUIRE_CLEAN_TREE="${REQUIRE_CLEAN_TREE:-$STRICT_ENV}"
case "$REQUIRE_CLEAN_TREE" in 0|1) ;; *) echo "REQUIRE_CLEAN_TREE must be 0 or 1" >&2; exit 1 ;; esac

# Optional CPU pinning, e.g. PIN_CPUS=0-7. leanVM's pool is sized from the
# affinity mask at startup, so this also fixes the thread count — pin and record
# it if you intend to compare across machines.
PIN_CPUS="${PIN_CPUS:-}"

read -r -a TARGET_LIST <<<"$TARGETS"
[ "${#TARGET_LIST[@]}" -gt 0 ] || { echo "TARGETS must not be empty" >&2; exit 1; }
declare -A SEEN_TARGETS=()
NEED_ROOT=0
NEED_MLDSA=0
for target in "${TARGET_LIST[@]}"; do
  case "$target" in
    signer|prover|verifier|raw_agg|combined) NEED_ROOT=1 ;;
    mldsa_signer|mldsa_raw_agg) NEED_MLDSA=1 ;;
    *) echo "unknown target: $target" >&2; exit 1 ;;
  esac
  [ -z "${SEEN_TARGETS[$target]:-}" ] || { echo "duplicate target: $target" >&2; exit 1; }
  SEEN_TARGETS[$target]=1
done

if [ -n "$PIN_CPUS" ]; then
  taskset -c "$PIN_CPUS" true >/dev/null 2>&1 || { echo "invalid/unavailable PIN_CPUS=$PIN_CPUS" >&2; exit 1; }
  EFFECTIVE_THREADS="$(taskset -c "$PIN_CPUS" nproc)"
  TARGET_AFFINITY="$(taskset -c "$PIN_CPUS" sh -c "sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status")"
else
  EFFECTIVE_THREADS="$(nproc)"
  TARGET_AFFINITY="$(taskset -cp $$ 2>/dev/null | sed 's/.*: //' || echo n/a)"
fi

TIME_BIN=""
[ -x /usr/bin/time ] && TIME_BIN=/usr/bin/time

TARGET_CPU_IDS="$(awk -v list="$TARGET_AFFINITY" 'BEGIN {
  count=split(list, parts, ",")
  for (i=1; i<=count; i++) {
    if (index(parts[i], "-")) {
      split(parts[i], bounds, "-")
      for (cpu=bounds[1]; cpu<=bounds[2]; cpu++) print cpu
    } else if (parts[i] ~ /^[0-9]+$/) {
      print parts[i]
    }
  }
}')"
GOVERNORS="$({
  for cpu in $TARGET_CPU_IDS; do
    path="/sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor"
    [ -r "$path" ] && cat "$path"
  done
} | sort -u | paste -sd, -)"
[ -n "$GOVERNORS" ] || GOVERNORS=n/a

GIT_DIRTY=no
[ -n "$(git status --porcelain 2>/dev/null)" ] && GIT_DIRTY=yes

# Publication mode is a preflight, not a warning printed after an expensive
# build. A dirty tree cannot be reconstructed from the commit recorded in the
# report, so strict runs refuse it unless the caller explicitly separates the
# exploratory policy with REQUIRE_CLEAN_TREE=0.
if [ "$STRICT_ENV" = 1 ]; then
  fatal=0
  [ "$GOVERNORS" = performance ] || { echo "STRICT: every target CPU governor must be 'performance', got '$GOVERNORS'" >&2; fatal=1; }
  [ -n "$TIME_BIN" ]             || { echo "STRICT: /usr/bin/time -v required for the RSS cross-check" >&2; fatal=1; }
  [ -f Cargo.lock ]               || { echo "STRICT: Cargo.lock required for a reproducible dependency set" >&2; fatal=1; }
  if [ "$NEED_MLDSA" = 1 ]; then
    [ -f mldsa/Cargo.lock ] || { echo "STRICT: mldsa/Cargo.lock required for reproducible ML-DSA binaries" >&2; fatal=1; }
  fi
  [ "$REQUIRE_CLEAN_TREE" = 0 ] || [ "$GIT_DIRTY" = no ] || {
    echo "STRICT: the Git working tree is dirty; commit the benchmark candidate first" >&2
    fatal=1
  }
  [ "$fatal" = 0 ] || { echo "refusing to produce publishable numbers on this configuration" >&2; exit 1; }
fi

BIN_DIR="$REPO/target/release"
MLDSA_BIN_DIR="$REPO/mldsa/target/release"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

mkdir -p "$OUTDIR"
ENV_FILE="$OUTDIR/env.txt"
SAMPLES="$OUTDIR/samples.csv"
RUNS_CSV="$OUTDIR/runs.csv"
SUMMARY_CSV="$OUTDIR/summary.csv"
SUMMARY_TXT="$OUTDIR/summary.txt"
DRIFT_CSV="$OUTDIR/drift.csv"
SOURCE_STATUS="$OUTDIR/source-status.txt"
SOURCE_PATCH="$OUTDIR/source.patch"

git status --porcelain=v1 > "$SOURCE_STATUS" 2>/dev/null || true
git diff --binary HEAD > "$SOURCE_PATCH" 2>/dev/null || true
SOURCE_PATCH_SHA256="$(sha256sum "$SOURCE_PATCH" 2>/dev/null | awk '{print $1}')"
[ -n "$SOURCE_PATCH_SHA256" ] || SOURCE_PATCH_SHA256=n/a

# ---------------------------------------------------------------- build ----
echo "building --release ..."
if [ "$NEED_ROOT" = 1 ]; then
  cargo build --release --locked >/dev/null 2>&1
  for b in signer prover verifier decentralized-root-of-trust raw_agg committee_fixture; do
    [ -x "$BIN_DIR/$b" ] || { echo "missing binary: $BIN_DIR/$b"; exit 1; }
  done
fi
if [ "$NEED_MLDSA" = 1 ]; then
  cargo build --manifest-path mldsa/Cargo.toml --release --locked >/dev/null 2>&1
  for b in mldsa_signer mldsa_raw_agg mldsa_fixture; do
    [ -x "$MLDSA_BIN_DIR/$b" ] || { echo "missing binary: $MLDSA_BIN_DIR/$b"; exit 1; }
  done
fi

AUTO_FIXTURE=0
if [ "$BENCH_SELF_CONTAINED" = 0 ] && [ -z "$BENCH_INPUT_DIR" ]; then
  for target in "${TARGET_LIST[@]}"; do
    case "$target" in prover|verifier|raw_agg)
      BENCH_INPUT_DIR="$SCRATCH/committee-fixture"
      AUTO_FIXTURE=1
      export BENCH_INPUT_DIR
      break
      ;;
    esac
  done
fi
AUTO_MLDSA_FIXTURE=0
if [ -n "${SEEN_TARGETS[mldsa_raw_agg]:-}" ] && [ -z "$MLDSA_INPUT_DIR" ]; then
  MLDSA_INPUT_DIR="$SCRATCH/mldsa-fixture"
  AUTO_MLDSA_FIXTURE=1
fi

if [ -n "$BENCH_INPUT_DIR" ]; then
  INPUT_MODE=fixture
elif [ "$BENCH_SELF_CONTAINED" = 1 ]; then
  INPUT_MODE=self-contained
else
  INPUT_MODE=target-native
fi
if [ -n "$MLDSA_INPUT_DIR" ]; then
  MLDSA_INPUT_MODE=fixture
else
  MLDSA_INPUT_MODE=not-selected
fi

# ------------------------------------------------------ environment ----
sysread() { [ -r "$1" ] && cat "$1" 2>/dev/null || echo "n/a"; }

load1_now() {
  awk '{print $1}' /proc/loadavg 2>/dev/null || echo ""
}

freq_now_mhz() {
  local cpu path values=""
  for cpu in $TARGET_CPU_IDS; do
    path="/sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_cur_freq"
    [ -r "$path" ] && values="$values $(cat "$path" 2>/dev/null)"
  done
  awk 'BEGIN{n=0;s=0} {for(i=1;i<=NF;i++){s+=$i;n++}} END{if(n) printf "%.1f", s/n/1000}' <<<"$values"
}

temp_now_c() {
  local path values=""
  for path in /sys/class/thermal/thermal_zone*/temp /sys/class/hwmon/hwmon*/temp*_input; do
    [ -r "$path" ] && values="$values $(cat "$path" 2>/dev/null)"
  done
  awk 'BEGIN{m=""} {for(i=1;i<=NF;i++){v=$i+0;if(v>1000)v/=1000;if(m==""||v>m)m=v}} END{if(m!="") printf "%.1f",m}' <<<"$values"
}

{
  echo "# Environment capture — benchmark of $(basename "$REPO")"
  echo "timestamp        : $(date -Is)"
  echo "host             : $(hostname)"
  echo "kernel           : $(uname -srmo)"
  echo
  echo "## CPU"
  echo "model            : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "arch             : $(uname -m)"
  echo "system CPUs      : $(nproc --all)"
  echo "harness CPUs     : $(nproc)"
  echo "target governors : $GOVERNORS"
  echo "scaling driver   : $(sysread /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver)"
  echo "boost            : $(sysread /sys/devices/system/cpu/cpufreq/boost)"
  echo "intel no_turbo   : $(sysread /sys/devices/system/cpu/intel_pstate/no_turbo)"
  echo "SMT active       : $(sysread /sys/devices/system/cpu/smt/active)"
  # leanVM sizes its worker pool from std::thread::available_parallelism(), cached
  # in a OnceLock, with no environment override. So the thread count is whatever
  # the CPU affinity mask allows at startup — a first-class independent variable
  # that nothing else in this file would otherwise record.
  echo "harness affinity : $(taskset -cp $$ 2>/dev/null | sed 's/.*: //' || echo 'n/a')"
  echo "target affinity  : $TARGET_AFFINITY"
  echo "effective threads: $EFFECTIVE_THREADS  <- leanVM worker pool size"
  echo "pinned to        : ${PIN_CPUS:-<not pinned>}"
  echo
  echo "## Memory"
  free -h 2>/dev/null | sed 's/^/  /'
  echo "swappiness       : $(sysread /proc/sys/vm/swappiness)"
  echo "THP enabled      : $(sysread /sys/kernel/mm/transparent_hugepage/enabled)"
  echo "  (relevant: leanVM's arena calls madvise(MADV_NOHUGEPAGE))"
  echo "ASLR             : $(sysread /proc/sys/kernel/randomize_va_space)"
  echo "stack ulimit     : $(ulimit -s)"
  echo
  echo "## Storage"
  # `signer` waits for one sync_data durability barrier per reserved slot INSIDE
  # its timed region, so its sign figure is a property of this filesystem as much
  # as of the scheme. A near-full filesystem allocates differently; record the
  # fill level too.
  echo "TMPDIR           : ${TMPDIR:-/tmp}"
  df -Th "${TMPDIR:-/tmp}" 2>/dev/null | sed 's/^/  /'
  echo "repo filesystem  :"
  df -Th "$REPO" 2>/dev/null | tail -1 | sed 's/^/  /'
  echo
  echo "## Toolchain"
  rustc -Vv 2>/dev/null | sed 's/^/  /'
  echo "  cargo: $(cargo -V 2>/dev/null)"
  echo "RUSTFLAGS (cfg)  : $(sed -n 's/^rustflags *= *//p' .cargo/config.toml 2>/dev/null)"
  echo "RUST_MIN_STACK   : $(sed -n 's/^RUST_MIN_STACK *= *//p' .cargo/config.toml 2>/dev/null)"
  echo
  echo "## Code under test"
  echo "git commit       : $(git rev-parse HEAD 2>/dev/null || echo n/a)"
  echo "git dirty        : $GIT_DIRTY"
  echo "source patch sha : $SOURCE_PATCH_SHA256"
  echo "source status    : $(basename "$SOURCE_STATUS")"
  echo "source patch     : $(basename "$SOURCE_PATCH")"
  echo "leanVM rev       : $(sed -n 's/.*leanEthereum\/leanVM.git", rev = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
  echo "Cargo.lock       : $(test -f Cargo.lock && echo present || echo MISSING)"
  echo "ML-DSA Cargo.lock: $(test -f mldsa/Cargo.lock && echo present || echo MISSING)"
  echo
  echo "## Parameters (src/params.rs)"
  grep -E '^pub const' src/params.rs | sed 's/^/  /'
  echo "  resolved N_MEMBERS = $BENCH_N"
  echo "  resolved T         = $BENCH_T"
  echo "  resolved N_UPDATES = $BENCH_UPDATES"
  echo
  echo "## Benchmark configuration"
  echo "runs (default)   : $RUNS measured, $WARMUP warmup(s) discarded"
  for t in "${TARGET_LIST[@]}"; do
    runs_var="RUNS_$t"; warmup_var="WARMUP_$t"
    tr="${!runs_var:-$RUNS}"; tw="${!warmup_var:-$WARMUP}"
    echo "  $t: $tr measured, $tw warmup(s)"
  done
  echo "targets          : $TARGETS"
  echo "committee        : N=$BENCH_N t=$BENCH_T"
  echo "XMSS inputs      : ${BENCH_INPUT_DIR:-generated inside each target}"
  echo "XMSS input mode  : $INPUT_MODE"
  echo "ML-DSA inputs    : ${MLDSA_INPUT_DIR:-<target not selected>}"
  echo "ML-DSA input mode: $MLDSA_INPUT_MODE"
  echo "cooldown         : ${COOLDOWN_SECONDS}s before every target process"
  echo "kernel RSS probe : ${TIME_BIN:-unavailable (self-reported VmHWM only)}"
  echo
  echo "## lscpu (full)"
  lscpu 2>/dev/null | sed 's/^/  /'
} > "$ENV_FILE"

gov="$GOVERNORS"

cat <<EOF

$(sed -n '2,4p' "$ENV_FILE")
runs      : $RUNS measured (+$WARMUP warmup discarded)
targets   : $TARGETS
committee : N=$BENCH_N t=$BENCH_T
outdir    : $OUTDIR
EOF
echo "order     : $([ "$INTERLEAVE" = 1 ] && echo 'balanced across targets' || echo 'contiguous blocks per target')"
echo "cooldown  : ${COOLDOWN_SECONDS}s before each target process"
[ -n "$PIN_CPUS" ] && echo "pinned    : $PIN_CPUS"
[ "$gov" = performance ] || echo "WARNING   : target CPU governors '$gov' are not uniformly performance -> inflated variance"
[ -n "$TIME_BIN" ] || echo "WARNING   : /usr/bin/time absent -> no independent kernel RSS cross-check"
[ -f Cargo.lock ] || echo "WARNING   : Cargo.lock missing -> dependency resolution is not reproducible"
[ "$NEED_MLDSA" = 0 ] || [ -f mldsa/Cargo.lock ] || echo "WARNING   : mldsa/Cargo.lock missing -> ML-DSA dependency resolution is not reproducible"
[ "$GIT_DIRTY" = no ] || echo "WARNING   : dirty source tree; source.patch omits untracked contents, so this run may not be reconstructible"
echo

# The default workload separates the roles faithfully: one unmeasured process
# creates the committee, raw StatusList fixtures and signed inputs once. The raw
# target verifies those StatusList records; the prover turns the same logical
# inputs into SnarkStatusList records. BENCH_SELF_CONTAINED=1 is retained only
# for diagnostic comparison with older runs.
if [ "$AUTO_FIXTURE" = 1 ]; then
  echo "generating one unmeasured signed committee fixture ..."
  "$BIN_DIR/committee_fixture" "$BENCH_INPUT_DIR" >/dev/null
  echo "  raw StatusList inputs: $BENCH_INPUT_DIR"
  echo
fi
if [ "$AUTO_MLDSA_FIXTURE" = 1 ]; then
  echo "generating one unmeasured ML-DSA committee fixture ..."
  "$MLDSA_BIN_DIR/mldsa_fixture" "$MLDSA_INPUT_DIR" "$BENCH_N" "$BENCH_T" "$BENCH_UPDATES" >/dev/null
  echo "  ML-DSA StatusList inputs: $MLDSA_INPUT_DIR"
  echo
fi
if [ -n "${SEEN_TARGETS[mldsa_raw_agg]:-}" ] &&
   ! printf 'N=%s\nt=%s\nupdates=%s\n' "$BENCH_N" "$BENCH_T" "$BENCH_UPDATES" |
     cmp -s - "$MLDSA_INPUT_DIR/manifest.txt"; then
  echo "ML-DSA fixture does not match requested N=$BENCH_N t=$BENCH_T updates=$BENCH_UPDATES" >&2
  exit 1
fi

# ----------------------------------------------------- fixed corpus ----
# The verifier must see the SAME workload on every run, so its input is
# generated once and frozen. Re-generating it per run would fold the prover's
# variance into the verifier's numbers.
CORPUS="$SCRATCH/corpus"
if grep -qw verifier <<<"$TARGETS"; then
  echo "generating fixed verifier corpus ..."
  env -u BENCH_HONEST_ONLY "$BIN_DIR/prover" "$CORPUS" >/dev/null 2>&1
  "$BIN_DIR/verifier" --init-state "$CORPUS" >/dev/null
  echo "  $(ls "$CORPUS" | wc -l) artifacts, $(du -sh "$CORPUS" | cut -f1)"
  echo
fi

# ------------------------------------------------------------ collect ----
echo 'target,run,idx,phase,ms,bytes,rss_mb' > "$SAMPLES"
# `t_start` is epoch seconds at the moment the run was launched. Without it a
# thermal ramp or a background job is invisible after the fact: you can see that
# early runs differ from late ones only if run index happens to track time, which
# stops being true the moment targets are interleaved.
#
# `n_items` is how many updates/verifications the run actually measured. A run
# that measured zero reports 0.000 ms medians, which is indistinguishable from a
# very fast result — so it is recorded and checked rather than assumed.
#
# Phases are carried under their OWN names — `sign_*`, `prove_*`, `verify_*` —
# and a target simply leaves blank the ones it does not have. They used to share
# two positional slots, `work_*` for the primary phase and `work2_*` for the
# secondary one, which meant the same column held different phases for different
# targets. summary.txt relabelled them per target, so it read correctly;
# summary.csv did not, so anyone plotting a column got two different quantities
# on one axis.
#
# `setup_ms` is the leanVM circuit and ONLY that; `keygen_ms` is the N-key
# generation every path pays, `raw_agg` included; `slot_state_ms` is the N durable
# slot counters, which only a real signer pays. Keeping them apart is what makes
# the fixed-cost columns comparable across targets: `raw_agg` leaves `setup_ms`
# empty because it has no circuit, which is the result, rather than borrowing the
# column for its keygen and making the SNARK look like the cheaper setup.
echo 'target,run,t_start,setup_ms,keygen_ms,slot_state_ms,n_items,sign_med_ms,sign_mean_ms,sign_sd_ms,sign_min_ms,sign_max_ms,sign_total_ms,prove_med_ms,prove_mean_ms,prove_sd_ms,prove_min_ms,prove_max_ms,prove_total_ms,verify_med_ms,verify_mean_ms,verify_sd_ms,verify_min_ms,verify_max_ms,verify_total_ms,artifact_med_bytes,rss_setup_mb,rss_max_mb,peak_rss_mb,kernel_maxrss_mb,failures,load1_start,load1_end,freq_start_mhz,freq_end_mhz,temp_start_c,temp_end_c,decode_med_ms,decode_mean_ms,decode_sd_ms,decode_min_ms,decode_max_ms,decode_total_ms,decode_verify_med_ms,decode_verify_mean_ms,decode_verify_sd_ms,decode_verify_min_ms,decode_verify_max_ms,decode_verify_total_ms,slot_burn_med_ms,slot_burn_total_ms,sign_crypto_med_ms,sign_crypto_total_ms' > "$RUNS_CSV"

# Column indices into runs.csv, named once. Every awk gate and every summary row
# below addresses columns through these, so inserting a column is one edit here
# rather than a hunt through half a dozen hardcoded `$17`s — one of which is the
# security gate, where a stale index fails open.
C_SETUP=4;       C_KEYGEN=5;      C_SLOTSTATE=6;  C_ITEMS=7
C_SIGN_MED=8;    C_SIGN_TOT=13
C_PROVE_MED=14;  C_PROVE_TOT=19
C_VERIFY_MED=20; C_VERIFY_TOT=25
C_ARTIFACT=26;   C_RSS_SETUP=27;  C_RSS_MAX=28
C_PEAK=29;       C_KERNEL=30;     C_FAIL=31
C_DECODE_MED=38; C_DECODE_TOT=43
C_DECODE_VERIFY_MED=44; C_DECODE_VERIFY_TOT=49
C_SLOT_BURN_MED=50; C_SIGN_CRYPTO_MED=52

RUN_T_START=""
RUN_LOAD_START=""; RUN_LOAD_END=""
RUN_FREQ_START=""; RUN_FREQ_END=""
RUN_TEMP_START=""; RUN_TEMP_END=""

run_once() { # $1 target -> prints stdout of the run to $SCRATCH/out.txt
  local target="$1" rc=0
  local -a cmd
  case "$target" in
    signer)   cmd=("$BIN_DIR/signer") ;;
    mldsa_signer) cmd=("$MLDSA_BIN_DIR/mldsa_signer" "$BENCH_UPDATES") ;;
    prover)
      rm -rf "$SCRATCH/pout"
      if [ -n "$BENCH_INPUT_DIR" ]; then
        cmd=(env BENCH_HONEST_ONLY=1 "$BIN_DIR/prover" "$SCRATCH/pout")
      else
        cmd=("$BIN_DIR/prover" "$SCRATCH/pout")
      fi
      ;;
    verifier) cmd=("$BIN_DIR/verifier" "$CORPUS") ;;
    combined) cmd=("$BIN_DIR/decentralized-root-of-trust") ;;
    raw_agg)  cmd=("$BIN_DIR/raw_agg") ;;
    mldsa_raw_agg) cmd=("$MLDSA_BIN_DIR/mldsa_raw_agg" "$MLDSA_INPUT_DIR" "$BENCH_UPDATES") ;;
    *) echo "unknown target: $target" >&2; exit 1 ;;
  esac
  # Pinning wraps the binary, not the harness: leanVM reads the affinity mask once
  # at startup to size its pool, so the mask has to be in place before exec.
  [ -n "$PIN_CPUS" ] && cmd=(taskset -c "$PIN_CPUS" "${cmd[@]}")
  [ -n "$TIME_BIN" ] && cmd=("$TIME_BIN" -v "${cmd[@]}")

  RUN_T_START="$(date +%s)"
  RUN_LOAD_START="$(load1_now)"
  RUN_FREQ_START="$(freq_now_mhz)"
  RUN_TEMP_START="$(temp_now_c)"
  EMIT_SAMPLES=1 "${cmd[@]}" >"$SCRATCH/out.txt" 2>"$SCRATCH/err.txt" || rc=$?
  RUN_LOAD_END="$(load1_now)"
  RUN_FREQ_END="$(freq_now_mhz)"
  RUN_TEMP_END="$(temp_now_c)"
  return $rc
}

kernel_maxrss_mb() {
  [ -n "$TIME_BIN" ] || { echo ""; return; }
  awk '/Maximum resident set size/ { printf "%d", $NF/1024 }' "$SCRATCH/err.txt"
}

# Normalise the one-line record each binary emits into a runs.csv row.
emit_run_row() { # $1 target  $2 run index
  local target="$1" run="$2" kmax; kmax="$(kernel_maxrss_mb)"
  local tag
  case "$target" in
    mldsa_signer) tag='^MLDSA_SIGNER ' ;;
    mldsa_raw_agg) tag='^MLDSA_RAW_AGG ' ;;
    signer) tag='^SIGNER ' ;; prover) tag='^PROVER ' ;; verifier) tag='^VERIFIER ' ;;
    combined) tag='^BENCH ' ;; raw_agg) tag='^RAW_AGG ' ;;
  esac
  local line; line="$(grep "$tag" "$SCRATCH/out.txt" || true)"
  [ -n "$line" ] || { echo "run $run ($target): record line missing" >&2; exit 1; }
  awk -v t="$target" -v r="$run" -v k="$kmax" -v ts="$RUN_T_START" \
      -v ls="$RUN_LOAD_START" -v le="$RUN_LOAD_END" \
      -v fs="$RUN_FREQ_START" -v fe="$RUN_FREQ_END" \
      -v cs="$RUN_TEMP_START" -v ce="$RUN_TEMP_END" '{
    for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
    # Every phase field starts empty, and a target fills only the phases it ran.
    # `col()` drops empty cells, so an absent phase yields no summary row at all —
    # which is the honest answer, rather than a 0.000 ms that reads as "instant".
    setup=""; keygen=""; slotstate=""
    sg_med=""; sg_mean=""; sg_sd=""; sg_lo=""; sg_hi=""; sg_tot=""
    pv_med=""; pv_mean=""; pv_sd=""; pv_lo=""; pv_hi=""; pv_tot=""
    vf_med=""; vf_mean=""; vf_sd=""; vf_lo=""; vf_hi=""; vf_tot=""
    dc_med=""; dc_mean=""; dc_sd=""; dc_lo=""; dc_hi=""; dc_tot=""
    dv_med=""; dv_mean=""; dv_sd=""; dv_lo=""; dv_hi=""; dv_tot=""
    rb_med=""; rb_tot=""; cr_med=""; cr_tot=""
    if (t=="signer") {
      # The only target that reports `sign`, and the only one whose keygen and
      # slot state are ONE key and ONE counter rather than the whole committee.
      # setup stays empty: a member builds no circuit. The artifact column carries the
      # signature size, which is what one member actually puts on the wire.
      keygen=v["keygen_ms"]; slotstate=v["slot_state_ms"]; n=v["n_rounds"]
      sg_med=v["sign_med_ms"]; sg_mean=v["sign_mean_ms"]; sg_sd=v["sign_sd_ms"]
      sg_lo=v["sign_min_ms"]; sg_hi=v["sign_max_ms"]; sg_tot=v["sign_total_ms"]
      rb_med=v["reserve_med_ms"]; rb_tot=v["reserve_total_ms"]
      cr_med=v["crypto_med_ms"]; cr_tot=v["crypto_total_ms"]
      pb=v["sig_bytes"]; rs=v["rss_keygen_mb"]; rm=v["rss_rounds_max_mb"]; pk=v["peak_rss_mb"]
      # Every round self-verifies; a missing key means the run told us nothing.
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="mldsa_signer") {
      # ML-DSA is stateless: there is one key but no durable slot counter.
      keygen=v["keygen_ms"]; n=v["n_rounds"]
      sg_med=v["sign_med_ms"]; sg_mean=v["sign_mean_ms"]; sg_sd=v["sign_sd_ms"]
      sg_lo=v["sign_min_ms"]; sg_hi=v["sign_max_ms"]; sg_tot=v["sign_total_ms"]
      cr_med=sg_med; cr_tot=sg_tot
      pb=v["sig_bytes"]; rs=v["rss_keygen_mb"]; rm=v["rss_rounds_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="prover") {
      # Aggregator. It signs to have something to aggregate, but does not time it:
      # those t signatures come from t machines in a deployment, one each.
      setup=v["setup_ms"]; keygen=v["keygen_ms"]; n=v["n_updates"]
      pv_med=v["prove_med_ms"]; pv_mean=v["prove_mean_ms"]; pv_sd=v["prove_sd_ms"]
      pv_lo=v["prove_min_ms"]; pv_hi=v["prove_max_ms"]; pv_tot=v["prove_total_ms"]
      pb=v["record_med_bytes"]; rs=v["rss_setup_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]; f=0
    } else if (t=="verifier") {
      # No keygen and no signing: this process only ever holds public keys.
      setup=v["setup_ms"]; n=v["n_verified"]
      vf_med=v["verify_med_ms"]; vf_mean=v["verify_mean_ms"]; vf_sd=v["verify_sd_ms"]
      vf_lo=v["verify_min_ms"]; vf_hi=v["verify_max_ms"]; vf_tot=v["verify_total_ms"]
      dc_med=v["decode_med_ms"]; dc_mean=v["decode_mean_ms"]; dc_sd=v["decode_sd_ms"]
      dc_lo=v["decode_min_ms"]; dc_hi=v["decode_max_ms"]; dc_tot=v["decode_total_ms"]
      dv_med=v["total_med_ms"]; dv_mean=v["total_mean_ms"]; dv_sd=v["total_sd_ms"]
      dv_lo=v["total_min_ms"]; dv_hi=v["total_max_ms"]; dv_tot=v["total_total_ms"]
      # An absent `failures=` key yields "", which awk would later coerce to 0 —
      # a silent pass for the one target that reports real accept/reject verdicts.
      # Missing means "this run told us nothing", which is a failure, not a zero.
      pb=""; rs=v["rss_setup_mb"]; rm=v["rss_verify_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="raw_agg") {
      # Baseline. `setup` stays EMPTY on purpose: this path builds no circuit, and
      # that absence is the headline result. It used to carry keygen instead, which
      # put a cost both paths pay into the column that means "what the SNARK costs
      # extra" — and made the SNARK setup look cheaper than a keygen it was not
      # being compared against. The artifact column is the complete serialized
      # StatusList record; the tamper sanity check drives the failure gate.
      keygen=v["keygen_ms"]; slotstate=v["slot_state_ms"]; n=v["n_updates"]
      vf_med=v["verify_med_ms"]; vf_mean=v["verify_mean_ms"]; vf_sd=v["verify_sd_ms"]
      vf_lo=v["verify_min_ms"]; vf_hi=v["verify_max_ms"]; vf_tot=v["verify_total_ms"]
      dc_med=v["decode_med_ms"]; dc_mean=v["decode_mean_ms"]; dc_sd=v["decode_sd_ms"]
      dc_lo=v["decode_min_ms"]; dc_hi=v["decode_max_ms"]; dc_tot=v["decode_total_ms"]
      dv_med=v["total_med_ms"]; dv_mean=v["total_mean_ms"]; dv_sd=v["total_sd_ms"]
      dv_lo=v["total_min_ms"]; dv_hi=v["total_max_ms"]; dv_tot=v["total_total_ms"]
      pb=v["record_med_bytes"]; rs=v["rss_keygen_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["tamper_rejected"]=="1")?0:1
    } else if (t=="mldsa_raw_agg") {
      # Fixture I/O is outside all timed regions. Decode, cryptographic verify,
      # and their contiguous per-record total stay distinct throughout the output schema.
      n=v["n_updates"]
      dc_med=v["decode_med_ms"]; dc_mean=v["decode_mean_ms"]; dc_sd=v["decode_sd_ms"]
      dc_lo=v["decode_min_ms"]; dc_hi=v["decode_max_ms"]; dc_tot=v["decode_total_ms"]
      vf_med=v["verify_med_ms"]; vf_mean=v["verify_mean_ms"]; vf_sd=v["verify_sd_ms"]
      vf_lo=v["verify_min_ms"]; vf_hi=v["verify_max_ms"]; vf_tot=v["verify_total_ms"]
      dv_med=v["total_med_ms"]; dv_mean=v["total_mean_ms"]; dv_sd=v["total_sd_ms"]
      dv_lo=v["total_min_ms"]; dv_hi=v["total_max_ms"]; dv_tot=v["total_total_ms"]
      pb=v["record_med_bytes"]; rs=v["rss_anchor_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["tamper_rejected"]=="1")?0:1
    } else {
      # `updates_total_ms` is the whole loop (sign + prove + verify + printing);
      # the phase totals are what compare with the prover column. Prove and verify
      # live in one process here and both are carried; signing happens too but is
      # untimed, for the reason at the top of this file.
      setup=v["setup_total_ms"]; keygen=v["keygen_ms"]; n=v["n_updates"]
      pv_med=v["upd_prove_med_ms"]
      pv_lo=v["upd_prove_min_ms"]; pv_hi=v["upd_prove_max_ms"]; pv_tot=v["upd_prove_total_ms"]
      vf_med=v["upd_verify_med_ms"]; vf_tot=v["upd_verify_total_ms"]
      pb=v["proof_med_bytes"]; rs=v["rss_setup_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["sec_ok"]=="1")?0:1
    }
    printf "%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
      t,r,ts,setup,keygen,slotstate,n,
      sg_med,sg_mean,sg_sd,sg_lo,sg_hi,sg_tot,
      pv_med,pv_mean,pv_sd,pv_lo,pv_hi,pv_tot,
      vf_med,vf_mean,vf_sd,vf_lo,vf_hi,vf_tot,
      pb,rs,rm,pk,k,f,ls,le,fs,fe,cs,ce,
      dc_med,dc_mean,dc_sd,dc_lo,dc_hi,dc_tot,
      dv_med,dv_mean,dv_sd,dv_lo,dv_hi,dv_tot,
      rb_med,rb_tot,cr_med,cr_tot
  }' <<<"$line" >> "$RUNS_CSV"

  # Raw per-update samples.
  awk -v t="$target" -v r="$run" '
    /^SAMPLE / {
      delete v; for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
      if (v["target"]=="signer") {
        printf "%s,%d,%s,sign_protocol,%s,%s,%s\n", t,r,v["idx"],v["sign_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,slot_burn,%s,%s,%s\n", t,r,v["idx"],v["reserve_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,sign_crypto,%s,%s,%s\n", t,r,v["idx"],v["crypto_ms"],v["bytes"],v["rss_mb"]
      } else if (v["target"]=="mldsa_signer") {
        printf "%s,%d,%s,sign_crypto,%s,%s,%s\n", t,r,v["idx"],v["sign_ms"],v["sig_bytes"],v["rss_mb"]
      } else if (v["target"]=="prover") {
        printf "%s,%d,%s,prove,%s,%s,%s\n",  t,r,v["idx"],v["prove_ms"], v["bytes"],v["rss_mb"]
      } else if (v["target"]=="verifier") {
        printf "%s,%d,%s,decode,%s,%s,%s\n", t,r,v["idx"],v["decode_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,decode_verify,%s,%s,%s\n", t,r,v["idx"],v["total_ms"],v["bytes"],v["rss_mb"]
      } else if (v["target"]=="raw_agg") {
        printf "%s,%d,%s,decode,%s,%s,%s\n", t,r,v["idx"],v["decode_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,decode_verify,%s,%s,%s\n", t,r,v["idx"],v["total_ms"],v["bytes"],v["rss_mb"]
      } else if (v["target"]=="mldsa_raw_agg") {
        printf "%s,%d,%s,decode,%s,%s,%s\n", t,r,v["idx"],v["decode_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,decode_verify,%s,%s,%s\n", t,r,v["idx"],v["total_ms"],v["bytes"],v["rss_mb"]
      }
    }' "$SCRATCH/out.txt" >> "$SAMPLES"
}

# Refuse to report timings for a build that failed its own security expectations.
#
# A field that is neither "0" nor a positive integer is itself a failure, not a
# zero: awk coerces any non-numeric string to 0, so a binary printing a bool
# ("tamper_rejected=true") would slip through a naive `$15+0>0` test and disarm
# this gate permanently. Malformed counts as bad — and so does empty, which is
# what a renamed or missing key produces. Every branch of `emit_run_row` always
# assigns `f`, so a blank failures column means the row itself is wrong.
count_failed_runs() {
  awk -F, -v c="$C_FAIL" 'NR>1 { if ($c !~ /^[0-9]+$/ || $c+0>0) n++ } END{print n+0}' "$RUNS_CSV"
}

# A run that measured nothing is not a fast run. `Series` returns 0.0 for an empty
# series rather than an error, so a corpus that went missing, or an artifact
# naming change, yields a clean-looking `0.000 ms` median and a `failures=0` that
# the gate above happily accepts. The item count is the only thing that separates
# the two, so it is checked — and checked for *consistency*, since a corpus that
# shrinks halfway through a sweep would otherwise silently change what the
# per-run medians are medians of.
count_bad_item_counts() {
  awk -F, -v c="$C_ITEMS" 'NR>1 {
    if ($c !~ /^[0-9]+$/ || $c+0==0) { n++; next }
    if (seen[$1] && count[$1] != $c) n++
    seen[$1]=1; count[$1]=$c
  } END{print n+0}' "$RUNS_CSV"
}

# One measured run of one target, plus the gates. Shared by both schedules.
do_one() { # $1 target  $2 1-based index within that target's schedule
  local target="$1" i="$2" tw tr
  local runs_var="RUNS_$target" warmup_var="WARMUP_$target"
  tw="${!warmup_var:-$WARMUP}"
  tr="${!runs_var:-$RUNS}"

  [ "$COOLDOWN_SECONDS" -eq 0 ] || sleep "$COOLDOWN_SECONDS"
  if ! run_once "$target"; then
    echo "  $target run $i FAILED (exit != 0) — see below" >&2
    # stderr first: a Rust panic lands there, and $SCRATCH is wiped on exit.
    tail -5 "$SCRATCH/err.txt" >&2
    tail -5 "$SCRATCH/out.txt" >&2
    exit 1
  fi
  if [ "$i" -le "$tw" ]; then
    printf '  %-9s warmup %d/%d\n' "$target" "$i" "$tw"
    return 0
  fi
  emit_run_row "$target" "$((i - tw))"
  printf '  %-9s run %d/%d\n' "$target" "$((i - tw))" "$tr"

  # Fail fast. This used to run once, after every target had finished, so a
  # broken last target (raw_agg is last by default) discarded an hour of
  # signer and prover runs. Checking after each row costs one awk pass and
  # turns that hour into one run.
  if [ "$(count_failed_runs)" -gt 0 ]; then
    echo
    echo "ABORT: $target run $((i - tw)) reported a security-expectation failure" >&2
    echo "(or an unparseable failure count). Numbers withheld." >&2
    grep -E '^(SIGNER|MLDSA_SIGNER|PROVER|VERIFIER|BENCH|RAW_AGG|MLDSA_RAW_AGG) ' "$SCRATCH/out.txt" >&2 || true
    exit 1
  fi
  if [ "$(count_bad_item_counts)" -gt 0 ]; then
    echo
    echo "ABORT: $target run $((i - tw)) measured 0 items, or a different number of" >&2
    echo "items than earlier runs of the same target. A per-run median is only" >&2
    echo "meaningful over a fixed workload. Numbers withheld." >&2
    grep -E '^(SIGNER|MLDSA_SIGNER|PROVER|VERIFIER|BENCH|RAW_AGG|MLDSA_RAW_AGG) ' "$SCRATCH/out.txt" >&2 || true
    exit 1
  fi
  if ! awk -F, -v targets="$target" -v expected_runs="$((i - tw))" \
      -v expected_items="$BENCH_UPDATES" -v allow_extra=1 \
      -f tools/validate_benchmark_csv.awk "$RUNS_CSV" "$SAMPLES"; then
    echo "ABORT: $target run $((i - tw)) has incomplete or malformed measurements" >&2
    exit 1
  fi
}

# Per-target run counts accommodate roles with different run costs without
# forcing one global sample count. RUNS_<target> overrides; RUNS is the default.
for target in "${TARGET_LIST[@]}"; do
  runs_var="RUNS_$target"; warmup_var="WARMUP_$target"
  tr="${!runs_var:-$RUNS}"; tw="${!warmup_var:-$WARMUP}"
  case "$tr" in ''|*[!0-9]*|0) echo "$runs_var must be a positive integer" >&2; exit 1 ;; esac
  case "$tw" in ''|*[!0-9]*) echo "$warmup_var must be a non-negative integer" >&2; exit 1 ;; esac
done

# Print one row of a Williams-style balanced order. An even design has N rows;
# an odd design needs the N rotations plus their reversals (2N rows). Dropping a
# virtual fourth target from an even design is not balanced for three real
# targets: one role never occupies the middle position and directed predecessor
# pairs occur at different rates.
balanced_row() { # $1 zero-based row
  local row="$1" n="${#TARGET_LIST[@]}" reverse=0 pos sequence_pos base index
  if [ $((n % 2)) -eq 1 ] && [ "$row" -ge "$n" ]; then
    reverse=1
  fi
  row=$((row % n))
  for ((pos=0; pos<n; pos++)); do
    sequence_pos="$pos"
    [ "$reverse" -eq 1 ] && sequence_pos=$((n - 1 - pos))
    if [ "$sequence_pos" -eq 0 ]; then
      base=0
    elif [ $((sequence_pos % 2)) -eq 1 ]; then
      base=$(((sequence_pos + 1) / 2))
    else
      base=$((n - sequence_pos / 2))
    fi
    index=$(((base + row) % n))
    printf '%s\n' "${TARGET_LIST[$index]}"
  done
}

if [ "$INTERLEAVE" = 1 ]; then
  echo "== balanced interleaved sweep =="
  max_warmup=0
  max_runs=0
  declare -A WARMUP_LENGTH=() RUN_LENGTH=()
  for target in "${TARGET_LIST[@]}"; do
    runs_var="RUNS_$target"; warmup_var="WARMUP_$target"
    tr="${!runs_var:-$RUNS}"; tw="${!warmup_var:-$WARMUP}"
    WARMUP_LENGTH[$target]="$tw"
    RUN_LENGTH[$target]="$tr"
    [ "$tw" -gt "$max_warmup" ] && max_warmup="$tw"
    [ "$tr" -gt "$max_runs" ] && max_runs="$tr"
  done

  # Warm-ups are a separate phase. Starting the measured design again at row 0
  # prevents the warm-up count from changing which target gets each measured
  # position or predecessor.
  for ((step=1; step<=max_warmup; step++)); do
    while IFS= read -r target; do
      [ "$step" -le "${WARMUP_LENGTH[$target]}" ] || continue
      do_one "$target" "$step"
    done < <(balanced_row "$((step - 1))")
  done
  for ((step=1; step<=max_runs; step++)); do
    while IFS= read -r target; do
      [ "$step" -le "${RUN_LENGTH[$target]}" ] || continue
      do_one "$target" "$((WARMUP_LENGTH[$target] + step))"
    done < <(balanced_row "$((step - 1))")
  done
else
  for target in "${TARGET_LIST[@]}"; do
    echo "== $target =="
    runs_var="RUNS_$target"; warmup_var="WARMUP_$target"
    tr="${!runs_var:-$RUNS}"; tw="${!warmup_var:-$WARMUP}"
    for ((i=1; i<=tw+tr; i++)); do
      do_one "$target" "$i"
    done
  done
fi

# Validate every target and every expected sample before aggregating statistics.
# Standalone runs may intentionally use different RUNS_<target> counts.
run_counts=""
for target in "${TARGET_LIST[@]}"; do
  runs_var="RUNS_$target"
  run_counts+="${run_counts:+ }$target:${!runs_var:-$RUNS}"
done
awk -F, -v targets="$TARGETS" -v run_counts="$run_counts" -v expected_runs="$RUNS" \
    -v expected_items="$BENCH_UPDATES" -f tools/validate_benchmark_csv.awk \
    "$RUNS_CSV" "$SAMPLES" || { echo "ABORT: incomplete campaign; numbers withheld" >&2; exit 1; }

# ---------------------------------------------------------- aggregate ----
# Descriptive stats on stdin (one number per line):
#   n min q1 median q3 max mean sd cv% ci95_halfwidth
# Quantiles use linear interpolation (type 7, the R/numpy default).
# CI95 uses Student's t with df = n-1; df > 30 falls back to the normal 1.960.
stats() {
  sort -g | awk '
    BEGIN {
      split("12.706 4.303 3.182 2.776 2.571 2.447 2.365 2.306 2.262 2.228 2.201 2.179 2.160 2.145 2.131 2.120 2.110 2.101 2.093 2.086 2.080 2.074 2.069 2.064 2.060 2.056 2.052 2.048 2.045 2.042", tt, " ")
    }
    { a[++n]=$1; s+=$1 }
    function q(p,   h,lo,fr) { h=(n-1)*p+1; lo=int(h); fr=h-lo
                               return (lo>=n) ? a[n] : a[lo]+fr*(a[lo+1]-a[lo]) }
    END {
      if (n==0) { print "0 0 0 0 0 0 0 0 0 0"; exit }
      m=s/n
      for (i=1;i<=n;i++) { d=a[i]-m; ss+=d*d }
      sd=(n>1) ? sqrt(ss/(n-1)) : 0
      cv=(m!=0) ? 100*sd/m : 0
      df=n-1; tc=(df<=0) ? 0 : (df<=30 ? tt[df] : 1.960)
      ci=(n>1) ? tc*sd/sqrt(n) : 0
      printf "%d %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.3f %.6f\n", n, a[1], q(0.25), q(0.50), q(0.75), a[n], m, sd, cv, ci
    }'
}

col() { awk -F, -v t="$1" -v c="$2" 'NR>1 && $1==t && $c!="" {print $c}' "$RUNS_CSV"; }

echo 'target,metric,unit,n,min,q1,median,q3,max,mean,sd,cv_pct,ci95_halfwidth' > "$SUMMARY_CSV"

emit() { # target metric unit column
  local vals; vals="$(col "$1" "$4")"
  [ -n "$vals" ] || return 0
  local st; st="$(printf '%s\n' "$vals" | stats)"
  printf '%s,%s,%s,%s\n' "$1" "$2" "$3" "$(tr ' ' ',' <<<"$st")" >> "$SUMMARY_CSV"
}

# The metric id in summary.csv now names the phase, so the file is readable on its
# own: `prove_per_item` and `verify_per_item` are different rows rather than the
# same `work_per_item` meaning different things on different lines.
for target in "${TARGET_LIST[@]}"; do
  emit "$target" setup            ms    "$C_SETUP"
  emit "$target" keygen           ms    "$C_KEYGEN"
  emit "$target" slot_state       ms    "$C_SLOTSTATE"
  if [ "$target" = signer ]; then
    emit "$target" sign_protocol_per_item ms "$C_SIGN_MED"
    emit "$target" sign_protocol_total ms "$C_SIGN_TOT"
    emit "$target" slot_burn_per_item ms "$C_SLOT_BURN_MED"
    emit "$target" sign_crypto_per_item ms "$C_SIGN_CRYPTO_MED"
  elif [ "$target" = mldsa_signer ]; then
    emit "$target" sign_crypto_per_item ms "$C_SIGN_MED"
    emit "$target" sign_crypto_total ms "$C_SIGN_TOT"
  fi
  emit "$target" prove_per_item   ms    "$C_PROVE_MED"
  emit "$target" prove_total      ms    "$C_PROVE_TOT"
  emit "$target" verify_per_item  ms    "$C_VERIFY_MED"
  emit "$target" verify_total     ms    "$C_VERIFY_TOT"
  emit "$target" decode_per_item  ms    "$C_DECODE_MED"
  emit "$target" decode_total     ms    "$C_DECODE_TOT"
  emit "$target" decode_verify_per_item ms "$C_DECODE_VERIFY_MED"
  emit "$target" decode_verify_total ms  "$C_DECODE_VERIFY_TOT"
  case "$target" in
    signer|mldsa_signer) emit "$target" signature_size bytes "$C_ARTIFACT" ;;
    prover)   emit "$target" record_size    bytes "$C_ARTIFACT" ;;
    raw_agg|mldsa_raw_agg) emit "$target" record_size bytes "$C_ARTIFACT" ;;
    combined) emit "$target" proof_size     bytes "$C_ARTIFACT" ;;
  esac
  emit "$target" rss_after_setup  MB    "$C_RSS_SETUP"
  emit "$target" rss_max          MB    "$C_RSS_MAX"
  emit "$target" peak_rss_vmhwm   MB    "$C_PEAK"
  emit "$target" peak_rss_kernel  MB    "$C_KERNEL"
done

# Detect a coarse early/late regime change without deleting or rewriting any
# observation. The first and last quarter medians are deliberately diagnostic,
# not an outlier rule: a warning means the session was not stationary enough for
# the t interval below to be interpreted as if runs were IID.
echo 'target,metric,n,window,early_median,late_median,change_pct,status' > "$DRIFT_CSV"
drift_metric() { # target metric column
  local target="$1" metric="$2" column="$3" n window early late change status
  n="$(col "$target" "$column" | awk 'END{print NR+0}')"
  if [ "$n" -lt 8 ]; then
    printf '%s,%s,%d,0,,,,insufficient_runs\n' "$target" "$metric" "$n" >> "$DRIFT_CSV"
    return
  fi
  window=$(((n + 3) / 4))
  [ "$window" -lt 3 ] && window=3
  early="$(awk -F, -v t="$target" -v c="$column" -v w="$window" 'NR>1 && $1==t && $2<=w && $c!="" {print $c}' "$RUNS_CSV" | stats | awk '{print $4}')"
  late="$(awk -F, -v t="$target" -v c="$column" -v lo="$((n - window))" 'NR>1 && $1==t && $2>lo && $c!="" {print $c}' "$RUNS_CSV" | stats | awk '{print $4}')"
  change="$(awk -v a="$early" -v b="$late" 'BEGIN{if(a==0){print 0}else{printf "%.3f",100*(b-a)/a}}')"
  status="$(awk -v d="$change" 'BEGIN{if(d<0)d=-d; print (d>15)?"warning":"ok"}')"
  printf '%s,%s,%d,%d,%s,%s,%s,%s\n' "$target" "$metric" "$n" "$window" "$early" "$late" "$change" "$status" >> "$DRIFT_CSV"
}
for target in "${TARGET_LIST[@]}"; do
  case "$target" in
    signer) drift_metric "$target" sign_protocol_per_item "$C_SIGN_MED" ;;
    mldsa_signer) drift_metric "$target" sign_crypto_per_item "$C_SIGN_MED" ;;
    prover) drift_metric "$target" prove_per_item "$C_PROVE_MED" ;;
    verifier|raw_agg) drift_metric "$target" decode_verify_per_item "$C_DECODE_VERIFY_MED" ;;
    mldsa_raw_agg)
      drift_metric "$target" decode_verify_per_item "$C_DECODE_VERIFY_MED"
      ;;
    combined)
      drift_metric "$target" prove_per_item "$C_PROVE_MED"
      drift_metric "$target" verify_per_item "$C_VERIFY_MED"
      ;;
  esac
done

# Human labels. Only `raw_agg` needs its own cases now — everything else follows
# from the metric name, which is the point of naming metrics after phases.
label() {
  case "$1:$2" in
    signer:keygen)           echo "keygen (1 key, once)" ;;
    signer:slot_state)       echo "slot state (1 counter)" ;;
    signer:sign_protocol_per_item) echo "XMSS protocol sign / round" ;;
    signer:slot_burn_per_item) echo "XMSS durable slot burn" ;;
    signer:sign_crypto_per_item) echo "XMSS crypto sign / round" ;;
    mldsa_signer:keygen)     echo "keygen ML-DSA (1 key)" ;;
    mldsa_signer:sign_crypto_per_item) echo "ML-DSA crypto sign / round" ;;
    signer:sign_protocol_total) echo "XMSS protocol sign total" ;;
    mldsa_signer:sign_crypto_total) echo "ML-DSA crypto sign total" ;;
    signer:signature_size)   echo "XMSS signature size" ;;
    mldsa_signer:signature_size) echo "ML-DSA signature size" ;;
    raw_agg:verify_per_item) echo "verify-only XMSS / update" ;;
    raw_agg:decode_per_item) echo "decode XMSS / update" ;;
    raw_agg:decode_verify_per_item) echo "XMSS decode + verify" ;;
    verifier:verify_per_item) echo "SNARK verify-only / update" ;;
    verifier:decode_per_item) echo "SNARK decode / update" ;;
    verifier:decode_verify_per_item) echo "SNARK decode + verify" ;;
    mldsa_raw_agg:verify_per_item) echo "verify-only ML-DSA" ;;
    mldsa_raw_agg:decode_per_item) echo "decode ML-DSA / update" ;;
    mldsa_raw_agg:decode_verify_per_item) echo "decode + verify ML-DSA" ;;
    raw_agg:record_size)     echo "XMSS StatusList size" ;;
    mldsa_raw_agg:record_size) echo "ML-DSA StatusList size" ;;
    prover:record_size)      echo "SnarkStatusList size" ;;
    *:setup)                 echo "setup (circuit, once)" ;;
    *:keygen)                echo "keygen (N keys, once)" ;;
    *:slot_state)            echo "slot state (counters)" ;;
    *:prove_per_item)        echo "prove / update" ;;
    *:prove_total)           echo "prove total / run" ;;
    *:verify_per_item)       echo "verify / update" ;;
    *:verify_total)          echo "verify total / run" ;;
    *:decode_total)          echo "decode total / run" ;;
    *:decode_verify_total)   echo "decode + verify total" ;;
    *:proof_size)            echo "proof size" ;;
    # RSS is expanded once, in the header legend above; these four then use the
    # acronym alone, which is what keeps the varying part of each label visible.
    # The first one is named after whatever fixed cost the target actually paid:
    # signer and raw_agg build no circuit, so for them the column is post-keygen.
    signer:rss_after_setup)  echo "RSS after keygen" ;;
    mldsa_signer:rss_after_setup) echo "RSS after keygen" ;;
    mldsa_raw_agg:rss_after_setup) echo "RSS after anchor" ;;
    raw_agg:rss_after_setup)
      [ -n "$BENCH_INPUT_DIR" ] && echo "RSS after anchor" || echo "RSS after keygen"
      ;;
    *:rss_after_setup)       echo "RSS after setup" ;;
    *:rss_max)               echo "RSS max during work" ;;
    *:peak_rss_vmhwm)        echo "peak RSS (VmHWM)" ;;
    *:peak_rss_kernel)       echo "peak RSS (kernel)" ;;
    *) echo "$2" ;;
  esac
}

{
  echo "BENCHMARK SUMMARY"
  echo "generated : $(date -Is)"
  echo "host      : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1) ($(uname -m)), $EFFECTIVE_THREADS effective threads"
  echo "governor  : $gov"
  echo "threads   : $EFFECTIVE_THREADS${PIN_CPUS:+ (pinned to $PIN_CPUS)}"
  echo "committee : N=$BENCH_N, t=$BENCH_T"
  echo "XMSS input: $INPUT_MODE"
  echo "MLDSA input: $MLDSA_INPUT_MODE"
  echo "order     : $([ "$INTERLEAVE" = 1 ] && echo 'Williams-style balanced across targets' || echo 'contiguous blocks per target')"
  echo "cooldown  : ${COOLDOWN_SECONDS}s before each target process"
  echo "runs      : n=$RUNS measured, $WARMUP warmup(s) discarded (default;"
  echo "            RUNS_<target> may override — the authoritative count is the"
  echo "            per-row 'n' column below)"
  echo "unit      : per-run value; for per-update metrics, the per-run median"
  echo "ci95      : Student's t, df=n-1 (normal approximation for n>31). This is a"
  echo "            PRECISION interval for the mean of repeated runs on THIS host in"
  echo "            THIS session. It says nothing about other hardware, other"
  echo "            builds, or this machine on another day."
  # The acronym is expanded here, once, and every memory row below is then free
  # to say just "RSS" — spelling it out on each of four rows per target buries
  # the one thing that actually differs between them (which peak, whose reading).
  echo "memory    : the MB rows are RSS, resident set size — the physical pages"
  echo "            the process holds. A 'peak' row is the high-water mark over"
  echo "            the whole run, read two independent ways: VmHWM is the"
  echo "            process's own /proc/self/status, kernel is ru_maxrss from"
  echo "            /usr/bin/time -v."
  if awk -F, 'NR>1 && $8=="warning" {found=1} END{exit !found}' "$DRIFT_CSV"; then
    echo "WARNING   : early/late regime change detected; do not treat this session"
    echo "            as stationary or publish its confidence intervals unchanged:"
    awk -F, 'NR>1 && $8=="warning" {printf "            %s %s: early %s ms, late %s ms (%+.1f%%)\n",$1,$2,$5,$6,$7}' "$DRIFT_CSV"
  fi
  echo
  printf '%-9s %-23s %-6s %3s %10s %10s %10s %10s %10s %8s %7s\n' \
    target metric unit n min median max mean sd 'cv%' 'ci95±'
  awk -F, 'NR>1' "$SUMMARY_CSV" | while IFS=, read -r t m u n mn q1 md q3 mx mean sd cv ci; do
    d=2; [ "$u" = bytes ] && d=0; [ "$u" = MB ] && d=1
    printf '%-9s %-23s %-6s %3s %10.*f %10.*f %10.*f %10.*f %10.*f %7.1f%% %7.*f\n' \
      "$t" "$(label "$t" "$m")" "$u" "$n" $d "$mn" $d "$md" $d "$mx" $d "$mean" $d "$sd" "$cv" $d "$ci"
  done

  # Headline comparison: the reason the split exists, across the three processes
  # that actually run in it. Guard on the RAW columns, not on stats() output:
  # stats() emits "0" for an empty column, so testing its result would pass with
  # c=0 and divide by zero when a run omits these targets.
  #
  # This used to read verifier-vs-combined, which measured the same reduction
  # against a process nobody deploys. Prover and verifier are two real roles that
  # already run apart, so comparing them is the same arithmetic with one fewer
  # fiction — and adding the signer is what shows the span is 1000x, not 3x.
  sp_raw="$(col signer "$C_PEAK")"
  vp_raw="$(col verifier "$C_PEAK")"; pp_raw="$(col prover "$C_PEAK")"
  if [ -n "$vp_raw" ] && [ -n "$pp_raw" ]; then
    vp="$(printf '%s\n' "$vp_raw" | stats | awk '{print $4}')"
    pp="$(printf '%s\n' "$pp_raw" | stats | awk '{print $4}')"
    sp=""; [ -n "$sp_raw" ] && sp="$(printf '%s\n' "$sp_raw" | stats | awk '{print $4}')"
    echo
    echo "PEAK RSS BY ROLE (median) — why the deployment splits"
    [ -n "$sp" ] && awk -v s="$sp" 'BEGIN{ printf "  member    (signer)  : %.0f MB\n", s }'
    awk -v v="$vp" 'BEGIN{ printf "  verifier            : %.0f MB\n", v }'
    awk -v p="$pp" 'BEGIN{ printf "  aggregator (prover) : %.0f MB\n", p }'
    awk -v v="$vp" -v p="$pp" 'BEGIN{
      printf "  a node that only verifies saves %.1f%% (%.0f MB) against proving\n", 100*(p-v)/p, p-v
    }'
    [ -n "$sp" ] && awk -v s="$sp" -v p="$pp" 'BEGIN{
      if (s > 0) printf "  a node that only signs is %.0fx smaller than the aggregator\n", p/s
    }'
  fi

  # Peak RSS cross-check. Two independent readings of the same quantity: the
  # process's own /proc/self/status VmHWM and the kernel's ru_maxrss via
  # /usr/bin/time -v. They should agree; VmHWM can under-report, because the
  # kernel only refreshes mm->hiwater_rss at certain points. Printing both and
  # never comparing them is not a cross-check, so compare them here.
  for target in "${TARGET_LIST[@]}"; do
    self_raw="$(col "$target" "$C_PEAK")"; kern_raw="$(col "$target" "$C_KERNEL")"
    [ -n "$self_raw" ] && [ -n "$kern_raw" ] || continue
    s="$(printf '%s\n' "$self_raw" | stats | awk '{print $4}')"
    k="$(printf '%s\n' "$kern_raw" | stats | awk '{print $4}')"
    awk -v t="$target" -v s="$s" -v k="$k" 'BEGIN{
      if (k <= 0) exit
      d = 100 * (k - s) / k
      if (d < 0) d = -d
      if (d > 5) printf "WARNING   : %s peak RSS disagrees — VmHWM %.0f MB vs kernel %.0f MB (%.1f%%)\n", t, s, k, d
    }'
  done

  echo
  echo "CAVEATS (carry these into any write-up)"
  echo "  * Binaries are built with target-cpu=native: they are host-specific and"
  echo "    NOT portable. Re-run on each machine you report."
  [ "$gov" = performance ] || echo "  * CPU governor was '$gov', not 'performance': variance is inflated,"
  [ "$gov" = performance ] || echo "    and absolute timings are NOT comparable with a 'performance' run."
  echo "  * leanVM sizes its worker pool from available_parallelism() at startup and"
  echo "    offers no override, so every timing here is a $EFFECTIVE_THREADS-thread figure."
  [ -n "$PIN_CPUS" ] || echo "    Nothing was pinned: set PIN_CPUS to fix it across machines."
  [ "$INTERLEAVE" = 1 ] || echo "  * Targets ran in contiguous blocks: any drift over the sweep is confounded"
  [ "$INTERLEAVE" = 1 ] || echo "    with target identity. Use the t_start column in runs.csv to check."
  echo "  * A ${COOLDOWN_SECONDS}s idle cooldown preceded every target process. The balanced"
  echo "    order reduces positional and predecessor bias but cannot guarantee equal"
  echo "    package temperature; inspect t_start and host telemetry when publishing."
  echo "  * runs.csv carries t_start (epoch s) per run. Plot the metric against it"
  echo "    before reporting. It also records load, selected-CPU frequency and the"
  echo "    highest readable host temperature before and after every process. Empty"
  echo "    telemetry fields mean the kernel exposed no portable sensor. drift.csv"
  echo "    flags >15% early/late shifts but never removes observations."
  [ "$GIT_DIRTY" = no ] || echo "  * The tree was dirty. source.patch records tracked changes only; untracked"
  [ "$GIT_DIRTY" = no ] || echo "    contents are omitted, so this run may not be exactly reconstructible."
  echo "  * A prover process calls zk_alloc::enable_arena(), which sets"
  echo "    M_TRIM_THRESHOLD=-1: its RSS never decreases, so 'peak' means"
  echo "    'high-water mark of a monotonic curve'. A verify-only process keeps"
  echo "    normal malloc behaviour and its RSS is flat in the number of verifications."
  echo "  * Setup is paid once per process and is not persisted across restarts:"
  echo "    every run re-executes the binary, so each target above paid it on all"
  echo "    $((RUNS + WARMUP)) of its executions. It dominates total time; never fold it into"
  echo "    per-update figures."
  echo "  * 'setup' is the leanVM circuit and nothing else."
  if [ "$INPUT_MODE" = fixture ]; then
    echo "    Committee key generation and signing ran in the separate fixture process"
    echo "    before measurement. The prover row is one aggregator holding public keys"
    echo "    and t ready-made signatures; the raw row is one relying-party verifier."
  elif [ "$INPUT_MODE" = self-contained ]; then
    echo "    Keygen is a separate row because EVERY path pays it, raw_agg included —"
    echo "    so the SNARK's extra fixed cost is the setup row alone, and raw_agg has no"
    echo "    setup row. Comparing raw keygen with SNARK setup inverts the answer."
  else
    echo "    No XMSS fixture-capable target was selected; XMSS signer and combined"
    echo "    use their native process shape."
  fi
  if [ "$MLDSA_INPUT_MODE" = fixture ]; then
    echo "  * ML-DSA key generation and quorum signing ran in a separate fixture"
    echo "    process. mldsa_raw_agg measures only record decode and verification."
  fi
  echo "  * Per-update samples within a run are not independent (shared allocator"
  echo "    and cache state). The table's unit is the per-run median; samples.csv"
  echo "    holds every raw observation if you need the pooled distribution."
  echo "  * sd / cv% / ci95 describe the spread BETWEEN runs, i.e. how reproducible"
  echo "    the experiment is — not how much one operation varies. A single"
  echo "    operation varies far more: see samples.csv, and the min/max columns of"
  echo "    the *_total rows. Do not quote 'median ± ci95' as the cost of one call."
  echo "  * '<phase> / update' is a median and '<phase> total / run' is a sum, so"
  echo "    total != n x per-update whenever the phase is skewed. Signing is: it"
  echo "    has stragglers several times the median, and its total runs visibly"
  echo "    above n x median. Verification is near-deterministic and does match."
  echo "  * Each signer target measures ONE member doing ONE signature per round."
  echo "    XMSS includes its durable slot burn (inactive journal generation plus"
  echo "    sync_data) through SignerNode. ML-DSA is stateless and randomized, so"
  echo "    it has no slot counter or persistence cost. Its crypto-sign row is not"
  echo "    a complete signer protocol cost: one-statement-per-version state is absent."
  if [ "$INPUT_MODE" = fixture ]; then
    echo "    The measured prover/raw verifier receive t signatures prepared by the"
    echo "    fixture process; neither produces signatures or holds secret keys."
  elif [ "$INPUT_MODE" = self-contained ]; then
    echo "    prover, combined and raw_agg create t signatures outside their timed"
    echo "    phase. In deployment they come one each from t member machines."
  else
    echo "    No measured aggregator or raw verifier was selected in this campaign."
  fi
  echo "  * Each keygen row is for ONE key. Only the XMSS signer has a slot-state"
  echo "    row, for ONE durable counter."
  if [ "$INPUT_MODE" = fixture ]; then
    echo "    The fixture-mode prover/raw verifier report neither: the committee paid"
    echo "    those costs outside the measured aggregator and verifier processes."
  elif [ "$INPUT_MODE" = self-contained ]; then
    echo "    prover/raw_agg report the whole committee's N. Do not read them as the"
    echo "    same quantity — divide by N first, or compare signer against N=1."
  else
    echo "    No committee-wide keygen or slot-state row is present in this campaign."
  fi
  echo "  * The XMSS signer cost applies unchanged to XMSS raw and PQ-SNARK records:"
  echo "    those forms use the same XMSS statement, key and derived slot. ML-DSA is"
  echo "    a separate raw alternative and its signer cost must not be substituted"
  echo "    into the XMSS-based proof path."

  # Derived from THIS sweep, never remembered. Keeping historical figures here
  # would make them look like results of the current run.
  t_param="$BENCH_T"
  pv_raw="$(col prover "$C_PROVE_MED")"
  [ -n "$pv_raw" ] || pv_raw="$(col combined "$C_PROVE_MED")"
  if [ -n "$pv_raw" ] && [ -n "$t_param" ]; then
    pv="$(printf '%s\n' "$pv_raw" | stats | awk '{print $4}')"
    awk -v m="$pv" -v tt="$t_param" 'BEGIN{
      printf "  * Prove cost is driven by t, not by the number of updates. At small t\n"
      printf "    the trace pads to a power of two, so prove time is a step function\n"
      printf "    (t=5..=8 all cost the same); from a few dozen signers upward the\n"
      printf "    linear term dominates. This sweep measured ONE t: t=%d at %.1f ms,\n", tt, m
      printf "    i.e. %.2f ms per aggregated signature -- a single point, not a\n", m/tt
      printf "    slope, since it still carries the t-independent part of the proof.\n"
      printf "    Re-run at a second t before quoting any per-signature figure, and\n"
      printf "    do not extrapolate the step behaviour past small t.\n"
    }'
  fi

} | tee "$SUMMARY_TXT"

echo
echo "written:"
echo "  $ENV_FILE"
echo "  $SAMPLES      ($(( $(wc -l < "$SAMPLES") - 1 )) raw observations)"
echo "  $RUNS_CSV"
echo "  $SUMMARY_CSV"
echo "  $SUMMARY_TXT"
echo "  $DRIFT_CSV"
echo "  $SOURCE_STATUS"
echo "  $SOURCE_PATCH"
