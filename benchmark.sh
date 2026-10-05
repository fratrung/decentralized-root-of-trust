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
#   schedule.csv    the process sequence that actually ran, warm-ups and cooldowns included
#   inputs.sha256   the signed fixture inputs, unchanged from first to last run
#   inputs/         those inputs when this script generated them, and the
#                   verifier corpus when small (corpus.sha256 always lists it)
#   logs/           stdout and stderr (with the full `time -v` report) of every
#                   process, warm-ups included; logs.sha256 binds them
#   prover-outputs.sha256  hash and size of every record each accepted prover
#                   execution wrote (the records themselves are not kept)
#   workload.txt    the declared workload: N, t, versions, list size, quorum
#                   selection. Every measured process reports the list sizes it
#                   handled, and a process that handled another list aborts
#   outputs.sha256  binds all of the above; written only for a complete campaign
#   status.txt      running | failed (numbers withheld) | complete
# OUTDIR must be new or empty, and summary/drift files appear only once every
# check has passed: a directory without `complete` holds no publishable result.
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
#   PLOT=1 ./benchmark.sh                  # add SVG figures and a Markdown table
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
PLOT="${PLOT:-0}"
# Binaries frozen earlier by tools/freeze_bins.sh (the scaling orchestrator
# passes its session's set, so fixture and measurement share one build). Unset,
# this script builds and freezes its own set into $OUTDIR/bin.
BENCH_BIN_DIR="${BENCH_BIN_DIR:-}"
# The verifier's fixed corpus is copied into OUTDIR when it is at most this
# large; above it only the hashes of its records are kept.
KEEP_CORPUS_MAX_MB="${KEEP_CORPUS_MAX_MB:-64}"
# The size of the status list every measured version carries. A record holds
# the whole list (32 bytes per credential) and every scheme reads it to
# authenticate it, so list size enters record size and verification time: it is
# a parameter of every figure, declared next to N and t. Unset keeps the
# default workload, one entry added per version (1..=N_UPDATES entries); a
# number L makes every version carry exactly L entries, one of them replaced
# per version. Passed to the fixture and signer binaries as BENCH_LIST_ENTRIES.
LIST_ENTRIES="${LIST_ENTRIES:-${BENCH_LIST_ENTRIES:-}}"

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
case "$PLOT" in 0|1) ;; *) echo "PLOT must be 0 or 1" >&2; exit 1 ;; esac
case "$KEEP_CORPUS_MAX_MB" in ''|*[!0-9]*) echo "KEEP_CORPUS_MAX_MB must be a non-negative integer" >&2; exit 1 ;; esac
if [ "$PLOT" = 1 ]; then
  command -v python3 >/dev/null 2>&1 || { echo "PLOT=1 requires python3" >&2; exit 1; }
  python3 "$REPO/tools/plot_benchmarks.py" --help >/dev/null || { echo "PLOT=1 requires a working plot_benchmarks.py" >&2; exit 1; }
fi
case "$BENCH_SELF_CONTAINED" in 0|1) ;; *) echo "BENCH_SELF_CONTAINED must be 0 or 1" >&2; exit 1 ;; esac
if [ "$BENCH_SELF_CONTAINED" = 1 ] && [ -n "$BENCH_INPUT_DIR" ]; then
  echo "BENCH_SELF_CONTAINED=1 conflicts with BENCH_INPUT_DIR" >&2
  exit 1
fi
case "$LIST_ENTRIES" in
  '') ;;
  *[!0-9]*|0*) echo "LIST_ENTRIES must be a positive integer without leading zeros (unset: the default growing list)" >&2; exit 1 ;;
esac
# How the fixtures choose each version's quorum (src/bench/workload.rs): t
# distinct members spread over the whole committee, derived from the version.
QUORUM_SELECTION=spread-splitmix64-v1
if [ -n "$LIST_ENTRIES" ]; then
  [ "$LIST_ENTRIES" -le 1048576 ] || { echo "LIST_ENTRIES=$LIST_ENTRIES exceeds the limit 1048576" >&2; exit 1; }
  # The self-contained processes build their own growing lists and do not read
  # the list size: a campaign labelled L would have measured something else.
  if [ "$BENCH_SELF_CONTAINED" = 1 ]; then
    echo "LIST_ENTRIES requires the fixture-shaped benchmark: it conflicts with BENCH_SELF_CONTAINED=1" >&2
    exit 1
  fi
  export BENCH_LIST_ENTRIES="$LIST_ENTRIES"
  WORKLOAD_LIST="$LIST_ENTRIES"
  EXPECT_LIST_MIN="$LIST_ENTRIES"; EXPECT_LIST_MAX="$LIST_ENTRIES"
  WORKLOAD_L="L=$LIST_ENTRIES"
  WORKLOAD_DESC="$LIST_ENTRIES entries in every version, one entry replaced per version"
else
  unset BENCH_LIST_ENTRIES
  WORKLOAD_LIST=growing
  EXPECT_LIST_MIN=1; EXPECT_LIST_MAX="$BENCH_UPDATES"
  WORKLOAD_L="L=1..$BENCH_UPDATES"
  WORKLOAD_DESC="growing, one entry added per version: 1..=$BENCH_UPDATES entries (default workload)"
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
  if [ "$target" = combined ] && [ -n "$LIST_ENTRIES" ]; then
    echo "LIST_ENTRIES conflicts with the combined target, which builds its own growing list" >&2
    exit 1
  fi
done

if [ -n "$PIN_CPUS" ]; then
  taskset -c "$PIN_CPUS" true >/dev/null 2>&1 || { echo "invalid/unavailable PIN_CPUS=$PIN_CPUS" >&2; exit 1; }
  EFFECTIVE_THREADS="$(taskset -c "$PIN_CPUS" nproc)"
  TARGET_AFFINITY="$(taskset -c "$PIN_CPUS" sh -c "sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status")"
else
  EFFECTIVE_THREADS="$(nproc)"
  TARGET_AFFINITY="$(taskset -cp $$ 2>/dev/null | sed 's/.*: //' || echo n/a)"
fi

# The measured binaries read their own RSS from /proc/self/status and stop if
# they cannot; outside Linux they would report 0, which is not a measurement.
[ -r /proc/self/status ] || { echo "benchmark.sh requires Linux /proc/self/status for RSS readings" >&2; exit 1; }

# The kernel's independent peak-RSS reading. BENCH_TIME_BIN names another
# `time -v` or, set empty, runs without one: peak_rss_kernel is then absent
# (never 0) and consumers fall back to the processes' own VmHWM.
TIME_BIN="${BENCH_TIME_BIN-/usr/bin/time}"
[ -n "$TIME_BIN" ] && [ ! -x "$TIME_BIN" ] && TIME_BIN=""

# The one wrapper every measured process gets. The runtime probe below goes
# through it too, so what the probe reports is what the targets receive.
wrap_target() { # command... -> WRAPPED
  WRAPPED=("$@")
  # Pinning wraps the binary, not the harness: leanVM reads the affinity mask
  # once at startup to size its pool, so the mask has to be in place before exec.
  if [ -n "$PIN_CPUS" ]; then WRAPPED=(taskset -c "$PIN_CPUS" "${WRAPPED[@]}"); fi
  if [ -n "$TIME_BIN" ]; then WRAPPED=("$TIME_BIN" -v "${WRAPPED[@]}"); fi
}

# What decides how the binaries are compiled: toolchain, every Cargo config file
# Cargo reads, and environment overrides of rustflags. An override silently
# replaces the repository's `target-cpu=native`, so the binaries would not be the
# build this report describes.
CARGO_ENV_FINGERPRINT="$("$REPO/tools/cargo_env_fingerprint.sh")"
RUSTFLAGS_OVERRIDDEN=0
grep -q '^rustflags-env: none$' <<<"$CARGO_ENV_FINGERPRINT" || RUSTFLAGS_OVERRIDDEN=1
FOREIGN_RUSTFLAGS_CONFIG="$(grep '^cargo-config: ' <<<"$CARGO_ENV_FINGERPRINT" |
  grep ' rustflags=yes$' | grep -vF "cargo-config: $REPO/.cargo/config.toml " || true)"

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

# Where the XMSS signer keeps its durable slot journal. Each signature waits for
# one sync_data on this filesystem inside the timed region, so the storage is a
# parameter of `sign_protocol` and `slot_burn`, not an accident of TMPDIR: on a
# RAM-backed filesystem the barrier costs almost nothing and the figure no
# longer describes durable signing. SIGNER_STATE_DIR selects the directory
# (default: TMPDIR); its class is recorded, and strict runs refuse RAM unless
# that scenario is requested by name with ALLOW_RAM_SIGNER_STATE=1.
SIGNER_STATE_DIR="${SIGNER_STATE_DIR:-${TMPDIR:-/tmp}}"
ALLOW_RAM_SIGNER_STATE="${ALLOW_RAM_SIGNER_STATE:-0}"
[ -d "$SIGNER_STATE_DIR" ] || { echo "SIGNER_STATE_DIR is not a directory: $SIGNER_STATE_DIR" >&2; exit 1; }
SIGNER_STORAGE="$("$REPO/tools/storage_class.sh" "$SIGNER_STATE_DIR")" || exit 1
SIGNER_STORAGE_CLASS="$(sed -n 's/^class=\([a-z]*\) .*/\1/p' <<<"$SIGNER_STORAGE")"
DROT_SIGNER_STATE_DIR="$(cd "$SIGNER_STATE_DIR" && pwd -P)"
export DROT_SIGNER_STATE_DIR
# Only these process shapes own slot state: the signer, and raw_agg when it
# produces its own signatures in the self-contained diagnostic mode.
SIGNER_STATE_USED=0
[ -z "${SEEN_TARGETS[signer]:-}" ] || SIGNER_STATE_USED=1
if [ -n "${SEEN_TARGETS[raw_agg]:-}" ] && [ "$BENCH_SELF_CONTAINED" = 1 ]; then SIGNER_STATE_USED=1; fi
SIGNER_STATE_ON_RAM=0
if [ "$SIGNER_STATE_USED" = 1 ] && [ "$SIGNER_STORAGE_CLASS" = ram ]; then SIGNER_STATE_ON_RAM=1; fi

# Publication mode is a preflight, not a warning printed after an expensive
# build. A dirty tree cannot be reconstructed from the commit recorded in the
# report, so strict runs refuse it unless the caller explicitly separates the
# exploratory policy with REQUIRE_CLEAN_TREE=0.
if [ "$STRICT_ENV" = 1 ]; then
  fatal=0
  [ "$GOVERNORS" = performance ] || { echo "STRICT: every target CPU governor must be 'performance', got '$GOVERNORS'" >&2; fatal=1; }
  [ -n "$TIME_BIN" ]             || { echo "STRICT: /usr/bin/time -v required for the RSS cross-check" >&2; fatal=1; }
  [ "$SIGNER_STATE_ON_RAM" = 0 ] || [ "$ALLOW_RAM_SIGNER_STATE" = 1 ] || {
    echo "STRICT: signer state is on RAM-backed storage ($SIGNER_STORAGE); set SIGNER_STATE_DIR to persistent storage, or ALLOW_RAM_SIGNER_STATE=1 to measure that scenario by name" >&2
    fatal=1
  }
  [ -f Cargo.lock ]               || { echo "STRICT: Cargo.lock required for a reproducible dependency set" >&2; fatal=1; }
  [ "$RUSTFLAGS_OVERRIDDEN" = 0 ] || { echo "STRICT: an environment variable overrides the repository's rustflags" >&2; fatal=1; }
  [ -z "$FOREIGN_RUSTFLAGS_CONFIG" ] || { echo "STRICT: a Cargo config outside the repository sets rustflags" >&2; fatal=1; }
  if [ "$NEED_MLDSA" = 1 ]; then
    [ -f mldsa/Cargo.lock ] || { echo "STRICT: mldsa/Cargo.lock required for reproducible ML-DSA binaries" >&2; fatal=1; }
  fi
  [ "$REQUIRE_CLEAN_TREE" = 0 ] || [ "$GIT_DIRTY" = no ] || {
    echo "STRICT: the Git working tree is dirty; commit the benchmark candidate first" >&2
    fatal=1
  }
  [ "$fatal" = 0 ] || { echo "refusing to produce publishable numbers on this configuration" >&2; exit 1; }
fi

# One directory holds exactly one campaign. Files are written in different
# phases, so a run that reused a populated OUTDIR and failed halfway would
# leave an earlier summary next to its own samples and metadata, with nothing
# downstream able to tell them apart. A non-empty OUTDIR is therefore refused;
# the scaling orchestrator moves a retried session's previous attempt aside.
if [ -e "$OUTDIR" ] &&
   { [ ! -d "$OUTDIR" ] || [ -n "$(find "$OUTDIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; }; then
  echo "OUTDIR already exists and is not empty: $OUTDIR (use a new directory)" >&2
  exit 1
fi

mkdir -p "$OUTDIR"
ENV_FILE="$OUTDIR/env.txt"
SAMPLES="$OUTDIR/samples.csv"
RUNS_CSV="$OUTDIR/runs.csv"
SOURCE_STATUS="$OUTDIR/source-status.txt"
SOURCE_PATCH="$OUTDIR/source.patch"
INPUTS_SHA="$OUTDIR/inputs.sha256"
OUTPUTS_SHA="$OUTDIR/outputs.sha256"
STATUS_FILE="$OUTDIR/status.txt"
# Derived results are written to a staging directory and moved under their
# published names only after every check has passed, so a summary.csv,
# summary.txt or drift.csv in OUTDIR is always the validated result of this
# campaign. status.txt says which state the directory is in: `running`,
# `failed` (numbers withheld) or `complete`; only `complete` comes with
# outputs.sha256, which binds metadata, inputs, samples and summaries.
STAGE="$OUTDIR/.staging"
mkdir -p "$STAGE"
SUMMARY_CSV="$STAGE/summary.csv"
SUMMARY_TXT="$STAGE/summary.txt"
DRIFT_CSV="$STAGE/drift.csv"
CAMPAIGN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')"
CAMPAIGN_STATE=running
printf 'running\ncampaign %s started %s\n' "$CAMPAIGN_ID" "$(date -Is)" > "$STATUS_FILE"

SCRATCH="$(mktemp -d)"
finish() {
  local rc=$?
  rm -rf "$SCRATCH"
  if [ "$CAMPAIGN_STATE" != complete ]; then
    rm -rf "$STAGE"
    printf 'failed\ncampaign %s stopped %s with exit status %s; numbers withheld\n' \
      "$CAMPAIGN_ID" "$(date -Is)" "$rc" > "$STATUS_FILE"
  fi
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

git status --porcelain=v1 > "$SOURCE_STATUS" 2>/dev/null || true
git diff --binary HEAD > "$SOURCE_PATCH" 2>/dev/null || true
SOURCE_PATCH_SHA256="$(sha256sum "$SOURCE_PATCH" 2>/dev/null | awk '{print $1}')"
[ -n "$SOURCE_PATCH_SHA256" ] || SOURCE_PATCH_SHA256=n/a

# ---------------------------------------------------------------- build ----
# Every process below runs from one frozen set of binaries whose hashes are
# recorded, never from target/release: Cargo may have written the new build
# elsewhere (CARGO_TARGET_DIR, CARGO_BUILD_TARGET), leaving an old executable at
# the conventional path to be measured under the new commit, and a rebuild
# during the campaign could swap binaries between runs. tools/freeze_bins.sh
# explains the mechanism; the copies are byte-identical, so no timing changes.
ROOT_BINS=(signer prover verifier decentralized-root-of-trust raw_agg committee_fixture check_prover_output)
MLDSA_BINS=(mldsa_signer mldsa_raw_agg mldsa_fixture)
# What the selected targets can run, fixtures and support processes included.
REQUIRED_BINS=()
for target in "${TARGET_LIST[@]}"; do
  case "$target" in
    signer) REQUIRED_BINS+=(signer) ;;
    prover) REQUIRED_BINS+=(prover check_prover_output committee_fixture) ;;
    verifier) REQUIRED_BINS+=(verifier prover committee_fixture) ;;
    raw_agg) REQUIRED_BINS+=(raw_agg committee_fixture) ;;
    combined) REQUIRED_BINS+=(decentralized-root-of-trust) ;;
    mldsa_signer) REQUIRED_BINS+=(mldsa_signer) ;;
    mldsa_raw_agg) REQUIRED_BINS+=(mldsa_raw_agg mldsa_fixture) ;;
  esac
done
if [ -n "$BENCH_BIN_DIR" ]; then
  [ -d "$BENCH_BIN_DIR" ] || { echo "BENCH_BIN_DIR is not a directory: $BENCH_BIN_DIR" >&2; exit 1; }
  BIN_DIR="$(cd "$BENCH_BIN_DIR" && pwd)"
  echo "using frozen binaries in $BIN_DIR (no build) ..."
  # The set must build the committee this invocation declares: DROT_BENCH_N/T
  # are compile-time, so a set frozen for another point would measure it instead.
  # Only the root crate reads them; the ML-DSA block is not evidence either way.
  if [ "$NEED_ROOT" = 1 ] && ! awk -v want="  DROT_BENCH_N=${DROT_BENCH_N:-} DROT_BENCH_T=${DROT_BENCH_T:-}" '
      root { found = ($0 == want); root = 0 }
      /^build crate=decentralized-root-of-trust / { root = 1 }
      END { exit !found }' "$BIN_DIR/PROVENANCE" 2>/dev/null; then
    echo "BENCH_BIN_DIR was not built with DROT_BENCH_N=${DROT_BENCH_N:-} DROT_BENCH_T=${DROT_BENCH_T:-}" >&2
    exit 1
  fi
else
  BIN_DIR="$OUTDIR/bin"
  echo "building --release and freezing binaries into $BIN_DIR ..."
  [ "$NEED_ROOT" = 0 ] || "$REPO/tools/freeze_bins.sh" "$BIN_DIR" "$REPO/Cargo.toml" "${ROOT_BINS[@]}"
  [ "$NEED_MLDSA" = 0 ] || "$REPO/tools/freeze_bins.sh" "$BIN_DIR" "$REPO/mldsa/Cargo.toml" "${MLDSA_BINS[@]}"
fi
MLDSA_BIN_DIR="$BIN_DIR"
# Every binary this campaign may run must be in the frozen set and intact.
verify_frozen_bins() {
  local b
  for b in "${REQUIRED_BINS[@]}"; do
    grep -q "  $b\$" "$BIN_DIR/SHA256SUMS" 2>/dev/null || { echo "frozen set lacks $b: $BIN_DIR" >&2; return 1; }
  done
  (cd "$BIN_DIR" && sha256sum --quiet --strict -c SHA256SUMS) || {
    echo "frozen binaries in $BIN_DIR do not match their recorded SHA-256" >&2
    return 1
  }
}
verify_frozen_bins || exit 1

# Runtime probe: a shell started exactly like a target (same wrapper, same
# EMIT_SAMPLES prefix, same inherited environment) reports what a target
# actually receives. .cargo/config.toml does not say that: Cargo's [env]
# reaches only processes Cargo starts, and this script execs the binaries
# directly.
RUNTIME_VARS=(RUST_MIN_STACK RUST_BACKTRACE RUST_LOG RAYON_NUM_THREADS MALLOC_ARENA_MAX MALLOC_CONF GLIBC_TUNABLES LD_PRELOAD LD_LIBRARY_PATH TMPDIR DROT_SIGNER_STATE_DIR BENCH_LIST_ENTRIES)
wrap_target sh -c 'for v do
    if val="$(printenv "$v")"; then echo "$v=$val"; else echo "$v=<unset>"; fi
  done
  sed -n "s/^Cpus_allowed_list:[[:space:]]*/cpus_allowed=/p" /proc/self/status
  echo "stack_ulimit_kib=$(ulimit -s)"' runtime-probe "${RUNTIME_VARS[@]}"
EMIT_SAMPLES=1 "${WRAPPED[@]}" >"$SCRATCH/runtime-probe.txt" 2>/dev/null || {
  echo "runtime probe failed to run through the target wrapper" >&2
  exit 1
}

mkdir -p "$OUTDIR/inputs"
AUTO_FIXTURE=0
if [ "$BENCH_SELF_CONTAINED" = 0 ] && [ -z "$BENCH_INPUT_DIR" ]; then
  for target in "${TARGET_LIST[@]}"; do
    case "$target" in prover|verifier|raw_agg)
      # Generated inside OUTDIR, not in scratch: the exact signed inputs the
      # campaign measured stay with its results (public records, no secret keys).
      BENCH_INPUT_DIR="$OUTDIR/inputs/xmss"
      AUTO_FIXTURE=1
      export BENCH_INPUT_DIR
      break
      ;;
    esac
  done
fi
AUTO_MLDSA_FIXTURE=0
if [ -n "${SEEN_TARGETS[mldsa_raw_agg]:-}" ] && [ -z "$MLDSA_INPUT_DIR" ]; then
  MLDSA_INPUT_DIR="$OUTDIR/inputs/mldsa"
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
  echo "campaign         : $CAMPAIGN_ID"
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
  echo "signer state     : $SIGNER_STORAGE"
  echo "signer state use : $([ "$SIGNER_STATE_USED" = 1 ] && echo 'the selected targets write a durable slot journal here' || echo 'not written by the selected targets')"
  df -Th "$DROT_SIGNER_STATE_DIR" 2>/dev/null | sed 's/^/  /'
  echo "repo filesystem  :"
  df -Th "$REPO" 2>/dev/null | tail -1 | sed 's/^/  /'
  echo
  echo "## Toolchain"
  rustc -Vv 2>/dev/null | sed 's/^/  /'
  echo "  cargo: $(cargo -V 2>/dev/null)"
  echo "cargo build environment (tools/cargo_env_fingerprint.sh):"
  printf '%s\n' "$CARGO_ENV_FINGERPRINT" | sed 's/^/  /'
  echo "  repository rustflags: $(sed -n 's/^rustflags *= *//p' .cargo/config.toml 2>/dev/null)"
  echo "  (overridden by any rustflags-env line other than 'none')"
  echo
  echo "## Runtime environment received by the measured processes"
  echo "  (a probe started through the same wrapper as every target)"
  sed 's/^/  /' "$SCRATCH/runtime-probe.txt"
  echo "  .cargo/config.toml [env] declares RUST_MIN_STACK=$(sed -n 's/^RUST_MIN_STACK *= *//p' .cargo/config.toml 2>/dev/null | tr -d '"'),"
  echo "  which reaches only processes Cargo starts (cargo run/test), not these."
  echo
  echo "## Binaries under test"
  echo "directory        : $BIN_DIR"
  echo "  (every measured and support process ran from these copies; hashes are"
  echo "  re-verified after the last run, before any statistic is written)"
  sed 's/^/  /' "$BIN_DIR/SHA256SUMS"
  echo "provenance       :"
  sed 's/^/  /' "$BIN_DIR/PROVENANCE"
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
  echo "status list      : $WORKLOAD_DESC"
  echo "quorum selection : $QUORUM_SELECTION (fixture corpora: t distinct members spread over the whole committee, derived from the version)"
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
[ "$SIGNER_STATE_ON_RAM" = 0 ] || echo "WARNING   : signer state on RAM-backed storage -> sign_protocol and slot_burn do not describe durable signing"
[ -f Cargo.lock ] || echo "WARNING   : Cargo.lock missing -> dependency resolution is not reproducible"
[ "$RUSTFLAGS_OVERRIDDEN" = 0 ] || echo "WARNING   : rustflags overridden from the environment -> binaries differ from the declared build"
[ -z "$FOREIGN_RUSTFLAGS_CONFIG" ] || echo "WARNING   : a Cargo config outside the repository sets rustflags -> see env.txt"
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
# A fixture states its own workload; one generated for another list size or
# quorum selection, or one without workload.txt, is refused before anything is
# measured.
check_fixture_workload() { # label directory
  local want found
  want="$(printf 'list_entries=%s\nquorum=%s\n' "$WORKLOAD_LIST" "$QUORUM_SELECTION")"
  found="$(cat "$2/workload.txt" 2>/dev/null || true)"
  if [ "$found" != "$want" ]; then
    echo "$1 fixture $2 does not declare the requested workload" >&2
    echo "  requested: list_entries=$WORKLOAD_LIST quorum=$QUORUM_SELECTION" >&2
    echo "  fixture  : ${found:-no workload.txt}" | tr '\n' ' ' >&2; echo >&2
    exit 1
  fi
}
[ "$INPUT_MODE" != fixture ] || check_fixture_workload XMSS "$BENCH_INPUT_DIR"
[ "$MLDSA_INPUT_MODE" != fixture ] || check_fixture_workload ML-DSA "$MLDSA_INPUT_DIR"
# The declared workload, machine-readable. Each process is checked against it.
printf 'n=%s\nt=%s\nupdates=%s\nlist_entries=%s\nlist_min=%s\nlist_max=%s\nquorum=%s\nxmss_input=%s\nmldsa_input=%s\n' \
  "$BENCH_N" "$BENCH_T" "$BENCH_UPDATES" "$WORKLOAD_LIST" "$EXPECT_LIST_MIN" "$EXPECT_LIST_MAX" \
  "$QUORUM_SELECTION" "$INPUT_MODE" "$MLDSA_INPUT_MODE" > "$OUTDIR/workload.txt"

# The signed inputs every measured process reads, hashed before the first run
# and again after the last, like the frozen binaries: a corpus that changed
# mid-campaign would have different runs measure different workloads.
fingerprint_inputs() {
  local pair label dir
  for pair in "xmss:$BENCH_INPUT_DIR" "mldsa:$MLDSA_INPUT_DIR"; do
    label="${pair%%:*}"; dir="${pair#*:}"
    [ -n "$dir" ] && [ -d "$dir" ] || continue
    (cd "$dir" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) |
      sed "s|  \./|  $label/|"
  done
}
fingerprint_inputs > "$INPUTS_SHA"

# ----------------------------------------------------- fixed corpus ----
# The verifier must see the SAME workload on every run, so its input is
# generated once and frozen. Re-generating it per run would fold the prover's
# variance into the verifier's numbers.
CORPUS="$SCRATCH/corpus"
CORPUS_SHA="$OUTDIR/corpus.sha256"
corpus_manifest() {
  (cd "$CORPUS" && find . -maxdepth 1 -type f ! -name 'verifier-highwater.state*' -print0 |
     sort -z | xargs -0 -r sha256sum)
}
if grep -qw verifier <<<"$TARGETS"; then
  echo "generating fixed verifier corpus ..."
  env -u BENCH_HONEST_ONLY "$BIN_DIR/prover" "$CORPUS" >/dev/null 2>&1
  "$BIN_DIR/verifier" --init-state "$CORPUS" >/dev/null
  echo "  $(ls "$CORPUS" | wc -l) artifacts, $(du -sh "$CORPUS" | cut -f1)"
  # The records every verifier run reads, bound by hash and re-checked after
  # the last run. The verifier's own high-water state is excluded: it is the
  # process's mutable state, not an input. Small corpora are also kept whole.
  corpus_manifest > "$CORPUS_SHA"
  corpus_mb="$(du -sm "$CORPUS" | cut -f1)"
  if [ "$corpus_mb" -le "$KEEP_CORPUS_MAX_MB" ]; then
    mkdir -p "$OUTDIR/inputs/verifier-corpus"
    find "$CORPUS" -maxdepth 1 -type f ! -name 'verifier-highwater.state*' \
      -exec cp -- {} "$OUTDIR/inputs/verifier-corpus/" \;
    echo "  corpus kept in $OUTDIR/inputs/verifier-corpus"
  else
    echo "  corpus is ${corpus_mb} MiB (> KEEP_CORPUS_MAX_MB=$KEEP_CORPUS_MAX_MB): hashes kept in corpus.sha256, records not copied"
  fi
  echo
fi

# ------------------------------------------------------------ collect ----
echo 'target,run,idx,phase,ms,bytes,rss_mib' > "$SAMPLES"
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
# and a target simply leaves blank the ones it does not have. A shared
# positional column would hold different phases for different targets, and
# anyone plotting it from summary.csv would put two quantities on one axis.
#
# `setup_ms` is the leanVM circuit and ONLY that; `keygen_ms` is the N-key
# generation every path pays, `raw_agg` included; `slot_state_ms` is the N durable
# slot counters, which only a real signer pays. Keeping them apart is what makes
# the fixed-cost columns comparable across targets: `raw_agg` leaves `setup_ms`
# empty because it has no circuit, which is the result, rather than borrowing the
# column for its keygen and making the SNARK look like the cheaper setup.
echo 'target,run,t_start,setup_ms,keygen_ms,slot_state_ms,n_items,sign_med_ms,sign_mean_ms,sign_sd_ms,sign_min_ms,sign_max_ms,sign_total_ms,prove_med_ms,prove_mean_ms,prove_sd_ms,prove_min_ms,prove_max_ms,prove_total_ms,verify_med_ms,verify_mean_ms,verify_sd_ms,verify_min_ms,verify_max_ms,verify_total_ms,artifact_med_bytes,rss_setup_mib,rss_max_mib,peak_rss_mib,kernel_maxrss_mib,failures,load1_start,load1_end,freq_start_mhz,freq_end_mhz,temp_start_c,temp_end_c,decode_med_ms,decode_mean_ms,decode_sd_ms,decode_min_ms,decode_max_ms,decode_total_ms,decode_verify_med_ms,decode_verify_mean_ms,decode_verify_sd_ms,decode_verify_min_ms,decode_verify_max_ms,decode_verify_total_ms,slot_burn_med_ms,slot_burn_total_ms,sign_crypto_med_ms,sign_crypto_total_ms,wall_s,cpu_user_s,cpu_sys_s,cpu_total_s,major_faults,minor_faults,vol_ctx_switches,invol_ctx_switches,swap_in_pages,swap_out_pages,mem_pressure_us,oom_kills,sign_cpu_med_ms,sign_cpu_total_ms,prove_cpu_med_ms,prove_cpu_total_ms,decode_verify_cpu_med_ms,decode_verify_cpu_total_ms,setup_cpu_ms,ready_ms,ready_cpu_ms' > "$RUNS_CSV"

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
C_WALL=54;       C_CPU_TOTAL=57;  C_SWAP_IN=62;  C_SWAP_OUT=63;  C_PRESSURE=64;  C_OOM=65
C_DECODE_MED=38; C_DECODE_TOT=43
C_DECODE_VERIFY_MED=44; C_DECODE_VERIFY_TOT=49
C_SLOT_BURN_MED=50; C_SIGN_CRYPTO_MED=52
# CPU (user + system, every thread) of the same intervals the elapsed columns
# time, read inside the binaries from the process CPU clock; and `ready`, what a
# verifier pays once per process before its first verification.
C_SIGN_CPU_MED=66; C_SIGN_CPU_TOT=67
C_PROVE_CPU_MED=68; C_PROVE_CPU_TOT=69
C_DECODE_VERIFY_CPU_MED=70; C_DECODE_VERIFY_CPU_TOT=71
C_SETUP_CPU=72;  C_READY=73;  C_READY_CPU=74

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
  wrap_target "${cmd[@]}"
  cmd=("${WRAPPED[@]}")

  local events_start events_end
  RUN_T_START="$(date +%s)"
  RUN_LOAD_START="$(load1_now)"
  RUN_FREQ_START="$(freq_now_mhz)"
  RUN_TEMP_START="$(temp_now_c)"
  events_start="$(memory_events_now)"
  EMIT_SAMPLES=1 "${cmd[@]}" >"$SCRATCH/out.txt" 2>"$SCRATCH/err.txt" || rc=$?
  events_end="$(memory_events_now)"
  RUN_LOAD_END="$(load1_now)"
  RUN_FREQ_END="$(freq_now_mhz)"
  RUN_TEMP_END="$(temp_now_c)"
  # Host-wide deltas over this process: pages swapped in and out, microseconds
  # some task was stalled on memory, OOM kills. Empty when the kernel does not
  # expose a counter; never a made-up 0.
  RUN_MEMORY_EVENTS="$(awk -v a="$events_start" -v b="$events_end" 'BEGIN {
    split(a, s, " "); split(b, e, " ")
    for (i = 1; i <= 4; i++) printf "%s%s", (i > 1 ? "," : ""), (s[i] == "NA" || e[i] == "NA") ? "" : e[i] - s[i]
  }')"
  return $rc
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

# One field of the `time -v` report this run left in err.txt; empty without it.
time_report() { # label regex
  [ -n "$TIME_BIN" ] || { echo ""; return; }
  awk -v label="$1" 'index($0, label) { print $NF; exit }' "$SCRATCH/err.txt"
}
# wall_s,cpu_user_s,cpu_sys_s,cpu_total_s,major_faults,minor_faults,
# vol_ctx_switches,invol_ctx_switches for the process that just ran. `time`
# reports CPU in hundredths of a second, summed over all threads and including
# setup: it is whole-process CPU, not the cost of one update.
process_accounting() {
  local wall user system
  wall="$(time_report 'Elapsed (wall clock) time')"
  user="$(time_report 'User time (seconds)')"
  system="$(time_report 'System time (seconds)')"
  awk -v wall="$wall" -v user="$user" -v sys="$system" \
      -v major="$(time_report 'Major (requiring I/O) page faults')" \
      -v minor="$(time_report 'Minor (reclaiming a frame) page faults')" \
      -v vol="$(time_report 'Voluntary context switches')" \
      -v invol="$(time_report 'Involuntary context switches')" 'BEGIN {
    seconds = ""
    if (wall != "") { n = split(wall, part, ":"); seconds = 0; for (i = 1; i <= n; i++) seconds = seconds * 60 + part[i]; seconds = sprintf("%.2f", seconds) }
    total = (user != "" && sys != "") ? sprintf("%.2f", user + sys) : ""
    printf "%s,%s,%s,%s,%s,%s,%s,%s", seconds, user, sys, total, major, minor, vol, invol
  }'
}

kernel_maxrss_mib() {
  [ -n "$TIME_BIN" ] || { echo ""; return; }
  # KiB to MiB with one decimal: a raw verifier uses a few MiB, so whole MiB
  # would be too coarse.
  awk '/Maximum resident set size/ { printf "%.1f", $NF/1024 }' "$SCRATCH/err.txt"
}

# A prover run counts only if a separate process accepts what it wrote. Its exit
# status proves it did not crash, not that its records verify, and the verifier
# target measures a corpus from an earlier, unmeasured prover invocation. This
# runs after the prover's telemetry is read and before the next cooldown, so it
# is inside no timer and no RSS reading. A rejection keeps the output and logs
# in $OUTDIR for diagnosis and withholds every number, warm-ups included.
#
# Acceptance needs positive evidence on three independent signals: exit status 0,
# `failures=0`, and `n_valid` equal to both the checker's `expected` and this
# script's own BENCH_UPDATES. A checker that exits 0 having validated nothing is
# rejected here as well as in the checker itself. It runs under the same CPU mask
# as the targets, so its extra load stays on the cores the campaign declares.
PROVER_CHECK_FAILURES=""
accept_prover_run() { # $1 1-based index within the prover schedule
  local keep line valid expected failures
  local -a cmd=("$BIN_DIR/check_prover_output" "$SCRATCH/pout")
  [ -n "$BENCH_INPUT_DIR" ] && cmd+=("$BENCH_INPUT_DIR")
  [ -n "$PIN_CPUS" ] && cmd=(taskset -c "$PIN_CPUS" "${cmd[@]}")
  PROVER_CHECK_FAILURES=""
  if "${cmd[@]}" >"$SCRATCH/check.txt" 2>&1; then
    line="$(grep '^PROVER_OUTPUT_CHECK ' "$SCRATCH/check.txt" || true)"
    valid="$(sed -n 's/.* n_valid=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    expected="$(sed -n 's/.* expected=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    failures="$(sed -n 's/.* failures=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    if [ "$failures" = 0 ] && [ -n "$valid" ] &&
       [ "$valid" = "$expected" ] && [ "$valid" = "$BENCH_UPDATES" ]; then
      PROVER_CHECK_FAILURES=0
      # The accepted records are large and reproducible from the kept inputs
      # only up to proof randomness, so their hashes and sizes are kept, not
      # the files (a rejected execution keeps everything, below).
      {
        echo "# prover execution $1"
        (cd "$SCRATCH/pout" && find . -maxdepth 1 -type f -print0 | sort -z |
           xargs -0 -r sh -c 'for f; do printf "%s  %s  %s\n" "$(sha256sum < "$f" | cut -d" " -f1)" "$(wc -c < "$f")" "${f#./}"; done' sh)
      } >> "$OUTDIR/prover-outputs.sha256"
      return 0
    fi
  fi
  keep="$OUTDIR/rejected-prover-execution-$1"
  rm -rf "$keep"
  mkdir -p "$keep"
  cp -r "$SCRATCH/pout" "$keep/output" 2>/dev/null || true
  cp "$SCRATCH/check.txt" "$SCRATCH/out.txt" "$SCRATCH/err.txt" "$keep/" 2>/dev/null || true
  echo >&2
  echo "ABORT: prover execution $1 wrote records that check_prover_output rejects:" >&2
  tail -20 "$SCRATCH/check.txt" >&2
  echo "output and logs kept in $keep. Numbers withheld." >&2
  exit 1
}

# Normalise the one-line record each binary emits into a runs.csv row.
emit_run_row() { # $1 target  $2 run index
  local target="$1" run="$2" kmax; kmax="$(kernel_maxrss_mib)"
  local tag
  case "$target" in
    mldsa_signer) tag='^MLDSA_SIGNER ' ;;
    mldsa_raw_agg) tag='^MLDSA_RAW_AGG ' ;;
    signer) tag='^SIGNER ' ;; prover) tag='^PROVER ' ;; verifier) tag='^VERIFIER ' ;;
    combined) tag='^BENCH ' ;; raw_agg) tag='^RAW_AGG ' ;;
  esac
  local line; line="$(grep "$tag" "$SCRATCH/out.txt" || true)"
  [ -n "$line" ] || { echo "run $run ($target): record line missing" >&2; exit 1; }
  awk -v t="$target" -v r="$run" -v k="$kmax" -v ts="$RUN_T_START" -v pc="$PROVER_CHECK_FAILURES" \
      -v accounting="$(process_accounting),$RUN_MEMORY_EVENTS" \
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
    # CPU of the timed phases and the cold-start cost of a verifier, under the
    # key names the binaries print; a target that reports none leaves it empty.
    sg_cpu_med=v["sign_cpu_med_ms"]; sg_cpu_tot=v["sign_cpu_total_ms"]
    pv_cpu_med=v["prove_cpu_med_ms"]; pv_cpu_tot=v["prove_cpu_total_ms"]
    dv_cpu_med=v["total_cpu_med_ms"]; dv_cpu_tot=v["total_cpu_total_ms"]
    setup_cpu=v["setup_cpu_ms"]; ready=v["ready_ms"]; ready_cpu=v["ready_cpu_ms"]
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
      pb=v["sig_bytes"]; rs=v["rss_keygen_mib"]; rm=v["rss_rounds_max_mib"]; pk=v["peak_rss_mib"]
      # Every round self-verifies; a missing key means the run told us nothing.
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="mldsa_signer") {
      # ML-DSA is stateless: there is one key but no durable slot counter.
      keygen=v["keygen_ms"]; n=v["n_rounds"]
      sg_med=v["sign_med_ms"]; sg_mean=v["sign_mean_ms"]; sg_sd=v["sign_sd_ms"]
      sg_lo=v["sign_min_ms"]; sg_hi=v["sign_max_ms"]; sg_tot=v["sign_total_ms"]
      cr_med=sg_med; cr_tot=sg_tot
      pb=v["sig_bytes"]; rs=v["rss_keygen_mib"]; rm=v["rss_rounds_max_mib"]; pk=v["peak_rss_mib"]
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="prover") {
      # Aggregator. It signs to have something to aggregate, but does not time it:
      # those t signatures come from t machines in a deployment, one each.
      setup=v["setup_ms"]; keygen=v["keygen_ms"]; n=v["n_updates"]
      pv_med=v["prove_med_ms"]; pv_mean=v["prove_mean_ms"]; pv_sd=v["prove_sd_ms"]
      pv_lo=v["prove_min_ms"]; pv_hi=v["prove_max_ms"]; pv_tot=v["prove_total_ms"]
      pb=v["record_med_bytes"]; rs=v["rss_setup_mib"]; rm=v["rss_updates_max_mib"]; pk=v["peak_rss_mib"]
      # The prover never verifies, so its verdict comes from accept_prover_run.
      # Empty means that check never reported, which is a failure, not a zero.
      f=(pc=="")?1:pc
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
      pb=""; rs=v["rss_setup_mib"]; rm=v["rss_verify_max_mib"]; pk=v["peak_rss_mib"]
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="raw_agg") {
      # Baseline. `setup` stays EMPTY on purpose: this path builds no circuit, and
      # that absence is the headline result. Key generation is a cost both paths
      # pay and must not enter the column that means "what the SNARK costs
      # extra". The artifact column is the complete serialized StatusList
      # record; the tamper sanity check drives the failure gate.
      keygen=v["keygen_ms"]; slotstate=v["slot_state_ms"]; n=v["n_updates"]
      vf_med=v["verify_med_ms"]; vf_mean=v["verify_mean_ms"]; vf_sd=v["verify_sd_ms"]
      vf_lo=v["verify_min_ms"]; vf_hi=v["verify_max_ms"]; vf_tot=v["verify_total_ms"]
      dc_med=v["decode_med_ms"]; dc_mean=v["decode_mean_ms"]; dc_sd=v["decode_sd_ms"]
      dc_lo=v["decode_min_ms"]; dc_hi=v["decode_max_ms"]; dc_tot=v["decode_total_ms"]
      dv_med=v["total_med_ms"]; dv_mean=v["total_mean_ms"]; dv_sd=v["total_sd_ms"]
      dv_lo=v["total_min_ms"]; dv_hi=v["total_max_ms"]; dv_tot=v["total_total_ms"]
      pb=v["record_med_bytes"]; rs=v["rss_keygen_mib"]; rm=v["rss_updates_max_mib"]; pk=v["peak_rss_mib"]
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
      pb=v["record_med_bytes"]; rs=v["rss_anchor_mib"]; rm=v["rss_updates_max_mib"]; pk=v["peak_rss_mib"]
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
      pb=v["proof_med_bytes"]; rs=v["rss_setup_mib"]; rm=v["rss_updates_max_mib"]; pk=v["peak_rss_mib"]
      f=(v["sec_ok"]=="1")?0:1
    }
    printf "%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
      t,r,ts,setup,keygen,slotstate,n,
      sg_med,sg_mean,sg_sd,sg_lo,sg_hi,sg_tot,
      pv_med,pv_mean,pv_sd,pv_lo,pv_hi,pv_tot,
      vf_med,vf_mean,vf_sd,vf_lo,vf_hi,vf_tot,
      pb,rs,rm,pk,k,f,ls,le,fs,fe,cs,ce,
      dc_med,dc_mean,dc_sd,dc_lo,dc_hi,dc_tot,
      dv_med,dv_mean,dv_sd,dv_lo,dv_hi,dv_tot,
      rb_med,rb_tot,cr_med,cr_tot,accounting,
      sg_cpu_med,sg_cpu_tot,pv_cpu_med,pv_cpu_tot,dv_cpu_med,dv_cpu_tot,setup_cpu,ready,ready_cpu
  }' <<<"$line" >> "$RUNS_CSV"

  # Raw per-update samples.
  awk -v t="$target" -v r="$run" '
    /^SAMPLE / {
      delete v; for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
      if (v["target"]=="signer") {
        printf "%s,%d,%s,sign_protocol,%s,%s,%s\n", t,r,v["idx"],v["sign_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,slot_burn,%s,%s,%s\n", t,r,v["idx"],v["reserve_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,sign_crypto,%s,%s,%s\n", t,r,v["idx"],v["crypto_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,sign_protocol_cpu,%s,%s,%s\n", t,r,v["idx"],v["cpu_ms"],v["bytes"],v["rss_mib"]
      } else if (v["target"]=="mldsa_signer") {
        printf "%s,%d,%s,sign_crypto,%s,%s,%s\n", t,r,v["idx"],v["sign_ms"],v["sig_bytes"],v["rss_mib"]
        printf "%s,%d,%s,sign_crypto_cpu,%s,%s,%s\n", t,r,v["idx"],v["cpu_ms"],v["sig_bytes"],v["rss_mib"]
      } else if (v["target"]=="prover") {
        printf "%s,%d,%s,prove,%s,%s,%s\n",  t,r,v["idx"],v["prove_ms"], v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,prove_cpu,%s,%s,%s\n",  t,r,v["idx"],v["cpu_ms"], v["bytes"],v["rss_mib"]
      } else if (v["target"]=="verifier") {
        printf "%s,%d,%s,decode,%s,%s,%s\n", t,r,v["idx"],v["decode_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,decode_verify,%s,%s,%s\n", t,r,v["idx"],v["total_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,decode_verify_cpu,%s,%s,%s\n", t,r,v["idx"],v["cpu_ms"],v["bytes"],v["rss_mib"]
      } else if (v["target"]=="raw_agg") {
        printf "%s,%d,%s,decode,%s,%s,%s\n", t,r,v["idx"],v["decode_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,decode_verify,%s,%s,%s\n", t,r,v["idx"],v["total_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,decode_verify_cpu,%s,%s,%s\n", t,r,v["idx"],v["cpu_ms"],v["bytes"],v["rss_mib"]
      } else if (v["target"]=="mldsa_raw_agg") {
        printf "%s,%d,%s,decode,%s,%s,%s\n", t,r,v["idx"],v["decode_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,decode_verify,%s,%s,%s\n", t,r,v["idx"],v["total_ms"],v["bytes"],v["rss_mib"]
        printf "%s,%d,%s,decode_verify_cpu,%s,%s,%s\n", t,r,v["idx"],v["cpu_ms"],v["bytes"],v["rss_mib"]
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

# The list sizes a process reports in its summary line must be the declared
# workload. The list size labels every figure of the campaign, so it is taken
# from the measured process, not from the variable this script exported: a
# binary that ignored it, or a corpus built for another size, stops here.
check_workload() { # target  schedule index
  local tag line lo hi
  case "$1" in
    mldsa_signer) tag='^MLDSA_SIGNER ' ;; mldsa_raw_agg) tag='^MLDSA_RAW_AGG ' ;;
    signer) tag='^SIGNER ' ;; verifier) tag='^VERIFIER ' ;;
    prover) tag='^PROVER ' ;; raw_agg) tag='^RAW_AGG ' ;;
    *) return 0 ;;
  esac
  # The self-contained diagnostic shape keeps each target's native workload.
  if [ "$INPUT_MODE" = self-contained ]; then
    case "$1" in prover|raw_agg|verifier) return 0 ;; esac
  fi
  line="$(grep "$tag" "$SCRATCH/out.txt" || true)"
  lo="$(sed -n 's/.* list_min=\([^ ]*\).*/\1/p' <<<"$line")"
  hi="$(sed -n 's/.* list_max=\([^ ]*\).*/\1/p' <<<"$line")"
  if [ "$lo" != "$EXPECT_LIST_MIN" ] || [ "$hi" != "$EXPECT_LIST_MAX" ]; then
    echo >&2
    echo "ABORT: $1 process $2 handled lists of ${lo:-?}..${hi:-?} entries;" >&2
    echo "the declared workload is $EXPECT_LIST_MIN..$EXPECT_LIST_MAX ($WORKLOAD_DESC). Numbers withheld." >&2
    exit 1
  fi
}

# One measured run of one target, plus the gates. Shared by both schedules.
# schedule.csv records the sequence that actually ran, warm-ups included: one
# `cooldown`, `start` and `end` event per process, with its design row and
# position when the order is interleaved. A `start` with no `end` is where an
# interrupted campaign stopped. runs.csv keeps only measured runs.
SCHEDULE="$OUTDIR/schedule.csv"
echo 'seq,time_ns,event,phase,target,index,design_row,position,detail' > "$SCHEDULE"
SCHEDULE_SEQ=0
LOG_DIR="$OUTDIR/logs"
mkdir -p "$LOG_DIR"
schedule_event() { # event phase target index row position detail
  SCHEDULE_SEQ=$((SCHEDULE_SEQ + 1))
  printf '%d,%s,%s,%s,%s,%s,%s,%s,%s\n' "$SCHEDULE_SEQ" "$(date +%s%N)" "$@" >> "$SCHEDULE"
}

do_one() { # $1 target  $2 1-based index within that target's schedule  [$3 design row  $4 position]
  local target="$1" i="$2" row="${3:-}" position="${4:-}" tw tr phase index rc=0 log_base
  local runs_var="RUNS_$target" warmup_var="WARMUP_$target"
  tw="${!warmup_var:-$WARMUP}"
  tr="${!runs_var:-$RUNS}"
  if [ "$i" -le "$tw" ]; then phase=warmup; index="$i"; else phase=measured; index=$((i - tw)); fi

  schedule_event cooldown "$phase" "$target" "$index" "$row" "$position" "${COOLDOWN_SECONDS}s"
  [ "$COOLDOWN_SECONDS" -eq 0 ] || sleep "$COOLDOWN_SECONDS"
  schedule_event start "$phase" "$target" "$index" "$row" "$position" ""
  run_once "$target" || rc=$?
  schedule_event end "$phase" "$target" "$index" "$row" "$position" "exit=$rc"
  # Keep what this process printed, warm-ups and failures included: stdout with
  # its summary and sample lines, stderr with the complete `time -v` report.
  log_base="$LOG_DIR/$(printf '%05d' "$SCHEDULE_SEQ")-$phase-$target-$index"
  cp -- "$SCRATCH/out.txt" "$log_base.out"
  cp -- "$SCRATCH/err.txt" "$log_base.err"
  if [ "$rc" -ne 0 ]; then
    echo "  $target run $i FAILED (exit != 0) — see below" >&2
    # stderr first: a Rust panic lands there, and $SCRATCH is wiped on exit.
    tail -5 "$SCRATCH/err.txt" >&2
    tail -5 "$SCRATCH/out.txt" >&2
    exit 1
  fi
  check_workload "$target" "$i"
  if [ "$target" = prover ]; then accept_prover_run "$i"; fi
  if [ "$i" -le "$tw" ]; then
    printf '  %-9s warmup %d/%d\n' "$target" "$i" "$tw"
    return 0
  fi
  emit_run_row "$target" "$((i - tw))"
  printf '  %-9s run %d/%d\n' "$target" "$((i - tw))" "$tr"

  # Fail fast: checking after each row costs one awk pass, and a broken target
  # stops the campaign at its first run instead of after every other target
  # has finished.
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
balanced_design_rows() { # rows in one complete design for the selected targets
  local n="${#TARGET_LIST[@]}"
  if [ $((n % 2)) -eq 1 ]; then echo $((2 * n)); else echo "$n"; fi
}
balanced_row() { # $1 zero-based row; any row number, the design repeats
  local row="$1" n="${#TARGET_LIST[@]}" reverse=0 pos sequence_pos base index
  # Reduce to a row of one design first, so that an odd design (N rotations
  # followed by their reversals) repeats as a whole and every order runs
  # equally often.
  row=$((row % $(balanced_design_rows)))
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

# The balance holds only over complete designs run by every target alike. Fewer
# runs than a multiple of the design, or per-target counts that differ, leave
# some positions and predecessors over-represented; say so rather than call the
# order balanced.
ORDER_NOTE=""
if [ "$INTERLEAVE" = 1 ]; then
  design_rows="$(balanced_design_rows)"
  equal_runs=1
  for target in "${TARGET_LIST[@]}"; do
    runs_var="RUNS_$target"
    [ "${!runs_var:-$RUNS}" = "$RUNS" ] || equal_runs=0
  done
  if [ "$equal_runs" = 0 ]; then
    ORDER_NOTE="per-target RUNS_<target> differ, so the design is incomplete"
  elif [ $((RUNS % design_rows)) -ne 0 ]; then
    ORDER_NOTE="$RUNS runs is not a multiple of the $design_rows-row design for ${#TARGET_LIST[@]} targets"
  fi
fi

if [ "$INTERLEAVE" = 1 ]; then
  echo "== balanced interleaved sweep =="
  [ -z "$ORDER_NOTE" ] || echo "WARNING: order only partly balanced: $ORDER_NOTE"
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
    position=0
    while IFS= read -r target; do
      position=$((position + 1))
      [ "$step" -le "${WARMUP_LENGTH[$target]}" ] || continue
      do_one "$target" "$step" "$((step - 1))" "$position"
    done < <(balanced_row "$((step - 1))")
  done
  for ((step=1; step<=max_runs; step++)); do
    position=0
    while IFS= read -r target; do
      position=$((position + 1))
      [ "$step" -le "${RUN_LENGTH[$target]}" ] || continue
      do_one "$target" "$((WARMUP_LENGTH[$target] + step))" "$((step - 1))" "$position"
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
# The recorded hashes must still describe what ran.
verify_frozen_bins || { echo "ABORT: binaries changed during the campaign; numbers withheld" >&2; exit 1; }
fingerprint_inputs | cmp -s - "$INPUTS_SHA" ||
  { echo "ABORT: signed inputs changed during the campaign; numbers withheld" >&2; exit 1; }
if [ -f "$CORPUS_SHA" ]; then
  corpus_manifest | cmp -s - "$CORPUS_SHA" ||
    { echo "ABORT: the verifier corpus changed during the campaign; numbers withheld" >&2; exit 1; }
fi

# ---------------------------------------------------------- aggregate ----
# Descriptive stats on stdin (one number per line), from the one module both
# harnesses share: n min q1 median q3 max mean sd cv% mean_ci95_halfwidth.
# Quantiles are type 7; the interval is the exact Student-t CI of the mean for
# df = n-1. A statistic that cannot be estimated (sd, cv and CI from one run;
# everything from none) is NA, never 0. See tools/stats.awk.
stats() { sort -g | awk -f "$REPO/tools/stats.awk"; }

col() { awk -F, -v t="$1" -v c="$2" 'NR>1 && $1==t && $c!="" {print $c}' "$RUNS_CSV"; }

echo 'target,metric,unit,n,min,q1,median,q3,max,mean,sd,cv_pct,mean_ci95_halfwidth' > "$SUMMARY_CSV"

emit() { # target metric unit column
  local vals; vals="$(col "$1" "$4")"
  [ -n "$vals" ] || return 0
  local st; st="$(printf '%s\n' "$vals" | stats)"
  # NA (not estimable) becomes an empty cell, the CSV's "absent", never a 0.
  printf '%s,%s,%s,%s\n' "$1" "$2" "$3" "$(awk -v OFS=, '{$1 = $1; for (i = 1; i <= NF; i++) if ($i == "NA") $i = ""; print}' <<<"$st")" >> "$SUMMARY_CSV"
}

# The metric id in summary.csv names the phase, so the file is readable on its
# own: `prove_per_item` and `verify_per_item` are different rows.
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
  # The CPU each timed phase used (user + system, every thread), per item and
  # per run, next to the elapsed rows above. Elapsed answers "how long does a
  # caller wait", CPU "how much computation is that": they differ whenever the
  # work is parallel (prover) or waits for a device (the XMSS durable burn).
  case "$target" in
    signer) emit "$target" sign_protocol_cpu_per_item ms "$C_SIGN_CPU_MED"
            emit "$target" sign_protocol_cpu_total ms "$C_SIGN_CPU_TOT" ;;
    mldsa_signer) emit "$target" sign_crypto_cpu_per_item ms "$C_SIGN_CPU_MED"
            emit "$target" sign_crypto_cpu_total ms "$C_SIGN_CPU_TOT" ;;
  esac
  emit "$target" prove_cpu_per_item ms "$C_PROVE_CPU_MED"
  emit "$target" prove_cpu_total ms "$C_PROVE_CPU_TOT"
  emit "$target" decode_verify_cpu_per_item ms "$C_DECODE_VERIFY_CPU_MED"
  emit "$target" decode_verify_cpu_total ms "$C_DECODE_VERIFY_CPU_TOT"
  emit "$target" setup_cpu ms "$C_SETUP_CPU"
  # What a verifier pays once per process before its first verification: read
  # and decode the anchor, build the verifier and, on the SNARK path, set up
  # the circuit (so `ready` contains `setup`). A resident verifier pays it
  # once; a process started per request pays it every time.
  emit "$target" ready ms "$C_READY"
  emit "$target" ready_cpu ms "$C_READY_CPU"
  case "$target" in
    signer|mldsa_signer) emit "$target" signature_size bytes "$C_ARTIFACT" ;;
    prover)   emit "$target" record_size    bytes "$C_ARTIFACT" ;;
    raw_agg|mldsa_raw_agg) emit "$target" record_size bytes "$C_ARTIFACT" ;;
    combined) emit "$target" proof_size     bytes "$C_ARTIFACT" ;;
  esac
  # KiB / 1024: MiB, as the `_mib` column names say.
  emit "$target" rss_after_setup  MiB   "$C_RSS_SETUP"
  emit "$target" rss_max          MiB   "$C_RSS_MAX"
  emit "$target" peak_rss_vmhwm   MiB   "$C_PEAK"
  emit "$target" peak_rss_kernel  MiB   "$C_KERNEL"
  # Whole-process accounting from `time -v`: elapsed time and user+system CPU
  # over every thread, setup included. A process that used several cores has
  # more CPU than wall time; `time` resolves both to 0.01 s.
  emit "$target" process_wall     s     "$C_WALL"
  emit "$target" process_cpu      s     "$C_CPU_TOTAL"
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

# Human labels. Only `raw_agg` needs its own cases; everything else follows
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
    signer:sign_protocol_cpu_per_item) echo "XMSS protocol sign CPU" ;;
    signer:sign_protocol_cpu_total) echo "XMSS sign CPU total" ;;
    mldsa_signer:sign_crypto_cpu_per_item) echo "ML-DSA crypto sign CPU" ;;
    mldsa_signer:sign_crypto_cpu_total) echo "ML-DSA sign CPU total" ;;
    *:prove_cpu_per_item)    echo "prove CPU / update" ;;
    *:prove_cpu_total)       echo "prove CPU total / run" ;;
    raw_agg:decode_verify_cpu_per_item) echo "XMSS decode+verify CPU" ;;
    verifier:decode_verify_cpu_per_item) echo "SNARK decode+verify CPU" ;;
    mldsa_raw_agg:decode_verify_cpu_per_item) echo "ML-DSA decode+verify CPU" ;;
    *:decode_verify_cpu_total) echo "decode+verify CPU total" ;;
    *:setup_cpu)             echo "setup CPU (circuit, once)" ;;
    *:ready)                 echo "ready to verify (once)" ;;
    *:ready_cpu)             echo "ready to verify CPU" ;;
    *:process_wall)          echo "process elapsed" ;;
    *:process_cpu)           echo "process CPU user+sys" ;;
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
  echo "workload  : (N=$BENCH_N, t=$BENCH_T, $WORKLOAD_L): status list $WORKLOAD_DESC;"
  echo "            $BENCH_UPDATES versions per process; quorums $QUORUM_SELECTION"
  echo "XMSS input: $INPUT_MODE"
  echo "MLDSA input: $MLDSA_INPUT_MODE"
  if [ "$SIGNER_STATE_USED" = 1 ]; then
    echo "signer st.: $SIGNER_STORAGE"
    [ "$SIGNER_STATE_ON_RAM" = 0 ] ||
      echo "WARNING   : signer state is on RAM-backed storage: the durable-burn barrier is not a device flush, so sign_protocol and slot_burn do not describe durable XMSS signing"
  fi
  echo "order     : $([ "$INTERLEAVE" = 1 ] && echo 'Williams-style balanced across targets' || echo 'contiguous blocks per target')"
  [ -z "$ORDER_NOTE" ] || echo "WARNING   : order only partly balanced: $ORDER_NOTE"
  echo "cooldown  : ${COOLDOWN_SECONDS}s before each target process"
  echo "runs      : n=$RUNS measured, $WARMUP warmup(s) discarded (default;"
  echo "            RUNS_<target> may override — the authoritative count is the"
  echo "            per-row 'n' column below)"
  echo "unit      : per-run value; for per-update metrics, the per-run median"
  echo "ci95      : of the MEAN of per-run values; exact Student t, df=n-1; n/a"
  echo "            with fewer than two runs (never a zero-width interval). This is a"
  echo "            PRECISION interval for the mean of repeated runs on THIS host in"
  echo "            THIS session. It says nothing about other hardware, other"
  echo "            builds, or this machine on another day."
  # The acronym is expanded here, once, and every memory row below is then free
  # to say just "RSS" — spelling it out on each of four rows per target buries
  # the one thing that actually differs between them (which peak, whose reading).
  echo "memory    : the MiB rows are RSS, resident set size — the physical pages"
  echo "            the process holds. A 'peak' row is the high-water mark over"
  echo "            the whole run, read two independent ways: VmHWM is the"
  echo "            process's own /proc/self/status (whole MiB), kernel is"
  echo "            ru_maxrss from ${TIME_BIN:-time -v (unavailable in this run: no kernel rows)}."
  echo "            A peak covers the WHOLE process: setup, the measured updates"
  echo "            and, for the verifiers, the negative controls that follow"
  echo "            them. 'RSS max during work' is the largest reading sampled"
  echo "            after each honest update, not a continuous peak. The median"
  echo "            column is a typical run and the max column the largest"
  echo "            observed; neither is a capacity bound for sizing a host."
  if awk -F, 'NR>1 && $8=="warning" {found=1} END{exit !found}' "$DRIFT_CSV"; then
    echo "WARNING   : early/late regime change detected; do not treat this session"
    echo "            as stationary or publish its confidence intervals unchanged:"
    awk -F, 'NR>1 && $8=="warning" {printf "            %s %s: early %s ms, late %s ms (%+.1f%%)\n",$1,$2,$5,$6,$7}' "$DRIFT_CSV"
  fi
  # Paging and memory stalls slow a process without failing it. These are
  # host-wide counters read around each measured process (runs.csv keeps them
  # per run); a run under paging is not comparable with one without.
  awk -F, -v si="$C_SWAP_IN" -v so="$C_SWAP_OUT" -v pr="$C_PRESSURE" -v oom="$C_OOM" '
    NR > 1 {
      if ($si == "" || $so == "") unknown++
      if ($si + $so > 0) { paged++; pages += $si + $so }
      if ($oom + 0 > 0) kills += $oom
      if ($pr != "") { stalled += $pr; seen = 1 }
    }
    END {
      if (paged || kills)
        printf "WARNING   : memory pressure during measured runs: %d run(s) with paging (%d pages), %d OOM kill(s); those timings include paging\n", paged, pages, kills
      else if (unknown == NR - 1)
        print "paging    : swap counters unavailable on this kernel; not checked"
      else
        printf "paging    : none during measured runs (0 pages swapped, 0 OOM kills%s)\n", seen ? sprintf("; %.1f ms of memory stall host-wide", stalled / 1000) : ""
    }' "$RUNS_CSV"
  echo
  printf '%-9s %-23s %-6s %3s %10s %10s %10s %10s %10s %8s %9s\n' \
    target metric unit n min median max mean sd 'cv%' 'mean±ci95'
  awk -F, 'NR>1' "$SUMMARY_CSV" | while IFS=, read -r t m u n mn q1 md q3 mx mean sd cv ci; do
    d=2; [ "$u" = bytes ] && d=0; [ "$u" = MiB ] && d=1
    # An empty sd/cv/ci cell is "not estimable" and is shown as such, not as 0.
    sd_s=n/a; cv_s=n/a; ci_s=n/a
    [ -n "$sd" ] && sd_s="$(printf '%.*f' $d "$sd")"
    [ -n "$cv" ] && cv_s="$(printf '%.1f%%' "$cv")"
    [ -n "$ci" ] && ci_s="$(printf '%.*f' $d "$ci")"
    printf '%-9s %-23s %-6s %3s %10.*f %10.*f %10.*f %10.*f %10s %8s %9s\n' \
      "$t" "$(label "$t" "$m")" "$u" "$n" $d "$mn" $d "$md" $d "$mx" $d "$mean" "$sd_s" "$cv_s" "$ci_s"
  done

  # Headline comparison: the reason the split exists, across the three processes
  # that actually run in it. Guard on the RAW columns, not on stats() output:
  # an empty column yields NA, which must skip this block rather than reach the
  # arithmetic when a run omits these targets.
  #
  # Prover and verifier are two deployed roles that run apart, so they are the
  # pair to compare (not the combined process, which nobody deploys); the
  # signer shows the full span between roles.
  sp_raw="$(col signer "$C_PEAK")"
  vp_raw="$(col verifier "$C_PEAK")"; pp_raw="$(col prover "$C_PEAK")"
  if [ -n "$vp_raw" ] && [ -n "$pp_raw" ]; then
    vp="$(printf '%s\n' "$vp_raw" | stats | awk '{print $4}')"
    pp="$(printf '%s\n' "$pp_raw" | stats | awk '{print $4}')"
    sp=""; [ -n "$sp_raw" ] && sp="$(printf '%s\n' "$sp_raw" | stats | awk '{print $4}')"
    echo
    echo "PEAK RSS BY ROLE (median) — why the deployment splits"
    [ -n "$sp" ] && awk -v s="$sp" 'BEGIN{ printf "  member    (signer)  : %.0f MiB\n", s }'
    awk -v v="$vp" 'BEGIN{ printf "  verifier            : %.0f MiB\n", v }'
    awk -v p="$pp" 'BEGIN{ printf "  aggregator (prover) : %.0f MiB\n", p }'
    awk -v v="$vp" -v p="$pp" 'BEGIN{
      printf "  a node that only verifies saves %.1f%% (%.0f MiB) against proving\n", 100*(p-v)/p, p-v
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
      a = k - s; if (a < 0) a = -a
      d = 100 * a / k
      # VmHWM is truncated to whole MiB and the kernel reading is not, so a
      # difference under 1 MiB is rounding, however large in percent.
      if (d > 5 && a >= 1) printf "WARNING   : %s peak RSS disagrees — VmHWM %.0f MiB vs kernel %.1f MiB (%.1f%%)\n", t, s, k, d
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
  echo "    every run re-executes the binary, so each target above paid it on every"
  echo "    execution (measured runs plus warm-ups):"
  for target in "${TARGET_LIST[@]}"; do
    runs_var="RUNS_$target"; warmup_var="WARMUP_$target"
    echo "      $target: $(( ${!runs_var:-$RUNS} + ${!warmup_var:-$WARMUP} )) executions"
  done
  echo "    It dominates total time; never fold it into per-update figures."
  if [ -n "${SEEN_TARGETS[prover]:-}" ]; then
    echo "  * Every prover execution, warm-ups included, was accepted only after a"
    echo "    separate, unmeasured check_prover_output process verified all of its"
    if [ -n "$BENCH_INPUT_DIR" ]; then
      echo "    records against the fixture's anchor, versions and lists."
    else
      echo "    records against their own anchor (self-contained: no external reference)."
    fi
    echo "    That process adds untimed CPU load before the next target's cooldown."
  fi
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
  echo "  * Every figure is for the declared workload ($WORKLOAD_L entries, 32 bytes each),"
  echo "    confirmed by each measured process. Record sizes include the list;"
  echo "    decode and verification read it once per record on every path. A member's"
  echo "    sign rows exclude hashing the list into the signed message (XMSS:"
  echo "    BLAKE2s; ML-DSA: SHAKE256), which each member also does once."
  echo "    Do not carry a figure to another list size."
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

# ------------------------------------------------------------ publish ----
# Every check has passed: move the derived results under their published names
# (a rename within OUTDIR), bind every file that describes this campaign with
# outputs.sha256, and only then declare it complete. A consumer that requires
# `complete` and a matching outputs.sha256 never mixes two campaigns' files.
for staged in summary.csv summary.txt drift.csv; do
  mv -- "$STAGE/$staged" "$OUTDIR/$staged"
done
rmdir "$STAGE"
# Every per-process log, bound through one manifest of their hashes.
(cd "$OUTDIR" && find logs -type f -print0 | sort -z | xargs -0 -r sha256sum) > "$OUTDIR/logs.sha256"
PUBLISHED=(env.txt workload.txt inputs.sha256 schedule.csv logs.sha256 samples.csv runs.csv summary.csv
           summary.txt drift.csv source-status.txt source.patch)
[ ! -f "$CORPUS_SHA" ] || PUBLISHED+=(corpus.sha256)
[ ! -f "$OUTDIR/prover-outputs.sha256" ] || PUBLISHED+=(prover-outputs.sha256)
(cd "$OUTDIR" && sha256sum -- "${PUBLISHED[@]}") > "$OUTPUTS_SHA"
CAMPAIGN_STATE=complete
printf 'complete\ncampaign %s validated and published %s\n' "$CAMPAIGN_ID" "$(date -Is)" > "$STATUS_FILE"

echo
echo "written (campaign $CAMPAIGN_ID, status complete):"
echo "  $ENV_FILE"
echo "  $SAMPLES      ($(( $(wc -l < "$SAMPLES") - 1 )) raw observations)"
echo "  $RUNS_CSV"
echo "  $OUTDIR/summary.csv"
echo "  $OUTDIR/summary.txt"
echo "  $OUTDIR/drift.csv"
echo "  $SOURCE_STATUS"
echo "  $SOURCE_PATCH"
echo "  $SCHEDULE"
echo "  $INPUTS_SHA"
echo "  $OUTPUTS_SHA"
echo "  $STATUS_FILE"
if [ "$PLOT" = 1 ]; then
  python3 "$REPO/tools/plot_benchmarks.py" "$OUTDIR"
fi
