#!/usr/bin/env bash
# Reproducible benchmark of the committee status list, split-deployment aware.
#
# The deployment has three ROLES, and each is measured on the process that would
# actually run it. No target is ever charged for another role's work:
#   signer    ONE committee member, one signature + one durable slot burn per
#             round                                 (src/bin/signer.rs)
#   prover    the aggregator: N updates, prove only (src/bin/prover.rs)
#   verifier  a relying party: verifies a FIXED artifact corpus
#                                                   (src/bin/verifier.rs)
# plus the baseline the SNARK has to beat:
#   raw_agg   crude multisig, NO SNARK              (src/bin/raw_agg.rs)
#             verify scales with t, unlike the constant-time SNARK verify, and
#             proof_size is the raw aggregate size (t signatures + bitmap on the
#             wire) rather than a proof
#
# `combined` (src/main.rs, the single-process demo) is NOT in the defaults. It
# measures a process that proves and verifies at once, which is not a role anyone
# deploys, and its numbers duplicate the prover's: same setup, prove within 0.5%,
# peak RSS within 2%. It stays available as `TARGETS="... combined"` when an
# independent second reading of prove time is wanted — that is what it is for.
#
# Only `signer` reports a `sign` row, and that is the point. In production nobody
# produces t signatures: each member signs ONCE per round on its own machine and
# broadcasts, and the aggregator receives t signatures and produces none. A `sign`
# figure taken from a process that signs t times is the summed work of t machines
# billed to one, and describes no process that exists. prover/raw_agg/combined
# still produce their t signatures — a record needs them — but do not time them.
#
# Produces, in $OUTDIR:
#   env.txt      full environment capture (reproducibility appendix)
#   samples.csv  tidy raw data, one row per individual update/verification
#   runs.csv     one row per process run
#   summary.csv  aggregate statistics, machine-readable
#   summary.txt  the same table, human-readable
#
# The unit of analysis for per-update metrics is the PER-RUN MEDIAN (n = RUNS),
# not the pooled sample: updates within one process share allocator and cache
# state and are not independent. samples.csv keeps every raw observation so the
# pooled distribution can be re-analysed if that is what you want to report.
#
# Targets are run ROUND-ROBIN by default, not in contiguous blocks, so that a
# thermal ramp or a background job during the sweep perturbs every target rather
# than biasing whichever one happened to be running. runs.csv records the epoch
# timestamp of each run so the assumption can be checked rather than trusted.
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

RUNS="${RUNS:-20}"
WARMUP="${WARMUP:-2}"
TARGETS="${TARGETS:-signer prover verifier raw_agg}"
OUTDIR="${OUTDIR:-bench-$(date +%Y%m%d-%H%M%S)}"

# Run targets round-robin instead of in contiguous blocks (default: on).
#
# Blocks confound target identity with time: a thermal ramp or a background job
# that lands during the prover block is indistinguishable, in the data, from the
# prover being slow. Interleaving spreads any time-varying disturbance across all
# targets, so it inflates variance instead of biasing one mean. Set 0 to restore
# block order (only useful when comparing against an older block-ordered run).
INTERLEAVE="${INTERLEAVE:-1}"

# Refuse to measure unless the governor is 'performance'. Off by default because
# it needs root to fix, on for anything whose numbers get published.
STRICT_ENV="${STRICT_ENV:-0}"

# Optional CPU pinning, e.g. PIN_CPUS=0-7. leanVM's pool is sized from the
# affinity mask at startup, so this also fixes the thread count — pin and record
# it if you intend to compare across machines.
PIN_CPUS="${PIN_CPUS:-}"

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO="$PWD"
BIN_DIR="$REPO/target/release"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

mkdir -p "$OUTDIR"
ENV_FILE="$OUTDIR/env.txt"
SAMPLES="$OUTDIR/samples.csv"
RUNS_CSV="$OUTDIR/runs.csv"
SUMMARY_CSV="$OUTDIR/summary.csv"
SUMMARY_TXT="$OUTDIR/summary.txt"

# ---------------------------------------------------------------- build ----
echo "building --release ..."
cargo build --release >/dev/null 2>&1
for b in signer prover verifier decentralized-root-of-trust raw_agg; do
  [ -x "$BIN_DIR/$b" ] || { echo "missing binary: $BIN_DIR/$b"; exit 1; }
done

TIME_BIN=""
[ -x /usr/bin/time ] && TIME_BIN=/usr/bin/time

# ------------------------------------------------------ environment ----
sysread() { [ -r "$1" ] && cat "$1" 2>/dev/null || echo "n/a"; }

{
  echo "# Environment capture — benchmark of $(basename "$REPO")"
  echo "timestamp        : $(date -Is)"
  echo "host             : $(hostname)"
  echo "kernel           : $(uname -srmo)"
  echo
  echo "## CPU"
  echo "model            : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "arch             : $(uname -m)"
  echo "online cpus      : $(nproc)"
  echo "governor         : $(sysread /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
  echo "scaling driver   : $(sysread /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver)"
  echo "boost            : $(sysread /sys/devices/system/cpu/cpufreq/boost)"
  echo "intel no_turbo   : $(sysread /sys/devices/system/cpu/intel_pstate/no_turbo)"
  echo "SMT active       : $(sysread /sys/devices/system/cpu/smt/active)"
  # leanVM sizes its worker pool from std::thread::available_parallelism(), cached
  # in a OnceLock, with no environment override. So the thread count is whatever
  # the CPU affinity mask allows at startup — a first-class independent variable
  # that nothing else in this file would otherwise record.
  echo "cpu affinity     : $(taskset -cp $$ 2>/dev/null | sed 's/.*: //' || echo 'n/a')"
  echo "effective threads: $(nproc)  <- leanVM worker pool size"
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
  # `signer` fsyncs twice per reserved slot INSIDE its timed region, so its sign
  # figure is a property of this filesystem as much as of the scheme. A near-full
  # filesystem allocates differently; record the fill level too.
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
  echo "git dirty        : $(test -n "$(git status --porcelain 2>/dev/null)" && echo yes || echo no)"
  echo "leanVM rev       : $(sed -n 's/.*leanEthereum\/leanVM.git", rev = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
  echo "Cargo.lock       : $(test -f Cargo.lock && echo present || echo MISSING)"
  echo
  echo "## Parameters (src/params.rs)"
  grep -E '^pub const' src/params.rs | sed 's/^/  /'
  echo
  echo "## Benchmark configuration"
  echo "runs (default)   : $RUNS measured, $WARMUP warmup(s) discarded"
  for t in $TARGETS; do
    eval "tr=\${RUNS_$t:-$RUNS}; tw=\${WARMUP_$t:-$WARMUP}"
    echo "  $t: $tr measured, $tw warmup(s)"
  done
  echo "targets          : $TARGETS"
  echo "kernel RSS probe : ${TIME_BIN:-unavailable (self-reported VmHWM only)}"
  echo
  echo "## lscpu (full)"
  lscpu 2>/dev/null | sed 's/^/  /'
} > "$ENV_FILE"

gov="$(sysread /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"

cat <<EOF

$(sed -n '2,4p' "$ENV_FILE")
runs      : $RUNS measured (+$WARMUP warmup discarded)
targets   : $TARGETS
outdir    : $OUTDIR
EOF
echo "order     : $([ "$INTERLEAVE" = 1 ] && echo 'round-robin across targets' || echo 'contiguous blocks per target')"
[ -n "$PIN_CPUS" ] && echo "pinned    : $PIN_CPUS"
[ "$gov" = performance ] || echo "WARNING   : governor '$gov' != performance -> inflated variance"
[ -n "$TIME_BIN" ] || echo "WARNING   : /usr/bin/time absent -> no independent kernel RSS cross-check"
[ -f Cargo.lock ] || echo "WARNING   : Cargo.lock missing -> dependency resolution is not reproducible"

# A publishable run should not silently proceed on a machine that will produce
# numbers nobody can reproduce, this author included.
if [ "$STRICT_ENV" = 1 ]; then
  fatal=0
  [ "$gov" = performance ] || { echo "STRICT: governor is '$gov', need 'performance'" >&2; fatal=1; }
  [ -n "$TIME_BIN" ]       || { echo "STRICT: /usr/bin/time -v required for the RSS cross-check" >&2; fatal=1; }
  [ -f Cargo.lock ]        || { echo "STRICT: Cargo.lock required for a reproducible dependency set" >&2; fatal=1; }
  [ "$fatal" = 0 ] || { echo "refusing to produce publishable numbers on this configuration" >&2; exit 1; }
fi
echo

# ----------------------------------------------------- fixed corpus ----
# The verifier must see the SAME workload on every run, so its input is
# generated once and frozen. Re-generating it per run would fold the prover's
# variance into the verifier's numbers.
CORPUS="$SCRATCH/corpus"
if grep -qw verifier <<<"$TARGETS"; then
  echo "generating fixed verifier corpus ..."
  "$BIN_DIR/prover" "$CORPUS" >/dev/null 2>&1
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
# secondary one, which meant the same column held prove for one target and verify
# for another, and sign (1220 ms) for one target and verify (32 ms) for the next.
# summary.txt relabelled them per target, so it read correctly; summary.csv did
# not, so anyone plotting a column got two different quantities on one axis.
#
# `setup_ms` is the leanVM circuit and ONLY that; `keygen_ms` is the N-key
# generation every path pays, `raw_agg` included; `slot_state_ms` is the N durable
# slot counters, which only a real signer pays. Keeping them apart is what makes
# the fixed-cost columns comparable across targets: `raw_agg` leaves `setup_ms`
# empty because it has no circuit, which is the result, rather than borrowing the
# column for its keygen and making the SNARK look like the cheaper setup.
echo 'target,run,t_start,setup_ms,keygen_ms,slot_state_ms,n_items,sign_med_ms,sign_mean_ms,sign_sd_ms,sign_min_ms,sign_max_ms,sign_total_ms,prove_med_ms,prove_mean_ms,prove_sd_ms,prove_min_ms,prove_max_ms,prove_total_ms,verify_med_ms,verify_mean_ms,verify_sd_ms,verify_min_ms,verify_max_ms,verify_total_ms,proof_med_bytes,rss_setup_mb,rss_max_mb,peak_rss_mb,kernel_maxrss_mb,failures' > "$RUNS_CSV"

# Column indices into runs.csv, named once. Every awk gate and every summary row
# below addresses columns through these, so inserting a column is one edit here
# rather than a hunt through half a dozen hardcoded `$17`s — one of which is the
# security gate, where a stale index fails open.
C_SETUP=4;       C_KEYGEN=5;      C_SLOTSTATE=6;  C_ITEMS=7
C_SIGN_MED=8;    C_SIGN_TOT=13
C_PROVE_MED=14;  C_PROVE_TOT=19
C_VERIFY_MED=20; C_VERIFY_TOT=25
C_PROOF=26;      C_RSS_SETUP=27;  C_RSS_MAX=28
C_PEAK=29;       C_KERNEL=30;     C_FAIL=31

RUN_T_START=""

run_once() { # $1 target -> prints stdout of the run to $SCRATCH/out.txt
  local target="$1" rc=0
  local -a cmd
  case "$target" in
    signer)   cmd=("$BIN_DIR/signer") ;;
    prover)   rm -rf "$SCRATCH/pout"; cmd=("$BIN_DIR/prover" "$SCRATCH/pout") ;;
    verifier) cmd=("$BIN_DIR/verifier" "$CORPUS") ;;
    combined) cmd=("$BIN_DIR/decentralized-root-of-trust") ;;
    raw_agg)  cmd=("$BIN_DIR/raw_agg") ;;
    *) echo "unknown target: $target" >&2; exit 1 ;;
  esac
  # Pinning wraps the binary, not the harness: leanVM reads the affinity mask once
  # at startup to size its pool, so the mask has to be in place before exec.
  [ -n "$PIN_CPUS" ] && cmd=(taskset -c "$PIN_CPUS" "${cmd[@]}")
  [ -n "$TIME_BIN" ] && cmd=("$TIME_BIN" -v "${cmd[@]}")

  RUN_T_START="$(date +%s)"
  EMIT_SAMPLES=1 "${cmd[@]}" >"$SCRATCH/out.txt" 2>"$SCRATCH/err.txt" || rc=$?
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
    signer) tag='^SIGNER ' ;; prover) tag='^PROVER ' ;; verifier) tag='^VERIFIER ' ;;
    combined) tag='^BENCH ' ;; raw_agg) tag='^RAW_AGG ' ;;
  esac
  local line; line="$(grep "$tag" "$SCRATCH/out.txt" || true)"
  [ -n "$line" ] || { echo "run $run ($target): record line missing" >&2; exit 1; }
  awk -v t="$target" -v r="$run" -v k="$kmax" -v ts="$RUN_T_START" '{
    for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
    # Every phase field starts empty, and a target fills only the phases it ran.
    # `col()` drops empty cells, so an absent phase yields no summary row at all —
    # which is the honest answer, rather than a 0.000 ms that reads as "instant".
    setup=""; keygen=""; slotstate=""
    sg_med=""; sg_mean=""; sg_sd=""; sg_lo=""; sg_hi=""; sg_tot=""
    pv_med=""; pv_mean=""; pv_sd=""; pv_lo=""; pv_hi=""; pv_tot=""
    vf_med=""; vf_mean=""; vf_sd=""; vf_lo=""; vf_hi=""; vf_tot=""
    if (t=="signer") {
      # The only target that reports `sign`, and the only one whose keygen and
      # slot state are ONE key and ONE counter rather than the whole committee.
      # `setup` stays empty: a member builds no circuit. proof_size carries the
      # signature size, which is what one member actually puts on the wire.
      keygen=v["keygen_ms"]; slotstate=v["slot_state_ms"]; n=v["n_rounds"]
      sg_med=v["sign_med_ms"]; sg_mean=v["sign_mean_ms"]; sg_sd=v["sign_sd_ms"]
      sg_lo=v["sign_min_ms"]; sg_hi=v["sign_max_ms"]; sg_tot=v["sign_total_ms"]
      pb=v["sig_bytes"]; rs=v["rss_keygen_mb"]; rm=v["rss_rounds_max_mb"]; pk=v["peak_rss_mb"]
      # Every round self-verifies; a missing key means the run told us nothing.
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="prover") {
      # Aggregator. It signs to have something to aggregate, but does not time it:
      # those t signatures come from t machines in a deployment, one each.
      setup=v["setup_ms"]; keygen=v["keygen_ms"]; n=v["n_updates"]
      pv_med=v["prove_med_ms"]; pv_mean=v["prove_mean_ms"]; pv_sd=v["prove_sd_ms"]
      pv_lo=v["prove_min_ms"]; pv_hi=v["prove_max_ms"]; pv_tot=v["prove_total_ms"]
      pb=v["proof_med_bytes"]; rs=v["rss_setup_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]; f=0
    } else if (t=="verifier") {
      # No keygen and no signing: this process only ever holds public keys.
      setup=v["setup_ms"]; n=v["n_verified"]
      vf_med=v["verify_med_ms"]; vf_mean=v["verify_mean_ms"]; vf_sd=v["verify_sd_ms"]
      vf_lo=v["verify_min_ms"]; vf_hi=v["verify_max_ms"]; vf_tot=v["verify_total_ms"]
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
      # being compared against. proof_size = the raw aggregate; the tamper sanity
      # check drives the failure gate.
      keygen=v["keygen_ms"]; slotstate=v["slot_state_ms"]; n=v["n_updates"]
      vf_med=v["verify_med_ms"]; vf_mean=v["verify_mean_ms"]; vf_sd=v["verify_sd_ms"]
      vf_lo=v["verify_min_ms"]; vf_hi=v["verify_max_ms"]; vf_tot=v["verify_total_ms"]
      pb=v["agg_med_bytes"]; rs=v["rss_keygen_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]
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
    printf "%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
      t,r,ts,setup,keygen,slotstate,n,
      sg_med,sg_mean,sg_sd,sg_lo,sg_hi,sg_tot,
      pv_med,pv_mean,pv_sd,pv_lo,pv_hi,pv_tot,
      vf_med,vf_mean,vf_sd,vf_lo,vf_hi,vf_tot,
      pb,rs,rm,pk,k,f
  }' <<<"$line" >> "$RUNS_CSV"

  # Raw per-update samples.
  awk -v t="$target" -v r="$run" '
    /^SAMPLE / {
      delete v; for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
      if (v["target"]=="signer") {
        printf "%s,%d,%s,sign,%s,%s,%s\n",   t,r,v["idx"],v["sign_ms"],  v["bytes"],v["rss_mb"]
      } else if (v["target"]=="prover") {
        printf "%s,%d,%s,prove,%s,%s,%s\n",  t,r,v["idx"],v["prove_ms"], v["bytes"],v["rss_mb"]
      } else if (v["target"]=="verifier") {
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mb"]
      } else if (v["target"]=="raw_agg") {
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mb"]
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
  eval "tw=\${WARMUP_$target:-$WARMUP}"
  eval "tr=\${RUNS_$target:-$RUNS}"

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
    grep -E '^(SIGNER|PROVER|VERIFIER|BENCH|RAW_AGG) ' "$SCRATCH/out.txt" >&2 || true
    exit 1
  fi
  if [ "$(count_bad_item_counts)" -gt 0 ]; then
    echo
    echo "ABORT: $target run $((i - tw)) measured 0 items, or a different number of" >&2
    echo "items than earlier runs of the same target. A per-run median is only" >&2
    echo "meaningful over a fixed workload. Numbers withheld." >&2
    grep -E '^(SIGNER|PROVER|VERIFIER|BENCH|RAW_AGG) ' "$SCRATCH/out.txt" >&2 || true
    exit 1
  fi
}

# Per-target run counts: `prover` costs ~30 s a run while `signer` costs under a
# second, so one global RUNS either wastes an hour or under-samples the cheap
# targets. RUNS_<target> overrides; RUNS is the default.
if [ "$INTERLEAVE" = 1 ]; then
  # Round-robin. Targets have different schedule lengths, so each one is stepped
  # only while it still has runs left; the longest simply finishes alone at the
  # end. Warmups stay at the front of each target's own schedule, where they
  # belong — they exist to fill caches for that binary, not for the sweep.
  echo "== interleaved sweep =="
  total=0
  for t in $TARGETS; do
    eval "tw=\${WARMUP_$t:-$WARMUP}; tr=\${RUNS_$t:-$RUNS}"
    eval "sched_$t=$((tw + tr))"
    [ "$((tw + tr))" -gt "$total" ] && total=$((tw + tr))
  done
  for step in $(seq 1 "$total"); do
    for target in $TARGETS; do
      eval "len=\$sched_$target"
      [ "$step" -le "$len" ] || continue
      do_one "$target" "$step"
    done
  done
else
  for target in $TARGETS; do
    echo "== $target =="
    eval "tw=\${WARMUP_$target:-$WARMUP}; tr=\${RUNS_$target:-$RUNS}"
    for i in $(seq 1 $((tw + tr))); do
      do_one "$target" "$i"
    done
  done
fi

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
for target in $TARGETS; do
  emit "$target" setup            ms    "$C_SETUP"
  emit "$target" keygen           ms    "$C_KEYGEN"
  emit "$target" slot_state       ms    "$C_SLOTSTATE"
  emit "$target" sign_per_item    ms    "$C_SIGN_MED"
  emit "$target" sign_total       ms    "$C_SIGN_TOT"
  emit "$target" prove_per_item   ms    "$C_PROVE_MED"
  emit "$target" prove_total      ms    "$C_PROVE_TOT"
  emit "$target" verify_per_item  ms    "$C_VERIFY_MED"
  emit "$target" verify_total     ms    "$C_VERIFY_TOT"
  emit "$target" proof_size       bytes "$C_PROOF"
  emit "$target" rss_after_setup  MB    "$C_RSS_SETUP"
  emit "$target" rss_max          MB    "$C_RSS_MAX"
  emit "$target" peak_rss_vmhwm   MB    "$C_PEAK"
  emit "$target" peak_rss_kernel  MB    "$C_KERNEL"
done

# Human labels. Only `raw_agg` needs its own cases now — everything else follows
# from the metric name, which is the point of naming metrics after phases.
label() {
  case "$1:$2" in
    signer:keygen)           echo "keygen (1 key, once)" ;;
    signer:slot_state)       echo "slot state (1 counter)" ;;
    signer:sign_per_item)    echo "sign / round (1 member)" ;;
    signer:sign_total)       echo "sign total / run" ;;
    signer:proof_size)       echo "signature size" ;;
    raw_agg:verify_per_item) echo "verify / update (raw)" ;;
    raw_agg:proof_size)      echo "aggregate size (t sigs)" ;;
    *:setup)                 echo "setup (circuit, once)" ;;
    *:keygen)                echo "keygen (N keys, once)" ;;
    *:slot_state)            echo "slot state (counters)" ;;
    *:sign_per_item)         echo "sign / round" ;;
    *:sign_total)            echo "sign total / run" ;;
    *:prove_per_item)        echo "prove / update" ;;
    *:prove_total)           echo "prove total / run" ;;
    *:verify_per_item)       echo "verify / update" ;;
    *:verify_total)          echo "verify total / run" ;;
    *:proof_size)            echo "proof size" ;;
    # RSS is expanded once, in the header legend above; these four then use the
    # acronym alone, which is what keeps the varying part of each label visible.
    # The first one is named after whatever fixed cost the target actually paid:
    # signer and raw_agg build no circuit, so for them the column is post-keygen.
    signer:rss_after_setup)  echo "RSS after keygen" ;;
    raw_agg:rss_after_setup) echo "RSS after keygen" ;;
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
  echo "host      : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1) ($(uname -m)), $(nproc) threads"
  echo "governor  : $gov"
  echo "threads   : $(nproc)${PIN_CPUS:+ (pinned to $PIN_CPUS)}"
  echo "order     : $([ "$INTERLEAVE" = 1 ] && echo 'round-robin across targets' || echo 'contiguous blocks per target')"
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
  for target in $TARGETS; do
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
  echo "    offers no override, so every timing here is a $(nproc)-thread figure."
  [ -n "$PIN_CPUS" ] || echo "    Nothing was pinned: set PIN_CPUS to fix it across machines."
  [ "$INTERLEAVE" = 1 ] || echo "  * Targets ran in contiguous blocks: any drift over the sweep is confounded"
  [ "$INTERLEAVE" = 1 ] || echo "    with target identity. Use the t_start column in runs.csv to check."
  echo "  * runs.csv carries t_start (epoch s) per run. Plot the metric against it"
  echo "    before reporting: a thermal ramp or a stray background job shows up"
  echo "    there and nowhere else."
  echo "  * A prover process calls zk_alloc::enable_arena(), which sets"
  echo "    M_TRIM_THRESHOLD=-1: its RSS never decreases, so 'peak' means"
  echo "    'high-water mark of a monotonic curve'. A verify-only process keeps"
  echo "    normal malloc behaviour and its RSS is flat in the number of verifications."
  echo "  * Setup is paid once per process and is not persisted across restarts:"
  echo "    every run re-executes the binary, so each target above paid it on all"
  echo "    $((RUNS + WARMUP)) of its executions. It dominates total time; never fold it into"
  echo "    per-update figures."
  echo "  * 'setup' is the leanVM circuit and nothing else. Keygen is a separate row"
  echo "    because EVERY path pays it, raw_agg included — so the SNARK's extra fixed"
  echo "    cost is the setup row alone, and raw_agg has no setup row at all. Reading"
  echo "    raw_agg's keygen against the others' setup compares two different things"
  echo "    and inverts the answer."
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
  echo "  * Exactly one target reports 'sign': signer, which measures ONE member"
  echo "    doing ONE signature per round, preceded by its durable slot burn (write"
  echo "    + fsync + rename + fsync dir) through SignerNode. prover, combined and"
  echo "    raw_agg still produce t signatures — a record needs them — but do not"
  echo "    time them: in a deployment those t signatures come one each from t"
  echo "    machines, so timing the loop would bill a committee's work to one node."
  echo "  * signer's keygen and slot-state rows are for ONE key and ONE counter;"
  echo "    prover/raw_agg report the whole committee's N. Do not read them as the"
  echo "    same quantity — divide by N first, or compare signer against N=1."
  echo "  * A member's signing cost is IDENTICAL on both published forms: same key,"
  echo "    same 32-byte message, same derived slot. What the two paths differ in is"
  echo "    only how the quorum is evidenced (t signatures + bitmap vs one proof)"
  echo "    and what a relying party pays to check it. So the signer row applies"
  echo "    unchanged to the SNARK and the raw path alike."

  # Derived from THIS sweep, never remembered. This block used to print figures
  # from an older run (406 ms at t=70, 718 ms at t=128) as if they were results,
  # which then contradicted the table a few lines above it in the same file.
  t_param="$(sed -n 's/^pub const T: usize = \([0-9][0-9]*\).*/\1/p' src/params.rs)"
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
