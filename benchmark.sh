#!/usr/bin/env bash
# Reproducible benchmark of the committee status list, split-deployment aware.
#
# Measures four targets independently:
#   prover    signs + aggregates N updates          (src/bin/prover.rs)
#   verifier  verifies a FIXED artifact corpus      (src/bin/verifier.rs)
#   combined  the single-process demo, for contrast (src/main.rs)
#   raw_agg   crude multisig baseline, NO SNARK      (src/bin/raw_agg.rs)
#             t raw XMSS sign+verify per update; work = verify (scales with t),
#             proof_size = the raw aggregate size (t signatures on the wire)
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
#   PROJECT_CM4=1 ./benchmark.sh          # adds an explicitly-labelled ESTIMATE
set -euo pipefail

# Every number here passes through `sort -g` and awk. Both honour LC_NUMERIC, and
# in a comma-decimal locale `sort -g` truncates "5.10" at the separator: the
# series silently mis-sorts, and since stats() reads min, max and every quantile
# off the sorted array, the whole summary is quietly wrong with no error. Pin C.
export LC_ALL=C

RUNS="${RUNS:-20}"
WARMUP="${WARMUP:-2}"
TARGETS="${TARGETS:-prover verifier combined raw_agg}"
OUTDIR="${OUTDIR:-bench-$(date +%Y%m%d-%H%M%S)}"
PROJECT_CM4="${PROJECT_CM4:-0}"
CM4_LOW="${CM4_LOW:-8}"
CM4_HIGH="${CM4_HIGH:-15}"

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
for b in prover verifier decentralized-root-of-trust raw_agg; do
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
  # raw_agg fsyncs twice per reserved slot inside its timed region, so its sign
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
# `work2_*` is the run's secondary phase (sign, where the target has one; verify
# for the combined process). It used to be measured by the binaries and dropped
# on the floor here, which is why the sign figures in the write-up could not be
# reproduced from summary.csv.
echo 'target,run,t_start,setup_ms,n_items,work_med_ms,work_mean_ms,work_sd_ms,work_min_ms,work_max_ms,work_total_ms,work2_med_ms,work2_total_ms,proof_med_bytes,rss_setup_mb,rss_max_mb,peak_rss_mb,kernel_maxrss_mb,failures' > "$RUNS_CSV"

RUN_T_START=""

run_once() { # $1 target -> prints stdout of the run to $SCRATCH/out.txt
  local target="$1" rc=0
  local -a cmd
  case "$target" in
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
    prover) tag='^PROVER ' ;; verifier) tag='^VERIFIER ' ;; combined) tag='^BENCH ' ;;
    raw_agg) tag='^RAW_AGG ' ;;
  esac
  local line; line="$(grep "$tag" "$SCRATCH/out.txt" || true)"
  [ -n "$line" ] || { echo "run $run ($target): record line missing" >&2; exit 1; }
  awk -v t="$target" -v r="$run" -v k="$kmax" -v ts="$RUN_T_START" '{
    for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
    # w2 is the secondary phase; empty where the target has only one.
    w2=""; w2t=""
    if (t=="prover") {
      setup=v["setup_ms"]; n=v["n_updates"]
      med=v["prove_med_ms"]; mean=v["prove_mean_ms"]; sd=v["prove_sd_ms"]
      lo=v["prove_min_ms"]; hi=v["prove_max_ms"]; tot=v["prove_total_ms"]
      w2=v["sign_med_ms"]
      pb=v["proof_med_bytes"]; rs=v["rss_setup_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]; f=0
    } else if (t=="verifier") {
      setup=v["setup_ms"]; n=v["n_verified"]
      med=v["verify_med_ms"]; mean=v["verify_mean_ms"]; sd=v["verify_sd_ms"]
      lo=v["verify_min_ms"]; hi=v["verify_max_ms"]; tot=v["verify_total_ms"]
      # An absent `failures=` key yields "", which awk would later coerce to 0 —
      # a silent pass for the one target that reports real accept/reject verdicts.
      # Missing means "this run told us nothing", which is a failure, not a zero.
      pb=""; rs=v["rss_setup_mb"]; rm=v["rss_verify_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["failures"]=="")?1:v["failures"]
    } else if (t=="raw_agg") {
      # Baseline: work = verify (scales with t); proof_size = raw aggregate bytes;
      # setup = keygen; the tamper sanity check drives the failure gate.
      setup=v["keygen_ms"]; n=v["n_updates"]
      med=v["verify_med_ms"]; mean=v["verify_mean_ms"]; sd=v["verify_sd_ms"]
      lo=v["verify_min_ms"]; hi=v["verify_max_ms"]; tot=v["verify_total_ms"]
      w2=v["sign_med_ms"]; w2t=v["sign_total_ms"]
      pb=v["agg_med_bytes"]; rs=v["rss_keygen_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["tamper_rejected"]=="1")?0:1
    } else {
      # `updates_total_ms` is the whole loop (sign + prove + verify + printing);
      # the phase total is what compares with the prover column.
      setup=v["setup_total_ms"]; n=v["n_updates"]
      med=v["upd_prove_med_ms"]; mean=""; sd=""
      lo=v["upd_prove_min_ms"]; hi=v["upd_prove_max_ms"]; tot=v["upd_prove_total_ms"]
      w2=v["upd_verify_med_ms"]; w2t=v["upd_verify_total_ms"]
      pb=v["proof_med_bytes"]; rs=v["rss_setup_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["sec_ok"]=="1")?0:1
    }
    printf "%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
      t,r,ts,setup,n,med,mean,sd,lo,hi,tot,w2,w2t,pb,rs,rm,pk,k,f
  }' <<<"$line" >> "$RUNS_CSV"

  # Raw per-update samples.
  awk -v t="$target" -v r="$run" '
    /^SAMPLE / {
      delete v; for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
      if (v["target"]=="prover") {
        printf "%s,%d,%s,sign,%s,%s,%s\n",  t,r,v["idx"],v["sign_ms"], v["bytes"],v["rss_mb"]
        printf "%s,%d,%s,prove,%s,%s,%s\n", t,r,v["idx"],v["prove_ms"],v["bytes"],v["rss_mb"]
      } else if (v["target"]=="verifier") {
        printf "%s,%d,%s,verify,%s,%s,%s\n", t,r,v["idx"],v["verify_ms"],v["bytes"],v["rss_mb"]
      } else if (v["target"]=="raw_agg") {
        printf "%s,%d,%s,sign,%s,%s,%s\n",   t,r,v["idx"],v["sign_ms"],  v["bytes"],v["rss_mb"]
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
  awk -F, 'NR>1 { if ($19 !~ /^[0-9]+$/ || $19+0>0) n++ } END{print n+0}' "$RUNS_CSV"
}

# A run that measured nothing is not a fast run. `Series` returns 0.0 for an empty
# series rather than an error, so a corpus that went missing, or an artifact
# naming change, yields a clean-looking `0.000 ms` median and a `failures=0` that
# the gate above happily accepts. The item count is the only thing that separates
# the two, so it is checked — and checked for *consistency*, since a corpus that
# shrinks halfway through a sweep would otherwise silently change what the
# per-run medians are medians of.
count_bad_item_counts() {
  awk -F, 'NR>1 {
    if ($5 !~ /^[0-9]+$/ || $5+0==0) { n++; next }
    if (seen[$1] && count[$1] != $5) n++
    seen[$1]=1; count[$1]=$5
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
  # prover and combined runs. Checking after each row costs one awk pass and
  # turns that hour into one run.
  if [ "$(count_failed_runs)" -gt 0 ]; then
    echo
    echo "ABORT: $target run $((i - tw)) reported a security-expectation failure" >&2
    echo "(or an unparseable failure count). Numbers withheld." >&2
    grep -E '^(PROVER|VERIFIER|BENCH|RAW_AGG) ' "$SCRATCH/out.txt" >&2 || true
    exit 1
  fi
  if [ "$(count_bad_item_counts)" -gt 0 ]; then
    echo
    echo "ABORT: $target run $((i - tw)) measured 0 items, or a different number of" >&2
    echo "items than earlier runs of the same target. A per-run median is only" >&2
    echo "meaningful over a fixed workload. Numbers withheld." >&2
    grep -E '^(PROVER|VERIFIER|BENCH|RAW_AGG) ' "$SCRATCH/out.txt" >&2 || true
    exit 1
  fi
}

# Per-target run counts: `prover` and `combined` cost ~70 s a run while
# `verifier` costs ~6 s, so one global RUNS either wastes an hour or
# under-samples the cheap target. RUNS_<target> overrides; RUNS is the default.
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

for target in $TARGETS; do
  emit "$target" setup            ms    4
  emit "$target" work_per_item    ms    6
  emit "$target" work_total       ms    11
  emit "$target" work2_per_item   ms    12
  emit "$target" work2_total      ms    13
  emit "$target" proof_size       bytes 14
  emit "$target" rss_after_setup  MB    15
  emit "$target" rss_max          MB    16
  emit "$target" peak_rss_vmhwm   MB    17
  emit "$target" peak_rss_kernel  MB    18
done

label() {
  case "$1:$2" in
    prover:work_per_item)   echo "prove / update" ;;
    verifier:work_per_item) echo "verify / update" ;;
    combined:work_per_item) echo "prove / update" ;;
    raw_agg:work_per_item)  echo "verify / update (raw)" ;;
    prover:work2_per_item)  echo "sign / update" ;;
    combined:work2_per_item) echo "verify / update" ;;
    raw_agg:work2_per_item) echo "sign / update (raw)" ;;
    prover:work_total)      echo "prove total / run" ;;
    combined:work_total)    echo "prove total / run" ;;
    verifier:work_total)    echo "verify total / run" ;;
    raw_agg:work_total)     echo "verify total / run" ;;
    combined:work2_total)   echo "verify total / run" ;;
    raw_agg:work2_total)    echo "sign total / run" ;;
    raw_agg:setup)          echo "keygen (once/process)" ;;
    raw_agg:proof_size)     echo "aggregate size (t sigs)" ;;
    *:setup)                echo "setup (once/process)" ;;
    *:proof_size)           echo "proof size" ;;
    *:rss_after_setup)      echo "RSS after setup" ;;
    *:rss_max)              echo "RSS max during work" ;;
    *:peak_rss_vmhwm)       echo "peak RSS (VmHWM)" ;;
    *:peak_rss_kernel)      echo "peak RSS (kernel)" ;;
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
  echo
  printf '%-9s %-22s %-6s %3s %10s %10s %10s %10s %10s %8s %7s\n' \
    target metric unit n min median max mean sd 'cv%' 'ci95±'
  awk -F, 'NR>1' "$SUMMARY_CSV" | while IFS=, read -r t m u n mn q1 md q3 mx mean sd cv ci; do
    d=2; [ "$u" = bytes ] && d=0; [ "$u" = MB ] && d=1
    printf '%-9s %-22s %-6s %3s %10.*f %10.*f %10.*f %10.*f %10.*f %7.1f%% %7.*f\n' \
      "$t" "$(label "$t" "$m")" "$u" "$n" $d "$mn" $d "$md" $d "$mx" $d "$mean" $d "$sd" "$cv" $d "$ci"
  done

  # Headline comparison: the reason the split exists. Guard on the RAW columns,
  # not on stats() output: stats() emits "0" for an empty column, so testing its
  # result would pass with c=0 and divide by zero when a run omits these targets.
  vp_raw="$(col verifier 17)"; cp_raw="$(col combined 17)"
  if [ -n "$vp_raw" ] && [ -n "$cp_raw" ]; then
    vp="$(printf '%s\n' "$vp_raw" | stats | awk '{print $4}')"
    cp="$(printf '%s\n' "$cp_raw" | stats | awk '{print $4}')"
    echo
    echo "SPLIT VS COMBINED (median peak RSS)"
    awk -v v="$vp" -v c="$cp" 'BEGIN{
      printf "  verify-only process : %.0f MB\n", v
      printf "  combined process    : %.0f MB\n", c
      printf "  reduction           : %.1f%% (%.0f MB) for a node that only verifies\n", 100*(c-v)/c, c-v
    }'
  fi

  # Peak RSS cross-check. Two independent readings of the same quantity: the
  # process's own /proc/self/status VmHWM and the kernel's ru_maxrss via
  # /usr/bin/time -v. They should agree; VmHWM can under-report, because the
  # kernel only refreshes mm->hiwater_rss at certain points. Printing both and
  # never comparing them is not a cross-check, so compare them here.
  for target in $TARGETS; do
    self_raw="$(col "$target" 17)"; kern_raw="$(col "$target" 18)"
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
  echo "  * Setup is paid once per process and is not persisted across restarts."
  echo "    It dominates total time; never fold it into per-update figures."
  echo "  * Per-update samples within a run are not independent (shared allocator"
  echo "    and cache state). The table's unit is the per-run median; samples.csv"
  echo "    holds every raw observation if you need the pooled distribution."
  echo "  * Prove cost is driven by t, not by the number of updates. At small t the"
  echo "    trace padding to a power of two makes it a step function (t=5..=8 all"
  echo "    cost the same); from a few dozen signers upward the linear term"
  echo "    dominates and prove time is ~linear in t (measured: 406 ms at t=70,"
  echo "    718 ms at t=128 -- a flat ~5.7 ms per aggregated signature). Do not"
  echo "    extrapolate the step behaviour past small t."

  if [ "$PROJECT_CM4" = 1 ]; then
    echo
    echo "RASPBERRY CM4 (BCM2711) PROJECTION — ESTIMATE, NOT A MEASUREMENT"
    echo "  Naive linear scaling x${CM4_LOW}..x${CM4_HIGH} of host wall-clock. It ignores"
    echo "  microarchitecture, memory bandwidth and thermal behaviour. Do not"
    echo "  publish these as results; run benchmark.sh natively on the board."
    for target in $TARGETS; do
      for c in 4 6; do
        # Guard on the RAW column, not on stats() output: stats() prints
        # "0 0 0 ..." for an empty column, so `[ -n "$v" ]` never fires and a
        # target with no data prints a bogus "host 0.0 ms -> CM4 0.0 .. 0.0 ms"
        # row. Same trap the SPLIT VS COMBINED block above documents.
        raw="$(col "$target" "$c")"
        [ -n "$raw" ] || continue
        v="$(printf '%s\n' "$raw" | stats | awk '{print $4}')"
        awk -v t="$target" -v l="$(label "$target" "$([ "$c" = 4 ] && echo setup || echo work_per_item)")" \
            -v m="$v" -v a="$CM4_LOW" -v b="$CM4_HIGH" 'BEGIN{
          f="%s"; printf "  %-9s %-22s host %8.1f ms  ->  CM4 %8.1f .. %8.1f ms\n", t, l, m, m*a, m*b }'
      done
    done
    echo "  RAM does not scale with CPU: the peak figures above carry over unchanged."
  fi
} | tee "$SUMMARY_TXT"

echo
echo "written:"
echo "  $ENV_FILE"
echo "  $SAMPLES      ($(( $(wc -l < "$SAMPLES") - 1 )) raw observations)"
echo "  $RUNS_CSV"
echo "  $SUMMARY_CSV"
echo "  $SUMMARY_TXT"
