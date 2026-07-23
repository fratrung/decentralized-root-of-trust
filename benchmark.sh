#!/usr/bin/env bash
# Reproducible benchmark of the committee status list, split-deployment aware.
#
# Measures three targets independently:
#   prover    signs + aggregates N updates          (src/bin/prover.rs)
#   verifier  verifies a FIXED artifact corpus      (src/bin/verifier.rs)
#   combined  the single-process demo, for contrast (src/main.rs)
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
#   ./benchmark.sh
#   RUNS=30 WARMUP=3 ./benchmark.sh
#   TARGETS="prover verifier" RUNS=50 ./benchmark.sh
#   PROJECT_CM4=1 ./benchmark.sh          # adds an explicitly-labelled ESTIMATE
set -euo pipefail

RUNS="${RUNS:-20}"
WARMUP="${WARMUP:-2}"
TARGETS="${TARGETS:-prover verifier combined}"
OUTDIR="${OUTDIR:-bench-$(date +%Y%m%d-%H%M%S)}"
PROJECT_CM4="${PROJECT_CM4:-0}"
CM4_LOW="${CM4_LOW:-8}"
CM4_HIGH="${CM4_HIGH:-15}"

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
for b in prover verifier decentralized-root-of-trust; do
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
  echo
  echo "## Memory"
  free -h 2>/dev/null | sed 's/^/  /'
  echo "swappiness       : $(sysread /proc/sys/vm/swappiness)"
  echo "THP enabled      : $(sysread /sys/kernel/mm/transparent_hugepage/enabled)"
  echo "  (relevant: leanVM's arena calls madvise(MADV_NOHUGEPAGE))"
  echo "ASLR             : $(sysread /proc/sys/kernel/randomize_va_space)"
  echo "stack ulimit     : $(ulimit -s)"
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
  echo "runs             : $RUNS measured, $WARMUP warmup(s) discarded"
  echo "targets          : $TARGETS"
  echo "kernel RSS probe : ${TIME_BIN:-unavailable (self-reported VmHWM only)}"
  echo
  echo "## lscpu (full)"
  lscpu 2>/dev/null | sed 's/^/  /'
} > "$ENV_FILE"

gov="$(sysread /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"

cat <<EOF

$(sed -n '3,6p' "$ENV_FILE")
runs      : $RUNS measured (+$WARMUP warmup discarded)
targets   : $TARGETS
outdir    : $OUTDIR
EOF
[ "$gov" = performance ] || echo "WARNING   : governor '$gov' != performance -> inflated variance"
[ -n "$TIME_BIN" ] || echo "WARNING   : /usr/bin/time absent -> no independent kernel RSS cross-check"
[ -f Cargo.lock ] || echo "WARNING   : Cargo.lock missing -> dependency resolution is not reproducible"
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
echo 'target,run,setup_ms,work_med_ms,work_mean_ms,work_sd_ms,work_min_ms,work_max_ms,work_total_ms,proof_med_bytes,rss_setup_mb,rss_max_mb,peak_rss_mb,kernel_maxrss_mb,failures' > "$RUNS_CSV"

run_once() { # $1 target -> prints stdout of the run to $SCRATCH/out.txt
  local target="$1" rc=0
  local -a cmd
  case "$target" in
    prover)   rm -rf "$SCRATCH/pout"; cmd=("$BIN_DIR/prover" "$SCRATCH/pout") ;;
    verifier) cmd=("$BIN_DIR/verifier" "$CORPUS") ;;
    combined) cmd=("$BIN_DIR/decentralized-root-of-trust") ;;
    *) echo "unknown target: $target" >&2; exit 1 ;;
  esac
  if [ -n "$TIME_BIN" ]; then
    EMIT_SAMPLES=1 "$TIME_BIN" -v "${cmd[@]}" >"$SCRATCH/out.txt" 2>"$SCRATCH/err.txt" || rc=$?
  else
    EMIT_SAMPLES=1 "${cmd[@]}" >"$SCRATCH/out.txt" 2>"$SCRATCH/err.txt" || rc=$?
  fi
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
  esac
  local line; line="$(grep "$tag" "$SCRATCH/out.txt" || true)"
  [ -n "$line" ] || { echo "run $run ($target): record line missing" >&2; exit 1; }
  awk -v t="$target" -v r="$run" -v k="$kmax" '{
    for (i=2;i<=NF;i++){ split($i,kv,"="); v[kv[1]]=kv[2] }
    if (t=="prover") {
      setup=v["setup_ms"]; med=v["prove_med_ms"]; mean=v["prove_mean_ms"]; sd=v["prove_sd_ms"]
      lo=v["prove_min_ms"]; hi=v["prove_max_ms"]; tot=v["prove_total_ms"]
      pb=v["proof_med_bytes"]; rs=v["rss_setup_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]; f=0
    } else if (t=="verifier") {
      setup=v["setup_ms"]; med=v["verify_med_ms"]; mean=v["verify_mean_ms"]; sd=v["verify_sd_ms"]
      lo=v["verify_min_ms"]; hi=v["verify_max_ms"]; tot=v["verify_total_ms"]
      pb=""; rs=v["rss_setup_mb"]; rm=v["rss_verify_max_mb"]; pk=v["peak_rss_mb"]; f=v["failures"]
    } else {
      setup=v["setup_total_ms"]; med=v["upd_prove_med_ms"]; mean=""; sd=""
      lo=v["upd_prove_min_ms"]; hi=v["upd_prove_max_ms"]; tot=v["updates_total_ms"]
      pb=v["proof_med_bytes"]; rs=v["rss_setup_mb"]; rm=v["rss_updates_max_mb"]; pk=v["peak_rss_mb"]
      f=(v["sec_ok"]=="1")?0:1
    }
    printf "%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
      t,r,setup,med,mean,sd,lo,hi,tot,pb,rs,rm,pk,k,f
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
      }
    }' "$SCRATCH/out.txt" >> "$SAMPLES"
}

for target in $TARGETS; do
  echo "== $target =="
  for i in $(seq 1 $((WARMUP + RUNS))); do
    if ! run_once "$target"; then
      echo "  run $i FAILED (exit != 0) — see below" >&2
      tail -5 "$SCRATCH/out.txt" >&2
      exit 1
    fi
    if [ "$i" -le "$WARMUP" ]; then printf '  warmup %d/%d\n' "$i" "$WARMUP"; continue; fi
    emit_run_row "$target" "$((i - WARMUP))"
    printf '  run %d/%d\n' "$((i - WARMUP))" "$RUNS"
  done
done

# Refuse to report timings for a build that failed its own security expectations.
bad="$(awk -F, 'NR>1 && $15!="" && $15+0>0 {n++} END{print n+0}' "$RUNS_CSV")"
if [ "$bad" -gt 0 ]; then
  echo
  echo "ABORT: $bad run(s) reported security-expectation failures. Numbers withheld." >&2
  exit 1
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
  emit "$target" setup            ms    3
  emit "$target" work_per_item    ms    4
  emit "$target" work_total       ms    9
  emit "$target" proof_size       bytes 10
  emit "$target" rss_after_setup  MB    11
  emit "$target" rss_max          MB    12
  emit "$target" peak_rss_vmhwm   MB    13
  emit "$target" peak_rss_kernel  MB    14
done

label() {
  case "$1:$2" in
    prover:work_per_item)   echo "prove / update" ;;
    verifier:work_per_item) echo "verify / update" ;;
    combined:work_per_item) echo "prove / update" ;;
    *:work_total)           echo "work total / run" ;;
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
  echo "runs      : n=$RUNS measured, $WARMUP warmup(s) discarded"
  echo "unit      : per-run value; for per-update metrics, the per-run median"
  echo "ci95      : Student's t, df=n-1 (normal approximation for n>31)"
  echo
  printf '%-9s %-22s %-6s %3s %10s %10s %10s %10s %10s %8s %7s\n' \
    target metric unit n min median max mean sd 'cv%' 'ci95±'
  awk -F, 'NR>1' "$SUMMARY_CSV" | while IFS=, read -r t m u n mn q1 md q3 mx mean sd cv ci; do
    d=2; [ "$u" = bytes ] && d=0; [ "$u" = MB ] && d=1
    printf '%-9s %-22s %-6s %3s %10.*f %10.*f %10.*f %10.*f %10.*f %7.1f%% %7.*f\n' \
      "$t" "$(label "$t" "$m")" "$u" "$n" $d "$mn" $d "$md" $d "$mx" $d "$mean" $d "$sd" "$cv" $d "$ci"
  done

  # Headline comparison: the reason the split exists.
  vp="$(col verifier 13 | stats | awk '{print $4}')"
  cp="$(col combined 13 | stats | awk '{print $4}')"
  if [ -n "$vp" ] && [ -n "$cp" ]; then
    echo
    echo "SPLIT VS COMBINED (median peak RSS)"
    awk -v v="$vp" -v c="$cp" 'BEGIN{
      printf "  verify-only process : %.0f MB\n", v
      printf "  combined process    : %.0f MB\n", c
      printf "  reduction           : %.1f%% (%.0f MB) for a node that only verifies\n", 100*(c-v)/c, c-v
    }'
  fi

  echo
  echo "CAVEATS (carry these into any write-up)"
  echo "  * Binaries are built with target-cpu=native: they are host-specific and"
  echo "    NOT portable. Re-run on each machine you report."
  [ "$gov" = performance ] || echo "  * CPU governor was '$gov', not 'performance': variance is inflated."
  echo "  * A prover process calls zk_alloc::enable_arena(), which sets"
  echo "    M_TRIM_THRESHOLD=-1: its RSS never decreases, so 'peak' means"
  echo "    'high-water mark of a monotonic curve'. A verify-only process keeps"
  echo "    normal malloc behaviour and its RSS is flat in the number of verifications."
  echo "  * Setup is paid once per process and is not persisted across restarts."
  echo "    It dominates total time; never fold it into per-update figures."
  echo "  * Per-update samples within a run are not independent (shared allocator"
  echo "    and cache state). The table's unit is the per-run median; samples.csv"
  echo "    holds every raw observation if you need the pooled distribution."
  echo "  * Prove cost is a step function of t (trace padded to a power of two),"
  echo "    not of the number of updates."

  if [ "$PROJECT_CM4" = 1 ]; then
    echo
    echo "RASPBERRY CM4 (BCM2711) PROJECTION — ESTIMATE, NOT A MEASUREMENT"
    echo "  Naive linear scaling x${CM4_LOW}..x${CM4_HIGH} of host wall-clock. It ignores"
    echo "  microarchitecture, memory bandwidth and thermal behaviour. Do not"
    echo "  publish these as results; run benchmark.sh natively on the board."
    for target in $TARGETS; do
      for c in 3 4; do
        v="$(col "$target" "$c" | stats | awk '{print $4}')"
        [ -n "$v" ] || continue
        awk -v t="$target" -v l="$(label "$target" "$([ "$c" = 3 ] && echo setup || echo work_per_item)")" \
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
