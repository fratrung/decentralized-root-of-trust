#!/usr/bin/env bash
# Reproduce the experiment behind the ML-DSA statement digest.
#
#   tools/mldsa_statement_experiment.sh
#   RUNS=10 T_LIST="67 334" L_LIST="100 1000 10000" tools/mldsa_statement_experiment.sh
#   PIN_CPUS=2 OUTDIR=my-run tools/mldsa_statement_experiment.sh
#
# Question. An ML-DSA committee member signs a statement that contains the whole
# status list (32 bytes per credential). ML-DSA begins by hashing H(pk) || M, a
# prefix that differs for every signer, so a verifier of t signatures re-reads
# the statement t times. The protocol therefore signs SHAKE256(statement, 64)
# instead (FIPS 204 section 5.4, hashing at the application level). How much
# does that change signing and quorum verification, and how does the answer
# depend on the quorum size t and the list size L?
#
# Hypotheses, stated before measuring:
#   H1  signing the statement: quorum verification grows with t x L;
#   H2  signing the digest: quorum verification depends on t but hardly on L
#       (one pass over the list, once);
#   H3  the two coincide for short lists and diverge as L grows.
#
# Method:
#   - the binary is built once, frozen and hashed (tools/freeze_bins.sh);
#   - one process per quorum size t measures every list size and both variants,
#     on the same keys, interleaving list sizes and alternating which variant
#     goes first. The comparisons this experiment is about (statement against
#     digest, long list against short list) are therefore ratios taken inside
#     one process: a change of CPU clock state between processes shifts both
#     terms and cancels;
#   - each process is repeated RUNS times; the order of the quorum sizes rotates
#     and reverses from run to run;
#   - the unit of analysis is the per-process value (n = RUNS), summarized with
#     tools/stats.awk (median, quartiles, mean and its Student-t 95% CI);
#   - every verification must succeed and four negative controls must fail,
#     or the process aborts and no number is reported.
#
# What should reproduce on another machine is the shape of the result, which
# the report checks explicitly at the end (SHAPE CHECK), not the milliseconds:
# those belong to this CPU, compiler and library version, recorded in env.txt.
#
# Output (OUTDIR, default mldsa-statement-experiment-<timestamp>):
#   env.txt      host, CPU, governor, toolchain, commit, parameters
#   bin/         the frozen binary with its SHA-256
#   logs/        stdout of every process (summary lines and per-repetition samples)
#   runs.csv     one row per process and list size: medians and in-process ratios
#   summary.csv  statistics across processes for every (t, L, metric)
#   report.txt   the tables, the checks of H1-H3 and the shape check
set -euo pipefail
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="$PWD"

RUNS="${RUNS:-5}"
REPETITIONS="${REPETITIONS:-15}"
# Untimed busy time at the start of every process, so its measurements are
# taken at a settled CPU frequency whatever the governor.
WARMUP_MS="${WARMUP_MS:-1500}"
T_LIST="${T_LIST:-4 67 334 1001}"
L_LIST="${L_LIST:-20 100 1000 10000}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-1}"
PIN_CPUS="${PIN_CPUS:-}"
OUTDIR="${OUTDIR:-mldsa-statement-experiment-$(date +%Y%m%d-%H%M%S)}"

positive() { case "$2" in ''|*[!0-9]*|0) echo "$1 must be a positive integer, got '$2'" >&2; exit 1 ;; esac; }
positive RUNS "$RUNS"
positive REPETITIONS "$REPETITIONS"
case "$WARMUP_MS" in ''|*[!0-9]*) echo "WARMUP_MS must be a non-negative integer" >&2; exit 1 ;; esac
case "$COOLDOWN_SECONDS" in ''|*[!0-9]*) echo "COOLDOWN_SECONDS must be a non-negative integer" >&2; exit 1 ;; esac
read -r -a T_VALUES <<<"$T_LIST"
read -r -a L_VALUES <<<"$L_LIST"
[ "${#T_VALUES[@]}" -ge 1 ] && [ "${#L_VALUES[@]}" -ge 1 ] || { echo "T_LIST and L_LIST must not be empty" >&2; exit 1; }
ascending() { # name values...: strictly increasing positive integers
  local name="$1" previous=0 value
  shift
  for value in "$@"; do
    positive "$name" "$value"
    [ "$value" -gt "$previous" ] || { echo "$name must be strictly increasing, got '$*'" >&2; exit 1; }
    previous="$value"
  done
}
ascending T_LIST "${T_VALUES[@]}"
ascending L_LIST "${L_VALUES[@]}"
if [ -n "$PIN_CPUS" ]; then
  command -v taskset >/dev/null 2>&1 || { echo "PIN_CPUS requires taskset" >&2; exit 1; }
fi
if [ -e "$OUTDIR" ] &&
   { [ ! -d "$OUTDIR" ] || [ -n "$(find "$OUTDIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; }; then
  echo "OUTDIR already exists and is not empty: $OUTDIR (use a new directory)" >&2
  exit 1
fi
mkdir -p "$OUTDIR/logs"
OUTDIR="$(cd "$OUTDIR" && pwd)"

echo "building and freezing the experiment binary ..."
"$REPO/tools/freeze_bins.sh" "$OUTDIR/bin" "$REPO/mldsa/Cargo.toml" mldsa_statement_experiment
BIN="$OUTDIR/bin/mldsa_statement_experiment"

governors() {
  local path values=""
  for path in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [ -r "$path" ] && values="$values $(cat "$path")"
  done
  tr ' ' '\n' <<<"$values" | sed '/^$/d' | sort -u | paste -sd, -
}
# Mains or battery: a laptop changes its CPU power limits with the power source,
# so the absolute milliseconds of two processes are comparable only if it did
# not change between them. Recorded per process; "unknown" where not exposed.
power_source() {
  local supply state="unknown"
  for supply in /sys/class/power_supply/*; do
    [ "$(cat "$supply/type" 2>/dev/null)" = Mains ] || continue
    case "$(cat "$supply/online" 2>/dev/null)" in 1) state=mains ;; 0) state=battery ;; esac
  done
  echo "$state"
}
{
  echo "# ML-DSA statement digest experiment"
  echo "timestamp   : $(date -Is)"
  echo "host        : $(hostname)"
  echo "kernel      : $(uname -srmo)"
  echo "cpu         : $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "governors   : $(governors)"
  echo "pinned      : ${PIN_CPUS:-no}"
  echo "power       : $(power_source) at start"
  echo "rustc       : $(sed -n 's/^  rustc: \([^;]*\).*/\1/p' "$OUTDIR/bin/PROVENANCE")"
  echo "git commit  : $(git rev-parse HEAD 2>/dev/null || echo n/a)"
  echo "git dirty   : $([ -n "$(git status --porcelain 2>/dev/null)" ] && echo yes || echo no)"
  echo "runs        : $RUNS processes per quorum size"
  echo "repetitions : $REPETITIONS quorum verifications per variant and list size, per process"
  echo "warm-up     : ${WARMUP_MS} ms of untimed work at the start of every process"
  echo "t values    : ${T_VALUES[*]}"
  echo "L values    : ${L_VALUES[*]} (all measured inside each process)"
  echo "cooldown    : ${COOLDOWN_SECONDS}s before each process"
  echo
  echo "## Binary"
  sed 's/^/  /' "$OUTDIR/bin/SHA256SUMS"
  sed 's/^/  /' "$OUTDIR/bin/PROVENANCE"
} > "$OUTDIR/env.txt"

count="${#T_VALUES[@]}"
first_l="${L_VALUES[0]}"; last_l="${L_VALUES[${#L_VALUES[@]}-1]}"
first_t="${T_VALUES[0]}"; last_t="${T_VALUES[$count-1]}"

RUNS_CSV="$OUTDIR/runs.csv"
METRICS=(sign_statement_ms sign_digest_ms verify_statement_ms verify_digest_ms preimage_ms digest_ms
  app_pass_ms mu_statement_ms mu_digest_ms verify_ratio sign_ratio verify_saving_ms model_saving_ms saving_vs_model
  verify_ratio_equal_hash verify_statement_growth verify_digest_growth)
FIRST_METRIC_COLUMN=5
echo "run,t,list_entries,statement_bytes,$(IFS=,; echo "${METRICS[*]}"),freq_end_mhz,power" > "$RUNS_CSV"

# Clock frequency of the measured CPU(s) right after a process ends, in MHz.
# Empty when cpufreq is not exposed.
freq_now_mhz() {
  local cpus cpu path values=""
  if [ -n "$PIN_CPUS" ]; then
    cpus="$(tr ',' ' ' <<<"$PIN_CPUS")"
  else
    cpus="$(ls -d /sys/devices/system/cpu/cpu[0-9]* 2>/dev/null | sed 's/.*cpu//')"
  fi
  for cpu in $cpus; do
    case "$cpu" in *-*) continue ;; esac
    path="/sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_cur_freq"
    [ -r "$path" ] && values="$values $(cat "$path" 2>/dev/null)"
  done
  awk '{ for (i = 1; i <= NF; i++) if ($i > max) max = $i } END { if (max) printf "%.0f", max / 1000 }' <<<"$values"
}

echo "measuring $count quorum sizes x ${#L_VALUES[@]} list sizes x $RUNS runs ..."
for ((run = 1; run <= RUNS; run++)); do
  for ((position = 0; position < count; position++)); do
    # Rotate the starting quorum size with the run and reverse every other run,
    # so no quorum size is always measured first or after the same one.
    index=$(((position + run - 1) % count))
    [ $((run % 2)) -eq 0 ] && index=$((count - 1 - index))
    t="${T_VALUES[$index]}"
    [ "$COOLDOWN_SECONDS" -eq 0 ] || sleep "$COOLDOWN_SECONDS"
    log="$OUTDIR/logs/run$(printf '%02d' "$run")-t$t.out"
    cmd=("$BIN" "$t" "$REPETITIONS" "$WARMUP_MS" "${L_VALUES[@]}")
    [ -z "$PIN_CPUS" ] || cmd=(taskset -c "$PIN_CPUS" "${cmd[@]}")
    rc=0
    EMIT_SAMPLES=1 "${cmd[@]}" > "$log" 2>"$log.err" || rc=$?
    freq_end="$(freq_now_mhz)"
    power_end="$(power_source)"
    if [ "$rc" -ne 0 ]; then
      echo "ABORT: run $run, t=$t failed; see $log.err. No result is reported." >&2
      tail -5 "$log.err" >&2
      exit 1
    fi
    # One summary line per list size, in L_LIST order. The in-process figures:
    #   verify_ratio, sign_ratio   statement / digest, same list size
    #   verify_saving_ms           statement - digest, same list size
    #   model_saving_ms            what the building blocks predict for that saving:
    #                              t x (ML-DSA's mu step over the statement - over
    #                              the digest) - one application SHAKE256 pass
    #   saving_vs_model            measured saving / model saving
    #   verify_ratio_equal_hash    the ratio if each of ML-DSA's passes over the
    #                              statement cost one application pass:
    #                              (digest variant + (t - 1) application passes) /
    #                              digest variant. This is the part of the ratio
    #                              that is one pass instead of t, with the speed
    #                              difference between the two SHAKE256
    #                              implementations removed. Computed, not measured;
    #                              it uses only the digest variant and the
    #                              application pass, the two stable measurements.
    #   verify_*_growth            this list size / the first list size, same variant
    rows="$(grep '^MLDSA_STATEMENT_EXPERIMENT ' "$log" | awk -v run="$run" -v t="$t" -v want="${L_VALUES[*]}" -v freq="$freq_end" -v power="$power_end" '
      function field(name,    i, pair) {
        for (i = 2; i <= NF; i++) { split($i, pair, "="); if (pair[1] == name) return pair[2] }
        return ""
      }
      BEGIN { OFS = ","; expected = split(want, sizes, " ") }
      {
        if (field("controls_ok") != 1 || field("t") != t || field("list_entries") != sizes[NR]) { bad = 1; exit }
        ss = field("sign_statement_med_ms"); sd = field("sign_digest_med_ms")
        vs = field("verify_statement_med_ms"); vd = field("verify_digest_med_ms")
        pre = field("preimage_med_ms"); dig = field("digest_med_ms")
        mus = field("mu_statement_med_ms"); mud = field("mu_digest_med_ms")
        if (NR == 1) { vs0 = vs; vd0 = vd }
        pass = field("app_pass_med_ms")
        if (mus == "" || mud == "" || pass == "" || !(sd > 0 && vd > 0 && vs0 > 0 && vd0 > 0)) { bad = 1; exit }
        model = t * (mus - mud) - pass
        print run, t, sizes[NR], field("statement_bytes"), ss, sd, vs, vd, pre, dig, pass, mus, mud, \
          sprintf("%.4f", vs / vd), sprintf("%.4f", ss / sd), sprintf("%.4f", vs - vd), \
          sprintf("%.4f", model), (model > 0 ? sprintf("%.4f", (vs - vd) / model) : ""), \
          sprintf("%.4f", (vd + (t - 1) * pass) / vd), \
          sprintf("%.4f", vs / vs0), sprintf("%.4f", vd / vd0), freq, power
      }
      END { if (bad || NR != expected) exit 1 }')" ||
      { echo "ABORT: run $run, t=$t printed no valid summary for every list size; see $log" >&2; exit 1; }
    printf '%s\n' "$rows" >> "$RUNS_CSV"
    printf '  run %d/%d  t=%-5s' "$run" "$RUNS" "$t"
    awk -F, '{ printf "  L=%s: %sx", $3, $14 } END { print "" }' <<<"$rows"
  done
done

stats() { sort -g | awk -f "$REPO/tools/stats.awk"; }
SUMMARY_CSV="$OUTDIR/summary.csv"
echo 't,list_entries,metric,n,min,q1,median,q3,max,mean,sd,cv_pct,mean_ci95_halfwidth' > "$SUMMARY_CSV"
for t in "${T_VALUES[@]}"; do
  for l in "${L_VALUES[@]}"; do
    column="$FIRST_METRIC_COLUMN"
    for metric in "${METRICS[@]}"; do
      line="$(awk -F, -v t="$t" -v l="$l" -v c="$column" 'NR > 1 && $2 == t && $3 == l && $c != "" { print $c }' "$RUNS_CSV" | stats)"
      printf '%s,%s,%s,%s\n' "$t" "$l" "$metric" \
        "$(awk -v OFS=, '{ $1 = $1; for (i = 1; i <= NF; i++) if ($i == "NA") $i = ""; print }' <<<"$line")" >> "$SUMMARY_CSV"
      column=$((column + 1))
    done
  done
done

value() { # t L metric column-name
  awk -F, -v t="$1" -v l="$2" -v m="$3" -v want="$4" '
    NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
    $1 == t && $2 == l && $3 == m { print $(col[want]); exit }' "$SUMMARY_CSV"
}
ci() { # t L metric format: the CI half-width, or n/a
  local v
  v="$(value "$1" "$2" "$3" mean_ci95_halfwidth)"
  if [ -n "$v" ]; then printf "$4" "$v"; else printf 'n/a'; fi
}
interval() { # t L metric: the 95% CI of the mean as [low, high], or n/a
  awk -v m="$(value "$1" "$2" "$3" mean)" -v h="$(value "$1" "$2" "$3" mean_ci95_halfwidth)" \
    'BEGIN { if (m == "" || h == "") print "n/a"; else printf "[%.2f, %.2f]", m - h, m + h }'
}
statement_bytes() { awk -F, -v l="$1" 'NR > 1 && $3 == l { print $4; exit }' "$RUNS_CSV"; }

{
  echo "ML-DSA STATEMENT DIGEST EXPERIMENT"
  sed -n '2,11p' "$OUTDIR/env.txt"
  echo "method      : $RUNS processes per quorum size t; each process measures every list size"
  echo "              and both variants, interleaved. A value is the median across processes"
  echo "              of the per-process median ($REPETITIONS repetitions); +- and [low, high] are the"
  echo "              Student-t 95% CI of the mean of the per-process values (n/a with one"
  echo "              process). Ratios and differences are computed inside each process."
  echo
  echo "1. QUORUM VERIFICATION, ms (build the statement, then verify t signatures)"
  printf '%6s %7s %10s | %11s %8s | %11s %8s | %8s %18s\n' t L stmt_bytes statement '+-ci95' digest '+-ci95' ratio 'ratio ci95'
  for t in "${T_VALUES[@]}"; do
    for l in "${L_VALUES[@]}"; do
      printf '%6s %7s %10s | %11.3f %8s | %11.3f %8s | %7.2fx %18s\n' "$t" "$l" "$(statement_bytes "$l")" \
        "$(value "$t" "$l" verify_statement_ms median)" "$(ci "$t" "$l" verify_statement_ms '%.3f')" \
        "$(value "$t" "$l" verify_digest_ms median)" "$(ci "$t" "$l" verify_digest_ms '%.3f')" \
        "$(value "$t" "$l" verify_ratio median)" "$(interval "$t" "$l" verify_ratio)"
    done
  done
  echo
  echo "2. PER SIGNATURE VERIFIED, ms (quorum verification / t)"
  printf '%6s %7s | %11s | %11s\n' t L statement digest
  for t in "${T_VALUES[@]}"; do
    for l in "${L_VALUES[@]}"; do
      printf '%6s %7s | %11.4f | %11.4f\n' "$t" "$l" \
        "$(awk -v v="$(value "$t" "$l" verify_statement_ms median)" -v t="$t" 'BEGIN { print v / t }')" \
        "$(awk -v v="$(value "$t" "$l" verify_digest_ms median)" -v t="$t" 'BEGIN { print v / t }')"
    done
  done
  echo
  echo "3. TIME SAVED PER QUORUM VERIFICATION, ms (statement - digest, same process), against"
  echo "   the building blocks: t x (ML-DSA's own hashing of the statement - of the digest)"
  echo "   - one application SHAKE256 pass. saved / model near 1 means the difference is"
  echo "   ML-DSA's hashing of the statement and nothing else; that step is timed alone, on"
  echo "   its own buffer, and need not run at exactly the speed it has inside verification."
  printf '%6s %7s | %11s %8s | %11s | %14s\n' t L saved '+-ci95' model 'saved / model'
  for t in "${T_VALUES[@]}"; do
    for l in "${L_VALUES[@]}"; do
      ratio="$(value "$t" "$l" saving_vs_model median)"
      printf '%6s %7s | %11.3f %8s | %11.3f | %14s\n' "$t" "$l" \
        "$(value "$t" "$l" verify_saving_ms median)" "$(ci "$t" "$l" verify_saving_ms '%.3f')" \
        "$(value "$t" "$l" model_saving_ms median)" "$([ -n "$ratio" ] && printf '%.2f' "$ratio" || echo n/a)"
    done
  done
  echo
  echo "4. GROWTH WITH THE LIST, same process: quorum verification at L / at L=$first_l"
  printf '%6s %7s | %10s %18s | %10s %18s\n' t L statement 'ci95' digest 'ci95'
  for t in "${T_VALUES[@]}"; do
    for l in "${L_VALUES[@]}"; do
      printf '%6s %7s | %9.2fx %18s | %9.2fx %18s\n' "$t" "$l" \
        "$(value "$t" "$l" verify_statement_growth median)" "$(interval "$t" "$l" verify_statement_growth)" \
        "$(value "$t" "$l" verify_digest_growth median)" "$(interval "$t" "$l" verify_digest_growth)"
    done
  done
  echo
  echo "5. ONE MEMBER SIGNING ONCE, ms (build the statement, then sign)"
  printf '%6s %7s | %11s %8s | %11s %8s | %8s %18s\n' t L statement '+-ci95' digest '+-ci95' ratio 'ratio ci95'
  for t in "${T_VALUES[@]}"; do
    for l in "${L_VALUES[@]}"; do
      printf '%6s %7s | %11.3f %8s | %11.3f %8s | %7.2fx %18s\n' "$t" "$l" \
        "$(value "$t" "$l" sign_statement_ms median)" "$(ci "$t" "$l" sign_statement_ms '%.3f')" \
        "$(value "$t" "$l" sign_digest_ms median)" "$(ci "$t" "$l" sign_digest_ms '%.3f')" \
        "$(value "$t" "$l" sign_ratio median)" "$(interval "$t" "$l" sign_ratio)"
    done
  done
  echo
  echo "6. BUILDING BLOCKS, ms, pooled over every process (they do not depend on t)."
  echo "   The two SHAKE256 passes over the statement are different code: the application's"
  echo "   digest (sha3 crate) and ML-DSA's own hashing of its message (mu). MiB/s is the"
  echo "   statement size over the time of that pass alone."
  printf '%7s %10s | %9s | %17s %6s | %17s %6s | %9s\n' L stmt_bytes 'build' 'application pass' 'MiB/s' 'ML-DSA mu pass' 'MiB/s' 'mu / app'
  for l in "${L_VALUES[@]}"; do
    pooled() { awk -F, -v l="$l" -v c="$1" 'NR > 1 && $3 == l { print $c }' "$RUNS_CSV" | stats | awk '{ print $4 }'; }
    awk -v l="$l" -v bytes="$(statement_bytes "$l")" -v p="$(pooled 9)" -v app="$(pooled 11)" \
        -v ms="$(pooled 12)" -v md="$(pooled 13)" 'BEGIN {
      mu = ms - md
      rate_app = (app > 0) ? sprintf("%.0f", bytes / 1048576 / (app / 1000)) : "n/a"
      rate_mu = (mu > 0) ? sprintf("%.0f", bytes / 1048576 / (mu / 1000)) : "n/a"
      printf "%7s %10s | %9.4f | %17.4f %6s | %17.4f %6s | %9s\n", l, bytes, p, app, rate_app, mu, rate_mu, \
        (app > 0 && mu > 0 ? sprintf("%.2fx", mu / app) : "n/a")
    }'
  done
  echo
  echo "6b. HOW MUCH OF THE RATIO IS STRUCTURAL: the measured statement/digest ratio, and the"
  echo "    ratio computed as if each of ML-DSA's passes over the statement cost one application"
  echo "    pass: (digest variant + (t - 1) application passes) / digest variant. One pass"
  echo "    instead of t, with the difference in SHAKE256 speed removed."
  printf '%6s %7s | %10s | %22s %18s\n' t L measured 'at equal hashing speed' 'ci95'
  for t in "${T_VALUES[@]}"; do
    for l in "${L_VALUES[@]}"; do
      printf '%6s %7s | %9.2fx | %21.2fx %18s\n' "$t" "$l" "$(value "$t" "$l" verify_ratio median)" \
        "$(value "$t" "$l" verify_ratio_equal_hash median)" "$(interval "$t" "$l" verify_ratio_equal_hash)"
    done
  done
  echo
  echo "7. CPU CLOCK AND POWER SOURCE right after each process (informative: the comparisons"
  echo "   above are in-process ratios and do not depend on them; the absolute ms do)"
  awk -F, -v col="$((FIRST_METRIC_COLUMN + ${#METRICS[@]}))" 'NR > 1 && $col != "" && !(($1, $2) in seen) {
      seen[$1, $2] = 1; n[$2]++; sum[$2] += $col
      if (lo == "" || $col < lo) lo = $col; if ($col > hi) hi = $col
      if (!($2 in listed)) { listed[$2] = 1; order[++count] = $2 }
    }
    END {
      if (!count) { print "  not exposed by this system"; exit }
      for (i = 1; i <= count; i++) printf "  t=%-5s mean %.0f\n", order[i], sum[order[i]] / n[order[i]]
      printf "  all processes: %d to %d MHz\n", lo, hi
    }' "$RUNS_CSV"
  awk -F, 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "power") col = i; next }
    !(($1, $2) in seen) { seen[$1, $2] = 1; n[$col]++; total++ }
    END {
      kinds = 0; for (k in n) { kinds++; list = list (list == "" ? "" : ", ") n[k] " on " k }
      printf "  power source: %s of %d processes%s\n", list, total, \
        (kinds > 1 ? "  ** it changed during the run: compare ratios, not milliseconds **" : "")
    }' "$RUNS_CSV"
  echo
  echo "HYPOTHESES (L from $first_l to $last_l entries; nothing is filtered or discarded)"
  for t in "${T_VALUES[@]}"; do
    awk -v t="$t" -v a="$first_l" -v b="$last_l" \
        -v s1="$(value "$t" "$first_l" verify_statement_ms median)" -v s2="$(value "$t" "$last_l" verify_statement_ms median)" \
        -v d1="$(value "$t" "$first_l" verify_digest_ms median)" -v d2="$(value "$t" "$last_l" verify_digest_ms median)" \
        -v sg="$(value "$t" "$last_l" verify_statement_growth median)" -v dg="$(value "$t" "$last_l" verify_digest_growth median)" \
        -v r1="$(value "$t" "$first_l" verify_ratio median)" -v r2="$(value "$t" "$last_l" verify_ratio median)" 'BEGIN {
      printf "  t=%-5s H1 statement variant: %.3f -> %.3f ms (x%.1f in-process)\n", t, s1, s2, sg
      printf "          H2 digest variant   : %.3f -> %.3f ms (x%.2f in-process, %+.3f ms)\n", d1, d2, dg, d2 - d1
      printf "          H3 statement/digest : %.2fx at L=%s, %.1fx at L=%s\n", r1, a, r2, b
    }'
  done
  echo
  # The qualitative result another machine should reproduce. Each criterion is
  # evaluated on the in-process ratios; a criterion that needs more than one
  # list or quorum size is skipped when the run has only one.
  echo "SHAPE CHECK (what should reproduce on other hardware; the milliseconds should not)"
  awk -F, -v first_l="$first_l" -v last_l="$last_l" -v first_t="$first_t" -v last_t="$last_t" \
      -v ts="${T_VALUES[*]}" -v ls="${L_VALUES[*]}" '
    NR == FNR {
      if (FNR > 1) { median[$1, $2, $3] = $7; mean[$1, $2, $3] = $10; half[$1, $2, $3] = $13 }
      next
    }
    FNR == 1 { for (i = 1; i <= NF; i++) column[$i] = i; next }
    $3 == last_l { processes++; if ($(column["verify_statement_growth"]) > $(column["verify_digest_growth"])) steeper++ }
    function verdict(ok) { return ok ? "REPRODUCED" : "NOT REPRODUCED" }
    END {
      nt = split(ts, t, " "); nl = split(ls, l, " ")
      if (nl < 2) { print "  skipped: a single list size cannot show a trend in L"; exit }
      c1 = 1; c2 = 1; ci_known = 1
      for (i = 1; i <= nt; i++) {
        for (j = 2; j <= nl; j++)
          if (median[t[i], l[j], "verify_ratio"] < median[t[i], l[j - 1], "verify_ratio"]) c1 = 0
        if (half[t[i], last_l, "verify_ratio"] == "") ci_known = 0
        else if (mean[t[i], last_l, "verify_ratio"] - half[t[i], last_l, "verify_ratio"] <= 1) c2 = 0
      }
      printf "  S1 the statement/digest ratio does not decrease as the list grows, for every t: %s\n", verdict(c1)
      c5 = 1
      for (i = 1; i <= nt; i++)
        if (median[t[i], last_l, "verify_ratio_equal_hash"] <= 1) c5 = 0
      if (ci_known)
        printf "  S2 at L=%s the 95%% CI of the ratio is wholly above 1, for every t: %s\n", last_l, verdict(c2)
      else
        printf "  S2 at L=%s the 95%% CI of the ratio is wholly above 1: not evaluated (one process)\n", last_l
      printf "  S3 from L=%s to L=%s the statement variant grows more than the digest variant: %s (%d of %d processes)\n", \
        first_l, last_l, verdict(steeper == processes), steeper, processes
      if (nt > 1)
        printf "  S4 at L=%s the ratio is larger for t=%s than for t=%s: %s (%.1fx against %.1fx)\n", last_l, last_t, first_t, \
          verdict(median[last_t, last_l, "verify_ratio"] > median[first_t, last_l, "verify_ratio"]), \
          median[last_t, last_l, "verify_ratio"], median[first_t, last_l, "verify_ratio"]
      printf "  S5 at L=%s the ratio stays above 1 with the SHAKE256 speed difference removed, for every t: %s\n", last_l, verdict(c5)
    }' "$SUMMARY_CSV" "$RUNS_CSV"
  echo
  echo "Every quorum verified in every repetition and all four negative controls"
  echo "failed to verify in every process, or this report would not exist."
} | tee "$OUTDIR/report.txt"

(cd "$OUTDIR" && find logs -type f -print0 | sort -z | xargs -0 -r sha256sum > logs.sha256 &&
   sha256sum env.txt runs.csv summary.csv report.txt logs.sha256 > outputs.sha256)
echo
echo "written: $OUTDIR/{env.txt,runs.csv,summary.csv,report.txt,logs/,bin/}"
