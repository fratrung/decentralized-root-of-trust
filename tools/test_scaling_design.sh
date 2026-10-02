#!/usr/bin/env bash
# Design checks for committee-scaling-benchmark.sh that need no build:
#   - publication mode refuses the overrides that break its counterbalanced
#     design (odd SWEEP_REPEATS, INTERLEAVE=0) or time the signer's durable
#     burn on RAM, before creating OUTDIR, i.e. before any build or fixture;
#   - the planned sweeps (plan.csv, written by PLAN_ONLY=1) alternate direction,
#     and with an even count every committee size has the same mean position in
#     the campaign, so N is not confounded with experiment time.
set -euo pipefail
cd "$(dirname "$0")/.."
scratch="$(mktemp -d /tmp/drot-scaling-design.XXXXXX)"
trap 'rm -rf "$scratch"' EXIT

refused() { # label expected-message env...
  local label="$1" message="$2" out="$scratch/refused-$RANDOM"
  shift 2
  if env "$@" OUTDIR="$out" ./committee-scaling-benchmark.sh >"$scratch/log" 2>&1; then
    echo "scaling design: accepted $label" >&2; exit 1
  fi
  grep -qF "$message" "$scratch/log" || {
    echo "scaling design: $label refused for another reason:" >&2; tail -3 "$scratch/log" >&2; exit 1
  }
  [ ! -e "$out" ] || { echo "scaling design: $label created OUTDIR before refusing" >&2; exit 1; }
}
publication=(STUDY_MODE=publication RUNS=24 STRICT_ENV=1 PIN_CPUS=0)
refused "publication with three sweeps" "requires an even SWEEP_REPEATS" \
  "${publication[@]}" SWEEP_REPEATS=3 INTERLEAVE=1
refused "publication with blocked roles" "requires INTERLEAVE=1" \
  "${publication[@]}" SWEEP_REPEATS=2 INTERLEAVE=0
refused "an invalid INTERLEAVE" "INTERLEAVE must be 0 or 1" INTERLEAVE=2
refused "an invalid list size" "LIST_ENTRIES must be a positive integer" LIST_ENTRIES=many
refused "a list size above the limit" "exceeds the limit" LIST_ENTRIES=1048577
# A publication campaign must not time the XMSS durable burn on RAM-backed
# storage unless that scenario is asked for by name. Skipped where /dev/shm is
# not a RAM filesystem.
if [ -d /dev/shm ] && tools/storage_class.sh /dev/shm | grep -q '^class=ram '; then
  refused "publication with signer state on RAM" "refuses signer state on RAM-backed storage" \
    "${publication[@]}" SWEEP_REPEATS=2 INTERLEAVE=1 SIGNER_STATE_DIR=/dev/shm
fi
case "$(tools/storage_class.sh "$scratch")" in
  class=ram\ *|class=local\ *|class=network\ *|class=other\ *) ;;
  *) echo "scaling design: storage_class.sh printed no class" >&2; exit 1 ;;
esac

plan() { # sweeps -> path of plan.csv
  local out="$scratch/plan-$1"
  OUTDIR="$out" PLAN_ONLY=1 SWEEP_REPEATS="$1" HARD_MEMORY_LIMIT=auto \
    ./committee-scaling-benchmark.sh >"$scratch/log" 2>&1 ||
    { echo "scaling design: PLAN_ONLY failed:" >&2; tail -3 "$scratch/log" >&2; exit 1; }
  echo "$out/plan.csv"
}
check_plan() { # sweeps counterbalanced(0|1)
  awk -F, -v sweeps="$1" -v want="$2" '
    NR == 1 { next }
    {
      expected = ($1 % 2) ? "ascending" : "descending"
      if ($2 != expected) { print "sweep " $1 " is " $2 ", expected " expected > "/dev/stderr"; bad = 1 }
      if ($5 != int(2 * $4 / 3) + 1) { print "N=" $4 " has t=" $5 > "/dev/stderr"; bad = 1 }
      seen[$1]++; total[$4] += $3; count[$4]++; sizes[$4] = 1
      if ($2 == "ascending") up[$3] = $4; else down[$3] = $4
    }
    END {
      for (s = 1; s <= sweeps; s++) if (!seen[s]) { print "sweep " s " missing" > "/dev/stderr"; bad = 1 }
      k = 0; for (n in sizes) k++
      for (p = 1; p <= k; p++)
        if (sweeps > 1 && up[p] != down[k + 1 - p]) { print "descending sweep is not the reverse" > "/dev/stderr"; bad = 1 }
      balanced = 1
      for (n in sizes) {
        if (count[n] != sweeps) { print "N=" n " planned " count[n] " times" > "/dev/stderr"; bad = 1 }
        if (total[n] / count[n] != (k + 1) / 2) balanced = 0
      }
      if (balanced != want) { print "sweeps=" sweeps ": counterbalanced=" balanced ", expected " want > "/dev/stderr"; bad = 1 }
      exit bad
    }' "$(plan "$1")" || { echo "scaling design: plan with $1 sweep(s) is wrong" >&2; exit 1; }
}
check_plan 2 1
check_plan 4 1
check_plan 3 0
check_plan 1 0
echo 'scaling design: OK'
