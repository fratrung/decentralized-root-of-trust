#!/usr/bin/env bash
# Regression test for benchmark.sh's Williams-style target order. It extracts
# the real functions from benchmark.sh and checks, over several complete
# designs for 2..6 targets, that
#   - every row of the design occurs equally often;
#   - every target occupies every position equally often;
#   - every ordered pair "a immediately before b" occurs equally often WITHIN
#     a row. The step from one row's last target to the next row's first is a
#     different transition (it crosses a cooldown) and is not counted.
# Odd designs (N rotations followed by their reversals) must repeat as a whole.
set -euo pipefail
cd "$(dirname "$0")/.."

functions="$(sed -n '/^balanced_design_rows() {/,/^}/p; /^balanced_row() {/,/^}/p' benchmark.sh)"
[ -n "$functions" ] || { echo "balanced order: functions not found in benchmark.sh" >&2; exit 1; }
eval "$functions"

CYCLES=3
for n in 2 3 4 5 6; do
  TARGET_LIST=()
  for ((i = 0; i < n; i++)); do TARGET_LIST+=("T$i"); done
  design="$(balanced_design_rows)"
  expected_design=$n; [ $((n % 2)) -eq 1 ] && expected_design=$((2 * n))
  [ "$design" -eq "$expected_design" ] || { echo "N=$n: design has $design rows, expected $expected_design" >&2; exit 1; }
  for ((row = 0; row < CYCLES * design; row++)); do
    balanced_row "$row" | paste -sd' ' -
  done | awk -v n="$n" -v design="$design" -v cycles="$CYCLES" '
    {
      if (NF != n) { print "N=" n ": row " NR " has " NF " targets" > "/dev/stderr"; bad = 1 }
      seen_row[$0]++
      delete in_row
      for (p = 1; p <= NF; p++) {
        if ($p in in_row) { print "N=" n ": row " NR " repeats " $p > "/dev/stderr"; bad = 1 }
        in_row[$p] = 1
        position[$p, p]++
        if (p > 1) pair[$(p - 1), $p]++
      }
    }
    END {
      each = cycles * design / n
      distinct = 0
      for (r in seen_row) {
        distinct++
        if (seen_row[r] != cycles) { print "N=" n ": order [" r "] ran " seen_row[r] " times, expected " cycles > "/dev/stderr"; bad = 1 }
      }
      if (distinct != design) { print "N=" n ": " distinct " distinct orders, expected " design > "/dev/stderr"; bad = 1 }
      for (a = 0; a < n; a++) {
        for (p = 1; p <= n; p++)
          if (position["T" a, p] != each) { print "N=" n ": T" a " at position " p " " position["T" a, p] + 0 " times, expected " each > "/dev/stderr"; bad = 1 }
        for (b = 0; b < n; b++)
          if (a != b && pair["T" a, "T" b] != each) { print "N=" n ": T" a " before T" b " " pair["T" a, "T" b] + 0 " times, expected " each > "/dev/stderr"; bad = 1 }
      }
      exit bad
    }'
done
echo 'balanced target order: OK'
