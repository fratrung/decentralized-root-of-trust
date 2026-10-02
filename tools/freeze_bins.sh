#!/usr/bin/env bash
# Build one crate and freeze the named executables into a campaign directory.
#
#   tools/freeze_bins.sh <dest-dir> <Cargo.toml> <bin>...
#
# `target/release/<bin>` is a path one assumes, not one Cargo guarantees. Cargo
# writes elsewhere under CARGO_TARGET_DIR, CARGO_BUILD_TARGET or a config
# `target-dir`, and then the fixed path either does not exist or still holds an
# old build, which would be measured and reported under the new commit. A
# rebuild during a long campaign could also swap binaries between runs.
#
# So this script asks Cargo where each executable actually is (the
# `compiler-artifact` messages of --message-format=json), copies it into
# <dest-dir>, and records what it copied:
#   SHA256SUMS  one `sha256  name` line per binary, for `sha256sum -c`
#   PROVENANCE  the build parameters and each binary's hash and Cargo source path
# The harnesses then execute only these copies. A copy, not a link: Cargo's own
# outputs are hard links it relinks on the next build.
#
# A byte-identical copy runs the same machine code; the programs start their
# timers after process start and none locates anything relative to its own
# executable, so where the copy lives does not enter any measurement.
set -euo pipefail
export LC_ALL=C

[ "$#" -ge 3 ] || { echo "usage: freeze_bins.sh <dest-dir> <Cargo.toml> <bin>..." >&2; exit 2; }
dest="$1"
manifest="$2"
shift 2
[ -f "$manifest" ] || { echo "freeze_bins: no Cargo manifest at $manifest" >&2; exit 2; }
manifest="$(cd "$(dirname "$manifest")" && pwd)/$(basename "$manifest")"
crate="$(basename "$(dirname "$manifest")")"

mkdir -p "$dest"
dest="$(cd "$dest" && pwd)"
for bin in "$@"; do
  [ ! -e "$dest/$bin" ] || { echo "freeze_bins: refusing to overwrite $dest/$bin" >&2; exit 1; }
done

# Fail before an expensive build if this filesystem refuses to execute (noexec).
true_bin="$(type -P true)"
cp -- "$true_bin" "$dest/.exec-probe"
chmod 0755 "$dest/.exec-probe"
if ! "$dest/.exec-probe"; then
  rm -f "$dest/.exec-probe"
  echo "freeze_bins: $dest does not allow execution (noexec mount?)" >&2
  exit 1
fi
rm -f "$dest/.exec-probe"

json="$(mktemp)"
trap 'rm -f "$json"' EXIT
log="$dest/build-$crate.log"
if ! cargo build --release --locked --manifest-path "$manifest" \
    --message-format=json-render-diagnostics >"$json" 2>"$log"; then
  echo "freeze_bins: cargo build failed for $manifest; last lines of $log:" >&2
  tail -20 "$log" >&2
  exit 1
fi

{
  echo "build crate=$crate manifest=$manifest"
  echo "  DROT_BENCH_N=${DROT_BENCH_N:-} DROT_BENCH_T=${DROT_BENCH_T:-}"
  echo "  CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-} CARGO_BUILD_TARGET=${CARGO_BUILD_TARGET:-}"
  "$(dirname "${BASH_SOURCE[0]}")/cargo_env_fingerprint.sh" | sed 's/^/  /'
} >> "$dest/PROVENANCE"

for bin in "$@"; do
  # Cargo prints one JSON object per line; a binary's artifact line names it in
  # the `target` object and gives its path in `executable`. Fresh (unchanged)
  # units are reported too, so this works whether or not anything recompiled.
  sources="$(awk -v want="$bin" '
    index($0, "\"reason\":\"compiler-artifact\"") == 0 { next }
    {
      t = index($0, "\"target\":{"); if (!t) next
      block = substr($0, t); block = substr(block, 1, index(block, "}"))
      if (index(block, "\"kind\":[\"bin\"]") == 0) next
      n = index(block, "\"name\":\""); if (!n) next
      name = substr(block, n + 8); name = substr(name, 1, index(name, "\"") - 1)
      if (name != want) next
      e = index($0, "\"executable\":\""); if (!e) next
      exe = substr($0, e + 14); exe = substr(exe, 1, index(exe, "\"") - 1)
      print exe
    }' "$json" | sort -u)"
  if [ -z "$sources" ] || [ "$(printf '%s\n' "$sources" | wc -l)" -ne 1 ]; then
    echo "freeze_bins: Cargo reported ${sources:+more than one }no unique executable for '$bin' in $crate" >&2
    exit 1
  fi
  case "$sources" in *\\*) echo "freeze_bins: unsupported escaped path for '$bin': $sources" >&2; exit 1 ;; esac
  [ -f "$sources" ] && [ -x "$sources" ] || { echo "freeze_bins: $sources is not an executable file" >&2; exit 1; }

  cp -- "$sources" "$dest/$bin"
  chmod 0555 "$dest/$bin"
  source_sha="$(sha256sum < "$sources" | awk '{print $1}')"
  copy_sha="$(sha256sum < "$dest/$bin" | awk '{print $1}')"
  [ "$source_sha" = "$copy_sha" ] || {
    echo "freeze_bins: $bin changed while being copied (concurrent build?)" >&2
    exit 1
  }
  printf '%s  %s\n' "$copy_sha" "$bin" >> "$dest/SHA256SUMS"
  printf '  binary %s sha256=%s source=%s\n' "$bin" "$copy_sha" "$sources" >> "$dest/PROVENANCE"
done
