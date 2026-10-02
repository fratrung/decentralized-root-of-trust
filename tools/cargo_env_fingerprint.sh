#!/usr/bin/env bash
# Print what actually decides how this repository's binaries are compiled.
#
#   tools/cargo_env_fingerprint.sh            # one `key: value` line per fact
#
# The repository's .cargo/config.toml sets `target-cpu=native`, but that file
# is not the whole story. Cargo takes rustflags from, in order,
# CARGO_ENCODED_RUSTFLAGS, RUSTFLAGS, the matching [target] tables and then
# [build]; and it merges every .cargo/config(.toml) from the working directory
# up to the filesystem root plus $CARGO_HOME. Any of these can replace the flags
# the report claims, and the resulting binaries would differ from the declared
# build without any error. So this lists them all:
#   rustc:          `rustc -vV` of the toolchain rust-toolchain.toml selects here
#   cargo:          `cargo -V`
#   cargo-config:   every config file Cargo would read, its SHA-256, and whether
#                   it sets rustflags (the repository's own is expected to)
#   rustflags-env:  each environment override of rustflags, or `none`
# benchmark.sh records it and refuses strict runs with overrides; freeze_bins.sh
# stores it with each frozen set; the scaling resume fingerprint hashes it.
set -euo pipefail
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo="$PWD"

echo "rustc: $(rustc -vV 2>/dev/null | paste -sd';' - || echo unavailable)"
echo "cargo: $(cargo -V 2>/dev/null || echo unavailable)"

dir="$repo"
while :; do
  for name in config.toml config; do
    file="$dir/.cargo/$name"
    [ -f "$file" ] || continue
    sets=no
    grep -Eq '^[[:space:]]*rustflags[[:space:]]*=' "$file" && sets=yes
    echo "cargo-config: $file sha256=$(sha256sum < "$file" | awk '{print $1}') rustflags=$sets"
  done
  [ "$dir" = / ] && break
  dir="$(dirname "$dir")"
done
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
for name in config.toml config; do
  file="$cargo_home/$name"
  [ -f "$file" ] || continue
  sets=no
  grep -Eq '^[[:space:]]*rustflags[[:space:]]*=' "$file" && sets=yes
  echo "cargo-config: $file sha256=$(sha256sum < "$file" | awk '{print $1}') rustflags=$sets"
done

overrides="$(env | grep -E '^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Z0-9_]+_RUSTFLAGS)=' | sort || true)"
if [ -n "$overrides" ]; then
  printf '%s\n' "$overrides" | sed 's/^/rustflags-env: /'
else
  echo "rustflags-env: none"
fi
