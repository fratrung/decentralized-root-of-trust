# Running the benchmarks for publication

An operational checklist for a dedicated Linux machine reached over SSH: how
to prepare it, how to launch `benchmark.sh` and
`committee-scaling-benchmark.sh` so their results are publishable, and how to
keep a long campaign from exhausting the host. What the harness measures and
why is in `README.md` ("Benchmark") and `docs/agents/benchmarking.md`; this
file only says how to run it.

## 1. Prepare the machine (once)

Packages, on Ubuntu and its flavours (Kubuntu included):

```sh
sudo apt install build-essential git curl time tmux python3 \
  linux-tools-common "linux-tools-$(uname -r)"
```

| package | why | needed |
|---|---|---|
| `build-essential` | Rust links through the system C linker (`cc`); without it `cargo build` fails | yes |
| `git` | clone; the scripts also check the tree is clean and record the commit | yes |
| `curl` | only to install rustup | to install |
| `time` | `/usr/bin/time -v`, not bash's `time` builtin: kernel peak RSS, user/sys CPU, page faults and context switches of every measured process; strict runs refuse without it | yes |
| `linux-tools-*` | the `cpupower` command, only to set the governor (below) | no: writing sysfs works too |
| `tmux` | keeps a campaign of hours alive when the SSH session drops; `screen` works too | strongly advised |
| `python3` | only afterwards, for `analyze_scaling.py`, the plots and the tool tests; the results can be analysed on another machine | no |

Everything else the scripts call (`taskset`, `setsid`, `lscpu`, `sha256sum`,
`df`, …) comes with coreutils, util-linux and procps, which every Ubuntu
install has; the scaling script stops at once with `missing required command`
if one is absent.

Then Rust:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
```

`rust-toolchain.toml` makes the first `cargo` call in the checkout install the
pinned 1.98.1 with `rustfmt` and `clippy`. Do not install or select another
toolchain for this checkout: a campaign records its compiler, and timings from
different compilers are not comparable.

CPU governor: strict runs refuse anything but `performance` on every CPU in
the mask.

```sh
sudo cpupower frequency-set -g performance
# or, without cpupower:
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c
```

The setting does not survive a reboot. On a desktop flavour such as Kubuntu,
also set the power profile to performance (`powerprofilesctl set
performance`, or from the Plasma battery/power applet) and check the governor
again right before launching: the harness checks it once, at start-up.
Turbo/boost is recorded in `env.txt`,
not enforced; leave it as it is, but keep it the same across every campaign
you intend to compare.

Memory guard: the scaling script runs every stage in a `systemd --user` scope
with a kernel-enforced `MemoryMax`, and publication mode refuses to start
without one. Log in over SSH as the user who will run the campaign (not
through `sudo su`). `loginctl enable-linger` is a setting, not a package: it
keeps the user's systemd manager alive after the SSH session closes, without
which the scopes stop working. The last command checks, before any build,
that the kernel cap really works:

```sh
loginctl enable-linger "$USER"
systemd-run --user --scope -p MemoryMax=64M -p MemorySwapMax=0 true && echo scope-ok
```

## 2. Prepare the checkout (once per commit)

Clone, then confirm the tree is clean and note the commit; publication mode
refuses a dirty tree, and every result names the commit it was built from.

```sh
git clone <repository> && cd decentralized-root-of-trust
git status --porcelain     # must print nothing
git rev-parse HEAD
```

Nothing in the environment may override the repository's rustflags
(`target-cpu=native`); a strict run refuses it.

```sh
tools/cargo_env_fingerprint.sh | grep rustflags   # expect "rustflags-env: none"
```

The first build compiles the whole leanVM tree. Build and test before
measuring, so that a broken checkout fails here and not inside a campaign:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
(cd mldsa && cargo test --locked)
for t in tools/test_*.sh; do bash "$t" || echo "FAIL $t"; done
for t in tools/test_*.py; do python3 -I "$t" || echo "FAIL $t"; done
```

Choose the two parameters every campaign on this host will share:

- **Signer state directory.** The XMSS signer's timing includes one
  `sync_data` per signature on the filesystem holding its slot journal, and
  strict runs refuse RAM-backed storage. `/tmp` is the default and is often
  `tmpfs`. Point `SIGNER_STATE_DIR` at a directory on the local disk and check
  its class:

  ```sh
  mkdir -p ~/drot-signer-state
  tools/storage_class.sh ~/drot-signer-state   # expect class=local
  ```

- **CPU mask.** leanVM sizes its thread pool from the affinity mask, so
  `PIN_CPUS` fixes both where and how wide the multithreaded roles run.
  Inspect the topology with `lscpu -e`, leave at least one core outside the
  mask for the OS, the SSH session and the harness itself, and use the same
  mask for every campaign you will compare.

## 3. Rules while anything is running

- Run inside `tmux`, so an SSH drop does not end the campaign.
- Keep the machine otherwise idle: no other builds, tests or jobs, and tell
  whoever else uses it. Other load is recorded (`load1`, frequency,
  temperature) but not removed.
- Do not touch the checkout: no `git pull`, no edits, no `cargo build`, no
  `tools/mutate.py`. The harness runs frozen binaries, but the scaling script
  rebuilds per point and a resume refuses a changed source fingerprint.
- One `OUTDIR` per campaign; both scripts refuse a non-empty one (except an
  explicit scaling `RESUME=1`).

## 4. Committee-scaling campaign

First ask the script which committee sizes this host admits. This builds
nothing and runs nothing:

```sh
PLAN_ONLY=1 STUDY_MODE=publication PIN_CPUS=1-15 \
  SIGNER_STATE_DIR=~/drot-signer-state LIST_ENTRIES=1000 \
  ./committee-scaling-benchmark.sh
```

It prints the RAM budget (the smaller of 70% of physical RAM and available
RAM minus a host reserve of at least 2 GiB) and the admitted grid: `N = 5, 10,
100` always, then `500`, `1000`, `1500` at 8, 12 and 20 GiB of budget.

Then a pilot, which is exploratory and not publishable (three runs, one
sweep). Its only purpose is to find out how long each stage takes and how much
memory each point uses on this host:

```sh
STUDY_MODE=pilot PIN_CPUS=1-15 SIGNER_STATE_DIR=~/drot-signer-state \
  LIST_ENTRIES=1000 OUTDIR=pilot-L1000 ./committee-scaling-benchmark.sh
```

Read `pilot-L1000/pressure.csv` and the stage durations in
`pilot-L1000/schedule.csv`. Every stage is killed after
`POINT_TIMEOUT_MINUTES` (default 90), and a publication session runs eight
times as many measured processes as a pilot session (24 runs instead of 3),
each after a 10 s cooldown instead of 2 s. If the pilot's slowest stage scaled
by that factor comes near the timeout, raise it for the
publication campaign. It is part of the campaign's fingerprint, so choose it
before starting, not on resume.

The publication campaign:

```sh
STUDY_MODE=publication PIN_CPUS=1-15 SIGNER_STATE_DIR=~/drot-signer-state \
  LIST_ENTRIES=1000 POINT_TIMEOUT_MINUTES=90 \
  OUTDIR=committee-scaling-L1000 ./committee-scaling-benchmark.sh
```

Publication mode defaults to 24 runs, two warm-ups, 10 s cooldown and two
sweeps (ascending, then descending), and refuses before building anything if
the tree is dirty, the governor is not `performance`, the mask is missing, the
signer state is on RAM, or no memory scope is available. One campaign has one
list size: run another campaign, with its own `OUTDIR`, for each `L`.

What protects the host: every stage runs in its own process group under a
scope capped at the computed budget with swap growth capped at
`MAX_SWAP_GROWTH_MB` (64). A poller also stops the stage when the group
exceeds the cap, available RAM falls below the reserve, free disk on any
filesystem used falls below `MIN_FREE_DISK_MB` (8 GiB), swap grows, or the
timeout expires. After such a stop no later point runs, the reason goes into
`manifest.csv` and `pressure.csv`, and no partial timing is published.
`Ctrl-C` terminates the active process group.

To continue after a stop, a reboot or an interruption, rerun with
`RESUME=1` and **exactly the same variables** and `OUTDIR`; completed sessions
are kept, and a changed configuration, source or toolchain is refused:

```sh
RESUME=1 STUDY_MODE=publication PIN_CPUS=1-15 SIGNER_STATE_DIR=~/drot-signer-state \
  LIST_ENTRIES=1000 POINT_TIMEOUT_MINUTES=90 \
  OUTDIR=committee-scaling-L1000 ./committee-scaling-benchmark.sh
```

After a reboot, set the governor again first.

## 5. A single fixed point with `benchmark.sh`

`benchmark.sh` measures one `(N, t, L)` with all six roles, including both
signers. It has **no memory guard of its own**, so for anything but a small
committee run it inside a capped scope; if it is exceeded, the kernel kills
the benchmark, which then withholds every number, instead of the host
swapping:

```sh
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 -- \
  env STRICT_ENV=1 PIN_CPUS=1-15 SIGNER_STATE_DIR="$HOME/drot-signer-state" \
      DROT_BENCH_N=100 DROT_BENCH_T=67 LIST_ENTRIES=1000 \
      OUTDIR=bench-N100-t67-L1000 ./benchmark.sh
```

- `DROT_BENCH_N`/`DROT_BENCH_T` must be set together. The built-in default
  (`N=200, t=128`) is not the two-thirds policy `t = floor(2N/3) + 1` used by
  the scaling study; state the pair you measured.
- `RUNS` (default 24) should be a multiple of the target design (six targets:
  six orders); the harness warns otherwise.
- Set `MemoryMax` from the scaling pilot's peak for that `N`, with margin.

## 6. Check and bring back the results

A result exists only where `status.txt` says `complete` and the hashes match:

```sh
cat OUTDIR/status.txt                                   # complete + campaign id
(cd OUTDIR && sha256sum --quiet -c outputs.sha256 && echo verified)
```

For a scaling campaign also read `report.txt`, `manifest.csv` (every point
and why it stopped, if it did) and the per-session `drift.csv`; a session
with an early/late shift above 15% is withheld, never trimmed. Then run the
analysis that the report's intervals leave out (session effect, drift,
simultaneous intervals) and the plots:

```sh
python3 tools/analyze_scaling.py committee-scaling-L1000
python3 tools/plot_benchmarks.py committee-scaling-L1000
```

Copy whole directories back and verify the hashes again on arrival:

```sh
rsync -a host:decentralized-root-of-trust/committee-scaling-L1000 .
```

When publishing, state the host (`env.txt` has `lscpu`, kernel, governor,
boost, mask and storage class), the commit, the compiler and the workload
`(N, t, L)`. Do not compare or merge numbers from this machine with numbers
from another host, compiler or commit: `target-cpu=native` makes every build
host-specific.
