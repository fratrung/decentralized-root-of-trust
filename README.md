# decentralized-root-of-trust

A **committee-controlled status list** (e.g. a revocation list) secured with
**post-quantum, hash-based signatures** (XMSS) that are **aggregated into a
single SNARK proof** by the [leanVM](https://github.com/leanEthereum/leanVM)
zkVM.

It replaces a *single-key* root of trust with a **`t`-of-`N` committee**, while
keeping the property that **anyone** can verify the list knowing a single fixed
trust anchor (the committee), without fetching anything in real time.

See [`docs/committee-status-list.md`](docs/committee-status-list.md) for the full
design rationale.

---

## Trust model

- The list is published (e.g. in a DHT) together with a **proof** that replaces
  the old single signature.
- The fixed **trust anchor** each verifier embeds is the **committee**: its `N`
  public keys and the threshold `t`.
- An update is authorized when **at least `t`** distinct committee members sign
  the new list root. *Which* subset signs may change at every update — the
  anchor does not.

Verification is four checks (three outside the circuit, negligible cost):

1. every signer ∈ committee (membership);
2. the proof is bound to **this** list (`message == status_list_root`);
3. quorum reached (`#signers ≥ t`);
4. the SNARK aggregate verifies (one verification, independent of `t`).

Check (2) is the security-critical binding: `verify_single_message_aggregate`
only attests "these keys signed *this* message"; the verifier must check that
message is the root of the list it holds.

---

## Signature scheme

Signing uses **leanVM's own synchronized XMSS** (Poseidon2, `[F; 8]` messages,
`LOG_LIFETIME = 32`) — the scheme leanVM can aggregate. It is a *stateful*
signature: a given `(key, slot)` must sign **at most once**, so each update uses
a new slot.

> Note: the standalone `leanSig` XMSS (Poseidon1, `[u8; 32]`, `LOG_LIFETIME = 18`)
> is a **different, incompatible** parametrization and **cannot** be fed to
> leanVM's aggregator. This project therefore signs with leanVM's XMSS only.

---

## Layout

```
src/
  status_list.rs   StatusList struct, entry -> field mapping, Poseidon2 root, wire format
  committee.rs     Committee anchor, sign_and_prove (prover), verify_proof (4 checks)
  params.rs        demo parameters (SLOT, N_MEMBERS, T, N_UPDATES, KEY_SLOTS, LOG_INV_RATE)
  mem.rs           VmRSS / VmHWM probes
  stats.rs         descriptive statistics for the benchmark records
  main.rs          combined demo: setup, N updates, 2 security tests, BENCH record
  bin/prover.rs    split deployment: signs and aggregates, writes artifacts, never verifies
  bin/verifier.rs  split deployment: verify-only, calls setup_verifier() alone
examples/
  footprint.rs     RAM cost of setup_prover vs setup_verifier
docs/
  committee-status-list.md   design rationale
benchmark.sh       reproducible multi-run benchmark (env capture, tidy CSV, CI95)
```

The demo constants live in `src/params.rs`. The `verifier` binary deliberately
uses none of them: everything it needs comes from the committee anchor it loads.

---

## Dependencies

All dependencies are **git-pinned** (no vendored clones):

- `lean-multisig`, `backend` — from `leanEthereum/leanVM` at a fixed revision.
  leanVM ships its own field/hash backend and **does not depend on Plonky3**, so
  the whole tree resolves reproducibly.
- `rand`, `sha3`, `postcard`, `serde` — from crates.io.

`Cargo.lock` is currently listed in `.gitignore`. Since the leanVM dependencies
are pinned by revision but their transitive tree is not, committing the lockfile
is what makes a build reproducible — `benchmark.sh` warns when it is missing.

`.cargo/config.toml` sets a large `RUST_MIN_STACK` (the prover uses a very deep
stack) and `target-cpu=native`.

---

## Build & run

```sh
cargo run --release
```

Example output (shape):

```
setup...
committee N=10 t=7; 10 updates rotating the signers

  update  1/10  signers ABCDEFG  slot 43  prove=...ms  verify=...ms  RAM=... MB  OK
  ...
--- Security (expected: both REJECTED) ---
A) tampered list + valid proof : rejected = true
B) proof from outside signers  : rejected = true
=> security OK: true
--- Setup (one-time per process) ---
...
--- 10 updates: min / median / max ---
...
--- RAM ---
...
BENCH setup_verifier_ms=... upd_prove_med_ms=... peak_rss_mb=... sec_ok=1
```

The prover **setup is paid once per process** (not persisted across restarts);
subsequent proofs in the same process reuse it. In production, keep the prover
process alive.

RAM footprint of setup alone:

```sh
cargo run --release --example footprint -- prover   # or: verifier | none
```

---

## Split deployment

The demo above does everything in one process. In practice the two roles have
very different costs, so they ship as two binaries:

```sh
cargo run --release --bin prover                # writes ./artifacts
cargo run --release --bin verifier              # reads ./artifacts, exits 0 if all expectations hold
```

Both take the artifact directory as an optional first argument. The prover must
run first — it produces `anchor.bin`, which the verifier needs.

```
artifacts/
  anchor.bin           the committee: N public keys + threshold t. The trust anchor.
  update-NN.bin        legitimate updates. The verifier MUST accept them.
  attack-tampered.bin  tampered list carrying a valid proof of a different list.
  attack-outsider.bin  quorum of keys outside the committee.
```

The name prefixes are the contract: `update-*` must be accepted, `attack-*` must
be rejected. The verifier checks both and exits non-zero if either expectation is
violated, so it drops into a script or CI:

```sh
cargo run --release --bin prover && cargo run --release --bin verifier
```

**Why bother:** a verify-only process calls `setup_verifier()` and nothing else.
It skips the arena and the DFT twiddles, and — more importantly — it never runs
`zk_alloc::enable_arena()`, which sets `M_TRIM_THRESHOLD = -1` so that a *prover*
process never returns freed memory to the OS. The measured effect:

| | prover | verifier | combined demo |
|---|---|---|---|
| resident after setup | 791 MB | **679 MB** | 746 MB |
| peak RSS (median of runs) | 1088 MB | **696 MB** | 1042 MB |

**33% less peak RAM** for a node that only verifies. The more useful property is
the *slope*: the verifier's RSS is flat in the number of verifications (679 → 680
MB over 10), while the prover's climbs monotonically and never comes back down.

Since the verifier's only input is the anchor plus the published structure, the
artifact directory can simply be copied to the target device:

```sh
scp -r artifacts/ pi@cm4:~/ && ssh pi@cm4 ./verifier ~/artifacts
```

Each `prover` run generates a **fresh random committee**, so artifacts from
different runs are not interchangeable — start from a clean directory.

---

## Benchmark

```sh
./benchmark.sh                                    # defaults: RUNS=20, WARMUP=2
RUNS=30 WARMUP=3 ./benchmark.sh
TARGETS="prover verifier" RUNS=50 ./benchmark.sh
PROJECT_CM4=1 ./benchmark.sh                      # adds an explicitly-labelled ESTIMATE
```

It measures the three binaries independently — `prover`, `verifier` and
`combined` (the single-process demo) — and writes to `bench-<timestamp>/`:

| file | contents |
|---|---|
| `env.txt` | CPU, governor, turbo/SMT, THP, ASLR, toolchain, git commit, pinned leanVM rev, parameters — the reproducibility appendix |
| `samples.csv` | tidy raw data, one row per individual update/verification |
| `runs.csv` | one row per process run |
| `summary.csv` / `.txt` | aggregates: n, min, q1, median, q3, max, mean, sd, CV%, CI95 |

Design points that matter if you quote these numbers:

- The verifier is measured against a **fixed artifact corpus**, generated once.
  Regenerating it per run would fold the prover's variance into the verifier's.
- The unit of analysis for per-update metrics is the **per-run median**
  (n = RUNS). Updates inside one process share allocator and cache state and are
  not independent; `samples.csv` keeps every raw observation if you prefer to
  report the pooled distribution.
- Quantiles use linear interpolation (type 7); CI95 uses Student's *t* with
  df = n−1.
- Peak RSS is cross-checked against `/usr/bin/time -v`, independently of the
  process's own `/proc/self/status` reading.
- The script **refuses to print any timing** if a run reports a violated security
  expectation.
- It warns when the CPU governor is not `performance`, when `Cargo.lock` is
  missing, and when GNU `time` is unavailable.

The CM4 projection is opt-in and is a **linear extrapolation, not a
measurement**. For real numbers, run `benchmark.sh` natively on the board (an
aarch64/NEON path exists).

### Reference numbers

Indicative, `N=10, t=7`, host **AMD Ryzen 7 4800H** (8c/16t, governor
`schedutil` → slightly noisy). Medians across runs:

| metric | prover | verifier | combined |
|---|---|---|---|
| setup (once/process) | ~5.3 s | ~5.2 s | ~5.2 s |
| sign (7 XMSS) / update | ~50 ms | — | ~50 ms |
| **prove / update** | **~297 ms** | — | ~286 ms |
| verify / update | — | **~30 ms** | ~31 ms |
| proof size | ~170 KB | ~170 KB | ~170 KB |
| resident after setup | 791 MB | **679 MB** | 746 MB |
| peak RSS (VmHWM) | 1088 MB | **696 MB** | 1042 MB |

Where the memory actually goes — measured with `--example footprint`:

| component | RSS |
|---|---|
| aggregation bytecode (`setup_verifier`, **retained**) | ~678 MB |
| + arena + DFT twiddles (`setup_prover`) | ~783 MB |
| + proving working set, 10 updates @ t=7 | ~1085 MB |
| status list + committee + proof bytes | **< 1 MB** |

The ~678 MB is `Bytecode.instructions_multilinear`, the multilinear encoding of
leanVM's unrolled aggregation program. It is *retained*, not a transient
compilation cost, so there is no fork-and-drop trick — and it is **not** driven
by `MAX_XMSS_AGGREGATED` (that constant only appears in asserts), so it cannot be
shrunk from this repository. Treat it as a fixed floor for anyone who verifies.

**Scaling:** prove-time and RAM grow with **`t`** (more XMSS verifications in the
circuit → bigger trace → bigger WHIR commitment + FFT buffers), **not** with the
number of updates. The growth is a **step function**: the trace is padded to a
power of two, so `t = 5..=8` all cost the same. Measured, `t=7` vs `t=8` vs `t=4`:

| t | prove / update | peak RSS | proof |
|---|---|---|---|
| 4 | 206 ms | 956 MB | 146 878 B |
| 7 | 298 ms | 1055 MB | 169 624 B |
| 8 | 298 ms | 1074 MB | 169 690 B |

So `t=7` pays for a quorum of 8 without using it: raising the threshold to 8
costs nothing in prove time, proof size or RAM (only signing, which is outside
the circuit, grows linearly in `t`). Dropping to `t=4` cuts prove time by 31% but
peak RSS by only 9%, because the ~678 MB floor dominates. Setup cost and
resident-after-setup are independent of `t`.

**Raspberry Pi CM4 (BCM2711, 2 GB)** — linear projection x8..x15 (estimate):
setup ~42–79 s (one-time at boot), prove ~2.3–4.3 s/update, verify ~0.25–0.47 s,
10 updates ~30–57 s. RAM does **not** scale with CPU: peak ~1 GB **fits the 2 GB
board** (~1 GB free for the OS); a **1 GB board is excluded**. RAM is the gate.

---

## Security tests

Two attacks that **must be rejected**:

- **A — tampered list + valid proof of another list:** rejected by the
  `message == status_list_root` binding (check 2).
- **B — proof from signers outside the committee:** rejected by the
  membership check (check 1).

In the combined demo both print `rejected = true` and the run reports
`security OK: true`. In the split deployment the same two attacks are written by
`prover` as `attack-*.bin` and rejected by `verifier`, which exits non-zero if
either is accepted — so the negative tests are checked by a process that knows
nothing but the anchor.

Not covered: a **sub-threshold quorum** (check 3), i.e. `t-1` legitimate members
signing the correct list. That path has no test.
