# AGENT.md

This file provides guidance to a generic Code Agent (Claude, GPT, Cursor etc..) when working with code in this repository.

## What this is

A committee-controlled status list (e.g. a revocation list) where the single-key
root of trust is replaced by a `t`-of-`N` committee. The `t` members sign the
list root with post-quantum hash-based signatures (leanVM's synchronized XMSS),
and those signatures are aggregated into **one** SNARK proof by the
[leanVM](https://github.com/leanEthereum/leanVM) zkVM. That proof takes the place
of the old single signature in the published structure.

The verifier embeds one fixed anchor — the committee (`N` public keys + threshold
`t`) — and needs no live data fetch. `docs/committee-status-list.md` holds the
design rationale; `README.md` holds the measured performance numbers.

## Commands

```sh
cargo run --release                                # combined demo: setup, 10 updates, 2 security tests
cargo run --release --bin prover   -- [outdir]     # split: sign + aggregate, writes artifacts (default ./artifacts)
cargo run --release --bin verifier -- [dir]        # split: verify-only, exits non-zero on any violated expectation
cargo run --release --example footprint -- prover  # RAM of setup alone; also: verifier | none
./benchmark.sh                                     # RUNS=30 WARMUP=3 TARGETS="prover verifier" ./benchmark.sh
```

**Always `--release`.** The prover is unusable in a debug build. The first build
compiles the whole leanVM tree and takes several minutes.

There are **no `#[test]` functions** — `cargo test` compiles but runs nothing.
Correctness is asserted by running the binaries: the combined demo must print
`security OK: true`, and `verifier` must exit 0 (it checks that every
`update-*` artifact is accepted and every `attack-*` artifact is rejected).
`benchmark.sh` refuses to print timings if any run reports a failure.

`.cargo/config.toml` sets `RUST_MIN_STACK=512MiB` (the prover recurses very
deeply) and `target-cpu=native`. Both are required — don't run the binary in a
context that bypasses that config. Note `target-cpu=native` makes builds
host-specific: benchmark numbers are not portable across machines.

## Architecture

One data flow, three binaries over it:

```
(Vec<[u8;32]>, version) --status_list_root_fe--> [KoalaBear;8] --t x xmss_sign--> t sigs
    --aggregate_single_message_signatures--> SNARK --postcard--> StatusList.zk_proof
```

Library:
- `src/status_list.rs` — the published object and its digest. `entry_to_field`
  maps each 32-byte entry to `[F;8]`; `status_list_root_fe(list, version)` folds
  the entries into the root and then closes with one more compression that mixes
  in the `version` (16-bit limbs, injective). **The fold is a Merkle–Damgård
  chain, not a tree**, despite the "root" naming: `acc = compress_pair(acc,
  entry(e))` from `[0;8]`. Cost is O(n) sequential and there are no per-entry
  inclusion proofs. It allocates nothing on the heap, so a large list could be
  streamed rather than held in RAM.
- `src/committee.rs` — the anchor, `sign_and_prove`/`make_proof`, the whole of
  `verify_proof`, and `select_freshest` (the DHT-layer freshness selection:
  newest declared version first, verify, fall back on failure).
- `src/params.rs` — demo parameters (`SLOT`, `N_MEMBERS`, `T`, `N_UPDATES`,
  `KEY_SLOTS`, `LOG_INV_RATE`), shared by `main.rs` and `prover`. The `verifier`
  deliberately imports none of them.
- `src/freshness.rs` — `HighWaterMark`, the persistent anti-rollback gate. Strict
  monotonic rule (`version > mark`), keyed to a fingerprint of the anchor so a
  committee rotation resets it, persisted with a write-then-rename. Lives *outside*
  `verify_proof`, which stays pure.
- `src/mem.rs`, `src/stats.rs` — RSS probes and descriptive statistics shared by
  every binary.

Binaries:
- `src/main.rs` — the combined single-process demo; still the reference for the
  end-to-end flow and the `BENCH` record.
- `src/bin/prover.rs` — holds the secret keys, writes artifacts, **never verifies**.
- `src/bin/verifier.rs` — calls **only** `setup_verifier()`; loads `anchor.bin`
  and hardcodes nothing else.

### The split deployment (and why it exists)

Measured on the reference host, memory decomposes as:

| | RSS |
|---|---|
| aggregation bytecode (`setup_verifier`, **retained**) | ~678 MB |
| + arena + DFT twiddles (`setup_prover`) | ~783 MB |
| + proving working set, 10 updates @ t=7 | ~1085 MB |
| status list + committee + proof bytes | **< 1 MB** |

Two consequences that drive design decisions here:

1. **The application's own data structures are noise.** Optimizing `StatusList`,
   `Committee` or the proof bytes for memory is pointless at demo scale; those
   changes matter only for list sizes orders of magnitude larger.
2. **A verify-only process is ~33% smaller** (~696 MB peak vs ~1042 MB) and, more
   importantly, its RSS is **flat** in the number of verifications. A prover
   process's is monotonically increasing, because `zk_alloc::enable_arena()` sets
   `M_TRIM_THRESHOLD=-1` and `M_MMAP_MAX=0` — freed memory is never returned to
   the OS. Never call `setup_prover()` in a process that only verifies.

The ~678 MB floor is `Bytecode.instructions_multilinear` in leanVM (the unrolled
aggregation program's multilinear encoding). It is **not** driven by
`MAX_XMSS_AGGREGATED` — that constant only appears in asserts — so shrinking it
via a leanVM fork does not work. Treat the floor as a fixed constraint.

### The security boundary (most important thing to understand)

`verify_single_message_aggregate` attests **only** "these listed public keys
signed this message at this slot". Every link to trust is a cleartext check
outside the circuit, in `verify_proof` (`src/committee.rs`):

1. every signer ∈ committee — membership against the fixed anchor;
2. `agg.info.message == status_list_root_fe(list, version)` — **the critical
   binding**; it ties the proof to both the list (without it a valid proof of a
   *different* list can be attached) and the `version` (without it the cleartext
   version field is forgeable — see the versioning note below);
3. `pubkeys.len() >= t` — quorum;
4. the SNARK verifies.

Check 3 is sound because leanVM's `check_single_message_pubkeys` requires
`pubkeys` to be strictly sorted with no duplicates (enforced both in `Deserialize`
and in `verify_single_message_aggregate`), so the count really is *distinct*
members. Keep that invariant in mind before "optimizing" check 3 away.

When touching `verify_proof`, all four checks must survive; dropping any one is
silently exploitable and the current tests would still pass for check 3.

### Known gaps in the model (deliberate, not bugs to fix silently)

- Verification is **stateless**: an old but legitimate (list, proof) pair verifies
  forever. Rollback is stopped one layer up, not by `verify_proof`:
  `select_freshest` picks the newest valid record, then `HighWaterMark`
  (`freshness.rs`) refuses anything not strictly newer than the last accepted
  version, persisted across restarts. The mark is per-object; the demo carries a
  single status list so it keeps a single mark in the artifact dir. Committee
  rotation (the anchor changing) is a separate, deferred protocol.
- `StatusList::version` **is** verified now: it is folded into the signed message
  (Option B), so `verify_proof` recomputes `status_list_root_fe(list, version())`
  and a tampered version fails check 2. `StatusList::alg` is still never verified
  (only appears in `Display`). The XMSS `slot` is decoupled from `version` by
  design and is not compared against it.
- `StatusList::proof()` decodes the *inner leanVM aggregate* with
  `postcard::from_bytes`, which accepts trailing bytes. (The *outer* wire format,
  `StatusList::from_bytes` / `Committee::from_bytes`, is canonical — it rejects
  them.) leanVM offers `SingleMessageAggregateSignature::from_bytes` for the
  inner one.
- Checks 1 and 2 have security tests (attacks A/B for the list binding and
  membership, attack C for the version binding). A sub-threshold quorum (check 3)
  and a cross-time rollback (an old but validly signed version) are untested.

## leanVM constraints that shape this code

Dependencies are git-pinned to leanVM rev `12e6151` (source at
`~/.cargo/git/checkouts/leanvm-*/12e6151` — read it when the API is unclear;
leanVM ships its own field/hash backend and does not depend on Plonky3).

- **XMSS is stateful.** A `(key, slot)` pair must sign **at most once** — reuse is
  insecure even on the same message, because the WOTS encoding randomness is
  non-deterministic. Every update therefore consumes a new slot. Keys are
  generated for `SLOT..=SLOT + KEY_SLOTS`, so raising `N_UPDATES` beyond
  `KEY_SLOTS` breaks keygen bounds.
- **`setup_verifier()` or `setup_prover()` must run before deserializing any
  proof** — `SingleMessageInfo::deserialize` recomputes the bytecode claim from
  the process-global bytecode and fails without it.
- **Never prove two things concurrently in one process**: leanVM's arena
  allocator has a single shared region. Parallelize with separate processes.
- Setup is paid **once per process** and is not persisted (~5-8 s, and it
  dominates everything else). Production keeps the prover process alive.
- Prove time and RAM scale with **`t`**, as a **step function**: the trace is
  padded to a power of two, so `t = 5..=8` all cost the same. Measured: `t=7` and
  `t=8` are indistinguishable in prove time, proof size and RAM; `t=4` is the
  next step down (~-31% prove time, but only ~-9% peak RSS because of the fixed
  floor above). Scaling is in `t`, not in the number of updates.
- Only leanVM's own XMSS parametrization (Poseidon2, `[F;8]` messages,
  `LOG_LIFETIME=32`) can be fed to the aggregator. The standalone `leanSig` XMSS
  (Poseidon1, `[u8;32]`, `LOG_LIFETIME=18`) is incompatible.

## Machine-readable record contracts

Each binary prints one summary line that `benchmark.sh` parses, plus optional
per-item raw samples when `EMIT_SAMPLES` is set in the environment:

| binary | summary line | sample lines |
|---|---|---|
| `main.rs` | `BENCH k=v ...` | — |
| `prover` | `PROVER k=v ...` | `SAMPLE target=prover idx=… sign_ms=… prove_ms=…` |
| `verifier` | `VERIFIER k=v ... failures=N` | `SAMPLE target=verifier idx=… verify_ms=…` |

`benchmark.sh` normalises all three in `emit_run_row`; adding or renaming a field
means updating that function. The script exits if a summary line is missing, and
aborts before printing any statistics if any run reports `failures > 0`.

### Artifact conventions between `prover` and `verifier`

```
anchor.bin       the committee (N public keys + threshold t)
update-NN.bin    legitimate updates — MUST verify
attack-*.bin     forgeries — MUST be rejected (a decode failure counts as rejection)
```

The `update-` / `attack-` name prefixes are the contract. Each `prover` run
generates a **fresh random committee**, so artifacts from different runs are not
interchangeable — start from a clean directory.

## Benchmarking

`benchmark.sh` is built for numbers that go into a write-up: it captures the full
environment (`env.txt`), emits tidy raw data (`samples.csv`), per-run rows
(`runs.csv`) and aggregates with quartiles, sd, CV and t-based CI95
(`summary.csv` / `summary.txt`).

The unit of analysis for per-update metrics is the **per-run median** (n = RUNS),
not the pooled sample: updates inside one process share allocator and cache state
and are not independent. Preserve that distinction if you touch the aggregation.

The CM4 projection is opt-in (`PROJECT_CM4=1`) and is a **linear extrapolation,
not a measurement** — it must stay labelled as such.
