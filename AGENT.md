# AGENT.md

This file provides guidance to a generic Code Agent (Claude, GPT, Cursor etc..) when working with code in this repository.

## What this is

A committee-controlled status list (e.g. a revocation list) where the single-key
root of trust is replaced by a `t`-of-`N` committee. The `t` members sign the list
root with post-quantum hash-based signatures (leanVM's synchronized XMSS).

The quorum is then published in **one of two interchangeable forms**, and a
verifier accepts either:

- **`StatusList`** — the `t` raw signatures plus a bitmap naming their signers by
  index into the anchor. No circuit, no setup, verification linear in `t`.
- **`SnarkStatusList`** — those same signatures aggregated into **one** proof by
  the [leanVM](https://github.com/leanEthereum/leanVM) zkVM. Constant-time
  verification, at the price of a prover needing seconds and gigabytes.

The verifier embeds one fixed anchor — the committee (`N` public keys, threshold
`t`, genesis slot) — and needs no live data fetch.
`README.md` holds the design rationale, the measured numbers and the architecture
diagram; the per-module reasoning lives in the doc comments themselves.

## Commands

```sh
cargo run --release --bin decentralized-root-of-trust  # combined SNARK demo: setup, N updates, 3 security tests
cargo run --release --bin raw_agg                      # the same protocol with no SNARK, through SignerNode/VerifierNode
cargo run --release --bin prover   -- [outdir]         # split: sign + aggregate, writes artifacts (default ./artifacts)
cargo run --release --bin verifier -- [dir]            # split: verify-only, exits non-zero on any violated expectation
cargo run --release --example footprint -- prover      # RAM of setup alone; also: verifier | none
cargo test                                             # 38 unit + 6 integration tests, ~10 s (incl. a real SNARK)
./benchmark.sh                                         # RUNS=30 WARMUP=3 TARGETS="prover verifier" ./benchmark.sh
tools/mutate.py                                        # mutation testing: 21 checks, each must be caught by a test
```

**Always `--release`** for anything touching the prover; it is unusable in a debug
build. The first build compiles the whole leanVM tree and takes several minutes.
`cargo test` is fine in debug: `Cargo.toml` optimizes dependencies in the dev
profile, which is what makes `tests/snark_path.rs` affordable there (~10 s) even
though it drives a real prover.

The tests cover the slot counter, the raw quorum path and — since
`tests/snark_path.rs` — each of the five checks in `verify_proof`. The binaries
remain the end-to-end assertion: the combined demo must print `security OK: true`,
`raw_agg` and `verifier` must exit 0. `benchmark.sh` refuses to print timings if
any run reports a failure.

`.cargo/config.toml` sets `RUST_MIN_STACK=512MiB` (the prover recurses very
deeply) and `target-cpu=native`. Both are required — don't run the binary in a
context that bypasses that config. Note `target-cpu=native` makes builds
host-specific: benchmark numbers are not portable across machines.

## Architecture

One data flow that forks at the end:

```
(Vec<[u8;32]>, version) --status_list_root_fe--> [KoalaBear;8]
    --t x xmss_sign at slot = genesis + version--> t sigs
        |-- (index, sig) pairs ------------------------> StatusList { bitmap, signatures }
        `-- aggregate_single_message_signatures --> SNARK --> SnarkStatusList.zk_proof
```

Library:
- `src/status_list.rs` — the published objects and their digest. `entry_to_field`
  maps each 32-byte entry to `[F;8]`; `status_list_root_fe(list, version)` folds
  the entries into the root and then closes with one more compression that mixes
  in the `version` (16-bit limbs, injective). **The fold is a Merkle–Damgård
  chain, not a tree**, despite the "root" naming: `acc = compress_pair(acc,
  entry(e))` from `[0;8]`. Cost is O(n) sequential and there are no per-entry
  inclusion proofs. It allocates nothing on the heap, so a large list could be
  streamed rather than held in RAM.
  `StatusList::new` sorts the `(index, signature)` pairs and rejects duplicates
  and out-of-range indices, so a value that exists is already canonical — the
  out-of-order and repeated-signer variants are unconstructible rather than
  defended against. `from_bytes` additionally rejects a bitmap whose population
  disagrees with the signature count.
- `src/committee.rs` — the anchor, `slot_for` (the **only** place the slot is
  derived), `sign_and_prove`/`make_proof`, both `verify_proof` and
  `verify_quorum`, and `select_freshest` (the DHT-layer freshness selection:
  newest declared version first, verify, fall back on failure).
  `select_freshest_above` is the same with a floor — the caller's high-water mark
  — applied before any proof is verified. That is a work saver, not a check: the
  floor can only drop records the caller was already going to refuse as stale.
- `src/atomic_slot_counter.rs` — the durable monotonic slot allocator. Burns the
  slot on disk **before** handing it out (write tmp → fsync → rename → fsync the
  parent dir), guarded by a lock on a separate file so two processes cannot share
  a key. `reserve` takes the next local slot; `reserve_at` takes a
  protocol-chosen one, jumping forward over missed rounds and refusing the past.
- `src/signer_node.rs` — one member: keypair + counter. `sign` for the local-slot
  path, `sign_at` for the derived-slot one.
- `src/verifier_node.rs` — one relying party: holds the anchor, verifies a single
  member signature or either whole record form. It delegates to `committee.rs`
  rather than reimplementing the checks; two copies would drift, and the copy
  that drifts is the one no benchmark exercises.
- `src/params.rs` — demo parameters (`SLOT` = the genesis slot, `N_MEMBERS`, `T`,
  `N_UPDATES`, `KEY_SLOTS`, `LOG_INV_RATE`), shared by `main.rs`, `prover` and
  `raw_agg`. The `verifier` deliberately imports none of them.
- `src/freshness.rs` — `HighWaterMark`, the persistent anti-rollback gate. Strict
  monotonic rule (`version > mark`), keyed to a fingerprint of the anchor so a
  committee rotation resets it, persisted with a write-then-rename. Lives *outside*
  `verify_proof`, which stays pure.
- `src/mem.rs`, `src/stats.rs` — RSS probes and descriptive statistics shared by
  every binary.
- `src/snark_prover_node.rs`, `src/snark_verifier_node.rs` — thin wrappers pairing
  `setup_prover()` / `setup_verifier()` with the proving and verifying calls. They
  own **no** policy: both derive the slot through `Committee::slot_for` and the
  verifier delegates to `committee::verify_proof`, so neither can drift from the
  checks. Keep it that way — an earlier copy of the verifier wrapper had drifted
  and silently lost the slot check.

Binaries:
- `src/main.rs` — the combined single-process demo; still the reference for the
  end-to-end flow and the `BENCH` record.
- `src/bin/prover.rs` — holds the secret keys, writes artifacts, **never verifies**.
- `src/bin/verifier.rs` — calls **only** `setup_verifier()`; loads `anchor.bin`
  and hardcodes nothing else.
- `src/bin/raw_agg.rs` — the no-SNARK baseline, and the only binary that runs the
  real node types end to end. Its `sign` figure therefore includes one `fsync`
  pair per signature that `prover.rs` never pays: compare *verify* and *size*
  across the two paths freely, compare *sign* knowing that.
Local scratch binaries (`src/bin/my_test*.rs`) are gitignored: hand-run
walkthroughs, not part of the published surface and not covered by the tests.

Tests (`cargo test`, ~10 s warm, 44 in total):
- `src/*.rs` unit tests cover each module against its own contract. `stats.rs`'s
  are worth a note: they are the only guard on the numbers that reach the paper,
  and they pin the two choices a "simplification" would silently undo — the
  median over a lone mean, and the Bessel-corrected (`n-1`) standard deviation
  `benchmark.sh` builds its confidence interval on.
- `tests/raw_path_round.rs` covers the seam: rotating quorums over durable
  counters, the published record verifying against the anchor, and the stale
  record that still verifies but is refused by the freshness gate. It stays on the
  raw path deliberately, so it costs milliseconds.
- `tests/snark_path.rs` covers `verify_proof` with **real** proofs on a small
  committee (`N=5, t=3`). One case per check, each breaking only that check and
  asserting the other four still hold; deleting any of the five makes exactly one
  assertion fail (verified by mutation). Check 5's case splices an honest
  aggregate's `info` onto another proof body — checks 1-4 then pass by
  construction, so only the SNARK itself can reject it.
  - It is one `#[test]`, not several: leanVM's arena has a single region per
    process and `setup_prover` forbids concurrent proving, which libtest's threads
    would otherwise do.
  - `Cargo.toml` sets `[profile.dev.package."*"] opt-level = 3` for this. leanVM's
    prover is unusable at `opt-level = 0`; optimizing only the dependencies keeps
    `cargo test` at seconds while this crate keeps its debug assertions and
    overflow checks. The release profile — what `benchmark.sh` measures — is
    untouched.
- `tests/lock_two_processes.rs` checks the cross-process lock with two **real**
  processes: it re-execs the test binary (`child_probe`, `#[ignore]`d, driven with
  `--ignored --exact`) and reads a marker line back. The unit tests only ever
  probed the lock from a second thread, which cannot tell a `flock` from a
  process-local mutex. Removing `try_lock` makes both tests fail with
  `PROBE=acquired:<slot>` naming the slot both holders would issue.
  It also asserts the negative control — after the holder exits, the next process
  gets the lock *and* resumes from the slot the first durably burned.

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
2. **A verify-only process is much smaller** — ~696 MB peak vs ~1042 MB at
   `N=10, t=7` (~33%), and ~692 MB vs ~2053 MB at the current `N=200, t=128`
   defaults (~66%), because only the prover's side scales with the committee. More
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
3. `committee.slot_for(version) == Some(agg.info.slot)` — the slot is the one the
   anchor assigns to this round;
4. `pubkeys.len() >= t` — quorum;
5. the SNARK verifies.

Check 4 is sound because leanVM's `check_single_message_pubkeys` requires
`pubkeys` to be strictly sorted with no duplicates (enforced both in `Deserialize`
and in `verify_single_message_aggregate`), so the count really is *distinct*
members. Keep that invariant in mind before "optimizing" check 4 away.

Check 3 adds no integrity — the slot already feeds the leaf hash, the WOTS tweaks
and the Merkle path directions, so a wrong one simply fails check 5. It pins
*policy*: one slot per round, the same for everybody, derived rather than chosen.
It also caps version inflation, since a slot-consistent forgery needs a key
covering `genesis + version`.

`verify_quorum` is the same five checks for the raw form, with two differences
worth knowing: membership is structural (an index *is* a member, so check 1
disappears), and the bitmap needs two extra well-formedness checks — exact width
`ceil(N/8)`, and padding bits past member `N-1` clear, without which one signer
set has several valid encodings.

When touching either function, every check must survive; dropping one is silently
exploitable, and on the SNARK path the current artifacts would still pass for the
quorum check.

### Known gaps in the model (deliberate, not bugs to fix silently)

- Verification is **stateless**: an old but legitimate (list, proof) pair verifies
  forever. Rollback is stopped one layer up, not by `verify_proof`:
  `select_freshest` picks the newest valid record, then `HighWaterMark`
  (`freshness.rs`) refuses anything not strictly newer than the last accepted
  version, persisted across restarts. The mark is per-object; the demo carries a
  single status list so it keeps a single mark in the artifact dir. Committee
  rotation (the anchor changing) is a separate, deferred protocol.
- `version` **is** verified: it is folded into the signed message (Option B), so
  verification recomputes `status_list_root_fe(list, version())` and a tampered
  version fails check 2. It is now *also* what fixes the slot, so the two bindings
  break together. `alg` is still never verified (it only appears in `Display`).
- The status list is never **sorted or deduplicated**, and `status_list_root_fe`
  folds sequentially, so `root([a,b]) != root([b,a])`: one logical revocation set
  has `n!` valid roots. Sorting inside the fold would fix it and is a
  wire-format-breaking change.
- **The published records are not canonically encoded.** Every decoder rejects
  trailing bytes, which closes the unbounded family of alternative encodings, but
  that is not canonicity: postcard's varint decoder errors only on overflow of the
  last permitted byte, so `87 00` and `07` both decode to `7`. The `version`
  field, each `Vec` length prefix and the `Algorithms` discriminant all admit that
  padding, so one logical update still has several valid byte forms and DHT
  deduplication is best-effort. Not a soundness issue — the signed message is
  recomputed from the decoded values, so a re-encoding verifies as the original
  and forges nothing. `Committee::from_bytes` *does* close it fully (re-encode and
  compare), because the anchor is read once at startup and the freshness gate
  fingerprints it; the same treatment on the verify path would cost a re-encode of
  the whole aggregate per record.
- **Committee rotation is not implemented.** Because the slot is derived, every
  key now runs out at the *same* round (`genesis + KEY_SLOTS`), which turns
  rotation from an asynchronous per-node event into a deadline everybody can
  compute from the anchor — but the hand-off protocol (the old committee signing
  the new one) is still missing.
- Both paths' checks now have tests: `raw_agg` forgeries plus `cargo test` for the
  raw path, `tests/snark_path.rs` for all five SNARK checks including the
  sub-threshold quorum.

## leanVM constraints that shape this code

Dependencies are git-pinned to leanVM rev `12e6151` (source at
`~/.cargo/git/checkouts/leanvm-*/12e6151` — read it when the API is unclear;
leanVM ships its own field/hash backend and does not depend on Plonky3).

- **XMSS is stateful.** A `(key, slot)` pair must sign **at most once** — reuse is
  insecure even on the same message, because the WOTS encoding randomness is
  non-deterministic. Every update therefore consumes a new slot. Keys are
  generated for `SLOT..=SLOT + KEY_SLOTS` (**both bounds inclusive**, so that is
  `KEY_SLOTS + 1` signatures), and raising `N_UPDATES` past it breaks keygen
  bounds.
- **A key's slot window cannot be extended.** Leaves outside `slot_start..=slot_end`
  are `gen_random_node` fillers that still feed the Merkle root, so the same seed
  with a wider window produces a *different* public key. An exhausted key can only
  be replaced, and it must be replaced *before* exhaustion — a key with no slots
  left cannot sign its own successor.
- **The whole quorum must share one slot.** `SingleMessageInfo` carries a single
  `slot` for all `pubkeys`, which is why the slot is derived from the anchor
  rather than from each member's counter. Raw verification has no such constraint
  (`xmss_verify` takes a per-signature slot), but the two paths deliberately share
  the derivation so a record can be re-issued either way.
- **`setup_verifier()` or `setup_prover()` must run before deserializing any
  proof** — `SingleMessageInfo::deserialize` recomputes the bytecode claim from
  the process-global bytecode and fails without it.
- **Never prove two things concurrently in one process**: leanVM's arena
  allocator has a single shared region. Parallelize with separate processes.
- Setup is paid **once per process** and is not persisted (~5-8 s, and it
  dominates everything else). Production keeps the prover process alive.
- Prove time and RAM scale with **`t`**, not with the number of updates. At small
  `t` the padding of the trace to a power of two makes it a step function (`t=5..=8`
  all cost the same, `t=4` is the next step down); from a few dozen signers upward
  the linear term dominates and prove time is ~linear in `t` — measured 406 ms at
  `t=70` and 718 ms at `t=128`, a flat ~5.7 ms per aggregated signature. **Do not
  extrapolate the step behaviour past small `t`.**
- Only leanVM's own XMSS parametrization (Poseidon2, `[F;8]` messages,
  `LOG_LIFETIME=32`) can be fed to the aggregator. The standalone `leanSig` XMSS
  (Poseidon1, `[u8;32]`, `LOG_LIFETIME=18`) is incompatible.

## Machine-readable record contracts

Each binary prints one summary line that `benchmark.sh` parses, plus optional
per-item raw samples when `EMIT_SAMPLES` is set in the environment:

| binary | summary line | sample lines |
|---|---|---|
| `main.rs` | `BENCH k=v ... sec_ok=1` | — |
| `prover` | `PROVER k=v ...` | `SAMPLE target=prover idx=… sign_ms=… prove_ms=…` |
| `verifier` | `VERIFIER k=v ... failures=N` | `SAMPLE target=verifier idx=… verify_ms=…` |
| `raw_agg` | `RAW_AGG k=v ... tamper_rejected=…` | `SAMPLE target=raw_agg idx=… sign_ms=… verify_ms=… bytes=…` |

`benchmark.sh` normalises all four in `emit_run_row`; adding or renaming a field
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
