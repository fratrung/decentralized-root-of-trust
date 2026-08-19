# AGENTS.md

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
cargo test                                             # 48 unit + 8 integration tests, ~25 s (incl. two real SNARKs)
./benchmark.sh                                         # RUNS=30 WARMUP=3 TARGETS="prover verifier" ./benchmark.sh
tools/mutate.py                                        # mutation testing: 24 checks, each must be caught by a test
```

**Always `--release`** for anything touching the prover; it is unusable in a debug
build. The first build compiles the whole leanVM tree and takes several minutes.
`cargo test` is fine in debug: `Cargo.toml` optimizes dependencies in the dev
profile, which is what makes `tests/snark_path.rs` affordable there (~10 s) even
though it drives a real prover.

The tests cover the slot counter, the raw quorum path and — since
`tests/snark_path.rs` — each of the five checks in `PQSNARKVerifierModule::verify`. The binaries
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
    --pack canonical LE u32--> [u8;32]   (status_list_message)
        --t x xmss_sign at slot = genesis + version--> t sigs
            |-- (index, sig) pairs --------------------> StatusList { bitmap, signatures }
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
  streamed rather than held in RAM. `status_list_message` closes it by packing the
  eight field elements into the 32 bytes leanVM's XMSS signs — canonical LE `u32`
  each, injective, so the binding argument is the fold's.
  Everything published is SSZ. Since leanVM v0.9 that includes leanVM's own types:
  `XmssSignature` (fixed 1208 B) and `XmssPublicKey` (32 B) are SSZ objects that
  refuse a field element at or above the modulus, so the signatures inside a
  record and the keys inside the anchor are canonical by schema rather than by a
  re-encode-and-compare this crate performs. The one exception is the leanVM
  aggregate, which cannot be a typed field (decoding it needs the process-global
  bytecode), so `SnarkStatusList::proof` still canonicalizes it by re-encoding.
  `StatusList::new` sorts the `(index, signature)` pairs and rejects duplicates
  and out-of-range indices, so a value that exists is already canonical — the
  out-of-order and repeated-signer variants are unconstructible rather than
  defended against. `from_bytes` additionally rejects a bitmap whose population
  disagrees with the signature count.
  The signer bitmap is an SSZ `BitList`, capped at `MAX_COMMITTEE_SIZE` (2048),
  which is the only thing about `N` fixed at compile time — the real committee
  size always comes from the anchor. Its length in bits rides in a sentinel bit,
  so bits past member `N-1` cannot exist and an index outside the committee is
  unrepresentable rather than checked for.
- `src/committee.rs` — the anchor and **nothing else**: members, `t`,
  `genesis_slot`, the SSZ wire encoding, and `slot_for` (the **only** place the
  slot is derived). `from_bytes` re-checks `t ∈ 1..=N`, the one invariant a wire
  format cannot know; canonicity it gets from SSZ, which has no varints to pad. The protocol predicates used to live here as free functions taking
  `&Committee`; they are now methods on the node type that owns the anchor, so a
  participant is one value with the operations its role can perform.
- `src/atomic_slot_counter.rs` — the durable monotonic slot allocator. Burns the
  slot on disk **before** handing it out (write tmp → fsync → rename → fsync the
  parent dir), guarded by a lock on a separate file so two processes cannot share
  a key. `reserve` takes the next local slot; `reserve_at` takes a
  protocol-chosen one, jumping forward over missed rounds and refusing the past.
- `src/signer_node.rs` — one member: keypair + counter. `sign` for the local-slot
  path, `sign_at` for the derived-slot one.
- `src/verifier_node.rs` — one relying party on the **raw** path: `verify` for a
  single member signature, `verify_status_list` for the whole record (the five
  checks that decide whether an update is authorized). It is a method on the node
  and not a free function because every answer depends on the anchor it holds:
  the same bytes verify under one committee and not under another. Needs no
  `setup_verifier()` and no circuit, which is what makes it the honest comparison
  against the SNARK path.
- `src/params.rs` — demo parameters (`SLOT` = the genesis slot, `N_MEMBERS`, `T`,
  `N_UPDATES`, `KEY_SLOTS`, `LOG_INV_RATE`), shared by `main.rs`, `prover` and
  `raw_agg`. The `verifier` deliberately imports none of them.
- `src/freshness.rs` — `HighWaterMark`, the persistent anti-rollback gate. Strict
  monotonic rule (`version > mark`), keyed to a fingerprint of the anchor so a
  committee rotation resets it, persisted with a write-then-rename. Lives *outside*
  the verification predicate, which stays pure.
- `src/mem.rs`, `src/stats.rs` — RSS (resident set size) probes and descriptive
  statistics shared by every binary.
- `src/snark_prover_node.rs` — the prover. Holding the value *is* the proof that
  `setup_prover()` ran. `make_proof` derives the slot through `Committee::slot_for`
  and takes a `version`, never a slot; `aggregate` takes an explicit slot and
  exists for the adversarial tests, which have to build what the honest path
  cannot express. `sign_and_prove` refuses a repeated signer **before** signing —
  leanVM dedups the aggregate, so nothing downstream could catch it and the key
  would already be damaged.
- `src/snark_verifier_node.rs` — the SNARK relying party, paired with
  `setup_verifier()`. Owns the five checks, `is_newer`, and `select_freshest` (the
  DHT-layer selection: newest declared version first, verify, fall back on
  failure). `select_freshest_above` is the same with a floor — the caller's
  high-water mark — applied before any proof is verified. That is a work saver,
  not a check: the floor can only drop records the caller was already going to
  refuse as stale. There is exactly **one** copy of each predicate and it lives
  here; an earlier second copy had drifted and silently lost the slot check.

Binaries:
- `src/main.rs` — the combined single-process demo; still the reference for the
  end-to-end flow and the `BENCH` record.
- `src/bin/prover.rs` — holds the secret keys, writes artifacts, **never verifies**.
- `src/bin/verifier.rs` — calls **only** `setup_verifier()`; loads `anchor.bin`
  and hardcodes nothing else.
- `src/bin/raw_agg.rs` — the no-SNARK baseline, and the only binary that spends
  slots through `SignerNode`/`AtomicSlotCounter`. Its `sign` figure therefore
  includes one `fsync` pair per signature that `prover.rs` never pays: compare
  *verify* and *size* across the two paths freely, compare *sign* knowing that.

Every binary goes through the node types, because there is nothing else to call:
`prover`/`main` through `PQSNARKProverModule`, `verifier`/`main` through
`PQSNARKVerifierModule`, `raw_agg` through `SignerNode`/`VerifierNode`. The
predicates are not reachable any other way, which is the point — a free function
duplicated next to a wrapper is how the verifier module once lost its slot check.
Local scratch binaries (`src/bin/my_test*.rs`) are gitignored: hand-run
walkthroughs, not part of the published surface and not covered by the tests.
They must still **compile**, though — `cargo test` builds every target in the
package, so one that has drifted out of date fails the whole suite even though
nothing tests it. Keep them migrated along with the library, or delete them.
`my_test`/`my_test_2`/`my_test_3` walk the SNARK path, the raw path with a
committee of one, and the raw path with a real `t`-of-`N` quorum. They write slot
state into the working directory (`next_slot`, `signers/`), which `.gitignore`
covers.

Tests (`cargo test`, ~15 s warm, 57 in total: 56 run plus one `#[ignore]`d):
- `src/*.rs` unit tests cover each module against its own contract.
  `status_list.rs`'s pin the seam this crate has with leanVM: that
  `status_list_message` is the *canonical* packing of the fold (each limb a field
  element's unique representative), that it moves with both the list and the
  version — which is the whole content of check 2 — and that the fold stays
  order-sensitive, a documented gap rather than an accident. `stats.rs`'s
  are worth a note: they are the only guard on the numbers that reach the paper,
  and they pin the two choices a "simplification" would silently undo — the
  median over a lone mean, and the Bessel-corrected (`n-1`) standard deviation
  `benchmark.sh` builds its confidence interval on.
- `tests/raw_path_round.rs` covers the seam: rotating quorums over durable
  counters, the published record verifying against the anchor, and the stale
  record that still verifies but is refused by the freshness gate. It stays on the
  raw path deliberately, so it costs milliseconds.
- `tests/snark_path.rs` covers `PQSNARKVerifierModule::verify` with **real** proofs on a small
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
- `tests/snark_modules.rs` covers the two SNARK node types the way the binaries
  use them, which `snark_path.rs` does not: that `PQSNARKProverModule` derives the
  slot from the **anchor** rather than from its caller — asserted against the slot
  recorded inside the finished proof — that the verifier module accepts an honest
  record and refuses a tampered list and a relabelled version, that
  `select_freshest` runs those same checks and is not fooled by a candidate that
  merely *declares* a higher version, that `is_newer` is strict, and that a version
  with no slot under the anchor panics instead of proving something unverifiable.
  One aggregation, so a few seconds; one `#[test]`, for the arena reason above.
- `tests/lock_two_processes.rs` checks the cross-process lock with two **real**
  processes: it re-execs the test binary (`child_probe`, `#[ignore]`d, driven with
  `--ignored --exact`) and reads a marker line back. The unit tests only ever
  probed the lock from a second thread, which cannot tell a `flock` from a
  process-local mutex. Removing `try_lock` makes both tests fail with
  `PROBE=acquired:<slot>` naming the slot both holders would issue.
  It also asserts the negative control — after the holder exits, the next process
  gets the lock *and* resumes from the slot the first durably burned.
- `tests/hostile_bytes.rs` is the only test whose input this crate did not
  produce, which is the shape the threat model actually has: records arrive from a
  DHT, so every byte is attacker-chosen. It mutates all three wire formats —
  truncation, bit flips, insertions, deletions, plus an offset-shaped pattern
  spliced at every early position — and asserts three properties in increasing
  order of importance: the decoders never panic, never treat a malformed length as
  an allocation request, and never accept a record that *means* something other
  than the one it was derived from (same list, same version, same signer set).
  The seed is fixed, so a failure is reproducible rather than intermittent, and
  the test guards its own relevance: it fails if too few mutants decode, or if
  none reaches `verify_status_list` at all. Raw path only — a fuzzer will not
  stumble onto a valid aggregate, so the SNARK predicate is covered case by case
  in `snark_path.rs` instead.

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

   leanVM v0.9 makes that arena opt-out: `setup_prover_without_arena()` runs the
   prover on the system allocator — slower, but the RSS curve stops being
   monotonic. This repo does **not** use it, so every figure here is the arena's.
   It is the first thing to try for a memory-constrained prover, and it has to be
   re-measured rather than assumed.

The ~678 MB floor is `Bytecode.instructions_multilinear` in leanVM (the unrolled
aggregation program's multilinear encoding). It is **not** driven by
`MAX_XMSS_AGGREGATED` — that constant only appears in asserts — so shrinking it
via a leanVM fork does not work. Treat the floor as a fixed constraint.

### The security boundary (most important thing to understand)

`verify_single_message_aggregate` attests **only** "these listed public keys
signed this message at this slot". Every link to trust is a cleartext check
outside the circuit, in `PQSNARKVerifierModule::verify` (`src/snark_verifier_node.rs`):

1. every signer ∈ committee — membership against the fixed anchor;
2. `agg.info.core.message == status_list_message(list, version)` — **the critical
   binding**; it ties the proof to both the list (without it a valid proof of a
   *different* list can be attached) and the `version` (without it the cleartext
   version field is forgeable — see the versioning note below);
3. `committee.slot_for(version) == Some(agg.info.core.slot)` — the slot is the one the
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

`VerifierNode::verify_status_list` is the same five checks for the raw form, with
two differences worth knowing. Membership is structural — an index *is* a member,
so check 1 disappears — and in its place the bitmap must name exactly this
committee: `signer_slots() == N`. That is one check rather than the two it used
to be, because the bitmap is an SSZ `BitList` whose length in bits is carried by a
sentinel and recovered on decode. A byte array fixed only the byte count, leaving
the bits above member `N-1` free, which took a second check to police and made an
index past the end of the committee representable at all.

When touching either function, every check must survive; dropping one is silently
exploitable, and on the SNARK path the current artifacts would still pass for the
quorum check.

### Known gaps in the model (deliberate, not bugs to fix silently)

- Verification is **stateless**: an old but legitimate (list, proof) pair verifies
  forever. Rollback is stopped one layer up, not by the predicate:
  `select_freshest` picks the newest valid record, then `HighWaterMark`
  (`freshness.rs`) refuses anything not strictly newer than the last accepted
  version, persisted across restarts. The mark is per-object; the demo carries a
  single status list so it keeps a single mark in the artifact dir. Committee
  rotation (the anchor changing) is a separate, deferred protocol.
- `version` **is** verified: it is folded into the signed message (Option B), so
  verification recomputes `status_list_message(list, version())` and a tampered
  version fails check 2. It is now *also* what fixes the slot, so the two bindings
  break together. `alg` is still never verified (it only appears in `Display`).
- The status list is never **sorted or deduplicated**, and `status_list_root_fe`
  (the fold behind `status_list_message`) folds sequentially, so `root([a,b]) != root([b,a])`: one logical revocation set
  has `n!` valid roots. Sorting inside the fold would fix it and is a
  wire-format-breaking change.
- **Published records are canonically encoded.** `StatusList`, `SnarkStatusList`
  and the anchor are SSZ containers, and since leanVM v0.9 the signatures and
  public keys inside them are SSZ too, with non-canonical field elements refused
  on decode. Only the leanVM aggregate is still a native blob, accepted only when
  decode followed by re-encode returns byte-for-byte identical data. Earlier wire
  formats are intentionally incompatible; regenerate artifacts after upgrading.
- **The SNARK path still ships the signers' public keys**, inside the aggregate.
  leanVM v0.9 added `to_bytes_without_pubkeys()` / `from_bytes_without_pubkeys()`
  for receivers that already know the signer set, which this project's verifier
  does: it holds the anchor. Adopting it would drop ~4 KB of the ~234 KB record
  (128 keys × 32 B), and — the part that actually matters — would make check 1
  *structural* rather than a lookup, exactly as the bitmap already makes it on the
  raw path, so the two published forms would stop disclosing different things. It
  is deliberately **not** adopted here: it changes the published schema (the
  record would have to carry a signer bitmap of its own), which is a protocol
  change rather than the leanVM alignment it arrived with. Note that
  `SingleMessageCore::with_pubkeys` sorts and deduplicates, and a signer set
  different from the aggregated one fails verification — so such a bitmap would
  have to name exactly the aggregated set, not a superset of it.
- **Committee rotation is not implemented.** Because the slot is derived, every
  key now runs out at the *same* round (`genesis + KEY_SLOTS`), which turns
  rotation from an asynchronous per-node event into a deadline everybody can
  compute from the anchor — but the hand-off protocol (the old committee signing
  the new one) is still missing.
- Both paths' checks now have tests: `raw_agg` forgeries plus `cargo test` for the
  raw path, `tests/snark_path.rs` for all five SNARK checks including the
  sub-threshold quorum.

## leanVM constraints that shape this code

Dependencies are git-pinned to leanVM **v0.9** (`a5909d1`, source at
`~/.cargo/git/checkouts/leanvm-*/a5909d1` — read it when the API is unclear;
leanVM ships its own field/hash backend and does not depend on Plonky3). The tag
is pinned by commit, not by name, because a tag can be moved.

v0.9 is a breaking release: keys, signatures and proofs from any earlier revision
are rejected. After a bump, delete `artifacts/` and any durable slot state — the
key fingerprint the counters are tied to changes with the key.

- **XMSS is stateful.** A `(key, slot)` pair must sign **at most once**, and what
  "once" protects is the *message*: v0.9 derives the signing randomness from
  `(secret seed, slot, attempt, hashed message)`, so re-signing the same message
  at the same slot returns a bit-identical signature and is harmless, while two
  *different* messages at one slot still expose enough WOTS chain positions to
  forge. Every update therefore still consumes a new slot. Do not weaken any
  guard on the strength of the derandomization: the counter cannot tell the two
  cases apart without keeping the message history it deliberately does not keep.
- **Keys are generated for `SLOT..=SLOT + KEY_SLOTS`**, both bounds inclusive,
  i.e. `KEY_SLOTS + 1` signatures. v0.9's `xmss_key_gen` takes an activation slot
  and a slot **count** instead of an inclusive end, so that `+ 1` lives in
  `params::KEY_SLOT_COUNT` and nowhere else. Raising `N_UPDATES` past the window
  breaks keygen bounds — see the `const` assertion in `params.rs`.
- **`xmss_key_gen` samples its own seed** and returns `(public, secret)`. This
  crate carries `(secret, public)`, so every call site swaps at the boundary;
  the two types are distinct, so a missed swap is a compile error.
  `xmss_key_gen_from_seed` is the deterministic form the tests use.
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
  proof** — deserializing a `SingleMessageInfo` recomputes the bytecode claim from
  the process-global bytecode and fails without it. This is why the aggregate is
  an opaque byte-list inside `SnarkStatusListWire` rather than a typed field.
- **The aggregate's public inputs live under `info.core`** since v0.9
  (`info.core.message`, `info.core.slot`, `info.core.bytecode_claim`), with
  `info.pubkeys` alongside. The split exists so the signer set can be dropped from
  the wire — see `to_bytes_without_pubkeys` in the note below.
- **Messages are 32 raw bytes** (`MESSAGE_LEN_BYTES`), not `[F; 8]`: leanVM hashes
  them into the field message itself. `status_list_message` is where this crate
  crosses that boundary.
- **Never prove two things concurrently in one process**: leanVM's arena
  allocator has a single shared region. Parallelize with separate processes.
- **The verifier is single-threaded** in v0.9 and allocates plain `Vec`, and
  `verify_single_message_aggregate` installs a `parallel::forbid_parallelism()`
  guard for the duration of verification. `setup_verifier()` remains all it needs.
- Setup is paid **once per process** and is not persisted (~5-8 s, and it
  dominates everything else). Production keeps the prover process alive.
- Prove time and RAM scale with **`t`**, not with the number of updates. At small
  `t` the padding of the trace to a power of two makes it a step function (`t=5..=8`
  all cost the same, `t=4` is the next step down); from a few dozen signers upward
  the linear term dominates and prove time is ~linear in `t`. **Do not extrapolate
  the step behaviour past small `t`**, and do not quote a per-signature figure from
  a single `t`: dividing one measurement by `t` still carries the `t`-independent
  part of the proof. `benchmark.sh` derives that line from the run it just made —
  it used to print remembered numbers, which then contradicted the table above them
  in the same file.
- Only leanVM's own XMSS parametrization (Poseidon2, `LOG_LIFETIME=32`) can be
  fed to the aggregator. The standalone `leanSig` XMSS (Poseidon1,
  `LOG_LIFETIME=18`) is incompatible. Since v0.9 both take a 32-byte message, so
  the message type no longer tells them apart — check which crate you are calling.

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

Fixed costs are reported as **three distinct fields**, and conflating them is how
the comparison between the two paths gets inverted:

| field | what it is | who pays it |
|---|---|---|
| `setup_ms` | the leanVM circuit (`setup_prover` / `setup_verifier`) | SNARK path only — `raw_agg` leaves it empty |
| `keygen_ms` | generating the `N` XMSS keys | every path, `raw_agg` included |
| `slot_state_ms` | creating the `N` durable `AtomicSlotCounter`s | only a real signer (`raw_agg`) |

Per-update phases are carried into `runs.csv` under their **own names**
(`sign_*`, `prove_*`, `verify_*`), never under a positional primary/secondary
slot: `raw_agg`'s secondary phase is signing while `combined`'s is verification,
so a shared column put ~1.2 s and ~32 ms under one heading and made `summary.csv`
unreadable on its own. A target leaves blank the phases it does not run, and
`col()` drops empty cells, so an absent phase produces no row rather than a
`0.000 ms` that reads as "instant".

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
