# AGENTS.md

This file provides guidance to a generic Code Agent (Claude, GPT, Cursor etc..) when working with code in this repository.

## What this is

A committee-controlled snapshot of the credentials that are currently valid,
represented by their fingerprints. Presence means validity; revocation means
absence. A version replaces the whole snapshot and may add or remove any number
of fingerprints in the same update, so the list may grow, shrink, or become
empty. The single-key root of trust is replaced by a `t`-of-`N` committee, whose
members sign the list root with post-quantum hash-based signatures (leanVM's
synchronized XMSS).

The quorum is then published in **one of two interchangeable forms**, and a
verifier accepts either:

- **`StatusList`** — the `t` raw signatures plus a bitmap naming their signers by
  index into the anchor. No circuit, no setup, verification linear in `t`.
- **`SnarkStatusList`** — those same signatures aggregated into **one** proof by
  the [leanVM](https://github.com/leanEthereum/leanVM) zkVM. It requires prover
  and verifier setup.

The verifier embeds one fixed anchor — the committee (`N` public keys, threshold
`t`, genesis slot).
The independent `mldsa/` crate provides a raw-quorum variant with FIPS 204
ML-DSA-65, its own anchor and SSZ record. Its signatures are not aggregated by
the XMSS SNARK path. Its members sign `SHAKE256(statement, 64)`, not the
statement: the statement carries the whole list, and ML-DSA's internal
`H(pk) || M` hash would otherwise re-read it once per signature. That is
application-level hashing under FIPS 204 section 5.4 with pure ML-DSA (not
HashML-DSA); the digest must stay at least 384 bits for ML-DSA-65, so never
shorten it to 32 bytes. `docs/mldsa-statement-digest.md` records the reasoning
and the measured comparison; `tools/mldsa_statement_experiment.sh` and the
`mldsa_statement_experiment` binary reproduce it and are not benchmark targets.
The size of that gain depends on the compiler. Built with Rust 1.90.0, the
SHAKE256 inside `ml-dsa` 0.1.1 (`shake` crate) absorbs a long message about
four times slower than the `sha3` crate the application digest uses; built
with the pinned Rust 1.98.1 the two are equal. Quote the structural gain (one
pass over the list instead of `t`), which is what the pinned build measures,
not the larger ratio of a 1.90.0 build, and compare variants inside one
process, never across processes (CPU clock state differs between them).
Changing the statement or its digest is a signed-message break (domain `v2`).
Secure distributed storage is an external assumption: a VDR
establishes and returns one canonical current record. This repository does not
implement storage, replica discovery, conflict resolution, or candidate
selection; it authenticates that one record and applies local anti-rollback.
`README.md` holds the design rationale, benchmark method and the architecture
diagram; the per-module reasoning lives in the doc comments themselves.

## Commands

```sh
cargo run --release --bin decentralized-root-of-trust  # combined SNARK demo: setup, N updates, 3 security tests
cargo run --release --bin raw_agg                      # the same protocol with no SNARK, through SignerNode/VerifierNode
cargo run --release --bin prover   -- [outdir]         # split: aggregate, writes artifacts (default ./artifacts)
cargo run --release --bin verifier -- --init-state [dir] # split: explicit first provisioning, run once per state path
cargo run --release --bin verifier -- [dir]            # split: verify-only, opens existing state and fails closed
cargo run --release --bin signer                       # split: ONE member, one signature + durable slot burn per round
cargo fmt --all -- --check                             # formatting gate used by CI
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked                                    # 83 unit + 16 integration tests; 98 run + 1 ignored
./benchmark.sh                                         # defaults: RUNS=24 WARMUP=2; six XMSS/ML-DSA role targets
LIST_ENTRIES=1000 ./benchmark.sh                       # every version carries exactly 1000 credentials
PLOT=1 ./benchmark.sh                                  # optional SVG figures and Markdown table in OUTDIR/plots
./committee-scaling-benchmark.sh                       # exploratory pilot; hard RAM/disk-gated N/t sweep
LIST_ENTRIES=1000 ./committee-scaling-benchmark.sh     # the same sweep at one list size; one campaign per size
tools/mldsa_statement_experiment.sh                    # reproduce docs/mldsa-statement-digest.md
python3 tools/plot_benchmarks.py committee-scaling-<timestamp> # plot a completed or partial scaling campaign
python3 tools/analyze_scaling.py committee-scaling-<timestamp> # session effect, drift, block and simultaneous intervals
STUDY_MODE=publication PIN_CPUS=0-7 ./committee-scaling-benchmark.sh # clean-tree, repeated counterbalanced sweep
PLAN_ONLY=1 ./committee-scaling-benchmark.sh           # persist the host-derived sweep limit only
tools/mutate.py                                        # mutation testing: 25 checks, each must be caught by a test
./demo/docker/demo.sh {raw|snark|mldsa} up             # container demo; every subcommand is in demo/AGENTS.md
```

**Always `--release`** for anything touching the prover; it is unusable in a debug
build. The first build compiles the whole leanVM tree.
`cargo test` is fine in debug: `Cargo.toml` optimizes dependencies in the dev
profile, which is what makes `tests/snark_path.rs` practical even though it
drives a real prover. The `lean_vm` dependency alone also has dev overflow checks
disabled: v0.10's aggregation warm-up shifts by shape-only dummy table heights
and otherwise panics before proving. That matches its release arithmetic without
disabling overflow checks in this crate.

The tests cover the slot counter, the raw quorum path and — since
`tests/snark_path.rs` — the v0.10 statement-shape guard and each of the five checks
in `PQSNARKVerifierModule::verify`. The binaries
remain the end-to-end assertion: the combined demo must print `security OK: true`,
`raw_agg`, `signer` and `verifier` must exit 0. `benchmark.sh` refuses to print
timings if any run reports a failure.

`.cargo/config.toml` sets `target-cpu=native` and `RUST_MIN_STACK=512MiB`.
`target-cpu=native` is required and makes builds host-specific: benchmark numbers
are not portable across machines. An environment `RUSTFLAGS` (or a Cargo config
outside the repository setting rustflags) silently replaces it;
`tools/cargo_env_fingerprint.sh` lists every such source, `benchmark.sh` records
it in `env.txt` and refuses strict runs with an override.
`RUST_MIN_STACK` is a precaution against deep recursion in the prover, **not**
a requirement of leanVM v0.10, which neither sets nor mentions it. Cargo's
`[env]` reaches only processes Cargo starts, so `cargo run`/`cargo test` get it
and `benchmark.sh`, which execs frozen binaries, does not: a prover at N=500,
t=334 aggregates and verifies 20 updates without it; N=1000/1500 are
untested. The demo containers set it explicitly. `env.txt`'s
runtime probe, started through the same wrapper as every target, records what the
measured processes actually receive; the scaling resume fingerprint includes it
together with the toolchain, Cargo configs and `TMPDIR`.
`rust-toolchain.toml` pins Rust 1.98.1 plus `rustfmt` and `clippy`. The pin
exists for reproducible lints and builds, not because leanVM requires it: v0.10
declares no minimum Rust version. Moving the pin requires `fmt`, `clippy` and
the tests of the three crates, the full mutation run, and binaries of both
compilers exchanging real artifacts (each verifier accepting the other's
proofs, XMSS records and ML-DSA records and rejecting the forgery corpus).
Timings from different compilers are not comparable: between Rust 1.90.0 and
1.98.1, at `N=10`, `L=1000`, the prover, the SNARK verifier and XMSS are
unchanged within session noise (about 3%), while ML-DSA verification is 14%
faster and its verifier start-up 45% faster under 1.98.1, for the SHAKE reason
above. A campaign's `env.txt` and each frozen
set's `PROVENANCE` record the compiler; never mix sessions across a pin
change. CI uses one
Linux job for both crates and caches Cargo sources only: sharing `target/`
between hosted runners would be unsafe because those artifacts were compiled
for the previous runner's native CPU.

## Architecture

One data flow that forks at the end:

```
Committee --BLAKE2s(context + format_LE + alg=1 + SHA3(anchor))--> Domain[32]
(Domain, Vec<[u8;32]>, version)
    --BLAKE2s(context + domain + version_LE + len_LE + entries)--> message[32]
        --t x leanvm::xmss::sign at slot = genesis + version--> t sigs
            |-- (index, sig) pairs --------------------> StatusList { bitmap, signatures }
            `-- leanvm::aggregate (XMSS inputs only) --> SNARK --> SnarkStatusList.zk_proof
```

Library:
- `src/protocol/status_list.rs` — the published objects and their digest.
  `status_list_message(domain, list, version)` streams one unambiguous preimage
  into leanVM v0.10's own BLAKE2s-256 implementation: a fixed context, the
  32-byte domain, little-endian `version`, little-endian `u64` entry count, then
  the ordered fixed-size entries. The explicit count makes the framing
  prefix-free; it allocates nothing and stays O(n) sequential, with no per-entry
  inclusion proofs.
  `Domain` is what stops evidence being portable between deployments. A signature
  binds only what is inside the message: with `(list, version)` alone, any two
  anchors that coincided would have interchangeable records. The domain
  hashes a separate context, SHA3-256 of the anchor's canonical encoding, the
  record's `alg`, and a construction generation. **Prefixed and not appended**:
  the application-controlled entries never precede the trust domain.
  It is unforgeable by construction rather than checked — `status_list_message`
  takes a `Domain`, so there is no way to compute a message without naming one.
  Note the boundary: one anchor has one domain, so this pins "a list is governed
  by one committee" and **not** "a committee governs one list". Two lists under
  one anchor still interchange; closing that needs a list id inside the anchor.
  Changing any of this is a signed-message break. Migration also reserves wire
  algorithm tag `1` and refuses retired tag `0`, while leaving the SSZ
  field layout unchanged. Everything published is SSZ. leanVM v0.10's
  `XmssSignature` (fixed 1208 B) and `XmssPublicKey` (32 B) are byte-oriented SSZ
  objects: exact length gives each value one encoding, with no field-modulus
  canonicality check. The one exception is the leanVM
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
- `src/protocol/committee.rs` — the anchor and **nothing else**: members, `t`,
  `genesis_slot`, the SSZ wire encoding, `slot_for` (the **only** place the slot is
  derived) and `domain`/`message_for` (the **only** place the signed message is).
  The two derivations are siblings on purpose: a second copy of either is a second
  place for a signer and a verifier to drift apart. The anchor caches its own
  fingerprint, and `from_bytes` hashes the bytes it was handed rather than
  re-encoding what it just decoded — a decoded anchor *is* its canonical encoding,
  and decode is the one path an attacker chooses how often to run. `from_bytes` re-checks `t ∈ 1..=N`, the one invariant a wire
  format cannot know; canonicity it gets from SSZ, which has no varints to pad. The protocol predicates are not free functions taking
  `&Committee`: they are methods on the node type that owns the anchor, so a
  participant is one value with the operations its role can perform.
- `src/state/slot_counter.rs` — the durable monotonic slot allocator. Burns the
  slot on disk **before** handing it out using a fixed two-record journal (write
  the inactive generation → `sync_data` → return the slot), guarded by a lock on
  a separate file so two processes cannot share a key. There is no batching.
  `reserve` takes the next local slot; `reserve_at` takes a
  protocol-chosen one, jumping forward over missed rounds and refusing the past.
- `src/node/signer.rs` — one member: keypair + counter. `sign` for the local-slot
  path, `sign_at` for the derived-slot one.
- `src/node/raw_verifier.rs` — the **raw** path's predicate: `verify` for a
  single member signature, `verify_status_list` for the whole record (the five
  checks that decide whether an update is authorized). It is a method on the node
  and not a free function because every answer depends on the anchor it holds:
  the same bytes verify under one committee and not under another. Needs no
  `setup_verifier()` and no circuit, which is what makes it the honest comparison
  against the SNARK path.
- `src/node/raw_node.rs` — the raw-path **relying party**: a `VerifierNode` and a
  `HighWaterMark` in one type. `accept` decodes, verifies, and only then offers the
  authenticated version to the gate. It accepts exactly one record, matching the
  external VDR contract; it never ranks or falls back across candidates. The
  ordering is the reason the type exists: a mark that advanced on an
  unauthenticated record could be pushed to `u32::MAX`, locking the node out of
  every genuine update. No I/O beyond the mark's own file — transport lives above
  it, which is what keeps the unit tests to byte strings.
- `src/params.rs` — demo parameters (`SLOT` = the genesis slot, `N_MEMBERS`, `T`,
  `N_UPDATES`, `KEY_SLOTS`, `LOG_INV_RATE`), shared by `main.rs`, `prover` and
  `raw_agg`. The `verifier` deliberately imports none of them. Ordinary builds
  use `DEFAULT_N_MEMBERS`/`DEFAULT_T`; the scaling script sets the paired
  compile-time overrides `DROT_BENCH_N`/`DROT_BENCH_T`. They are benchmark-only:
  setting only one is refused, and invalid pairs fail before key generation.
- `src/state/freshness.rs` — `HighWaterMark`, the persistent anti-rollback gate. Strict
  monotonic rule (`version > mark`), keyed to a fingerprint of the anchor and
  persisted with a write-then-rename. `create` is first provisioning only;
  `open` refuses missing, corrupt, unreadable, or foreign state rather than
  resetting it. `load_from_trusted_source` is the explicit recovery operation:
  its version must come from the VDR's authenticated canonical-latest record,
  and it never replaces valid same-anchor state. Lives *outside* the verification
  predicate, which stays pure; `RawNode` and `SnarkNode` continue to receive it
  by dependency injection.
- `src/bench/` — measurement support shared by the binaries: RSS probes,
  statistics, the `decode_then_verify` timer boundary, the process CPU clock
  and the benchmark workload. Each module is described in
  `docs/agents/benchmarking.md`. `process_cpu_time` in `src/bench/timing.rs`
  holds the crate's only `unsafe` call (its twin is in
  `mldsa/src/bin/support/mod.rs`), a recorded decision whose measured
  alternatives are in README "Dependencies". Do not add another `unsafe`, do
  not call this one from `node`, `protocol` or `state`, and do not replace it
  with the whole-process derivation.
- `src/node/snark_prover.rs` — the prover. Holding the value *is* the proof that
  `setup_prover()` ran. `make_proof` derives the slot through `Committee::slot_for`
  and takes a `version`, never a slot; `aggregate` takes an explicit slot only
  to aggregate already-produced signatures for adversarial tests. The prover
  module deliberately has no signing API: production signatures must come from
  `SignerNode`, whose durable counter burns an XMSS slot before signing.
- `src/node/snark_verifier.rs` — the SNARK path's predicate, paired with
  `setup_verifier()`. Owns the five checks and `is_newer`. It authenticates one
  record and performs no storage-layer selection. There is exactly **one** copy
  of each predicate and it lives here: a second copy can drift and silently
  lose a check. The checks live in the private `check`; `verify`
  (decodes the aggregate itself) and `verify_decoded` (takes a
  `DecodedSnarkStatusList`, built only by `SnarkStatusList::decode`) are thin
  entry points over it, so a caller can time decoding apart without a second
  predicate and without pairing a record with a foreign aggregate.

- `src/node/snark_node.rs` — the same composition over the aggregated form, and
  the only thing the two paths differ in once a form is chosen. Owns a
  `PQSNARKVerifierModule`, so holding one also means `setup_verifier()` has run;
  `accept` authenticates one VDR-supplied record before offering its version to
  the mark. `tests/snark_node.rs` is the seam test: a genuine proof carrying a
  lying version must not move the gate.
- `src/node/mod.rs` — `Outcome` (`Accepted` / `Stale` / `Refused`) and
  `Outcome::advance`, the single place a mark is moved. `Refused` deliberately does
  not carry the version the record claimed: an unverified version is a peer's
  assertion, not a fact, and handing it back invites a caller to order by it.

Binaries:
- `src/main.rs` — the combined single-process demo: the reference for the
  end-to-end flow, the three forgery tests and the `BENCH` record. It is a **demo**,
  not a measurement target — `benchmark.sh` does not run it by default. It is
  also the one binary that does not go through the node types end to end: it calls
  `setup_prover`/`setup_verifier` directly, to time the two phases apart, and signs
  with `leanvm::xmss::sign` rather than through `SignerNode`.
- `src/bin/prover.rs` — writes artifacts and **never verifies**. Its normal demo
  mode generates signing keys locally. With `BENCH_INPUT_DIR` it receives raw
  signed fixtures and becomes the measured production-shaped role: one
  aggregator, public keys plus `t` signatures, no committee secret keys.
  Outside `BENCH_HONEST_ONLY` it also writes six forgeries, one per check and
  each rejectable only by its own: `attack-outsider` (1), `attack-tampered` and
  `attack-version` (2), `attack-slot` (3), `attack-short` (4, `t - 1` genuine
  signatures, hence `t >= 2`, checked at startup only when writing the corpus,
  so a `t = 1` build still compiles and still aggregates honest-only input), `attack-proofbody` (5, one
  proof-body bit flipped while the claims stay decodable and identical).
- `src/bin/verifier.rs` — calls **only** `setup_verifier()`; loads `anchor.bin`
  and hardcodes nothing else. Its `decode` timer covers the SSZ container *and*
  the aggregate (`from_bytes` + `decode`), then `verify_decoded` runs the checks,
  so its phase split matches the raw decoders, which parse every signature.
  All six `attack-*` files are required; a missing one counts as a failure.
  Removing any one of the five SNARK checks makes this gate fail on exactly the
  control that isolates it (verified by mutation).
- `src/bin/raw_agg.rs` — the no-SNARK baseline. It spends slots through
  `SignerNode`/`AtomicSlotCounter`, so its `t` signatures are produced the way a
  real member produces them, but it does **not** time them: what it measures is
  the relying party's side, verify and size. Its failure gate
  (`tamper_rejected`) is the AND of six controls: tampered list, relabelled
  version, `t - 1` quorum, outsider, a full quorum signed one slot late, and one
  signature with a flipped bit.
- `src/bin/signer.rs` — one committee **member**, in isolation: one key, one
  durable counter, one signature per round. The only binary that reports a `sign`
  figure, because it is the only one whose process shape matches the role. Every
  round self-verifies as a failure gate.
- `src/bin/check_prover_output.rs`, `src/bin/committee_fixture.rs` — benchmark
  support, never measured roles: the first validates every `prover` execution
  outside its timers, the second generates the committee and the signed
  fixtures that `prover` and `raw_agg` consume. Their contracts are in
  `docs/agents/benchmarking.md`.

Every binary goes through the node types, because there is nothing else to call:
`prover`/`main` through `PQSNARKProverModule`, `verifier`/`main` through
`PQSNARKVerifierModule`, `raw_agg` through `SignerNode`/`VerifierNode`, `signer`
through `SignerNode` alone. The
predicates are not reachable any other way, which is the point — a free function
duplicated next to a wrapper is how a predicate loses a check unnoticed.
Local scratch examples (`examples/my_test*.rs`) are gitignored: hand-run
walkthroughs, not part of the published surface and not covered by the tests.
The `#[doc(hidden)]` re-exports of old module paths in `src/lib.rs` exist for
them. They must still **compile**, though — `cargo test` builds every example in
the package, so one that has drifted out of date fails the whole suite even though
nothing tests it. Keep them migrated along with the library, or delete them.
`my_test`/`my_test_2`/`my_test_3` walk the SNARK path, the raw path with a
committee of one, and the raw path with a real `t`-of-`N` quorum. They write slot
state into the working directory (`next_slot`, `signers/`), which `.gitignore`
covers.

Tests (`cargo test`, 99 registered: 98 run plus one `#[ignore]`d). What each
test file covers, and why it has the shape it has, is in
`docs/agents/tests.md`: read it before adding, splitting or deleting a test.
Rules that hold regardless:
- Each SNARK test file (`tests/snark_path.rs`, `tests/snark_modules.rs`,
  `tests/snark_node.rs`) is a single `#[test]`: leanVM's arena has one region
  per process and `setup_prover` forbids concurrent proving, which libtest's
  threads would otherwise do.
- `tests/cpu_clock.rs` stays alone in its own test binary: the CPU clock covers
  the whole process.
- Every security check must be killed by a test: deleting any of the five SNARK
  checks must make exactly one assertion fail, and `tools/mutate.py` must
  report no survivor.
- `[profile.dev.package."*"] opt-level = 3` and the `lean_vm` overflow-check
  exception in `Cargo.toml` are what make the real-proof tests practical in a
  debug build; do not remove them.

### The split deployment (and why it exists)

A verify-only process calls `setup_verifier()` and never `setup_prover()`. The
latter enables leanVM's process-wide arena and belongs only in the prover role.
leanVM v0.10 also provides `setup_prover_without_arena()` for deployments that
choose the system allocator; this repository does not use it. Keep the roles
split so `benchmark.sh` can measure each process shape independently.

### The container demos (`demo/`)

A **separate crate**, with its own `[workspace]` and its own lockfile: the
measured root and `mldsa/` crates contain protocol code; the demo adds
networking, orchestration and a credential format. Nothing in `demo/` may be
reachable from a `benchmark.sh` build, and the parent `Cargo.toml` must stay
unaware of it. Roles, modes and the `crash` scenario are described in
`demo/AGENTS.md`: read it before touching `demo/`. Four properties are
load-bearing and easy to break by "simplifying":

1. The aggregator never names the slot: every member derives it through
   `Committee::slot_for`.
2. The address map decides where to look, never whether a signature is good.
3. Member keys are derived from a per-container secret plus the run identifier.
4. An XMSS member signs only the next version (`published + 1`).

### The security boundary (most important thing to understand)

`AggregateSignature::verify` attests only the XMSS and SPHINCS claims the
aggregate itself declares. v0.10 permits several epochs/messages and two
signature families, so the protocol first requires **exactly one XMSS group and
no SPHINCS claims**. Every remaining link to trust is a cleartext check outside
the circuit, in `PQSNARKVerifierModule::verify` (`src/node/snark_verifier.rs`):

1. every signer ∈ committee — membership against the fixed anchor;
2. `message == status_list_message(committee.domain(record.alg), list, version)`
   — **the critical binding**; it ties the proof to the list (without it a valid
   proof of a *different* list can be attached), to the `version` (without it the
   cleartext version field is forgeable — see the versioning note below), and,
   through the domain, to *this committee* and *this algorithm*, so evidence
   cannot be carried between deployments;
3. `committee.slot_for(version) == Some(slot)` — the slot is the one the
   anchor assigns to this round;
4. `pubkeys.len() >= t` — quorum;
5. the SNARK verifies.

Check 4 is sound because v0.10's aggregate parser and verifier require every
XMSS group's `pubkeys` to be strictly sorted with no duplicates, so the count
really is *distinct* members. Keep that invariant in mind before "optimizing"
check 4 away or counting across groups.

Check 3 pins policy rather than proof integrity. The SNARK authenticates whichever
slot the aggregate declares; it does not know which slot this anchor assigns to
the record's cleartext version. The explicit comparison enforces one slot per
round, the same for everybody, derived rather than chosen.
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
  the external VDR supplies one canonical current record, the node authenticates
  it, then `HighWaterMark` (`freshness.rs`) refuses anything not strictly newer
  than the last accepted version, persisted across restarts. The mark is
  per-object; the demo carries a single status list so it keeps a single mark in
  the artifact dir. Missing,
  invalid, or foreign state stops normal startup. Recovery requires a record
  independently established as both cryptographically valid and canonical-latest
  by the trusted VDR; an old signed record is not a safe checkpoint. Committee
  rotation (the anchor changing) is a separate, deferred protocol.
- `version` **is** verified: it is framed into the signed message (Option B), so
  verification recomputes `status_list_message(domain, list, version())` and a
  tampered version fails check 2. It is *also* what fixes the slot, so the two
  bindings break together. `alg` is verified the same way since the domain took it
  in: relabelling it changes the domain, so the evidence produced under the
  original label does not match. Only one tag decodes today, so that binding is latent —
  it is there because adding it after a second algorithm exists means breaking the
  format twice.
- **One anchor governs exactly one status list**, and this is an operator
  invariant rather than something the code enforces. The domain binds the
  committee, so a record cannot move *between* anchors; but one anchor has one
  domain, so two lists under the same committee still produce interchangeable
  evidence. Closing it needs a list identifier inside the anchor — a further wire
  change. Pinned in `committee.rs`'s
  `one_anchor_is_one_domain_so_it_governs_one_list`, which is where to start.
- The status list is never **sorted or deduplicated**. Entries are hashed in wire
  order, so `message([a,b]) != message([b,a])`: one logical validity set has `n!`
  valid messages. Sorting before hashing would fix it and is a protocol-breaking
  change.
- **Published records are canonically encoded.** `StatusList`, `SnarkStatusList`
  and the anchor are SSZ containers; leanVM v0.10 signatures and public keys are
  fixed-size, byte-oriented SSZ values. Only the leanVM aggregate is still a native blob, accepted only when
  decode followed by re-encode returns byte-for-byte identical data. Earlier wire
  formats are intentionally incompatible; regenerate artifacts after upgrading.
- **The SNARK path still ships the signers' public keys**, inside the aggregate.
  leanVM v0.10 exposes `to_bytes_without_pubkeys()` / `from_bytes_without_pubkeys()`
  for receivers that already know the signer set, which this project's verifier
  does: it holds the anchor. Adopting it would omit the public-key payload. More
  importantly, it would make check 1
  *structural* rather than a lookup, exactly as the bitmap already makes it on the
  raw path, so the two published forms would stop disclosing different things. It
  is deliberately **not** adopted here: it changes the published schema (the
  record would have to carry a signer bitmap of its own), which is a protocol
  change rather than the leanVM alignment it arrived with. Note that
  the aggregate's XMSS key lists are strictly sorted and deduplicated, and a
  signer set different from the aggregated one fails verification — so such a
  bitmap would have to name exactly the aggregated set, not a superset of it.
- **Committee rotation is not implemented.** Because the slot is derived, every
  key runs out at the *same* round (`genesis + KEY_SLOTS`), which turns
  rotation from an asynchronous per-node event into a deadline everybody can
  compute from the anchor — but the hand-off protocol (the old committee signing
  the new one) is still missing.
- **`reserve_at` jumps forward without an upper bound.** It burns every slot up
  to the requested one, so a member that signs whatever version it is asked for
  can have its whole key window exhausted by one proposal for a far-future
  version. Bounding the accepted version is the signer's policy, not the
  counter's: the container demo signs only `published + 1`. A deployment must
  derive that bound from its authenticated view of the VDR.
- Both paths' checks have tests: `raw_agg` forgeries plus `cargo test` for the
  raw path, `tests/snark_path.rs` for all five SNARK checks including the
  sub-threshold quorum. The benchmark's own gates cover every check too: the
  verifier corpus carries one forgery per SNARK check, `raw_agg` six controls,
  and `mldsa_raw_agg` five (no slot: ML-DSA is stateless).
- **Secure distributed storage is not implemented here.** The VDR is assumed to
  establish global canonicality and latestness and to return one record. This
  library independently authenticates that record and applies local
  anti-rollback; it provides no replica discovery, candidate ranking or fallback.

## leanVM constraints that shape this code

Dependencies are git-pinned to leanVM **v0.10** (`73a5f5d`). The tag is pinned by
commit, not by name, because a tag can move. Do not switch this dependency to the
moving `main`: its aggregate API has already evolved beyond v0.10. Upstream's
`sha2` and `sha3` branches are benchmark alternatives, not selectable algorithms
in the v0.10 release; stable v0.10 uses BLAKE2s.

This is a breaking migration from v0.9. Old keys, signatures and proofs are
incompatible, wire algorithm tag `0` is explicitly rejected, and the
signed-message generation is `2`. Delete `artifacts/` and every durable slot-state
file when deploying the new anchor. There is no mixed-version mode.

- **Use leanVM v0.10's XMSS API directly.** Import types and `key_gen`,
  `key_gen_from_seed`, `sign` and `verify` from `leanvm::xmss`; there is no local
  compatibility module. XMSS randomness comes from `leanvm::rand::rng()`. The
  root crate's rand 0.10 remains separate and is used only for application data.
- **XMSS is stateful.** A `(key, slot)` pair must sign **at most once**. v0.10
  draws fresh signing randomness, so even signing the same message twice at one
  slot is unsafe. The durable counter must refuse every reuse before the key is
  touched; burn-before-sign cannot be weakened.
- **Keys are generated for `SLOT..=SLOT + KEY_SLOTS`**, both bounds inclusive,
  i.e. `KEY_SLOTS + 1` signatures. Pass those inclusive `u32` bounds directly
  to upstream v0.10; do not reintroduce a count-based adapter.
- **`key_gen` and `key_gen_from_seed` return `(secret, public)`**, which is the
  ordering used throughout the project. Tests and containers use the
  deterministic form with namespaced seeds; production/demo random keygen uses
  leanVM's own RNG.
- **A key's slot window cannot be extended.** Leaves outside `slot_start..=slot_end`
  are `gen_random_node` fillers that still feed the Merkle root, so the same seed
  with a wider window produces a *different* public key. An exhausted key can only
  be replaced, and it must be replaced *before* exhaustion — a key with no slots
  left cannot sign its own successor.
- **The whole quorum must be exactly one XMSS claim group.** v0.10's general
  `AggregateSignature` can contain multiple `(epoch, message, pubkeys)` groups and
  SPHINCS claims. `PQSNARKVerifierModule::verify` first requires exactly one XMSS
  group and no SPHINCS, then applies membership, message, slot and quorum checks
  to that group. Do not count `num_total_sigs()` or signers across groups.
- **`setup_verifier()` or `setup_prover()` must run before deserializing any
  proof** — deserializing an `AggregateSignature` recomputes the deferred claim from
  the process-global bytecode and fails without it. This is why the aggregate is
  an opaque byte-list inside `SnarkStatusListWire` rather than a typed field.
- **Aggregate fields are private.** Read claims through `xmss_signers()` and
  `sphincs_signers()`, and verify through `AggregateSignature::verify()`. The
  signer set can still be omitted with `to_bytes_without_pubkeys`, but this
  project deliberately keeps it on wire until it has a replacement bitmap.
- **Messages are 32 raw bytes** (`leanvm::xmss::MESSAGE_LEN`). `status_list_message` uses
  the exact BLAKE2s-256 implementation from leanVM's `primitives` crate and is the
  application/VM boundary.
- **Never prove two things concurrently in one process**: leanVM's arena
  allocator has a single shared region. Parallelize with separate processes.
- Setup is paid **once per process** and is not persisted.
- Only the XMSS types exported by the pinned `leanvm` crate may enter the
  aggregator. The type path is part of the boundary; another hash-based signature
  crate taking the same `[u8; 32]` message is not interchangeable.

## Benchmarking

The full contract (record formats, what each target measures, the evidence a
campaign keeps, the scaling orchestrator and the analysis tool) is in
`docs/agents/benchmarking.md`. **Read it before changing** `benchmark.sh`,
`committee-scaling-benchmark.sh`, anything under `tools/` or `src/bench/`, or a
measured binary (`src/bin/`, `mldsa/src/bin/`), and before interpreting their
output. These rules hold even when that file has not been read:

- Never run a measured process from `target/release`: every process runs from
  the frozen, hashed copies made by `tools/freeze_bins.sh`.
- One `OUTDIR`, one campaign. Only a directory whose `status.txt` is `complete`
  with a matching `outputs.sha256` holds a result. Any failure withholds every
  number; never turn a resource abort or a failed check into a partial timing
  row.
- Every figure belongs to a workload `(N, t, L)` and to the compiler that built
  the binaries; never mix sessions across a toolchain change.
- The unit of analysis is the per-run median (n = RUNS), not the pooled samples.
- Two clocks, never merged: do not add elapsed milliseconds of processes with
  different parallelism, and do not present CPU time as latency.
- One target per role. Only `signer` and `mldsa_signer` report a `sign` row;
  `combined` stays out of the default targets; `setup_ms`, `keygen_ms` and
  `slot_state_ms` are three different costs.
- The signer's storage is part of its measurement: never weaken the durable
  burn or move it to RAM to improve a number, and keep `slot_burn`,
  `sign_crypto` and `sign_protocol` apart.
- A missing reading is never 0 (memory, statistics, CSV cells): it is `NA`, an
  empty cell, or a refusal.
- Adding or renaming a field of a binary's summary line means updating
  `emit_run_row` in `benchmark.sh` and `tools/validate_benchmark_csv.awk`. The
  `update-` / `attack-` artifact prefixes are a contract between `prover` and
  `verifier`.
- `committee-scaling-benchmark.sh` stays an orchestrator over `benchmark.sh`,
  not a second measurement implementation.
- No extrapolation to other hardware or between grid points, no projection
  block, and no decision threshold, unit or deployment scenario chosen by the
  harness.
