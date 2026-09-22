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
`t`, genesis slot). Secure distributed storage is an external assumption: a VDR
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
cargo test --locked                                    # 73 unit + 10 integration tests; 82 run + 1 ignored
./benchmark.sh                                         # defaults: RUNS=20 WARMUP=2 TARGETS="signer prover verifier raw_agg"
./committee-scaling-benchmark.sh                       # exploratory pilot; hard RAM/disk-gated N/t sweep
STUDY_MODE=publication PIN_CPUS=0-7 ./committee-scaling-benchmark.sh # clean-tree, repeated counterbalanced sweep
PLAN_ONLY=1 ./committee-scaling-benchmark.sh           # persist the host-derived sweep limit only
tools/mutate.py                                        # mutation testing: 25 checks, each must be caught by a test
./demo/docker/demo.sh {raw|snark} up                   # container demo: 1 bootstrap + 10 members, N=10 t=7
./demo/docker/demo.sh {raw|snark} round                # node A requests a credential, then verifies the record
./demo/docker/demo.sh {raw|snark} revoke               # remove that credential's fingerprint, then verify its absence
./demo/docker/demo.sh {raw|snark} verify               # node A re-checks what is published (expect a stale refusal)
./demo/docker/demo.sh {raw|snark} crash                # SIGKILL a member mid-protocol; it must refuse to re-sign
./demo/docker/demo.sh {raw|snark} down                 # stop and delete that demo's volumes
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

`.cargo/config.toml` sets `RUST_MIN_STACK=512MiB` (the prover recurses very
deeply) and `target-cpu=native`. Both are required — don't run the binary in a
context that bypasses that config. Note `target-cpu=native` makes builds
host-specific: benchmark numbers are not portable across machines.
`rust-toolchain.toml` pins Rust 1.90.0 plus `rustfmt` and `clippy`. CI uses one
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
  binds only what is inside the message, and that used to be `(list, version)`
  alone, so any two anchors that coincided had interchangeable records. The domain
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
  objects: exact length gives each value one encoding; there is no field-modulus
  canonicality check anymore. The one exception is the leanVM
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
  format cannot know; canonicity it gets from SSZ, which has no varints to pad. The protocol predicates used to live here as free functions taking
  `&Committee`; they are now methods on the node type that owns the anchor, so a
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
- `src/bench/mem.rs`, `src/bench/stats.rs` — RSS (resident set size) probes and descriptive
  statistics shared by every binary.
- `src/node/snark_prover.rs` — the prover. Holding the value *is* the proof that
  `setup_prover()` ran. `make_proof` derives the slot through `Committee::slot_for`
  and takes a `version`, never a slot; `aggregate` takes an explicit slot only
  to aggregate already-produced signatures for adversarial tests. The prover
  module deliberately has no signing API: production signatures must come from
  `SignerNode`, whose durable counter burns an XMSS slot before signing.
- `src/node/snark_verifier.rs` — the SNARK path's predicate, paired with
  `setup_verifier()`. Owns the five checks and `is_newer`. It authenticates one
  record and performs no storage-layer selection. There is exactly **one** copy
  of each predicate and it lives here; an earlier second copy had drifted and
  silently lost the slot check.

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
  not a measurement target — `benchmark.sh` no longer runs it by default. It is
  also the one binary that does not go through the node types end to end: it calls
  `setup_prover`/`setup_verifier` directly, to time the two phases apart, and signs
  with `leanvm::xmss::sign` rather than through `SignerNode`.
- `src/bin/prover.rs` — writes artifacts and **never verifies**. Its normal demo
  mode generates signing keys locally. With `BENCH_INPUT_DIR` it receives raw
  signed fixtures and becomes the measured production-shaped role: one
  aggregator, public keys plus `t` signatures, no committee secret keys.
- `src/bin/verifier.rs` — calls **only** `setup_verifier()`; loads `anchor.bin`
  and hardcodes nothing else.
- `src/bin/raw_agg.rs` — the no-SNARK baseline. It spends slots through
  `SignerNode`/`AtomicSlotCounter`, so its `t` signatures are produced the way a
  real member produces them, but it does **not** time them: what it measures is
  the relying party's side, verify and size.
- `src/bin/signer.rs` — one committee **member**, in isolation: one key, one
  durable counter, one signature per round. The only binary that reports a `sign`
  figure, because it is the only one whose process shape matches the role. Every
  round self-verifies as a failure gate.
- `src/bin/committee_fixture.rs` — scaling support, never a measured role. It
  generates a fresh committee and canonical raw records while preserving the
  XMSS one-key/one-slot rule, then exits. This gives measured `prover` and
  `raw_agg` the same ready-made signatures without either holding member secrets.

Every binary goes through the node types, because there is nothing else to call:
`prover`/`main` through `PQSNARKProverModule`, `verifier`/`main` through
`PQSNARKVerifierModule`, `raw_agg` through `SignerNode`/`VerifierNode`, `signer`
through `SignerNode` alone. The
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

Tests (`cargo test`, 83 registered: 82 run plus one `#[ignore]`d):
- `src/*.rs` unit tests cover each module against its own contract.
  `status_list.rs`'s pin the seam this crate has with leanVM: that
  `status_list_message` is BLAKE2s-256 of the exact domain/version/count/entries
  framing, that it moves with both list and version — the content of check 2 —,
  that it stays order-sensitive, and that retired wire tag `0` is
  rejected. `stats.rs`'s
  are worth a note: they are the only guard on the numbers that reach the paper,
  and they pin the two choices a "simplification" would silently undo — the
  median over a lone mean, and the Bessel-corrected (`n-1`) standard deviation
  `benchmark.sh` builds its confidence interval on.
- `tests/raw_path_round.rs` covers the seam: rotating quorums over durable
  counters, the published record verifying against the anchor, and the stale
  record that still verifies but is refused by the freshness gate. It stays on the
  raw path deliberately so it does not invoke the prover.
- `tests/snark_path.rs` covers `PQSNARKVerifierModule::verify` with **real** proofs on a small
  committee (`N=5, t=3`). One case per check, each breaking only that check and
  asserting the other four still hold; deleting any of the five makes exactly one
  assertion fail (verified by mutation). Check 5's case flips a proof-body bit
  while requiring the aggregate to remain decodable with identical public claims
  — checks 1-4 then pass by construction, so only the SNARK itself can reject it.
  Separate genuine aggregates carry either two XMSS epoch/message groups or the
  one permitted XMSS group plus a SPHINCS claim. Both are rejected: this protocol
  supports only XMSS with BLAKE2s, regardless of leanVM's broader capabilities.
  - It is one `#[test]`, not several: leanVM's arena has a single region per
    process and `setup_prover` forbids concurrent proving, which libtest's threads
    would otherwise do.
  - `Cargo.toml` sets `[profile.dev.package."*"] opt-level = 3` for this. leanVM's
    prover is unusable at `opt-level = 0`; optimizing only the dependencies keeps
    this crate's debug assertions and overflow checks. The targeted
    `[profile.dev.package.lean_vm] overflow-checks = false` exception is required
    by v0.10's shape-only warm-up and does not apply to this crate. The release
    profile is untouched.
- `tests/snark_modules.rs` covers the two SNARK node types the way the binaries
  use them, which `snark_path.rs` does not: that `PQSNARKProverModule` derives the
  slot from the **anchor** rather than from its caller — asserted against the slot
  recorded inside the finished proof — that the verifier module accepts an honest
  record and refuses a tampered list and a relabelled version, that
  `is_newer` is strict, and that a version with no slot under the anchor panics
  instead of proving something unverifiable.
  One aggregation and one `#[test]`, for the arena reason above.
- `tests/snark_node.rs` covers the *seam* the other two do not: that `SnarkNode`
  never lets a record which failed the predicate reach the gate. A genuine proof
  relabelled to version 9 is refused and leaves the mark untouched, which is the
  case that matters — a mark an unauthenticated peer can advance locks the node
  out of every honest update below it. Then the honest record is accepted, the
  same bytes replayed are `Stale`. One aggregation; one `#[test]`, for the arena
  reason above. The raw half of the same seam is unit-tested in
  `src/node/raw_node.rs`, where it costs nothing.
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
  repository-external registry, so every byte remains untrusted until local
  authentication succeeds. It mutates all three wire formats —
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

A verify-only process calls `setup_verifier()` and never `setup_prover()`. The
latter enables leanVM's process-wide arena and belongs only in the prover role.
leanVM v0.10 also provides `setup_prover_without_arena()` for deployments that
choose the system allocator; this repository does not use it. Keep the roles
split so `benchmark.sh` can measure each process shape independently.

### The container demos (`demo/`)

A **separate crate**, with its own `[workspace]` and its own lockfile. That is
the whole rule: the library and the four benchmark binaries are the artifact this
project measures, and the demo adds networking, orchestration and a credential
format, none of which belong in that surface. Nothing in `demo/` may be reachable
from a `benchmark.sh` build, and the parent `Cargo.toml` must stay unaware of it.

Ten containers run one image and differ only by environment. `demo/src/bin/`
holds `bootstrap` (assembles the anchor from ten published public keys, in index
order, then exits), `signer` (a member; in raw mode any member may aggregate a
round, while in SNARK mode only the configured prover subset aggregates and runs
`setup_prover()` at startup), `holder` (node A) and `probe` (asks one member to sign
directly, exit `0` signed / `3` abstained, which is what lets the crash scenario
assert instead of grep).

`holder` is **resident**, and `round`/`revoke`/`verify` only send it a trigger (the same
binary with `HOLDER_TRIGGER` set, run as the throwaway `trigger` service).
`setup_verifier()` is a per-process cost, so a node A that exited after every
check would repeatedly include process startup. Keep it resident: the one-shot
shape still exists (neither `HOLDER_SERVE` nor `HOLDER_TRIGGER`) for cold-start
benchmarking.
Node A holds a `RawNode` or a `SnarkNode`, so the anti-rollback mark is inside
the node and survives a container restart on its `holder-state` volume. It also
keeps the last credential in its private state: `round` accepts it only when its
fingerprint is present in the authenticated snapshot, while `revoke` accepts the
next snapshot only when that fingerprint is absent.

Three things about it are load-bearing and easy to break by "simplifying":

1. **The aggregator never names the slot.** It proposes a version; every member
   derives the slot through `Committee::slot_for`. An aggregator that could name
   it could have two versions signed at one XMSS slot.
2. **The address map decides where to look, never whether a signature is good.**
   `config::MEMBER_IPS` turns a peer into a committee index; every signature is
   then verified against `members[index]` from the anchor before it is counted.
   A wrong entry must cost a rejected contribution, not a forged record.
3. **Member keys are derived** from a per-container secret plus the shared run
   identifier, so a restarted container comes back as the *same* member and its
   counter file still belongs to its key. A new run rotates the identifier, and
   therefore all ten keys, which is what stops a re-run from signing new content
   at slots the previous run already spent.

The `crash` scenario is the only test in the repository that kills a real process
mid-protocol. The `AtomicSlotCounter` unit tests additionally inject an invalid
inactive journal record, damage the older record while retaining the latest one,
and refuse a journal with no valid record. Those byte-level cases exercise the
recovery decisions but cannot emulate a storage device violating `sync_data`'s
durability contract. Treat the scenario as coverage, not decoration: if it
starts passing for the wrong reason
(a member that never signed in step 1, say), it stops proving anything.

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
  tampered version fails check 2. It is now *also* what fixes the slot, so the two
  bindings break together. `alg` is verified the same way since the domain took it
  in: relabelling it changes the domain, so the evidence produced under the old
  label no longer matches. Only one tag decodes today, so that binding is latent —
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
  key now runs out at the *same* round (`genesis + KEY_SLOTS`), which turns
  rotation from an asynchronous per-node event into a deadline everybody can
  compute from the anchor — but the hand-off protocol (the old committee signing
  the new one) is still missing.
- Both paths' checks now have tests: `raw_agg` forgeries plus `cargo test` for the
  raw path, `tests/snark_path.rs` for all five SNARK checks including the
  sub-threshold quorum.
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

## Machine-readable record contracts

Each binary prints one summary line that `benchmark.sh` parses, plus optional
per-item raw samples when `EMIT_SAMPLES` is set in the environment:

| binary | summary line | sample lines |
|---|---|---|
| `main.rs` | `BENCH k=v ... sec_ok=1` | — |
| `signer` | `SIGNER k=v ... failures=N` | `SAMPLE target=signer idx=… sign_ms=… bytes=…` |
| `prover` | `PROVER k=v ...` | `SAMPLE target=prover idx=… prove_ms=… bytes=…` |
| `verifier` | `VERIFIER k=v ... failures=N` | `SAMPLE target=verifier idx=… verify_ms=…` |
| `raw_agg` | `RAW_AGG k=v ... tamper_rejected=…` | `SAMPLE target=raw_agg idx=… verify_ms=… bytes=…` |

`benchmark.sh` normalises all five in `emit_run_row`; adding or renaming a field
means updating that function. The script exits if a summary line is missing, and
aborts before printing any statistics if any run reports `failures > 0`.

Fixed costs are reported as **three distinct fields**, and conflating them is how
the comparison between the two paths gets inverted:

| field | what it is | who pays it |
|---|---|---|
| `setup_ms` | the leanVM circuit (`setup_prover` / `setup_verifier`) | SNARK path only — `raw_agg` and `signer` leave it empty |
| `keygen_ms` | generating XMSS keys | every path; `N` keys, except `signer`, which generates **one** |
| `slot_state_ms` | creating durable `AtomicSlotCounter`s | only a real signer — `N` for `raw_agg`, **one** for `signer` |

Per-update phases are carried into `runs.csv` under their **own names**
(`sign_*`, `prove_*`, `verify_*`), never under a positional primary/secondary
slot: a shared column put unlike phases under one heading and made `summary.csv`
unreadable on its own. A target leaves blank the phases it does not
run, and `col()` drops empty cells, so an absent phase produces no row rather than
a `0.000 ms` that reads as "instant".

### Artifact conventions between `prover` and `verifier`

```
anchor.bin       the committee (N public keys + threshold t)
update-NN.bin    legitimate updates — MUST verify
canonical.bin    the one current record used by the anti-rollback flow
attack-*.bin     forgeries — MUST be rejected (a decode failure counts as rejection)
```

The `update-` / `attack-` name prefixes are the contract. Each `prover` run
generates a **fresh random committee**, so artifacts from different runs are not
interchangeable — start from a clean directory.

## Benchmarking

`benchmark.sh` is built for numbers that can be audited before a write-up: it captures the full
environment (`env.txt`), emits tidy raw data (`samples.csv`), per-run rows
(`runs.csv`) and aggregates with quartiles, sd, CV and t-based CI95
(`summary.csv` / `summary.txt`). `runs.csv` also records load, selected-CPU
frequency and the highest readable temperature before and after each process.
`drift.csv` flags an early/late median shift above 15% without deleting data.
Strict runs require a clean tree; exploratory dirty runs preserve
`source.patch` and `source-status.txt`.

The unit of analysis for per-update metrics is the **per-run median** (n = RUNS),
not the pooled sample: updates inside one process share allocator and cache state
and are not independent. Preserve that distinction if you touch the aggregation.

### One target per role

The sweep has three targets that correspond to real processes, plus two contrast
targets. What each one measures is decided by **which role would run that
process**, and no target is charged for another role's work:

| target | role | reports |
|---|---|---|
| `signer` | one committee member | `sign` per round (incl. its durable slot burn), 1 key, 1 counter |
| `prover` | the aggregator | `prove` per update, `setup`, complete `SnarkStatusList` size |
| `verifier` | a relying party | `verify` per record, `setup` |
| `raw_agg` | the no-SNARK baseline | `verify` per record + record size |

`combined` (`main.rs`) is **not** in the default `TARGETS`. It measures a process
that proves and verifies at once — not a role anyone deploys. It stays available
as `TARGETS="... combined"` for one purpose: an independent second reading of
prove time. Do not add it back to the defaults for any other reason.

**Only `signer` reports a `sign` row, and that is deliberate.** In production
nobody produces `t` signatures: each member signs *once* per round on its own
machine and broadcasts, and the aggregator receives `t` and produces none. Timing
a loop that signs `t` times sums the work of `t` machines and bills it to one —
which is what the `sign / update` column used to do for a process that does not
exist. By default, one unmeasured `committee_fixture` produces the signed raw
records before the sweep. `raw_agg` verifies those `StatusList` records, while
`prover` consumes the same logical signed inputs and writes
`SnarkStatusList` records. Neither measured process holds committee secret keys.
`BENCH_SELF_CONTAINED=1` retains the former all-in-one process shape only for
diagnostic back-comparison; in that mode `prover`, `combined` and `raw_agg`
produce signatures outside their timed phase.

A member's signing cost is identical on both published forms — same key, same
32-byte message, same derived slot — so the `signer` row applies unchanged to the
SNARK and the raw path, and what separates the two paths is only how the quorum is
evidenced and what a relying party pays to check it.

`signer`'s `keygen` and `slot_state` are for **one** key and **one** counter.
In the default fixture-shaped benchmark, `prover` and `raw_agg` report neither
cost because the measured aggregator and verifier do not own signer state. The
self-contained diagnostic mode reports the whole committee's `N`; do not read
those figures as the same quantity as the signer row.

The default schedule uses a Williams-style balanced target order and an idle
`COOLDOWN_SECONDS=2` before every process. Warm-ups form a separate phase, so
their count does not shift the measured design. Even target counts use N rows;
odd counts use N rotations plus their reversals. This balances position and
directed predecessor across complete designs and reduces thermal carry-over. It
does not prove equal temperature, so retain the telemetry and inspect
`drift.csv` before publishing.
`INTERLEAVE=0` remains the contiguous legacy order.

`runs.csv` calls its shared size column `artifact_med_bytes`. In
`summary.csv`, the public metric name is `signature_size`, `record_size` or
`proof_size` according to the actual serialized object. `prover` and
`raw_agg` measure the complete published record; only `combined` measures the
proof body. All even-sized byte samples use the arithmetic mean of their two
central observations.

Nothing in the output is extrapolated to other hardware, and nothing should be
added that is: `target-cpu=native` makes the binaries host-specific, so the only
honest way to get numbers for another machine is to run `benchmark.sh` there. A
projection block existed once and was removed — do not reintroduce it.

### Committee-scaling orchestrator

`committee-scaling-benchmark.sh` must remain an orchestrator over
`benchmark.sh`, not a second measurement implementation. `benchmark.sh` remains
the authority for scheduling, raw samples, descriptive statistics, confidence
intervals, drift diagnostics and security failure gates. The scaling layer measures the `signer`
target once for the whole campaign, then chooses `(N,t)`, prepares unmeasured
signatures, enforces resources, invokes complete benchmark sessions and
aggregates their run-level medians. The signer result stays separate in
`signer.csv`: it is a one-member cost common to both publication forms, not a
quantity to multiply by `t` or repeat at every committee size.

The requested grid is `N = 5, 10, 100, 500, 1000, 1500`, with
`t = floor(2N/3) + 1`. This is a strict two-thirds authorization policy, not PBFT
or another consensus protocol. `N=5,10,100` is the base grid. At startup the script
derives a usable process budget as the smaller of 70% of physical RAM and
`MemAvailable - host reserve`; it admits `N=500`, `N=1000` and `N=1500` at 8,
12 and 20 GiB respectively. It prints and persists that decision before building
anything.

Admission never disables the live guard. Build, fixture and benchmark stages run
serially in separate process groups and, by default, systemd user scopes with
kernel-enforced `MemoryMax`/`MemorySwapMax`. Polling separately checks group RSS,
`MemAvailable`, swap, free disk and timeout. If a hard scope is unavailable,
`HARD_MEMORY_LIMIT=required` refuses to run; `auto` is the explicit weaker
fallback. After a stop no later point runs. Keep it explicit in `manifest.csv`;
never turn a resource abort into a partial timing row.

`STUDY_MODE=pilot` is exploratory: three runs, one warm-up, one ascending sweep.
`publication` defaults to 24 runs and two complete sweeps, ascending then
descending, and requires a clean tree, strict environment, explicit CPU mask and
hard memory backend. Its run count must be a multiple of six, completing the
Williams design for the three per-point targets. It withholds a session on a
drift warning. `RESUME=1` is accepted only when the recorded
source/configuration fingerprint matches and the current usable RAM cap still
meets the admission threshold for the largest originally selected N.

The combined report derives quantities from run-level medians across complete
sweeps. A verification crossover is reportable only when the paired 95% CI for
`raw_verify - snark_verify` is wholly positive. Speedup and break-even retain
quartiles. `ceil(prove / (raw_verify - snark_verify))` excludes process setup,
networking, signing and fixture generation; withhold it if any paired run has no
positive saving rather than deleting that run. Do not call it end-to-end latency
or extrapolate a crossover between measured grid points; refine the grid around
the first favorable point.
