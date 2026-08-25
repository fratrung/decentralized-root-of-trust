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
cargo run --release --bin prover   -- [outdir]         # split: aggregate, writes artifacts (default ./artifacts)
cargo run --release --bin verifier -- [dir]            # split: verify-only, exits non-zero on any violated expectation
cargo run --release --bin signer                       # split: ONE member, one signature + durable slot burn per round
cargo test                                             # 65 unit + 10 integration tests, 75 in all (incl. four real SNARKs)
./benchmark.sh                                         # RUNS=30 WARMUP=3 TARGETS="prover verifier" ./benchmark.sh
tools/mutate.py                                        # mutation testing: 28 checks, each must be caught by a test
./demo/docker/demo.sh {raw|snark} up                   # container demo: 1 bootstrap + 10 members, N=10 t=7
./demo/docker/demo.sh {raw|snark} round                # node A requests a credential, then verifies the record
./demo/docker/demo.sh {raw|snark} verify               # node A re-checks what is published (expect a stale refusal)
./demo/docker/demo.sh {raw|snark} crash                # SIGKILL a member mid-protocol; it must refuse to re-sign
./demo/docker/demo.sh {raw|snark} down                 # stop and delete that demo's volumes
```

**Always `--release`** for anything touching the prover; it is unusable in a debug
build. The first build compiles the whole leanVM tree and takes several minutes.
`cargo test` is fine in debug: `Cargo.toml` optimizes dependencies in the dev
profile, which is what makes `tests/snark_path.rs` affordable there (~10 s) even
though it drives a real prover.

The tests cover the slot counter, the raw quorum path and — since
`tests/snark_path.rs` — each of the five checks in `PQSNARKVerifierModule::verify`. The binaries
remain the end-to-end assertion: the combined demo must print `security OK: true`,
`raw_agg`, `signer` and `verifier` must exit 0. `benchmark.sh` refuses to print
timings if any run reports a failure.

`.cargo/config.toml` sets `RUST_MIN_STACK=512MiB` (the prover recurses very
deeply) and `target-cpu=native`. Both are required — don't run the binary in a
context that bypasses that config. Note `target-cpu=native` makes builds
host-specific: benchmark numbers are not portable across machines.

## Architecture

One data flow that forks at the end:

```
Committee --SHA3-256 of the anchor + alg + format--> Domain   (the fold's IV)
(Domain, Vec<[u8;32]>, version) --status_list_root_fe--> [KoalaBear;8]
    --pack canonical LE u32--> [u8;32]   (status_list_message)
        --t x xmss_sign at slot = genesis + version--> t sigs
            |-- (index, sig) pairs --------------------> StatusList { bitmap, signatures }
            `-- aggregate_single_message_signatures --> SNARK --> SnarkStatusList.zk_proof
```

Library:
- `src/protocol/status_list.rs` — the published objects and their digest. `entry_to_field`
  maps each 32-byte entry to `[F;8]`; `status_list_root_fe(domain, list, version)` folds
  the entries into the root and then closes with one more compression that mixes
  in the `version` (16-bit limbs, injective). **The fold is a Merkle–Damgård
  chain, not a tree**, despite the "root" naming: `acc = compress_pair(acc,
  entry(e))` — from the **domain**, not from `[0;8]`.
  `Domain` is what stops evidence being portable between deployments. A signature
  binds only what is inside the message, and that used to be `(list, version)`
  alone, so any two anchors that coincided had interchangeable records. The domain
  seeds the fold with SHA3-256 of the anchor's canonical encoding, the record's
  `alg`, and a construction generation. **Prefixed and not appended**: a chain
  from a shared IV lets every domain share intermediate states, so one internal
  collision against attacker-chosen entries would be reusable across all of them.
  It is unforgeable by construction rather than checked — `status_list_message`
  takes a `Domain`, so there is no way to compute a message without naming one.
  Note the boundary: one anchor has one domain, so this pins "a list is governed
  by one committee" and **not** "a committee governs one list". Two lists under
  one anchor still interchange; closing that needs a list id inside the anchor.
  Changing any of this is a signed-message break, not a wire-schema one — the SSZ
  containers and the record sizes are unchanged, but old artifacts stop verifying. Cost is O(n) sequential and there are no per-entry
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
  slot on disk **before** handing it out (write tmp → fsync → rename → fsync the
  parent dir), guarded by a lock on a separate file so two processes cannot share
  a key. `reserve` takes the next local slot; `reserve_at` takes a
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
  version to the gate; `accept_best` takes what several peers returned, drops
  everything at or below the mark, and tries the rest newest-first. The ordering is
  the reason the type exists: a mark that advanced on an unauthenticated record
  could be pushed to `u32::MAX` by any peer, locking the node out of every genuine
  update. No I/O beyond the mark's own file — transport lives above it, which is
  what keeps the unit tests to byte strings.
- `src/params.rs` — demo parameters (`SLOT` = the genesis slot, `N_MEMBERS`, `T`,
  `N_UPDATES`, `KEY_SLOTS`, `LOG_INV_RATE`), shared by `main.rs`, `prover` and
  `raw_agg`. The `verifier` deliberately imports none of them.
- `src/state/freshness.rs` — `HighWaterMark`, the persistent anti-rollback gate. Strict
  monotonic rule (`version > mark`), keyed to a fingerprint of the anchor so a
  committee rotation resets it, persisted with a write-then-rename. Lives *outside*
  the verification predicate, which stays pure.
- `src/state/status_list_head.rs` — `SignedHead`, the append-only guard on what a
  *member* is willing to sign next. `successor` validates one transition: the
  proposal must name the head's digest as its predecessor, sit at exactly
  `head.version + 1`, contain more entries than the signed head, and — the
  check that actually decides it — its prefix up to the stored head length must
  re-fold to the digest this member signed last round. A storage layer that swaps
  the published record therefore cannot walk a member onto a fork.
  Four things about it are easy to get wrong:
  - **It is in-memory, alone in `state/` in being so.** There is no file. A restart
    loses the head, and `from_authenticated` is how it comes back — a constructor
    that *trusts its caller*, computes no quorum and checks no signature. The
    contract "authenticate first" is stated in the doc comment and enforced
    nowhere, so every call site is a place to get it wrong.
  - **The durable backstop is `AtomicSlotCounter`, not this type.** After a restart
    a rewound head cannot actually be exploited, because re-signing an old version
    derives an already-spent slot and `reserve_at` answers `AlreadySpent`. That is
    the property that makes the in-memory head safe; keep the counter durable and
    this stays true.
  - **One or more entries per version.** `list[..head.len]` must equal the
    previous list, so the transition is append-only but not single-entry. A
    provisioning round can batch several credentials into one status-list
    version. `predecessor` is redundant with the prefix recomputation — it can
    only reject, never authorize, and the recomputation is the real check.
  - **A member with no head can only sign v0.** A fresh process that fails to
    recover is not merely behind, it is out: v0's slot is long spent, so it
    abstains forever. Recovery is not optional.
  Its only consumer is `demo/`; nothing in the library or the four benchmark
  binaries calls it. It is also **not** covered by `tools/mutate.py`.
- `src/bench/mem.rs`, `src/bench/stats.rs` — RSS (resident set size) probes and descriptive
  statistics shared by every binary.
- `src/node/snark_prover.rs` — the prover. Holding the value *is* the proof that
  `setup_prover()` ran. `make_proof` derives the slot through `Committee::slot_for`
  and takes a `version`, never a slot; `aggregate` takes an explicit slot and
  exists for the adversarial tests, which have to build what the honest path
  cannot express. `sign_and_prove` refuses a repeated signer **before** signing —
  leanVM dedups the aggregate, so nothing downstream could catch it and the key
  would already be damaged.
- `src/node/snark_verifier.rs` — the SNARK path's predicate, paired with
  `setup_verifier()`. Owns the five checks, `is_newer`, and `select_freshest` (the
  DHT-layer selection: newest declared version first, verify, fall back on
  failure). `select_freshest_above` is the same with a floor — the caller's
  high-water mark — applied before any proof is verified. That is a work saver,
  not a check: the floor can only drop records the caller was already going to
  refuse as stale. There is exactly **one** copy of each predicate and it lives
  here; an earlier second copy had drifted and silently lost the slot check.

- `src/node/snark_node.rs` — the same composition over the aggregated form, and
  the only thing the two paths differ in once a form is chosen. Owns a
  `PQSNARKVerifierModule`, so holding one also means `setup_verifier()` has run;
  `accept_best` delegates selection to `select_freshest_above` with the mark as the
  floor. `tests/snark_node.rs` is the seam test: a genuine proof carrying a lying
  version must not move the gate.
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
  with `xmss_sign` rather than through `SignerNode`.
- `src/bin/prover.rs` — holds the secret keys, writes artifacts, **never verifies**.
- `src/bin/verifier.rs` — calls **only** `setup_verifier()`; loads `anchor.bin`
  and hardcodes nothing else.
- `src/bin/raw_agg.rs` — the no-SNARK baseline. It spends slots through
  `SignerNode`/`AtomicSlotCounter`, so its `t` signatures are produced the way a
  real member produces them, but it does **not** time them: what it measures is
  the relying party's side, verify and size.
- `src/bin/signer.rs` — one committee **member**, in isolation: one key, one
  durable counter, one signature per round. The only binary that reports a `sign`
  figure, because it is the only one whose process shape matches the role. Every
  round self-verifies as a failure gate; RSS is ~2 MB against the aggregator's
  ~2 GB, which is the number that separates the two roles.

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

Tests (`cargo test`, 75 in total: 74 run plus one `#[ignore]`d):
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
- `tests/snark_node.rs` covers the *seam* the other two do not: that `SnarkNode`
  never lets a record which failed the predicate reach the gate. A genuine proof
  relabelled to version 9 is refused and leaves the mark untouched, which is the
  case that matters — a mark an unauthenticated peer can advance locks the node
  out of every honest update below it. Then the honest record is accepted, the
  same bytes replayed are `Stale`, and a selection whose candidates are all at or
  below the mark verifies nothing. One aggregation; one `#[test]`, for the arena
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

### The container demos (`demo/`)

A **separate crate**, with its own `[workspace]` and its own lockfile. That is
the whole rule: the library and the four benchmark binaries are the artifact this
project measures, and the demo adds networking, orchestration and a credential
format, none of which belong in that surface. Nothing in `demo/` may be reachable
from a `benchmark.sh` build, and the parent `Cargo.toml` must stay unaware of it.

Ten containers run one image and differ only by environment. `demo/src/bin/`
holds `bootstrap` (assembles the anchor from ten published public keys, in index
order, then exits), `signer` (a member, and the aggregator for one round when a
holder dials it), `holder` (node A) and `probe` (asks one member to sign
directly, exit `0` signed / `3` abstained, which is what lets the crash scenario
assert instead of grep).

`holder` is **resident**, and `round`/`verify` only send it a trigger (the same
binary with `HOLDER_TRIGGER` set, run as the throwaway `trigger` service).
`setup_verifier()` is a per-process cost, so a node A that exited after every
check would pay 5 s and ~700 MB per record and the demo would be measuring
process startup. Keep it that way: the one-shot shape still exists (neither
`HOLDER_SERVE` nor `HOLDER_TRIGGER`) and is the honest cold-start measurement.
Node A holds a `RawNode` or a `SnarkNode`, so the anti-rollback mark is inside
the node and survives a container restart on its `holder-state` volume.

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
mid-protocol. The unit tests around `AtomicSlotCounter` restart it *cleanly*
(`drop` then `open`, with the lock released and the file fully written), so the
tmp/fsync/rename/fsync-dir chain is argued but not exercised there. Treat the
scenario as coverage, not decoration: if it starts passing for the wrong reason
(a member that never signed in step 1, say), it stops proving anything.

### The security boundary (most important thing to understand)

`verify_single_message_aggregate` attests **only** "these listed public keys
signed this message at this slot". Every link to trust is a cleartext check
outside the circuit, in `PQSNARKVerifierModule::verify` (`src/node/snark_verifier.rs`):

1. every signer ∈ committee — membership against the fixed anchor;
2. `agg.info.core.message == status_list_message(committee.domain(record.alg), list, version)`
   — **the critical binding**; it ties the proof to the list (without it a valid
   proof of a *different* list can be attached), to the `version` (without it the
   cleartext version field is forgeable — see the versioning note below), and,
   through the domain, to *this committee* and *this algorithm*, so evidence
   cannot be carried between deployments;
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
- **Selection is budgeted, not unbounded.** `select_freshest_above` and
  `RawNode::accept_best` verify at most `MAX_VERIFICATIONS_PER_SELECTION` (4)
  candidates. The floor is a work saver and *not* the defence it reads as: it
  drops records at or below the mark, which is precisely what a hostile peer never
  sends. Records claiming versions above the mark pass it untouched, and each one
  costs a full verification — a SNARK on one path, `t` signature checks on the
  other. Candidates are tried newest first, so reaching the cap means the four
  freshest records a lookup returned all failed; an honest lookup succeeds on the
  first. What is bounded is deliberately the *expensive* half: decoding stays
  unbounded because it is cheap and already limited by the input size.

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
slot: a shared column put ~1.2 s and ~32 ms under one heading and made
`summary.csv` unreadable on its own. A target leaves blank the phases it does not
run, and `col()` drops empty cells, so an absent phase produces no row rather than
a `0.000 ms` that reads as "instant".

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

### One target per role

The sweep has three targets that correspond to real processes, plus two contrast
targets. What each one measures is decided by **which role would run that
process**, and no target is charged for another role's work:

| target | role | reports |
|---|---|---|
| `signer` | one committee member | `sign` per round (incl. its durable slot burn), 1 key, 1 counter |
| `prover` | the aggregator | `prove` per update, `setup`, `N` keys |
| `verifier` | a relying party | `verify` per record, `setup` |
| `raw_agg` | the no-SNARK baseline | `verify` per record + record size |

`combined` (`main.rs`) is **not** in the default `TARGETS`. It measures a process
that proves and verifies at once — not a role anyone deploys — and its numbers
duplicate the prover's: same setup, `prove` within 0.5%, peak RSS within 2%. It
stays available as `TARGETS="... combined"` for one purpose: an independent second
reading of prove time, which is how CPU contention in a prover window was caught
once. Do not add it back to the defaults for any other reason.

**Only `signer` reports a `sign` row, and that is deliberate.** In production
nobody produces `t` signatures: each member signs *once* per round on its own
machine and broadcasts, and the aggregator receives `t` and produces none. Timing
a loop that signs `t` times sums the work of `t` machines and bills it to one —
which is what the `sign / update` column used to do, reading ~1 s at `t=128` for a
process that does not exist. `prover`, `combined` and `raw_agg` still *produce*
their `t` signatures, because a record needs them; they just do not time them.

A member's signing cost is identical on both published forms — same key, same
32-byte message, same derived slot — so the `signer` row applies unchanged to the
SNARK and the raw path, and what separates the two paths is only how the quorum is
evidenced and what a relying party pays to check it.

`signer`'s `keygen` and `slot_state` are for **one** key and **one** counter,
where `prover`/`raw_agg` report the whole committee's `N`. Do not read them as the
same quantity.

Nothing in the output is extrapolated to other hardware, and nothing should be
added that is: `target-cpu=native` makes the binaries host-specific, so the only
honest way to get numbers for another machine is to run `benchmark.sh` there. A
projection block existed once and was removed — do not reintroduce it.
