# decentralized-root-of-trust

**Removing the single key at the root of a trust hierarchy, without giving up
offline verification — and without assuming an adversary that cannot run a
quantum computer.**

---

## The problem

Systems that issue credentials — PKI, verifiable credentials, firmware update
channels, device attestation — publish a **status list**: the set of identifiers
that have been revoked. That list is the security-critical object. If an attacker
can rewrite it, they can un-revoke a stolen key; if they can freeze it, they can
keep a compromised device trusted indefinitely.

Almost universally, that list is authorized by **one signing key**. This
concentrates two separate failures into a single point:

- **Compromise.** Whoever holds the key controls revocation for the entire
  system. There is no quorum to overrule them and no partial failure mode.
- **Cryptographic obsolescence.** The signature is typically ECDSA or Ed25519,
  both broken by a sufficiently large quantum computer. Records that are archived
  and verified years later are exposed to *store-now-decrypt-later* on the
  signature layer.

The obvious fix — have `N` parties sign instead of one — reintroduces a cost that
is usually what stopped people: `t` signatures are `t` times the bytes and `t`
times the verification work, on every published update, forever. For a
constrained verifier (an embedded controller, a light client, an offline device)
that is not a marginal cost.

## What this builds

A status list controlled by a **`t`-of-`N` committee**, where the published
evidence of quorum is **one constant-size object** rather than `t` signatures.

- Members sign with **XMSS** — hash-based, stateful, post-quantum, and *not*
  reliant on any number-theoretic assumption.
- The `t` signatures are aggregated by the [leanVM](https://github.com/leanEthereum/leanVM)
  zkVM into a **single SNARK proof** that attests "a quorum of this committee
  signed this list at this version".
- A verifier holds **one fixed trust anchor** — the committee's `N` public keys,
  the threshold `t`, and a genesis slot — and needs **no live data fetch**,
  no directory lookup, and no revocation service to check an update.

Both the aggregated form and the raw `t`-signature form are implemented and
measured, so the trade-off is a number in this repository rather than an
assertion.

## What it demonstrates

The repository is built to make four claims falsifiable, each with the artifact
that tests it:

| Claim | Where it is checked |
|---|---|
| A quorum of the committee — and nothing else — can authorize an update | five checks in `PQSNARKVerifierModule::verify`, exercised by the forgery corpus |
| Evidence cannot be lifted from one list, version or slot onto another | `attack-tampered`, `attack-outsider`, `attack-version` must all be rejected |
| A stale but validly signed record cannot be replayed | the persistent anti-rollback gate in [`src/freshness.rs`](src/freshness.rs) |
| Aggregation is worth its cost above some `t`, and is not below it | [Benchmark](#benchmark), which measures both forms on the same host |

Two properties are treated as safety-critical rather than best-effort, because
their failure modes are silent and unrecoverable:

- **XMSS is stateful.** A `(key, slot)` pair that signs twice leaks enough of the
  WOTS hash chains to forge for that slot. Slot allocation therefore goes through
  a durable, crash-safe counter that burns a slot *before* the key touches it
  ([`src/atomic_slot_counter.rs`](src/atomic_slot_counter.rs)).
- **Verification is stateless.** An old record verifies forever, so the
  cryptography alone cannot refuse a rollback. That is a separate, explicitly
  stateful gate.

## What it is not

A research prototype measured on one machine, not a deployment. Committee
rotation is not implemented, and every number in [Benchmark](#benchmark) is
host-specific — the binaries are built with `target-cpu=native`. The open gaps
are listed in [`AGENTS.md`](AGENTS.md) rather than left for the reader to discover.

---

![The committee signs one status-list root at a slot derived from the anchor; the quorum is then published either as raw signatures with a signer bitmap, or as one aggregated SNARK proof. Both are checked against the same anchor.](docs/architecture.png)

Editable source: [`docs/architecture.svg`](docs/architecture.svg).

---

## Trust model

- The list is published (e.g. in a DHT) together with **evidence of a quorum**
  that replaces the old single signature.
- The fixed **trust anchor** each verifier embeds is the **committee**: its `N`
  public keys, the threshold `t`, and the genesis slot.
- An update is authorized when **at least `t`** distinct committee members sign
  the new list root. *Which* subset signs may change at every update — the
  anchor does not.

The evidence comes in two interchangeable forms, described in
[Two published forms](#two-published-forms). Both are checked in five steps:

1. every signer ∈ committee (membership);
2. the evidence is bound to **this** list *and this version*
   (`message == status_list_root(list, version)`);
3. the slot is the one the anchor assigns to this version
   (`slot == genesis_slot + version`);
4. quorum reached (`#signers ≥ t`);
5. the signatures — or the one aggregate that stands for them — verify.

Check (2) is the security-critical binding: a signature only attests "this key
signed *this* message"; the verifier must recompute that message from the list
*and version* it holds and compare. See
[Versioning and freshness](#versioning-and-freshness) for why the version is part
of the message and not a field next to it.

Check (3) pins policy rather than integrity — the slot is already authenticated
inside every signature, since it feeds the leaf hash, the WOTS tweaks and the
Merkle path directions. What it forbids is a quorum re-signing one version at
slots of its own choosing. See [Slot derivation](#slot-derivation).

---

## Signature scheme

Signing uses **leanVM's own synchronized XMSS** (Poseidon2, `LOG_LIFETIME = 32`)
— the scheme leanVM can aggregate. Since leanVM v0.9 its public API takes a raw
32-byte message and embeds it into the eight field elements the WOTS encoding
consumes; this project hands it `status_list_message`, the canonical packing of
the Poseidon2 root described under [Two published forms](#two-published-forms).

It is a *stateful* signature: a given `(key, slot)` must sign **at most once**, so
each update uses a new slot. v0.9 narrowed what that protects without removing
the rule. Signing is now derandomized — the randomness is derived from
`(secret seed, slot, attempt, hashed message)` — so re-signing the *same* message
at the same slot returns a bit-identical signature and is harmless. Two
**different** messages at one slot still expose enough of the WOTS hash chains to
forge, and that is the case the durable slot counter exists for. It cannot tell
the two apart without keeping a history of every message it has signed, which is
exactly the state a counter exists to avoid.

> Note: the standalone `leanSig` XMSS (Poseidon1, `LOG_LIFETIME = 18`)
> is a **different, incompatible** parametrization and **cannot** be fed to
> leanVM's aggregator. This project therefore signs with leanVM's XMSS only.

A key is generated for a **window** — an activation slot and a slot count, or
`SLOT..=SLOT + KEY_SLOTS` as this project states it — and the window is
baked into its identity: leaves outside it are pseudorandom fillers
(`gen_random_node`) that feed the Merkle root, so regenerating the same seed with
a wider window yields a *different* public key. A window cannot be extended — an
exhausted key can only be replaced. `remaining_slots()` is what a node watches to
start that replacement in time, since a key with no slots left cannot even sign
its own successor.

---

## Two published forms

Both carry the same payload and the same signed message. They differ only in how
the quorum is evidenced, and a verifier accepts either.

### Wire format and canonicality

Published `StatusList` and `SnarkStatusList` records use **SSZ
(SimpleSerialize)**, with a fixed schema and field order. SSZ gives each decoded
record one valid byte representation: malformed offsets, trailing bytes and
alternative length encodings are rejected. This makes a content-addressed record
stable — equal records have equal bytes and therefore the same object identifier.

The committee anchor is SSZ too, which matters because the freshness gate
fingerprints it to identify its trust domain: a second byte-encoding of the same
committee would read as a rotation and silently reset the anti-rollback mark.

Since leanVM v0.9 the cryptographic objects *inside* those containers are SSZ as
well. `XmssSignature` is a fixed 1208 bytes and `XmssPublicKey` a fixed 32, field
elements written as canonical little-endian `u32` and refused on decode at or
above the modulus. So canonicality is a property of the schema rather than
something this project enforces by decoding and re-encoding, as it had to when
those objects were opaque postcard blobs. The one exception is the aggregate
proof, which cannot be a typed field — deserializing it needs the process-global
aggregation bytecode — and is therefore still canonicalized by re-encoding and
comparing.

This is a wire-format commitment. Records, anchors, keys and proofs produced
before leanVM v0.9 are not compatible and must be regenerated.

| | `StatusList` | `SnarkStatusList` |
|---|---|---|
| evidence | the `t` raw signatures + a signer bitmap | one aggregated SNARK proof |
| naming the signers | `ceil(N/8)` = 25 B bitmap | public keys inside the aggregate |
| prover | none | 750 ms · 2.1 GB |
| verifier setup | none | ~5 s · 651 MB resident |
| verify | `t` × `xmss_verify`, linear in `t` | one check, flat in `t` |
| payload at `t=128` | ≈ 155 KB | ≈ 234 KB |
| entry point | `VerifierNode::verify_status_list` | `PQSNARKVerifierModule::verify` |

A signer is named by its **index into the committee's member list**. The anchor
already fixes and authenticates that order, so the index is a stable identifier
that costs one bit. Against a list of identifiers — public keys, DIDs, names —
the bitmap buys three things:

- **Structural distinctness.** A bit is set or it is not, so a member cannot
  appear twice. With a list you must remember to reject duplicates, and
  forgetting turns `t`-of-`N` into "one member signs `t` times".
- **A canonical encoding.** One signer set has exactly one bitmap, where a list
  of `t` identifiers has `t!` orderings — all valid, all distinct on the wire,
  which breaks deduplication once records are content-addressed in a DHT.
- **No key material on the wire.** Membership stops being a check at all: an
  index *is* a member, so a non-member is unnameable rather than merely rejected.

Two encodings of one signer set would still be possible if the bits past member
`N-1` were free, so `VerifierNode::verify_status_list` requires them clear, and
`from_bytes` rejects a bitmap whose population disagrees with the number of
signatures.

What the bitmap does **not** hide is the participation pattern: anyone holding the
anchor learns who signed, and correlating records over time reveals which members
are always present. That is disclosure of behaviour, not of secrets, and it is
unavoidable — a verifier cannot check a signature without knowing whose key to
check it against. Note this leaks *less* than the SNARK path, whose aggregate
carries the signers' full public keys.

---

## Slot derivation

XMSS is stateful, so each update must consume a fresh slot, and leanVM's
aggregation requires all `t` signatures of one update to sit at **the same** slot.
Letting each member advance a counter of its own cannot satisfy that once
`t < N`: the members who sit out a round do not advance, so by the next round they
disagree about the slot and aggregation becomes impossible — not eventually, but
by round two.

So the slot is **derived, never negotiated**, the way a validator computes its
slot from the clock:

```
slot = committee.genesis_slot() + version
```

`genesis_slot` lives in the anchor, which makes the derivation authenticated
rather than a convention each node must be trusted to follow. `Committee::slot_for`
is the only place it is computed — signer and verifier must agree bit for bit, and
two independent `genesis + version` expressions are two places to drift.

Three consequences:

- **`AtomicSlotCounter::reserve_at`** replaces "give me my next slot" with "give me
  *this* slot". Above the counter it burns every slot up to the requested one in a
  single durable write: a member that missed six rounds skips six slots rather
  than reclaiming them. Skipping is free — the window is `2^32` wide — while reuse
  costs the key.
- **Below the counter it refuses** (`AlreadySpent`), which doubles as the
  anti-double-sign guard: a version this member already signed maps to a spent
  slot and is unreachable, with no extra state to keep. Being refused is normal —
  the member abstains and the quorum proceeds without it. That is what `t < N` is
  for.
- **A failed round consumes a version.** If a round does not reach `t`, the
  members who did sign have already burned that slot, so the retry moves to the
  next version. `version` therefore counts *rounds attempted*, and the published
  sequence has gaps. Nothing downstream breaks: `try_advance` requires strictly
  greater, not consecutive.

It also bounds an attack. To forge a slot-consistent record at an inflated
version, an attacker needs a key covering `genesis + version` — so the reachable
lie stops at the end of the key window, not at `u32::MAX`.

---

## Versioning and freshness

Every published list carries a `version` (a `u32`), a counter the committee raises
at each update. The version is **part of the signed message**, not a loose field
sitting next to the proof: the committee signs `status_list_root(list, version)`,
so one proof attests to the pair `(list, version)` as a whole. Alter the version
after signing and the proof stops matching — the record is rejected. That is the
third security test below.

The version is independent of the XMSS *slot* used to sign. The slot is the
one-time-signature epoch, bounded by the key lifetime; the version is an
application counter. Keeping them separate means the version keeps climbing across
a future committee re-key, when the slot window would reset.

### Does the verifier trust the version, or keep its own?

For a single record, neither — it **checks** it. `PQSNARKVerifierModule::verify` recomputes the
signed message from the version found *in the record* and compares it against what
the committee signed. The value is accepted only because it survived that check,
so once verification passes the version is as trustworthy as the list itself.
There is no separate step and nothing stored: a record is self-describing and
self-authenticating.

Picking *the newest* version is a different job, and it belongs one layer up,
where records are fetched. A Kademlia lookup returns several records from the
closest peers — different versions, some stale, perhaps one from a hostile peer.
`PQSNARKVerifierModule::select_freshest` is that policy:

1. order the candidates by their declared version, newest first;
2. verify them in that order and return the first that passes;
3. if the newest fails, fall back to the next, and so on.

The declared version only decides the *order*; it is trusted only after step 2
verifies the record. A peer that stamps a garbage record with version `4294967295`
to jump the queue therefore costs one failed verification before it is skipped —
it can never be selected. The `verifier` binary runs this over the `N_UPDATES`
updates plus a planted forgery (`attack-version.bin`) and selects the real
newest — at the current defaults, 20 updates and `version 19` — every time.

The forgery's declared version is `KEY_SLOTS` (64), not an arbitrarily large
number, and the reason is worth stating: `slot = genesis + version`, so lying
about the version means signing at the slot that version derives to, and the
attacker needs a key covering it. The end of the key window is therefore the
largest lie available. The forgery is built slot-consistent on purpose, so that
check 3 passes and check 2 — the message binding the version — is the one that
rejects it.

### Anti-rollback across time

Selecting the newest of the records *in hand* is not enough. Verification is
stateless — an old but validly signed `(list, version)` verifies forever — so a
peer that serves you *only* stale records slips past `select_freshest`. For an
authorization list this is the attack that matters: an old status list re-grants
access to a node that has since been revoked.

The fix is memory. `HighWaterMark` (in `freshness.rs`) records the highest version
this verifier has accepted and refuses anything not **strictly newer**. The rule
is strict on purpose: a tolerance window would reopen exactly the rollback it is
meant to close. The mark lives *outside* the verification predicate, which stays pure — crypto
first (`select_freshest`), freshness second (the mark) — and it is persisted, so
it survives a restart. It is keyed to a fingerprint of the anchor, so a committee
rotation legitimately resets the counter instead of rejecting the new generation.
This is local verifier state and must never be published.

The mark also feeds *back into* selection. `select_freshest_above` takes it as a
floor and drops every candidate not strictly above it before verifying anything —
`select_freshest` is that function with no floor. This removes work, not attacks:
a record at or below the mark would verify and then be refused as stale anyway,
so the only difference is whether a SNARK verification was paid for first. It is
worth having because selection is the one place an unauthenticated peer chooses
how much work you do, and because the stale case is the *common* one — a node
polling a list that has not changed hits it every round. Filtering on the declared
version is sound for the same reason ordering by it is: understating your own
version only forfeits a record that was going to be refused, and cannot suppress
what a different peer served.

The `verifier` binary demonstrates both halves: it advances the mark to the newest
update, then replays an old but valid record and shows it refused. Run it twice
and the second run loads the mark from disk, reports how many candidates the floor
removed, and verifies none of them.

### What this does and does not guarantee

- **The version cannot be forged.** A record's version is exactly the one the
  committee signed, or the record does not verify.
- **Within a batch, the newest valid record wins.** `select_freshest` is robust to
  inflated versions and to peers returning junk.
- **A replay of an old version is refused** once a newer one has been accepted, and
  the refusal survives restarts — this is the high-water mark above.
- **A fork at the same version** — two different lists both validly signed at one
  version — cannot be ordered by version alone. Because XMSS forbids reusing a
  `(key, slot)` pair, an honest member never signs two lists at the same version,
  and with `t > N/2` two disjoint quorums cannot both reach threshold. A
  same-version fork therefore requires misbehaving members, not just a network
  attacker.
- **Not covered yet: committee rotation.** When the anchor changes, the mark
  resets, and how a verifier learns the new anchor (an `old signs new` hand-off, a
  chain of committees) is a separate protocol, deferred to its own design.

---

## Layout

```
src/
  status_list.rs        StatusList (raw + bitmap) and SnarkStatusList, versioned Poseidon2 root, wire format
  committee.rs          Committee anchor: members, threshold, genesis_slot, slot_for, wire encoding
  atomic_slot_counter.rs durable monotonic slot allocator: reserve, reserve_at, fsync + cross-process lock
  signer_node.rs        one member: XMSS keypair + its counter; sign (local slot) and sign_at (protocol slot)
  verifier_node.rs      raw-path relying party: verify (one signature) and verify_status_list (the whole record)
  freshness.rs          HighWaterMark: persistent, anchor-scoped anti-rollback gate
  params.rs             demo parameters (SLOT, N_MEMBERS, T, N_UPDATES, KEY_SLOTS, LOG_INV_RATE)
  mem.rs                VmRSS / VmHWM probes
  stats.rs              descriptive statistics for the benchmark records
  main.rs               combined demo: setup, N updates, 3 security tests, BENCH record
  bin/prover.rs         split deployment: signs and aggregates, writes artifacts, never verifies
  bin/verifier.rs       split deployment: verify-only, calls setup_verifier() alone
  bin/raw_agg.rs        the same protocol without a SNARK, through SignerNode / VerifierNode
  snark_prover_node.rs  the prover: make_proof (slot derived from the anchor), aggregate, sign_and_prove
  snark_verifier_node.rs the SNARK relying party: the five checks, is_newer, select_freshest(_above)
tests/
  raw_path_round.rs     end-to-end: rotating quorums over durable counters, then the rollback refusal
  snark_path.rs         the five checks of PQSNARKVerifierModule::verify, each broken in isolation
  snark_modules.rs      the two SNARK node types as the binaries use them (slot derived from the anchor)
  lock_two_processes.rs the cross-process slot lock, checked by re-executing the test binary
  hostile_bytes.rs      the decoders against attacker-written bytes: no panic, no bomb, no forgery
examples/
  footprint.rs          RAM cost of setup_prover vs setup_verifier
docs/
  architecture.svg / .png    the diagram at the top of this file
benchmark.sh            reproducible multi-run benchmark (env capture, tidy CSV, CI95)
```

The demo constants live in `src/params.rs`. The `verifier` binary deliberately
uses none of them: everything it needs comes from the committee anchor it loads.

---

## Dependencies

The leanVM dependencies are **git-pinned** (no vendored clones):

- `lean-multisig`, `backend` — from `leanEthereum/leanVM`, pinned to the **v0.9**
  release by its commit `a5909d1` rather than by the tag name, since a tag can be
  moved. leanVM ships its own field/hash backend and **does not depend on
  Plonky3**, so the whole tree resolves reproducibly.
- `ethereum_ssz` / `ethereum_ssz_derive` — SSZ encoding compatible with the
  Ethereum consensus specification. leanVM v0.9 uses the same crate for its own
  keys and signatures, which is what lets them appear as typed fields in the
  schemas here instead of opaque byte-lists.
- `rand`, `sha3` — from crates.io. `serde` and `postcard` are no longer direct
  dependencies: every wire format in the library is SSZ, and the one leanVM-native
  blob left is written through leanVM's own `to_bytes` / `from_bytes`.
  (`serde_json` and `serde_jcs` remain in the manifest for the gitignored scratch
  binaries under `src/bin/my_test*.rs`; nothing in the library uses them.)

Upgrading leanVM across a breaking release invalidates persisted state as well as
wire formats: v0.9 changed the XMSS leaf hash, so keys, signatures and proofs from
v0.8 no longer verify. Delete `artifacts/` and any durable slot state before
re-running — a counter is bound to a fingerprint of its key.

`Cargo.lock` is committed. The direct leanVM revision alone does not lock its
transitive tree; the lockfile is part of the reproducible build contract and
`benchmark.sh` warns when it is missing.

`.cargo/config.toml` sets a large `RUST_MIN_STACK` (the prover uses a very deep
stack) and `target-cpu=native`.

---

## Build & run

```sh
cargo run --release --bin decentralized-root-of-trust   # the SNARK demo, one process
cargo run --release --bin raw_agg                       # the same protocol, no SNARK
```

Example output (shape):

```
setup...
committee N=10 t=7; 10 updates rotating the signers

  update  1/10  signers ABCDEFG  slot 43  prove=...ms  verify=...ms  RAM=... MB  OK
  ...
--- Security (expected: all REJECTED) ---
A) tampered list + valid proof : rejected = true
B) proof from outside signers  : rejected = true
C) valid proof, spoofed version: rejected = true
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
  attack-version.bin   a valid proof re-labelled with an inflated version.
```

The name prefixes are the contract: `update-*` must be accepted, `attack-*` must
be rejected. The verifier checks both and exits non-zero if either expectation is
violated, so it drops into a script or CI. It also writes
`verifier-highwater.state` here (its anti-rollback memory); that file is *local
verifier state*, not part of the published set, and must not be copied to other
nodes.

```sh
cargo run --release --bin prover && cargo run --release --bin verifier
```

**Why bother:** a verify-only process calls `setup_verifier()` and nothing else.
It skips the arena and the DFT twiddles, and — more importantly — it never runs
`zk_alloc::enable_arena()`, which sets `M_TRIM_THRESHOLD = -1` so that a *prover*
process never returns freed memory to the OS. The measured effect on RSS
(*resident set size* — the physical pages a process actually holds, and the
quantity behind every memory row in this document):

At the **small** committee (`N=10, t=7`), median of 30 runs:

| | prover | verifier | combined demo |
|---|---|---|---|
| resident after setup | 786 MB | **676 MB** | 754 MB |
| peak RSS | 1082 MB | **694 MB** | 1049 MB |

**36% less peak RAM** for a node that only verifies. The saving grows with the
committee, because only the prover's side scales: at the current defaults
(`N=200, t=128`, see [Reference numbers](#reference-numbers)) the same three
figures are 2053 / 692 / 2014 MB — a **66%** reduction. The verifier's peak is
essentially constant in `t`; the prover's is not.

The more useful property is the *slope*: the verifier's RSS is flat in the number
of verifications (676 → 678 MB over 10), while the prover's climbs monotonically
and never comes back down.

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
STRICT_ENV=1 PIN_CPUS=0-7 RUNS=30 ./benchmark.sh  # settings for numbers you publish
PROJECT_CM4=1 ./benchmark.sh                      # adds an explicitly-labelled ESTIMATE
```

It measures four targets independently — `prover`, `verifier`, `combined` (the
single-process demo) and `raw_agg` (the no-proof baseline: `t` individual
`xmss_sign`/`xmss_verify` calls, which is what the SNARK has to beat) — and
writes to `bench-<timestamp>/`:

| file | contents |
|---|---|
| `env.txt` | CPU, governor, turbo/SMT, THP, ASLR, toolchain, git commit, pinned leanVM rev, parameters — the reproducibility appendix |
| `samples.csv` | tidy raw data, one row per individual update/verification, for `prover`, `verifier` and `raw_agg` (the `combined` demo reports per-run aggregates only) |
| `runs.csv` | one row per process run |
| `summary.csv` / `.txt` | aggregates: n, min, q1, median, q3, max, mean, sd, CV%, CI95 |

Design points that matter if you quote these numbers:

- Targets run **round-robin**, not in contiguous blocks. In block order any
  drift over the sweep — a thermal ramp, a stray background job — is perfectly
  confounded with target identity: the target that happened to run during the
  disturbance simply looks slower. Interleaving spreads the disturbance across
  all targets, so it inflates variance instead of biasing one mean.
- `runs.csv` records **`t_start`** (epoch seconds) per run, so that assumption
  can be checked rather than trusted. Plot the metric against it before
  reporting; drift shows up there and nowhere else.
- The verifier is measured against a **fixed artifact corpus**, generated once.
  Regenerating it per run would fold the prover's variance into the verifier's.
- The unit of analysis for per-update metrics is the **per-run median**
  (n = RUNS). Updates inside one process share allocator and cache state and are
  not independent; `samples.csv` keeps every raw observation if you prefer to
  report the pooled distribution.
- Phases are recorded under **their own names** — `sign_*`, `prove_*`,
  `verify_*` — and a target leaves blank the ones it does not run, so no column
  ever holds two different quantities. Each `<phase>_total_ms` is the sum of that
  phase alone, not the wall clock of the update loop, which for `combined` also
  contains the other two phases and the printing.
- **Fixed costs are three separate rows**, because they are three different
  things: `setup` is the leanVM circuit (the SNARK path's *extra* cost — the raw
  path has no setup row at all), `keygen` is the *N*-key generation that every
  path pays, and `slot_state` is the *N* durable slot counters that only a real
  signer pays. Reading one against another compares unlike costs and inverts the
  answer.
- **`sd` / `cv%` / `ci95` are between-run figures.** They say how reproducible
  the sweep is, not how much one call varies — a single prove or sign varies far
  more, and `samples.csv` is where to look for that. Do not quote
  `median ± ci95` as the cost of one operation.
- **A `/ update` row is a median and a `total / run` row is a sum**, so the two
  do not satisfy `total = n × per-update` unless the phase is symmetric.
  Verification is near-deterministic and does match; signing has stragglers
  several times the median and its total sits visibly above `n × median`.
- The `sign` rows of `raw_agg` and of `prover`/`combined` are **not
  like-for-like**: `raw_agg` signs through `SignerNode`, so every signature is
  preceded by a durable slot burn (write, `fsync`, rename, `fsync` dir), while
  the SNARK binaries call `xmss_sign` directly and pay none of it. The gap is
  disk, not cryptography.
- **`n_items`** records how many updates or verifications each run actually
  measured. A run that measured zero would otherwise report `0.000 ms` medians,
  which is indistinguishable from a very fast result; the script aborts on a zero
  count and on any change in the count across runs of one target.
- Quantiles use linear interpolation (type 7); CI95 uses Student's *t* with
  df = n−1. It is a **precision** interval for repeated runs on one host in one
  session — not an interval that generalizes to other hardware or other days.
- Peak RSS is cross-checked against `/usr/bin/time -v`, independently of the
  process's own `/proc/self/status` reading.
- leanVM sizes its worker pool from `available_parallelism()` at startup and
  offers no override, so **every timing is an *n*-thread figure**. `env.txt`
  records the affinity mask and thread count; `PIN_CPUS` fixes them.
- The script **refuses to print any timing** if a run reports a violated security
  expectation. `STRICT_ENV=1` additionally refuses to run at all unless the
  governor is `performance`, GNU `time` is present and `Cargo.lock` exists —
  otherwise those are warnings.

The CM4 projection is opt-in and is a **linear extrapolation, not a
measurement**. For real numbers, run `benchmark.sh` natively on the board (an
aarch64/NEON path exists).

### Reference numbers

Host **AMD Ryzen 7 4800H** (8c/16t), CPU governor `performance`, medians across
n=30 runs.

> **The timings below predate the leanVM v0.9 upgrade** and need `./benchmark.sh`
> re-run on a quiesced host before they can be quoted again. Sizes are current:
> they are deterministic, and the raw record shrank from ≈189 KB to ≈155 KB when
> `XmssSignature` became a fixed 1208-byte SSZ object. The proof is unchanged.

**Current defaults — `N=200, t=128`, 20 updates:**

Each *update* is one publication of a new status-list version. Three distinct
phases are timed separately, and "/ update" always means **per published update**,
never per signature:

| phase | what it does |
|---|---|
| `sign` | the `t` quorum members each produce one XMSS signature |
| `prove` | those `t` signatures are aggregated into one SNARK (SNARK path only) |
| `verify` | a relying party checks the evidence for **one** update: decode, committee membership of the `t` signers, message/version binding, quorum ≥ `t`, then the aggregate itself |

| metric | prover | verifier | combined | raw XMSS (no proof) ‡ |
|---|---|---|---|---|
| setup (once/process) | ~5.21 s | ~5.11 s | ~5.09 s | none |
| sign / update (`t` sigs) | 917 ms | — | 917 ms | 950 ms |
| **prove / update** | ~718 ms&nbsp;† | — | **718 ms** | — |
| **verify / update** | — | **31.3 ms** | 31.3 ms | 54.3 ms |
| bytes / update | 234 208 B | — | 233 846 B | 155 018 B |
| resident after setup | 792 MB | **676 MB** | 755 MB | 3 MB |
| peak RSS (VmHWM) | 2053 MB | **692 MB** | 2014 MB | **3 MB** |

The `sign` row is the one that is easy to misread: **both paths pay it**. The
SNARK aggregates genuine XMSS signatures, it does not replace them. So the
marginal cost of proving is +76% on top of a production cost both schemes share
(950 ms → ~1 670 ms), not "718 ms against zero".

Committee keygen (200 keys × 65 slots) is a further ~3.65 s, paid once. It is
**not** part of the `setup` row: `setup` is the leanVM circuit and nothing else,
while keygen is paid by every path including the raw one, which is why
`benchmark.sh` gives it a row of its own on every target. The raw path
additionally pays a `slot state` row (~0.6 s): `N` durable `AtomicSlotCounter`s,
one `fsync`'d file each.

Raw XMSS needs **no circuit setup at all** — it is pure Poseidon2, with no WHIR
bytecode to materialise. That absence is itself a result, and it shows up as an
empty `setup` row.

† The `prover` target's own reading was contaminated by external CPU contention
in that sweep, so the figure comes from the independent `combined` target
(718.12 ms, CV 3.6%), which agrees with the clean prover window to 0.1%. Flat
`setup_ms` across a sweep with a moving prove time is how contention is told
apart from a regression: the single-threaded setup is unaffected, the
multi-threaded prove is not.

prove/update is strongly governor-sensitive: on `schedutil` the same measurement
inflates by ~60% because the CPU underclocks the sustained prover — always pin
`performance` before quoting prove time. Memory does not depend on the governor.

‡ `raw_agg` signs through `SignerNode`, so each signature is preceded by a
durable slot burn that `prover.rs` never pays. Compare *verify* and *size* across
the two paths freely; compare *sign* knowing only one side pays for durability.

**Small committee — `N=10, t=7`:**

| metric | prover | verifier | combined |
|---|---|---|---|
| setup (once/process) | ~5.05 s | ~4.96 s | ~5.05 s |
| **prove / update** | **~170 ms** | — | ~167 ms |
| verify / update | — | **~28 ms** | ~30 ms |
| proof size | ~170 KB | — | ~170 KB |
| resident after setup | 786 MB | **676 MB** | 754 MB |
| peak RSS (VmHWM) | 1082 MB | **694 MB** | 1049 MB |

### Where the SNARK starts paying off

The `raw_agg` baseline costs **0.424 ms and exactly 1 208 B per signature**, both
strictly linear in `t` — the byte figure is `SIGNATURE_SSZ_LEN`, a constant of the
scheme rather than a measurement. The SNARK's verify cost and proof size grow
roughly *logarithmically*, and its verifier memory does not grow at all. Across
the two operating points:

| | t=70 | t=128 | Δ for +83% signers |
|---|---|---|---|
| verify, SNARK | 29.91 ms | 31.33 ms | **+4.7%** |
| proof size | 222 238 B | 234 208 B | **+5.4%** |
| peak RSS, verifier | 691.5 MB | 692.0 MB | **+0.07%** |
| verify, raw | 28.31 ms | 54.29 ms | +92% |
| aggregate size, raw | 84 954 B | 155 018 B | +83% |

That +0.07% is the property the whole construction exists for: **verification cost
is independent of committee size**, because the verifier touches only the anchor
root and never the members' public keys. The break-even points follow:

- **Verify time: `t ≈ 74`** — crossed. At `t=128` the SNARK verifies **1.73×
  faster** than checking the signatures individually.
- **Proof size: `t ≈ 207`** — not crossed, and it moved *up* with leanVM v0.9:
  fixed-width SSZ signatures made the raw bundle 18% smaller, so the SNARK has
  further to go. At `t=128` the proof is 1.51× *larger* than the raw bundle. Both
  figures are projections off two operating points; the raw side of them is exact
  arithmetic, the proof side is not.
- **Verifier RAM: never.** 692 MB against 3 MB is a fixed floor the SNARK never
  recovers, at any `t`. Irrelevant on a server, disqualifying on a small board.

Counting production cost too, the SNARK wins on *total system* CPU once the
number of relying parties `V` exceeds ~30:

```
raw   :  950 + 54.6·V
SNARK : 1635 + 31.9·V      →  break-even at V ≈ 30
```

The `t` signatures are common to both sides and largely cancel; what remains is
that proving is a fixed cost paid **once** by whoever publishes an update, while
verification is the cost that **multiplies** across every relying party. In a
decentralised root of trust those number in the thousands, so the break-even is
not close.

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
number of updates. How they grow depends on the regime.

*At small `t`* the growth is a **step function**: the trace is padded to a power
of two, so `t = 5..=8` all cost the same. Measured, `t=7` vs `t=8` vs `t=4`:

| t | prove / update | peak RSS | proof |
|---|---|---|---|
| 4 | 206 ms | 956 MB | 146 878 B |
| 7 | 298 ms | 1055 MB | 169 624 B |
| 8 | 298 ms | 1074 MB | 169 690 B |

(These prove-times are from an earlier `schedutil` run — read the *pattern*, not
the absolutes; on `performance`, `t=7` is ~170 ms as above. Peak RSS and proof
size do not depend on the governor.)

So `t=7` pays for a quorum of 8 without using it: raising the threshold to 8
costs nothing in prove time, proof size or RAM (only signing, which is outside
the circuit, grows linearly in `t`). Dropping to `t=4` cuts prove time by 31% but
peak RSS by only 9%, because the ~678 MB floor dominates.

*At large `t`* the padding is no longer what dominates, and prove time becomes
essentially **linear**: 406.5 ms at `t=70` against 718.1 ms at `t=128`. Through
those two points the marginal cost is **~5.4 ms per aggregated signature**
((718.1 − 406.5) / 58) over a `t`-independent floor of ~31 ms. The ratios
`prove/t` — 5.81 ms at `t=70`, 5.61 ms at `t=128` — are *averages*, not slopes:
they still carry that floor, which is why they drift downward as `t` grows and
why neither is the number to use when projecting a different `t`. Two points is
also the minimum that makes a slope meaningful at all; a per-signature figure
quoted from a single `t` is just that measurement divided by `t`. Peak RSS grows
sub-linearly over the same interval (1451 → 2053 MB, +41% for +83% in `t`)
because the ~678 MB bytecode floor does not move.

**Do not extrapolate the step behaviour past a few dozen signers** — it is an
artifact of a small trace, not a property of the scheme. Setup cost,
resident-after-setup and the *verifier's* RSS remain independent of `t` in both
regimes.

**Raspberry Pi CM4 (BCM2711, 2 GB)** — linear projection x8..x15 (estimate, from
the `performance` host figures). RAM does **not** scale with CPU, and it is the
gate, so the verdict depends on `t`:

| | `N=10, t=7` | `N=200, t=128` |
|---|---|---|
| setup (one-time at boot) | ~40–76 s | ~41–78 s |
| prove / update | ~1.4–2.6 s | ~5.7–10.8 s |
| verify / update | ~0.22–0.42 s | ~0.25–0.47 s |
| peak RSS, **prover** | ~1.08 GB — fits 2 GB | **2.05 GB — does not fit** |
| peak RSS, **verifier** | 0.69 GB — fits | 0.69 GB — fits |

At the small-committee point a 2 GB board can run either role (~1 GB left for the
OS) and a **1 GB board is excluded outright**. At the current `t=128` defaults the
**proving role no longer fits any CM4**, while the verify-only role still fits
comfortably and is unchanged — which is the deployment split this repository is
built around: prove on a server, verify on the board.

---

## Security tests

Three attacks that **must be rejected**:

- **A — tampered list + valid proof of another list:** rejected by the list
  binding in check 2.
- **B — proof from signers outside the committee:** rejected by the membership
  check (check 1).
- **C — a valid proof re-labelled with a different version:** rejected by the
  version binding in check 2. Before the version was signed, this was accepted —
  it is the regression test for [versioning](#versioning-and-freshness).

  The forgery is deliberately built **slot-consistent**: signed at the slot its
  inflated version derives to, so check 3 passes and check 2 is what fires. A
  sloppier forgery would be caught one step earlier and the artifact would
  silently stop testing the binding it exists for.

In the combined demo all three print `rejected = true` and the run reports
`security OK: true`. In the split deployment the same attacks are written by
`prover` as `attack-*.bin` and rejected by `verifier`, which exits non-zero if any
is accepted — so the negative tests are checked by a process that knows nothing
but the anchor. Attack C doubles as the decoy for freshness selection: `verifier`
adds it to the candidate set with an inflated version, and `select_freshest` skips
it and returns the real newest.

A **rollback** — replaying an old but validly signed version — is refused by the
high-water mark, not by the predicate: `verifier` accepts the newest update, then
replays an old one and shows it refused
(see [Versioning and freshness](#versioning-and-freshness)).

The raw path runs its own four in `raw_agg`, each built from a *genuine* quorum so
that only the binding under test can fail: tampered list, re-labelled version,
**sub-threshold quorum** (`t-1` valid signatures), and an outsider occupying a
member's seat. The binary exits non-zero if any is accepted.

`cargo test` adds the cases that are awkward to stage in a binary: a member
supplying the whole quorum by itself, signatures re-attributed to other indices,
padding bits set past member `N-1`, and the wire encoding being independent of the
order the signers were collected in.

Two of them are worth calling out because they guard things the binaries cannot
reach:

- `tests/lock_two_processes.rs` re-executes the test binary so the **operating
  system**, not a thread, arbitrates the slot-counter lock. A same-process test
  cannot tell a real `flock` from a process-local mutex, and the failure it guards
  against is ordinary — one state directory, two nodes started from it — while its
  cost is a destroyed key. Removing the lock makes it fail with
  `PROBE=acquired:102`, naming the slot both holders would have issued.
- `src/stats.rs`'s tests are the only guard on the numbers in
  [Benchmark](#benchmark). They pin the median against the mean on skewed samples,
  and the standard deviation as the Bessel-corrected (`n-1`) one that the
  confidence interval is built from.

It also carries the SNARK path's own negative suite (`tests/snark_path.rs`), on a
small committee (`N=5, t=3`, ~10 s) so it can afford real proofs. Each of the five
checks in `PQSNARKVerifierModule::verify` gets a case that breaks **only** that check, and the case
asserts the other four still hold — so a rejection can only have come from the
check under test. Deleting any one of the five makes exactly one assertion fail.

The interesting one is check 5. Checks 1 to 4 all read the aggregate's `info`
(message, slot, public keys); nothing relates that header to the computation
underneath it. The test splices an honest record's `info` onto another
aggregate's proof body: checks 1-4 pass by construction, and only verifying the
SNARK tells the two apart.

`tests/snark_modules.rs` covers the two node wrappers the binaries go through.
The assertion that earns its keep is the first one: the slot recorded *inside* the
finished proof must equal the slot the anchor derives for that version. Nothing in
the call hands `PQSNARKProverModule` a slot, and this is what would notice if it
ever started accepting one — which is the same drift that once removed the slot
check from the verifier wrapper.

Every check named in this section has a mutant in `tools/mutate.py`, which
deletes one and reports which test complains. 25 of them. The last full sweep
caught all 25; the patterns were updated for leanVM v0.9 and verified to still
match their targets, but the sweep itself has not been re-run since. Its findings
so far: three checks that no test reached at all (`verify_status_list`'s padding
bits, the bitmap width, and `t == 0`), plus a padding test that had been locating
the bitmap by searching a signature blob for a byte value.
