# Post-Quantum Decentralized Root of trust

**Removing the single key at the root of a trust hierarchy, without giving up
offline verification — and without assuming an adversary that cannot run a
quantum computer.**

---

## The problem

Systems that issue credentials — PKI, verifiable credentials, firmware update
channels, device attestation — publish a **status list**: the set of fingerprints
of the credentials that are currently valid. Presence means validity; revocation
is represented by removing a credential's fingerprint from the next version (and
therefore by its absence from that snapshot). That list is the security-critical
object. If an attacker can rewrite it, they can put a revoked credential back; if
they can freeze it, they can keep a compromised credential trusted indefinitely.

Almost universally, that list is authorized by **one signing key**. This
concentrates two separate failures into a single point:

- **Compromise.** Whoever holds the key controls which credentials remain valid
  across the entire system. There is no quorum to overrule them and no partial
  failure mode.
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
  no directory lookup, and no live status service to check an update.

Both the aggregated form and the raw `t`-signature form are implemented.

## What it demonstrates

The repository is built to make six claims falsifiable, each with the artifact
that tests it:

| Claim | Where it is checked |
|---|---|
| A quorum of the committee — and nothing else — can authorize an update | five checks in `PQSNARKVerifierModule::verify`, exercised by the forgery corpus |
| Evidence cannot be lifted from one list, version or slot onto another | `attack-tampered`, `attack-outsider`, `attack-version` must all be rejected |
| Evidence cannot be lifted from one *committee* onto another | the domain seeding the signed message ([Domain separation](#domain-separation-one-anchor-one-list)) |
| A peer cannot choose how much verification work a node does | the selection budget in `accept_best` / `select_freshest_above` |
| A stale but validly signed record cannot be replayed | the persistent anti-rollback gate in [`src/state/freshness.rs`](src/state/freshness.rs) |
| Raw and aggregated costs can be compared without mixing roles | [Benchmark](#benchmark) |

Two properties are treated as safety-critical rather than best-effort, because
their failure modes are silent and unrecoverable:

- **XMSS is stateful.** A `(key, slot)` pair that signs twice leaks enough of the
  WOTS hash chains to forge for that slot. Slot allocation therefore goes through
  a durable, crash-safe counter that burns a slot *before* the key touches it
  ([`src/state/slot_counter.rs`](src/state/slot_counter.rs)).
- **Verification is stateless.** An old record verifies forever, so the
  cryptography alone cannot refuse a rollback. That is a separate, explicitly
  stateful gate.

## What it is not

A research prototype, not a deployment. Committee rotation is not implemented.
The open gaps are listed in [`AGENTS.md`](AGENTS.md) rather than left for the
reader to discover.

---

![The committee signs one status-list root at a slot derived from the anchor; the quorum is then published either as raw signatures with a signer bitmap, or as one aggregated SNARK proof. Both are checked against the same anchor.](docs/architecture.png)

Editable source: [`docs/architecture.svg`](docs/architecture.svg).

---

## Trust model

- Every published list is a **complete snapshot of the currently valid
  credential fingerprints**. A relying party first authenticates the record, then
  recomputes the credential's fingerprint and requires it to be present. Removing
  that fingerprint in a newer version is how the committee revokes the
  credential; an absent fingerprint is not valid under that snapshot.
- The list is published (e.g. in a DHT) together with **evidence of a quorum**
  that replaces the old single signature.
- The fixed **trust anchor** each verifier embeds is the **committee**: its `N`
  public keys, the threshold `t`, and the genesis slot.
- An update is authorized when **at least `t`** distinct committee members sign
  the new list root. *Which* subset signs may change at every update — the
  anchor does not.

The evidence comes in two interchangeable forms, described in
[Two published forms](#two-published-forms). The SNARK form is first required to
contain exactly one XMSS `(slot, message, pubkeys)` group and no SPHINCS claims;
this prevents leanVM v0.10's more general aggregate language from widening the
protocol. Both forms then follow the same five logical checks:

1. every signer ∈ committee (membership);
2. the evidence is bound to **this** committee, **this** list *and this version*
   (`message == status_list_message(domain, list, version)`);
3. the slot is the one the anchor assigns to this version
   (`slot == genesis_slot + version`);
4. quorum reached (`#signers ≥ t`);
5. the signatures — or the one aggregate that stands for them — verify.

Check (2) is the security-critical binding: a signature only attests "this key
signed *this* message"; the verifier must recompute that message from the list
*and version* it holds and compare. See
[Versioning and freshness](#versioning-and-freshness) for why the version is part
of the message and not a field next to it, and
[Domain separation](#domain-separation-one-anchor-one-list) for why the committee
is part of it too.

Check (3) pins policy rather than integrity — the slot is already authenticated
inside every signature, since it feeds the leaf hash, the WOTS tweaks and the
Merkle path directions. What it forbids is a quorum re-signing one version at
slots of its own choosing. See [Slot derivation](#slot-derivation).

---

## Signature scheme

Signing uses **leanVM v0.10's synchronized XMSS over BLAKE2s-256** — the scheme
the pinned VM aggregates. Its API signs a raw 32-byte message; this project hands
it `status_list_message`, a BLAKE2s-256 digest of an explicitly framed domain,
version, entry count and ordered list described under
[Domain separation](#domain-separation-one-anchor-one-list).

It is a *stateful* signature: a given `(key, slot)` must sign **at most once**, so
each update uses a new slot. v0.10 draws fresh signature randomness, which makes
even a retry of the **same** message at the same slot unsafe. The durable counter
therefore refuses every reuse and burns the slot before signing.

Only the XMSS types re-exported by the pinned `leanvm` crate enter the protocol;
the local `crypto` module is the single compatibility boundary around that API.

A key is generated for a **window** — the inclusive range
`SLOT..=SLOT + KEY_SLOTS`. leanVM v0.10 accepts that inclusive pair; this
project's compatibility module keeps the existing `(start, count)` contract and
performs the checked conversion in one place. The window is
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

The cryptographic objects *inside* those containers are SSZ as well.
`XmssSignature` is a fixed 1208 bytes and `XmssPublicKey` a fixed 32. In v0.10
they are byte-oriented: every value of the exact size has one SSZ encoding, so
canonicality comes from fixed lengths rather than field-modulus rejection. The
one exception is the aggregate
proof, which cannot be a typed field — deserializing it needs the process-global
aggregation bytecode — and is therefore still canonicalized by re-encoding and
comparing.

This is a wire-format commitment. The migration reserves algorithm tag `1` for
the BLAKE2s construction and explicitly rejects retired tag `0`. v0.9 records,
keys, signatures and proofs are incompatible and must be regenerated.

| | `StatusList` | `SnarkStatusList` |
|---|---|---|
| evidence | the `t` raw signatures + a signer bitmap | one aggregated SNARK proof |
| naming the signers | bitmap (`N + 1` bits) | public keys inside the aggregate |
| verification | verify each named XMSS signature | verify one aggregate plus the cleartext bindings |
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

The bitmap is an SSZ `BitList`, not a byte array, and that is a security choice.
A byte array pins down how many *bytes* there are but never how many *bits* mean
something, so the bits above member `N-1` are free: one signer set gets several
encodings, and an index past the end of the committee becomes representable — a
verifier that indexed its member list with one would panic. A `BitList` appends a
sentinel bit after the last real bit, so the length in bits is recovered exactly
on decode, excess bits are rejected, and the whole class disappears. It costs one
bit, and it turns two hand-written checks into a single comparison against the
anchor. What no schema can express is a relation between two fields, so
`from_bytes` still rejects a bitmap whose population disagrees with the number of
signatures.

What the bitmap does **not** hide is the participation pattern: anyone holding the
anchor learns who signed, and correlating records over time reveals which members
are always present. That is disclosure of behaviour, not of secrets, and it is
unavoidable — a verifier cannot check a signature without knowing whose key to
check it against. Note this leaks *less* than the SNARK path, whose aggregate
carries the signers' full public keys.

---

## Domain separation: one anchor, one list

A signature attests "this key signed *these bytes*" and nothing more. So whatever
is **not** inside the signed message is not bound by the signature — and until the
message carried a domain, what it carried was `(list, version)` alone.

That made evidence portable in a way nothing in the protocol acknowledged. Any two
deployments whose anchors happened to coincide had interchangeable records: a
record published under one verified, in full, under the other. Membership, quorum,
slot and message binding all pass, because from the verifier's side there is
nothing to distinguish them.

The fix is to prefix the signed statement with a **domain-specific BLAKE2s-256
digest**. The domain is derived once, by the anchor itself
(`Committee::domain`), from a fixed context string and three things:

| bound | why |
|---|---|
| SHA3-256 of the anchor's canonical encoding | every member key, `t` and `genesis_slot`. A different committee — or a rotated one — is a different domain, so evidence never crosses between them |
| the record's `alg` | a record cannot be relabelled to another signature scheme while keeping evidence produced under the first. Latent while one algorithm exists, and cheapest to add before it does |
| a construction generation | bumping it retires every message signed under the old shape |

It is **prefixed, not appended**, and that part is load-bearing: two committees
must not share the application-message prefix an attacker controls. A second
fixed context string separates the status-list message from the domain hash. The
full preimage is:

```text
BLAKE2s-256(
  "decentralized-root-of-trust/status-list-domain" ||
  construction_generation_le_u32 || alg_u8 || anchor_fingerprint[32]
) -> domain[32]

BLAKE2s-256(
  "decentralized-root-of-trust/status-list-message" ||
  domain[32] || version_le_u32 || entry_count_le_u64 || entries[32]...
)
```

The fixed-width integers and explicit count make the encoding unambiguous. It is
streamed without allocation and remains deliberately order-sensitive.

There is no way to compute a message without naming a domain, because
`status_list_message` takes one — so this is enforced by the type, not by a check
somebody has to remember.

**What it does not do.** The domain binds the *committee*, and one anchor has one
domain. So it settles "a status list is governed by exactly one committee", but
**not** "one committee governs exactly one status list": two lists under the same
anchor still produce interchangeable evidence. Closing that needs a list
identifier inside the anchor, which is a further wire change. Until then *one
anchor governs exactly one status list* is an operator invariant, pinned in
`committee.rs`'s `one_anchor_is_one_domain_so_it_governs_one_list`.

> This is both a **signed-message** and algorithm-tag change. The SSZ field layout
> is unchanged, but tag `0` is rejected and the construction generation is now
> `2`. Regenerate `artifacts/`, committee keys and durable signer state.

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
sitting next to the proof: the committee signs `status_list_root(domain, list, version)`,
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
peer that serves you *only* stale records slips past `select_freshest`. For a list
of valid credentials this is the attack that matters: an old snapshot can still
contain a fingerprint that the committee removed in a newer version, re-granting
validity to a credential that has since been revoked.

The fix is memory. `HighWaterMark` (in `freshness.rs`) records the highest version
this verifier has accepted and refuses anything not **strictly newer**. The rule
is strict on purpose: a tolerance window would reopen exactly the rollback it is
meant to close. The mark lives *outside* the verification predicate, which stays pure — crypto
first (`select_freshest`), freshness second (the mark) — and it is persisted, so
it survives a restart. It is keyed to a fingerprint of the anchor, so a committee
rotation legitimately resets the counter instead of rejecting the new generation.
This is local verifier state and must never be published.

Outside the predicate, but not outside a type. `RawNode` and `SnarkNode`
(`src/node/raw_node.rs`, `src/node/snark_node.rs`) hold an anchor and a mark
together and expose one entry point — `accept(bytes) -> Outcome` — which decodes,
verifies, and only then offers the version to the gate. The ordering is not
advice. A mark that advanced on a record which had not been authenticated could
be pushed to `u32::MAX` by any peer that can spell a version number, after which
every genuine update is refused as stale: a denial of service for the price of a
forged integer. Owning both halves is what makes that sequence the only one
expressible, the same way `SignerNode` owns its slot counter instead of trusting
callers to burn a slot first.

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

### Status-list snapshots: what an update means

Everything above is the relying party's side. At the application layer, each
version replaces the previous validity snapshot as a whole. An update may add
any number of fingerprints for newly valid credentials, remove any number of
fingerprints to revoke credentials, or do both in one round. There is no `+1` or
`-1` transition rule. The raw and SNARK verification predicates authenticate the
exact `(list, version)` selected by the quorum; they deliberately do not interpret
why an entry was added or removed.

This also means that the sequence is **not append-only at the entry level**. A
newer valid list may be shorter than its predecessor, and it may be empty after
the last valid credential is revoked. History remains monotonic through the
signed `version` and the verifier's high-water mark, not by retaining every old
fingerprint forever.

The committee authorizes each snapshot by signing it. Credential-lifecycle rules
that decide which additions and removals a member is willing to approve belong to
the application; the protocol does not impose an append-only transition rule.
Independently of that policy, `AtomicSlotCounter` still guarantees that one member
cannot sign two competing snapshots at the same version's XMSS slot.

---

## Dependencies

The leanVM dependencies are **git-pinned** (no vendored clones):

- `leanvm`, `primitives` — from `leanEthereum/leanVM`, pinned to the **v0.10**
  release by its commit `73a5f5d` rather than by the tag name, since a tag can be
  moved. `primitives` supplies the exact BLAKE2s-256 implementation used by the
  VM, avoiding a second hash implementation at the application/VM seam.
- `ethereum_ssz` / `ethereum_ssz_derive` — SSZ encoding compatible with the
  Ethereum consensus specification. leanVM v0.10 uses the same crate for its own
  keys and signatures, which is what lets them appear as typed fields in the
  schemas here instead of opaque byte-lists.
- `rand`, `sha3` — from crates.io. `serde` and `postcard` are no longer direct
  dependencies: every wire format in the library is SSZ, and the one leanVM-native
  blob left is written through leanVM's own `to_bytes` / `from_bytes`.
  (`serde_json` and `serde_jcs` remain in the manifest for the gitignored scratch
  binaries under `src/bin/my_test*.rs`; nothing in the library uses them.)

Upgrading leanVM across a breaking release invalidates persisted state as well as
wire formats. The v0.10 binary-field/BLAKE2s construction is incompatible with
v0.9 keys, signatures and proofs; the status-list message format also moved to
generation `2` and wire algorithm tag `1`. Delete `artifacts/` and any durable
slot state before re-running — a counter is bound to a fingerprint of its key.
There is intentionally no mixed-version acceptance window. The Poseidon2 version
is preserved in the `poseidon2` branch.

`Cargo.lock` is committed. The direct leanVM revision alone does not lock its
transitive tree; the lockfile is part of the reproducible build contract and
`benchmark.sh` warns when it is missing.

`.cargo/config.toml` sets a large `RUST_MIN_STACK` (the prover uses a very deep
stack) and `target-cpu=native`.

For `cargo test`, dependencies are optimized while this crate remains a debug
build. `lean_vm` alone uses release-equivalent overflow arithmetic in the dev
profile because v0.10's shape-only aggregation warm-up otherwise trips a debug
shift check before proving; this crate retains its debug overflow checks.

---

## Build & run

```sh
cargo run --release --bin decentralized-root-of-trust   # the SNARK demo, one process
cargo run --release --bin raw_agg                       # the same protocol, no SNARK
cargo run --release --bin signer                        # one member alone: sign + durable slot burn
cargo run --release --example local_demo -- raw          # small local walkthrough, raw records
cargo run --release --example local_demo -- snark        # same walkthrough, leanVM proof records
```

Example output (shape):

```
setup...
committee N=10 t=7; 10 updates rotating the signers

  update  1/10  signers 0..6 (7)  v0  slot 43  prove=...ms  verify=...ms  RAM=... MB  OK
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
process alive. `benchmark.sh` captures the setup-resident and peak RSS figures
from the actual role binaries.

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
process keeps prover allocation policy out of a verification-only role. The
benchmark treats prover, verifier and signer as separate targets so this boundary
can be measured without initializing components the role would not deploy.

Since the verifier's only input is the anchor plus the published structure, the
artifact directory can simply be copied to the target device:

```sh
scp -r artifacts/ host:~/ && ssh host ./verifier ~/artifacts
```

Each `prover` run generates a **fresh random committee**, so artifacts from
different runs are not interchangeable — start from a clean directory.

---

## Optional network demo

[`demo/`](demo/) is a separate, unmeasured crate that places the protocol in a
ten-member container network. `round` issues a credential and adds its
fingerprint to the valid snapshot; `revoke` removes it and verifies that absence
means revoked. It exists as an integration walkthrough, not as the main artifact
or source of the benchmark results above. Those two commands are deliberately
small examples; the proposal they exercise always carries the complete snapshot
and imposes no one-entry transition limit.

```sh
./demo/docker/demo.sh raw up
./demo/docker/demo.sh raw round
./demo/docker/demo.sh raw revoke
./demo/docker/demo.sh raw down
```

The same commands accept `snark`; topology and operational details live only in
[`demo/README.md`](demo/README.md).

---

## Benchmark

```sh
./benchmark.sh                                    # defaults: RUNS=20, WARMUP=2
RUNS=30 WARMUP=3 ./benchmark.sh
TARGETS="signer prover verifier" RUNS=50 ./benchmark.sh
STRICT_ENV=1 PIN_CPUS=0-7 RUNS=30 ./benchmark.sh  # settings for numbers you publish
```

It measures **one target per role**, each on the process that would actually run
it — `signer` (one committee member), `prover` (the aggregator), `verifier` (a
relying party) — plus `raw_agg`, the no-proof baseline that the SNARK has to beat.
It writes to `bench-<timestamp>/`:

`combined` (`src/main.rs`, the single-process demo) is **not** in the defaults. It
measures a process that proves and verifies at once, which is not a role anyone
deploys. Add it with `TARGETS="... combined"` when an independent second reading
of prove time is what you want — that is what it is good for.

| file | contents |
|---|---|
| `env.txt` | CPU, governor, turbo/SMT, THP, ASLR, toolchain, git commit, pinned leanVM rev, parameters — the reproducibility appendix |
| `samples.csv` | tidy raw data, one row per individual round/update/verification (the `combined` demo, if enabled, reports per-run aggregates only) |
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
  phase alone, not the wall clock of the update loop, which also contains the
  other phases and the printing.
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
- **Only `signer` reports a `sign` row.** In production nobody produces `t`
  signatures: each member signs *once* per round on its own machine and
  broadcasts, and the aggregator receives `t` and produces none. A `sign` figure
  taken from a process that signs `t` times is the summed work of `t` machines
  billed to one, and describes no process that exists — which is what the old
  `sign / update` column did. `prover`, `combined` and
  `raw_agg` still *produce* their `t` signatures, because a record needs them;
  they simply do not time them. The `signer` target signs through `SignerNode`,
  so its figure includes the durable slot burn (write, `fsync`, rename, `fsync`
  dir) that a safe stateful signer cannot skip.
- **The `signer` row applies to both paths unchanged.** A member's signing cost is
  identical whichever form is published — same key, same 32-byte message, same
  slot derived from the anchor — so what separates the raw path from the SNARK
  path is only how the quorum is evidenced and what a relying party pays to check
  it.
- **`signer`'s fixed costs are for one member**: one key, one counter. `prover`
  and `raw_agg` report the whole committee's `N`. Do not read them as the same
  quantity.
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

Everything the script prints is **measured on the host it ran on**, and nothing is
extrapolated to other hardware. `target-cpu=native` already makes the binaries
host-specific, so the way to get numbers for another machine is to run
`benchmark.sh` there.

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
every possible bitmap byte on a five-member committee, and the wire encoding
being independent of the order the signers were collected in.

Two of them are worth calling out because they guard things the binaries cannot
reach:

- `tests/lock_two_processes.rs` re-executes the test binary so the **operating
  system**, not a thread, arbitrates the slot-counter lock. A same-process test
  cannot tell a real `flock` from a process-local mutex, and the failure it guards
  against is ordinary — one state directory, two nodes started from it — while its
  cost is a destroyed key. Removing the lock makes it fail with
  `PROBE=acquired:102`, naming the slot both holders would have issued. Its
  `child_probe` entry is the suite's single `#[ignore]`: it is a subprocess
  fixture, not a skipped security case. The two parent tests launch it explicitly
  with `--ignored --exact`, supply the required protocol arguments and assert its
  output; running it directly under the normal test harness would have no parent
  protocol to execute.
- `src/bench/stats.rs`'s tests are the only guard on the numbers in
  [Benchmark](#benchmark). They pin the median against the mean on skewed samples,
  and the standard deviation as the Bessel-corrected (`n-1`) one that the
  confidence interval is built from.

It also carries the SNARK path's own negative suite (`tests/snark_path.rs`), on a
small committee (`N=5, t=3`) so it can afford real proofs. Each of the five
checks in `PQSNARKVerifierModule::verify` gets a case that breaks **only** that check, and the case
asserts the other four still hold — so a rejection can only have come from the
check under test. Deleting any one of the five makes exactly one assertion fail.

The interesting one is check 5. Checks 1 to 4 read the aggregate's declared XMSS
group (message, slot, public keys); nothing relates that statement to the
computation underneath it. The test changes one bit in the proof body while
requiring the aggregate to remain decodable with identical claims: checks 1-4
pass by construction, and only verifying the SNARK tells the two apart. A second
case proves that v0.10's more general multi-group aggregate is rejected rather
than silently widening this protocol's statement.

`tests/snark_modules.rs` covers the two node wrappers the binaries go through.
The assertion that earns its keep is the first one: the slot recorded *inside* the
finished proof must equal the slot the anchor derives for that version. Nothing in
the call hands `PQSNARKProverModule` a slot, and this is what would notice if it
ever started accepting one — which is the same drift that once removed the slot
check from the verifier wrapper.

Every check named in this section has a mutant in `tools/mutate.py`, which
deletes one and reports which test complains. There are currently 30. One former
padding-bits mutant disappeared when the signer bitmap became an SSZ `BitList`:
excess indices are now unrepresentable, so there is no longer a hand-written
padding check to delete. The last full sweep caught every then-current mutant;
the present patterns have since been updated and verified to still match their
targets, but the full 30-mutant sweep itself has not been re-run. Earlier sweeps
exposed three checks that no test reached (`verify_status_list`'s former padding
check, the bitmap width, and `t == 0`), plus a padding test that located the bitmap
by searching a signature blob for a byte value. The current `BitList` structure
and tests address those findings.

---

## Provenance

This code was written with AI assistance GPT-5.6 Sol/Terra, GPT-5.5 and Fable 5. None of it was taken on
trust: everything here was built, run and tested, the code was reviewed line by
line before it landed, and the author takes responsibility for every commit.
