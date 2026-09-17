# Post-Quantum Decentralized Root of Trust

This project replaces a single signing key at the root of a credential-status
system with a post-quantum `t`-of-`N` committee.

The committee publishes complete snapshots of the credential fingerprints that
are currently valid. Presence means validity; removing a fingerprint in a newer
snapshot revokes the corresponding credential.

Committee members sign each snapshot with leanVM's synchronized XMSS over
BLAKE2s-256. The quorum can be published in either of two forms:

- `StatusList`: the raw XMSS signatures and a bitmap identifying their signers;
- `SnarkStatusList`: one leanVM aggregate proof over the same signatures.

A verifier needs only a fixed committee anchor. It does not need a live
certificate authority or status service.

> This is a research prototype. Committee rotation is not implemented.

## Architecture

![The committee signs a status-list message at a slot derived from the anchor; the quorum is published either as raw signatures or as one leanVM aggregate proof.](docs/architecture.png)

The editable diagram is available at
[`docs/architecture.svg`](docs/architecture.svg).

The protocol flow is:

```text
Committee anchor
    |
    +-- derive deployment domain
    |
Status-list entries + version + domain
    |
    +-- BLAKE2s-256 framed message
    |
    +-- slot = genesis_slot + version
    |
    +-- t XMSS signatures
            |
            +-- StatusList      (bitmap + raw signatures)
            |
            +-- SnarkStatusList (leanVM aggregate proof)
```

## Trust anchor

The `Committee` anchor contains:

- the ordered list of `N` XMSS public keys;
- the threshold `t`, with `1 <= t <= N`;
- the genesis XMSS slot.

The anchor is fixed for the lifetime of the committee and is embedded by each
verifier. The member order is significant because raw records identify signers
by their index in this list.

An update is authorized only when at least `t` distinct members sign the same
message at the slot assigned to its version.

## Signed message

The signed message is a 32-byte BLAKE2s-256 digest. It binds:

- the committee anchor;
- the algorithm identifier;
- the message-format generation;
- the status-list version;
- the number of entries;
- every entry in order.

The deployment domain is:

```text
BLAKE2s-256(
    "decentralized-root-of-trust/status-list-domain" ||
    format_generation_le_u32 ||
    algorithm_tag_u8 ||
    anchor_fingerprint[32]
)
```

`anchor_fingerprint` is SHA3-256 of the anchor's canonical SSZ encoding. SHA3 is
used here as an application-level object fingerprint; XMSS signing and the
status-list message use BLAKE2s-256.

The status-list message is:

```text
BLAKE2s-256(
    "decentralized-root-of-trust/status-list-message" ||
    domain[32] ||
    version_le_u32 ||
    entry_count_le_u64 ||
    entries[32]...
)
```

All integers have a fixed-width little-endian encoding. The explicit entry count
and fixed-size entries make the framing unambiguous. Entry order is significant.

The current construction uses message-format generation `2` and algorithm tag
`1`.

## XMSS slot discipline

XMSS is stateful. A member must never sign twice with the same key and slot,
including retries of the same message.

The protocol assigns one common slot to each version:

```text
slot = genesis_slot + version
```

`Committee::slot_for` is the authoritative implementation of this derivation.

`AtomicSlotCounter` holds an exclusive cross-process lock for the signer state.
Each slot reservation is persisted before signing:

1. write the advanced counter to a temporary file;
2. `fsync` the temporary file;
3. rename it over the state file;
4. `fsync` the parent directory;
5. produce the XMSS signature.

A crash may therefore discard a signature, but cannot make a spent slot
available again. Members that miss a round skip the corresponding slot when
they next participate.

## Published records

Both record types carry:

- the algorithm tag;
- the complete status-list snapshot;
- the version;
- evidence of a quorum.

| Property | `StatusList` | `SnarkStatusList` |
|---|---|---|
| Evidence | raw XMSS signatures | leanVM aggregate proof |
| Signer identity | SSZ bitmap | public keys declared by the aggregate |
| Cryptographic verification | one XMSS verification per signer | one aggregate-proof verification |
| Verification entry point | `VerifierNode::verify_status_list` | `PQSNARKVerifierModule::verify` |

### Raw record

`StatusList` uses an SSZ `BitList` whose logical length must equal the committee
size. Each set bit selects one public key from the anchor, and the signature list
must contain exactly one signature for each set bit.

The representation provides:

- canonical signer ordering;
- structural signer distinctness;
- no public-key duplication in the record;
- an exact committee-width boundary.

### Aggregated record

`SnarkStatusList` carries a leanVM aggregate. leanVM supports a broader
statement language, but this protocol accepts only:

- exactly one XMSS group;
- exactly one slot and message for that group;
- no claims from other signature families.

The aggregate currently includes the signers' public keys. The verifier checks
each key against the committee anchor before accepting the proof.

## Verification

The SNARK verifier applies these checks in order:

1. the aggregate contains exactly one XMSS group and no other signature family;
2. every declared signer belongs to the committee;
3. the aggregate message equals the message recomputed from the record;
4. the aggregate slot equals `committee.slot_for(version)`;
5. the signer count reaches the threshold;
6. the leanVM aggregate proof verifies.

The raw verifier enforces the equivalent policy:

1. the signer bitmap has exactly the committee width;
2. its population equals the signature count;
3. the signature count reaches the threshold;
4. the version maps to a valid slot;
5. every named committee key verifies its signature over the recomputed message.

Verification authenticates a record but does not establish freshness.

## Freshness and selection

`HighWaterMark` stores the highest accepted version for one anchor fingerprint.
A verified record is accepted only when its version is strictly greater than the
stored mark.

The mark is updated only after successful cryptographic verification. A hostile
record cannot advance it by declaring a large version.

`RawNode::accept_best` and `SnarkNode::accept_best`:

1. discard candidates at or below the current mark;
2. order the remaining candidates by declared version;
3. verify them from newest to oldest;
4. accept the first valid record;
5. verify at most `MAX_VERIFICATIONS_PER_SELECTION` candidates.

The verification budget is currently four candidates per selection.

## Wire format

The committee anchor, `StatusList`, `SnarkStatusList`, XMSS public keys and
XMSS signatures use SSZ.

- `XmssPublicKey` is 32 bytes.
- `XmssSignature` is 1208 bytes.
- malformed SSZ offsets, lengths and trailing bytes are rejected;
- raw records require bitmap population and signature count to agree;
- leanVM aggregate bytes are accepted only when decode followed by re-encode is
  byte-for-byte identical.

Records from incompatible protocol generations are rejected rather than
silently upgraded.

## Build

The repository pins Rust 1.90.0, with `rustfmt` and `clippy`, in
[`rust-toolchain.toml`](rust-toolchain.toml). Rustup selects and installs that
toolchain automatically.

```sh
cargo build --release
```

Use `--release` for commands that initialize the prover. The initial build
compiles the leanVM dependency tree and may take several minutes.

`.cargo/config.toml` configures:

- `RUST_MIN_STACK=512MiB`, required by the prover's deep recursion;
- `target-cpu=native`, which makes release binaries host-specific.

## Run

Combined SNARK demonstration:

```sh
cargo run --release --bin decentralized-root-of-trust
```

Raw quorum path:

```sh
cargo run --release --bin raw_agg
```

Single committee member:

```sh
cargo run --release --bin signer
```

Small local walkthrough:

```sh
cargo run --release --example local_demo -- raw
cargo run --release --example local_demo -- snark
```

## Split deployment

The prover and verifier can run as separate processes:

```sh
cargo run --release --bin prover -- ./artifacts
cargo run --release --bin verifier -- ./artifacts
```

The prover writes:

```text
artifacts/
  anchor.bin
  update-NN.bin
  attack-tampered.bin
  attack-outsider.bin
  attack-version.bin
```

`update-*` records must be accepted. `attack-*` records must be rejected. The
verifier exits with a non-zero status when either expectation is violated.

`verifier-highwater.state` is local verifier state and must not be published or
shared between nodes.

Each prover run creates a fresh committee, so artifacts from different runs are
not interchangeable.

## Container demo

The independent crate under [`demo/`](demo/) runs a ten-member container
network.

```sh
./demo/docker/demo.sh raw up
./demo/docker/demo.sh raw round
./demo/docker/demo.sh raw revoke
./demo/docker/demo.sh raw verify
./demo/docker/demo.sh raw crash
./demo/docker/demo.sh raw down
```

Replace `raw` with `snark` to publish aggregated records. See
[`demo/README.md`](demo/README.md) for the topology and scenario details.

## Tests

Run the complete test suite with:

```sh
cargo test
```

The suite covers:

- XMSS slot allocation, persistence and exhaustion;
- cross-process state-file locking;
- raw quorum construction and verification;
- status-list message framing and domain separation;
- SSZ decoding under hostile byte mutations;
- freshness and rollback protection;
- all verifier checks using real leanVM proofs;
- rejection of multi-group and non-XMSS aggregate statements;
- node-level proof-to-freshness integration.

`tests/lock_two_processes.rs::child_probe` is intentionally marked
`#[ignore]`. It is a subprocess fixture, not skipped coverage. The two parent
tests re-execute that exact test with `--ignored --exact`, provide the required
arguments and assert its output. Running it as an ordinary standalone test would
not provide the parent process protocol it expects.

Mutation-test patterns can be checked or executed with:

```sh
tools/mutate.py check
tools/mutate.py
```

The current catalog contains 30 mutations. Each removes or weakens one
security-relevant check and must be detected by the test suite.

GitHub Actions runs formatting, Clippy with warnings denied, the mutation
catalog consistency check, and the complete tests for both the root crate and
the independent `demo/` crate. It uses one Linux job so the expensive leanVM
build is shared by all checks in that run. Benchmarks, container scenarios and
the full mutation campaign remain explicit local jobs; they are intentionally
excluded from pull-request CI.

## Benchmark

The benchmark harness measures the signer, prover, verifier and raw-verification
roles as separate processes:

```sh
./benchmark.sh
RUNS=30 WARMUP=3 ./benchmark.sh
TARGETS="signer prover verifier raw_agg" ./benchmark.sh
```

Defaults:

- `RUNS=20`;
- `WARMUP=2`;
- `N_UPDATES=20` rounds inside each process run;
- `TARGETS="signer prover verifier raw_agg"`;
- `COOLDOWN_SECONDS=2` before every target process;
- balanced target ordering (`INTERLEAVE=1`).

Thus the default harness starts each target 22 times: two warm-ups whose data
is discarded, followed by 20 measured process runs. Each measured run contains
20 update-level observations. Those observations share one process and are not
treated as independent replicates; the reported cross-run statistics use each
run's median as their unit of analysis.

Before measurement, the default harness runs `committee_fixture` once. That
unmeasured process creates the committee, the raw `StatusList` records and their
XMSS signatures. `raw_agg` verifies those records directly. `prover` consumes
the same signed inputs and emits `SnarkStatusList` records; the fixed verifier
corpus is generated from them once and reused by every verifier run. Consequently
the measured raw process is a relying-party verifier and the measured prover is
one aggregator, not a hidden committee signer. `BENCH_SELF_CONTAINED=1` retains
the older diagnostic mode in which each target generates its own keys and
signatures.

The default order is a Williams-style balanced crossover sequence rather than a
fixed round-robin: across a complete block, target position and immediate
predecessor are balanced. The cooldown reduces thermal carry-over between
processes; it does not assert equal package temperature, so `runs.csv` retains
each start time for drift analysis.

Size rows name the serialized object they measure: `signature_size` for one
XMSS signature and `record_size` for the complete `StatusList` or
`SnarkStatusList`. The optional `combined` target alone reports
`proof_size`, because it measures `SnarkStatusList::proof_bytes()` rather than
the whole record. Even-sized samples use the conventional median, the arithmetic
mean of the two central observations.

Each run writes a `bench-<timestamp>/` directory containing environment
metadata, raw samples, per-process rows and summary statistics. The harness
refuses to report timings when a target reports a failed security expectation.

### Committee scaling

[`committee-scaling-benchmark.sh`](committee-scaling-benchmark.sh) orchestrates
`benchmark.sh` over `N = 5, 10, 100, 500` and, when the host has enough
available memory, `1000` and `1500`. It applies the strict two-thirds policy

```text
t = floor(2N/3) + 1
```

as an explicit committee-authorization threshold, not as a claim that this
project implements a consensus protocol.

```sh
./committee-scaling-benchmark.sh
PLAN_ONLY=1 ./committee-scaling-benchmark.sh
RUNS=10 WARMUP=2 STRICT_ENV=1 PIN_CPUS=0-7 ./committee-scaling-benchmark.sh
```

Before doing any work, the script prints and records the host's physical and
available RAM, the operating-system reserve, the enforced RSS cap and the
largest admitted committee. Its conservative defaults admit `N=1000` only with
at least 12 GiB of usable benchmark budget and `N=1500` with at least 20 GiB;
otherwise the planned sweep stops at `N=500`.

Every build, fixture generation and benchmark point then runs serially in its
own process group. The active group is terminated and that point is withheld if
its RSS exceeds the announced cap, available RAM falls below the reserve, swap
grows by more than 64 MiB, or a stage exceeds the 90-minute default timeout.
`MAX_RSS_MB`, `RESERVE_MB`, `MAX_SWAP_GROWTH_MB` and
`POINT_TIMEOUT_MINUTES` can make these limits stricter. An unsafe
`MAX_RSS_MB` request is clamped to the host-derived ceiling.

Before the sweep, `benchmark.sh` measures the `signer` target once as a separate
single-member campaign, using the same run and warm-up counts. It is not repeated
for every `(N,t)`: one member's XMSS operation is identical for both publication
forms and independent of committee size. The result is kept in `signer.csv` and
reported separately rather than multiplied by `t`; those signatures are produced
by distinct member machines and may proceed in parallel.

An unmeasured `committee_fixture` process then generates the signatures once per
point. The measured `prover` is therefore one aggregator holding public keys
and ready-made signatures—never `N` aggregators or one process retaining all
committee secret keys. The raw measurement likewise runs as a verifier-only
process over the same signed records.

The top-level output contains:

- `memory-decision.txt` — the announced admission and runtime limits;
- `signer.csv` and `signer/benchmark/` — the single-member campaign, measured
  once for the complete sweep;
- `manifest.csv` — completed, stopped and RAM-excluded points;
- `scaling.csv` — proving/verification medians, wire size, RSS and derived ratios;
- `report.txt` — the first observed wire-size, verification-time and joint
  crossover;
- `Nxxxx-tyyyy/benchmark/` — the complete `benchmark.sh` output for each point,
  including raw observations and confidence intervals.

When SNARK verification is faster, the report also computes the number of
independent relying-party verifications needed to amortize one proof:

```text
ceil(prove_ms / (raw_verify_ms - snark_verify_ms))
```

This deliberately excludes one-time setup, signing, network transfer and
fixture generation; those costs have different owners and must not be folded
into one latency figure.

## Dependencies

The root crate pins leanVM v0.10 to commit
`73a5f5dcd34d8dfe76a32a44dce0c0f87c86feeb`.

The main direct dependencies are:

- `leanvm`: XMSS aggregation and proof verification;
- `primitives` from the same leanVM revision: BLAKE2s-256;
- `ethereum_ssz` and `ethereum_ssz_derive`: canonical wire containers;
- `sha3`: credential and anchor fingerprints;
- `rand`: application-level randomness.

`demo/` is a separate Cargo workspace.

## Limitations

- Committee rotation and hand-off are not implemented.
- One anchor is expected to govern exactly one status list. A list identifier is
  not currently included in the anchor.
- Status-list entries are not sorted or deduplicated. Different orderings of the
  same logical set produce different signed messages.
- The verifier predicate is stateless; rollback protection depends on the
  persistent high-water mark.
- The SNARK record carries the participating XMSS public keys.
- Selection bounds verification work per lookup but does not provide network
  admission control.
- The project implements only XMSS with BLAKE2s-256. Other signature families
  supported by leanVM are outside the protocol and are rejected.

## Compatibility

The current wire format, signed-message construction, keys, signatures and proofs
are incompatible with earlier protocol generations. Existing artifacts and
durable signer state must be regenerated after upgrading.

There is no mixed-version acceptance mode. The Poseidon2 implementation is
preserved in the `poseidon2` branch.

## Development provenance

This project was developed with assistance from AI coding systems, including
GPT-5.6 Sol/Terra, GPT-5.5 and Fable 5. AI-assisted changes are reviewed and
tested before being accepted. Responsibility for the design, implementation and
published commits remains with the repository maintainer.
