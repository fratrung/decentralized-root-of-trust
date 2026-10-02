# ML-DSA raw status-list form

This independent crate implements the ML-DSA-65 raw form of a committee-signed
status list: a signer, a canonical SSZ trust anchor, a canonical SSZ record,
and a stateless quorum verifier. Local anti-rollback protection is the caller's
responsibility. The measurement binaries can be run directly or through
`benchmark.sh` and `committee-scaling-benchmark.sh`.

```rust
use drot_mldsa::status_list::MlDsaStatusList;
use drot_mldsa::{Committee, MlDsa65Signer, RawVerifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = MlDsa65Signer::generate()?;
    let seed = signer.export_seed(); // secret: persist securely, never publish
    let committee = Committee::new(vec![signer.public_key()], 1)?;
    let list = vec![[0x42; 32]];
    let statement = committee.statement_for(&list, 0);
    let signature = signer.sign(&statement)?;
    let record = MlDsaStatusList::new(list, 0, 1, vec![(0, signature)])?;
    let decoded = MlDsaStatusList::from_bytes(&record.to_bytes())?;
    assert!(RawVerifier::new(committee).verify_status_list(&decoded));

    let restored = MlDsa65Signer::from_seed(&seed);
    assert_eq!(restored.public_key(), signer.public_key());
    Ok(())
}
```

`sign` accepts a byte string of any length. It uses randomized ML-DSA with
fresh OS randomness and the empty FIPS 204 context; failure to obtain
randomness is returned as an error. ML-DSA is stateless: repeated signing does
not consume an XMSS leaf or need a slot journal. A status-list signer uses
`Committee::statement_for` to obtain the 64-byte statement digest it signs.
Signing a precomputed digest with the generic signer is ordinary ML-DSA over
those digest bytes, not the standardized HashML-DSA mode. The seed is private
key material; its durable, access-controlled storage is left to the embedding
application. ML-DSA permits a key to sign conflicting statements for the same
version. This crate authenticates a quorum but does not enforce a
one-statement-per-version signer policy; deployments that require that property
must implement it separately.

## Trust anchor and record

`Committee` contains ordered ML-DSA-65 public keys and threshold `t` of a
`t`-of-`N` committee. Empty committees, thresholds outside `1..=N`, duplicate
keys and noncanonical SSZ are rejected. Member order is the authenticated
mapping between a record's bitmap bits and public keys.

The anchor identifier is derived locally from the canonical SSZ anchor:

```text
anchor_id = SHA3-384(
    "decentralized-root-of-trust/ml-dsa-65/anchor-id/v1\0"
    || canonical_anchor_ssz
)
```

The 48-byte result is bound into every status-list statement.
`MlDsaStatusList` publishes
`(alg=2, status_list, version, signers, signatures)` as an SSZ container. The
status list contains ordered 32-byte credential fingerprints and may be empty.
`signers` is an SSZ `BitList` of the committee's size; exactly one fixed
3,309-byte ML-DSA-65 signature follows each set bit, in ascending member-index
order. The constructor sorts `(index, signature)` pairs and refuses duplicate
or out-of-range indices. Decoding checks the bitmap/signature count, canonical
SSZ and canonical ML-DSA signature encoding. Records are limited to 64 MiB
and at most 2,048 member slots. Measurement fixture generation is limited
to 64 updates per run to bound disk use.

The statement is an application-domain prefix followed by the SSZ encoding of
`(alg=2, anchor_id[48], version, status_list)`
(`Committee::statement_preimage`). Members sign its digest,
`SHAKE256(statement, 64 bytes)`, returned by `Committee::statement_for`, with
ordinary, randomized FIPS 204 ML-DSA. The bitmap and signatures are assembled
after members sign the common digest.

Why a digest: the statement contains the whole list, and ML-DSA starts by
hashing `H(pk) || M`, a prefix that differs for every signer, so signing the
statement itself made a verifier re-read the entire list once per signature.
Hashing once and signing 64 bytes keeps the per-signer hash small. This is
hashing at the application level followed by pure ML-DSA, as FIPS 204 section
5.4 describes (its example is CMS, RFC 9882); it is not the separate HashML-DSA
mode. The same section requires an approved hash or XOF with at least lambda
bits of collision strength, i.e. a digest of at least 2*lambda bits: 384 for
ML-DSA-65. SHAKE256 with 512 output bits (FIPS 202) provides 256, and is the
function and output length of ML-DSA's own message representative; a 32-byte
digest would not be enough. The statement domain is generation `v2`: signatures
made over the generation-1 statement do not verify.
[`docs/mldsa-statement-digest.md`](../docs/mldsa-statement-digest.md) has the
two flows, the measured comparison and the script that reproduces it.

`RawVerifier::verify_status_list` requires exactly `N` bitmap positions, at
least `t` distinct signer bits, and a valid signature under every public key
selected by those bits. Its input is an already decoded record; callers decode
untrusted bytes with `MlDsaStatusList::from_bytes` first. This predicate is
stateless. A version previously authenticated by the predicate still needs a
separate local anti-rollback gate before acceptance as the current record.

## Individual signature sizes

These are fixed encoded sizes, independent of the benchmark host:

| Scheme | One encoded signature | Source constant |
| --- | ---: | --- |
| XMSS (pinned leanVM) | 1,208 B | `leanvm::xmss::SIGNATURE_SSZ_LEN` |
| ML-DSA-65 | 3,309 B | `status_list::SIGNATURE_BYTES` |

The XMSS `signer` emits `SIGNER sig_bytes`; `benchmark.sh` records that
value as `signer,signature_size` in `summary.csv`. The ML-DSA signer and raw
verifier emit the same single-signature quantity as `sig_bytes`.

`record_med_bytes` describes the entire published status-list record, including
all signatures, the signer bitmap, the status list and framing. It must be
compared with the other scheme's record size, not with one signature.

## Measurement binaries

The binaries mirror the role separation of the existing raw XMSS measurements.
`mldsa_fixture` generates fresh keys and canonical records in a **new**
directory. The measured verifier process loads only the public anchor and
published records. Each run verifies the expected update count and executes
negative controls after timed samples.

```sh
FIXTURE_PARENT="$(mktemp -d)"
cargo run --release --manifest-path mldsa/Cargo.toml --bin mldsa_fixture -- "$FIXTURE_PARENT/records" 5 3 20
EMIT_SAMPLES=1 cargo run --release --manifest-path mldsa/Cargo.toml --bin mldsa_raw_agg -- "$FIXTURE_PARENT/records" 20
EMIT_SAMPLES=1 cargo run --release --manifest-path mldsa/Cargo.toml --bin mldsa_signer -- 20
```

The signer binary measures one member's ML-DSA signing operation per update;
statement construction, self-verification and key generation are outside its
`sign_ms` samples. The raw verifier reports `decode_ms` (SSZ plus signature
decoding), `verify_ms` (bitmap, threshold and cryptographic checks), and
`total_ms` from one continuous interval around decode and verification. File I/O and
fixture creation are outside every timed verifier sample. `bytes` is the
complete serialized record; `sig_bytes` is the fixed size of one signature
(3,309 B), and `signatures_bytes` is the aggregate signature payload `t × 3,309`
B. Runtime and memory measurements require Linux `/proc/self/status`. These
binaries emit raw samples; `benchmark.sh` and
`committee-scaling-benchmark.sh` organize comparisons with the XMSS raw and
XMSS/SNARK paths.

Three more things are reported the way the XMSS binaries report them, so the
paths can be compared on the same footing. `BENCH_LIST_ENTRIES=L` makes the
fixture and the signer use lists of exactly `L` entries (one replaced per
version) instead of a list growing by one entry per version; the fixture
records it in `workload.txt`, quorums are `t` distinct members spread over the
whole committee, and each summary line ends with the list sizes the process
actually handled (`list_min`, `list_max`). Every sample has `cpu_ms`, the
process CPU time (user plus system, all threads) over the interval its elapsed
figure times. The verifier also reports `ready_ms` and `ready_cpu_ms`: reading
and decoding the anchor, every member's public key included, and building the
verifier, which a process pays once before its first verification.

The dependency is pinned to RustCrypto `ml-dsa` 0.1.1 with key zeroization
enabled. Its maintainers state that this implementation has not been
independently audited; passing unit tests does not establish production
readiness.

`libc` is used by the measurement binaries only, for one call: the process CPU
clock (`clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ..)`) in `bin/support`, which
is the single `unsafe` line of this crate. The library (signer, committee,
record, verifier) does not use it. The repository README, under
"Dependencies", records what the call does, why it is there and the
alternatives that were measured and rejected.

Run `cargo test --manifest-path mldsa/Cargo.toml` from the repository root
to check this crate without building the XMSS workspace.
