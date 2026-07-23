# decentralized-root-of-trust

A **committee-controlled status list** (e.g. a revocation list) secured with
**post-quantum, hash-based signatures** (XMSS) that are **aggregated into a
single SNARK proof** by the [leanVM](https://github.com/leanEthereum/leanVM)
zkVM.

It replaces a *single-key* root of trust with a **`t`-of-`N` committee**, while
keeping the property that **anyone** can verify the list knowing a single fixed
trust anchor (the committee), without fetching anything in real time.

See [`docs/committee-status-list.md`](docs/committee-status-list.md) for the full
design rationale.

---

## Trust model

- The list is published (e.g. in a DHT) together with a **proof** that replaces
  the old single signature.
- The fixed **trust anchor** each verifier embeds is the **committee**: its `N`
  public keys and the threshold `t`.
- An update is authorized when **at least `t`** distinct committee members sign
  the new list root. *Which* subset signs may change at every update — the
  anchor does not.

Verification is four checks (three outside the circuit, negligible cost):

1. every signer ∈ committee (membership);
2. the proof is bound to **this** list (`message == status_list_root`);
3. quorum reached (`#signers ≥ t`);
4. the SNARK aggregate verifies (one verification, independent of `t`).

Check (2) is the security-critical binding: `verify_single_message_aggregate`
only attests "these keys signed *this* message"; the verifier must check that
message is the root of the list it holds.

---

## Signature scheme

Signing uses **leanVM's own synchronized XMSS** (Poseidon2, `[F; 8]` messages,
`LOG_LIFETIME = 32`) — the scheme leanVM can aggregate. It is a *stateful*
signature: a given `(key, slot)` must sign **at most once**, so each update uses
a new slot.

> Note: the standalone `leanSig` XMSS (Poseidon1, `[u8; 32]`, `LOG_LIFETIME = 18`)
> is a **different, incompatible** parametrization and **cannot** be fed to
> leanVM's aggregator. This project therefore signs with leanVM's XMSS only.

---

## Layout

```
src/
  status_list.rs   StatusList struct, entry -> field mapping, Poseidon2 root, Display
  committee.rs     Committee anchor, make_proof (prover), verify_proof (4 checks)
  main.rs          demo: setup, N updates rotating the t signers, 2 security tests
examples/
  footprint.rs     RAM cost of setup_prover vs setup_verifier
docs/
  committee-status-list.md   design rationale
benchmark.sh       multi-run benchmark (host stats + Raspberry CM4 projection)
```

The demo constants live at the top of `src/main.rs`:
`SLOT`, `N_MEMBERS`, `T`, `N_UPDATES`, `LOG_INV_RATE`.

---

## Dependencies

All dependencies are **git-pinned** (no vendored clones):

- `lean-multisig`, `backend` — from `leanEthereum/leanVM` at a fixed revision.
  leanVM ships its own field/hash backend and **does not depend on Plonky3**, so
  the whole tree resolves reproducibly.
- `rand`, `sha3`, `postcard` — from crates.io.

`Cargo.lock` is committed; keep it to reproduce the exact build.

`.cargo/config.toml` sets a large `RUST_MIN_STACK` (the prover uses a very deep
stack) and `target-cpu=native`.

---

## Build & run

```sh
cargo run --release
```

Example output (shape):

```
setup...
committee N=10 t=7; 10 updates rotating the signers

  update  1/10  signers ABCDEFG  slot 43  prove=...ms  verify=...ms  RAM=... MB  OK
  ...
--- Security (expected: both REJECTED) ---
A) tampered list + valid proof : rejected = true
B) proof from outside signers  : rejected = true
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

## Benchmark

```sh
./benchmark.sh                      # defaults: RUNS=10, WARMUP=1
RUNS=30 WARMUP=3 ./benchmark.sh
CM4_LOW=8 CM4_HIGH=15 ./benchmark.sh
```

It builds `--release`, runs the binary `RUNS` times, parses the single-line
`BENCH` record, prints min/median/mean/stddev/max per metric, saves a CSV, and
adds a **linear projection** to a Raspberry Pi CM4. For real CM4 numbers, run
`benchmark.sh` natively on the board (an aarch64/NEON path exists). The projection
is an estimate, not a measurement. It warns if the CPU governor is not
`performance`.

### Reference numbers

Indicative, `N=10, t=7`, host **AMD Ryzen 7 4800H** (8c/16t, governor
`schedutil` → slightly noisy):

| metric | value |
|---|---|
| setup (once/process) | ~5.3 s (`setup_verifier` ~5.2 s dominates; prover extra ~60 ms) |
| sign (7 XMSS) / update | ~47 ms |
| **prove / update** | **~287 ms** (per-update range ~240–335 ms) |
| verify / update | ~31 ms |
| proof size | ~165 KB |
| RAM resident after setup | ~730–758 MB |
| peak RAM (VmHWM) | ~1029–1058 MB |

**Scaling:** prove-time and RAM grow with **`t`** (more XMSS verifications in the
circuit → bigger trace → bigger WHIR commitment + FFT buffers; in power-of-two
steps due to trace padding), **not** with the number of updates. Setup cost and
resident-after-setup are independent of `t`.

**Raspberry Pi CM4 (BCM2711, 2 GB)** — linear projection x8..x15 (estimate):
setup ~42–79 s (one-time at boot), prove ~2.3–4.3 s/update, verify ~0.25–0.47 s,
10 updates ~30–57 s. RAM does **not** scale with CPU: peak ~1 GB **fits the 2 GB
board** (~1 GB free for the OS); a **1 GB board is excluded**. RAM is the gate.

---

## Security tests

`main.rs` ends with two attacks that **must be rejected**:

- **A — tampered list + valid proof of another list:** rejected by the
  `message == status_list_root` binding (check 2).
- **B — proof from signers outside the committee:** rejected by the
  membership check (check 1).

Both print `rejected = true` and the run reports `security OK: true`.
