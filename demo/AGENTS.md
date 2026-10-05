# AGENTS.md: the container demos

Guidance for work under `demo/`. The root `AGENTS.md` holds the protocol, the
security boundary and the rules that apply everywhere; paths below are
relative to the repository root.

A **separate crate**, with its own `[workspace]` and its own lockfile. That is
the whole rule: the measured root and `mldsa/` crates contain protocol code;
the demo adds networking, orchestration and a credential format. Nothing in
`demo/` may be reachable from a `benchmark.sh` build, and the parent
`Cargo.toml` must stay unaware of it.

```sh
./demo/docker/demo.sh {raw|snark|mldsa} up             # container demo: 1 bootstrap + 10 members, N=10 t=7
./demo/docker/demo.sh {raw|snark|mldsa} round          # node A requests a credential, then verifies the record
./demo/docker/demo.sh {raw|snark|mldsa} revoke         # remove its fingerprint, then verify absence
./demo/docker/demo.sh {raw|snark|mldsa} verify         # re-check the canonical record (expect stale on replay)
./demo/docker/demo.sh {raw|snark} crash                # XMSS-only durable one-time-slot crash test
./demo/docker/demo.sh {raw|snark|mldsa} down           # stop and delete that demo's volumes
```

The container roles share one image and differ by command and environment. `demo/src/bin/`
holds `bootstrap` (assembles the anchor from ten published public keys, in index
order, then exits), `signer` (a member; in raw mode any member may aggregate a
round, while in SNARK mode only the configured prover subset aggregates and runs
`setup_prover()` at startup), `holder` (node A) and `probe` (asks one member to sign
directly, exit `0` signed / `3` abstained, which is what lets the crash scenario
assert instead of grep).

The `mldsa` mode has separate `mldsa_bootstrap`, `mldsa_signer` and
`mldsa_holder` binaries. Its holder decodes the SSZ record, verifies the
ML-DSA quorum and only then advances the same durable freshness gate.

The selected mode's holder is **resident**; `round`/`revoke`/`verify` send it a
trigger via the throwaway `trigger` service. `setup_verifier()` has a
per-process cost in SNARK mode. The one-shot shape still exists (neither
`HOLDER_SERVE` nor `HOLDER_TRIGGER`) for cold-start benchmarking.
In XMSS modes node A holds a `RawNode` or `SnarkNode`; in ML-DSA mode it
composes `RawVerifier` with the same durable `HighWaterMark`. In every mode
the mark survives a container restart on the `holder-state` volume. Node A
also keeps the last credential in its private state: `round` accepts it only
when its fingerprint is present in the authenticated snapshot, while
`revoke` accepts the next snapshot only when that fingerprint is absent.

Four things about it are load-bearing and easy to break by "simplifying":

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
4. **An XMSS member signs only the next version.** Before touching its counter,
   `on_proposal` requires `version == published + 1` (0 before anything is
   published). Proposals are unauthenticated and `reserve_at` burns forward, so
   without this one far-future proposal exhausts every key window. A repeated
   version still passes the rule and is refused by the durable counter, which is
   exactly what the `crash` scenario asserts.

The `crash` scenario is the only test in the repository that kills a real process
mid-protocol. The `AtomicSlotCounter` unit tests additionally inject an invalid
inactive journal record, damage the older record while retaining the latest one,
and refuse a journal with no valid record. Those byte-level cases exercise the
recovery decisions but cannot emulate a storage device violating `sync_data`'s
durability contract. Treat the scenario as coverage, not decoration: if it
starts passing for the wrong reason
(a member that never signed in step 1, say), it stops proving anything.
