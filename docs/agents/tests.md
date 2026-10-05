# Tests: what each file covers and why it has its shape

Moved out of the root `AGENTS.md`, which keeps the rules that always apply.
Read this before adding, splitting or deleting a test. Paths are relative to
the repository root.

Tests (`cargo test`, 99 registered: 98 run plus one `#[ignore]`d):
- `src/*.rs` unit tests cover each module against its own contract.
  `status_list.rs`'s pin the seam this crate has with leanVM: that
  `status_list_message` is BLAKE2s-256 of the exact domain/version/count/entries
  framing, that it moves with both list and version — the content of check 2 —,
  that it stays order-sensitive, and that retired wire tag `0` is
  rejected. `stats.rs`'s
  are worth a note: they guard the per-run numbers every binary prints, and
  they pin the two choices a "simplification" would silently undo — the
  median over a lone mean, and the Bessel-corrected (`n-1`) standard deviation.
  The between-run statistics and confidence intervals are computed by
  `tools/stats.awk`, guarded by `tools/test_stats.sh`.
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
  `verify_decoded` agrees with `verify` on the honest and the tampered record,
  that `is_newer` is strict, and that a version with no slot under the anchor panics
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
- `tests/cpu_clock.rs` checks `bench::timing::process_cpu_time`: a sleep costs
  almost no CPU, a busy loop costs about its elapsed time, and work done on
  another thread is counted. One `#[test]` in its own binary, because the clock
  covers the whole process and the unit-test binary's parallel tests would be
  counted too.
- `tests/check_prover_output.rs` runs the real checker binary on directories it
  must refuse: missing, unreadable (a directory in place of a file, which works
  even as root) or malformed `anchor.bin`, an unreadable intermediate update or
  `canonical.bin`, undecodable records, a short run, an extra record and a
  missing fixture. Each must exit non-zero and report fewer valid records than
  expected. The accepting path needs twenty real proofs and is exercised by
  every `benchmark.sh` prover execution instead.
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
