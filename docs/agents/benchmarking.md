# Benchmarking: record contracts, targets, evidence and the scaling layer

Moved out of the root `AGENTS.md`, which keeps the rules that always apply.
Read this before changing `benchmark.sh`, `committee-scaling-benchmark.sh`,
anything under `tools/` or `src/bench/`, or a measured binary (`src/bin/`,
`mldsa/src/bin/`), and before interpreting their output. Paths are relative to
the repository root.

## Machine-readable record contracts

Each binary prints one summary line that `benchmark.sh` parses, plus optional
per-item raw samples when `EMIT_SAMPLES` is set in the environment:

| binary | summary line | sample lines |
|---|---|---|
| `main.rs` | `BENCH k=v ... sec_ok=1` | — |
| `signer` | `SIGNER k=v ... failures=N` | `SAMPLE target=signer idx=… sign_ms=… bytes=… cpu_ms=…` |
| `prover` | `PROVER k=v ...` | `SAMPLE target=prover idx=… prove_ms=… bytes=… cpu_ms=…` |
| `check_prover_output` | `PROVER_OUTPUT_CHECK n_valid=… expected=… reference=fixture\|self failures=N` (gates the prover row) | — |
| `verifier` | `VERIFIER k=v ... failures=N` | `SAMPLE target=verifier idx=… verify_ms=… cpu_ms=…` |
| `raw_agg` | `RAW_AGG k=v ... tamper_rejected=…` | `SAMPLE target=raw_agg idx=… verify_ms=… bytes=… cpu_ms=…` |
| `mldsa_signer` | `MLDSA_SIGNER k=v ... failures=N` | `SAMPLE target=mldsa_signer idx=… sign_ms=… bytes=… cpu_ms=…` |
| `mldsa_raw_agg` | `MLDSA_RAW_AGG k=v ... tamper_rejected=…` | decode, verify, decode-plus-verify and CPU samples |

Every measured summary line also carries `list_min=… list_max=…` (the list
sizes the process handled, checked against the declared workload) and the CPU
of its timed phase: `sign_cpu_*`, `prove_cpu_*` or `total_cpu_*` (median and
total), `setup_cpu_ms` where there is a circuit, and for the three verifiers
`ready_ms`/`ready_cpu_ms`. A sample's `cpu_ms` is the CPU of the interval its
elapsed figure times (decode plus verify for a verifier).

`benchmark.sh` normalises every selected target in `emit_run_row`; adding or renaming a field
means updating that function. The script exits if a summary line is missing, and
aborts before printing any statistics if any run reports `failures > 0`.

Fixed costs are reported as **three distinct fields**, and conflating them is how
the comparison between the two paths gets inverted:

| field | what it is | who pays it |
|---|---|---|
| `setup_ms` | the leanVM circuit (`setup_prover` / `setup_verifier`) | SNARK path only |
| `keygen_ms` | generating the target scheme's keys | one key for each signer target; fixture generation is unmeasured |
| `slot_state_ms` | creating durable `AtomicSlotCounter`s | XMSS signer only; ML-DSA is stateless |

Per-update phases are carried into `runs.csv` under their **own names**
(`sign_*`, `prove_*`, `verify_*`, `decode_*`, `decode_verify_*`, and their CPU
counterparts `sign_cpu_*`, `prove_cpu_*`, `decode_verify_cpu_*`), never under a positional primary/secondary
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
                 outsider, tampered, version, slot, short, proofbody: all required
```

The `update-` / `attack-` name prefixes are the contract. Each `prover` run
generates a **fresh random committee**, so artifacts from different runs are not
interchangeable — start from a clean directory.

## Support modules and binaries

Library (`src/bench/`):
- `src/bench/mem.rs`, `src/bench/stats.rs` — RSS (resident set size) probes and descriptive
  statistics shared by every binary.
- `src/bench/timing.rs` — `decode_then_verify`, the one measurement boundary of
  the relying-party targets: `total` starts before decoding and ends when the
  predicate returns, and the decoded record is handed back alive, so its release
  is never timed and RSS is read while it exists. `raw_agg` and `verifier` call
  it; `mldsa_raw_agg`, in its own crate, writes the same sequence inline.
  A verifier that consumed the record (for example through
  `Result::is_ok_and`) would drop it inside the verify and total timers. The
  unit test counts destructor calls: none before the function returns. `process_cpu_time` is the second
  clock: user plus system CPU of the whole process over every thread
  (`CLOCK_PROCESS_CPUTIME_ID` through `libc`, the crate's only `unsafe` call,
  confined to this benchmark module). Each timed phase is bracketed by it
  outside the elapsed timer, so reading it never enters an elapsed figure.
  That `unsafe` line (and its twin in `mldsa/src/bin/support/mod.rs`) is a
  recorded decision, not an oversight: README "Dependencies" has what it does,
  who calls it and the alternatives measured (a safe wrapper crate, `/proc`,
  and deriving per-operation CPU from whole-process CPU, which was 24-25% off
  for a SNARK verification and up to 67% off for a raw one). Do not add
  another `unsafe`, do not call this one from `node`, `protocol` or `state`,
  and do not replace it with the whole-process derivation.
- `src/bench/workload.rs` — the benchmark workload: `BENCH_LIST_ENTRIES` (fixed
  list size, one entry replaced per version; unset keeps the default growing
  list), `quorum_indices` (`t` distinct members spread over the whole
  committee, SplitMix64 partial Fisher-Yates, pinned by vectors shared with the
  ML-DSA fixture), `workload_manifest` (what a fixture writes to
  `workload.txt`) and `ListSizes` (the `list_min=.. list_max=..` every measured
  binary prints). `src/bench/state.rs` names the signer's state directory.

Binaries that support a measurement and are never a measured role:
- `src/bin/check_prover_output.rs` — benchmark support, never a measured role.
  `benchmark.sh` runs it after every `prover` execution, outside that process's
  timers and RSS and under the same `PIN_CPUS` mask: the output must be exactly
  `anchor.bin`, `update-*` and `canonical.bin`, match the fixture's anchor,
  versions, algorithm, lists and exact signer set, and pass the complete SNARK
  predicate. Success needs positive evidence: every I/O error is a failure and
  `n_valid` must equal `N_UPDATES`; `benchmark.sh` independently requires exit
  0, `failures=0` and `n_valid == expected == BENCH_UPDATES`, so an `anchor.bin` that is listed
  but unreadable cannot end in exit 0 with nothing checked.
  Its verdict is the prover row's `failures` column; a rejection keeps the
  output and logs in `OUTDIR/rejected-prover-execution-*` and withholds every
  number. Without a fixture it can check the records only against their own
  anchor.
- `src/bin/committee_fixture.rs` — scaling support, never a measured role. It
  generates a fresh committee and canonical raw records while preserving the
  XMSS one-key/one-slot rule, then exits. This gives measured `prover` and
  `raw_agg` the same ready-made signatures without either holding member secrets.
  Besides `raw-update-*` it writes the negative-control inputs:
  `raw-attack-honest.bin` (slot `genesis + N_UPDATES`), `raw-attack-slot.bin`
  (the same statement signed at `genesis + N_UPDATES + 1`),
  `raw-attack-outsider.bin` with `outsider-anchor.bin`, and
  `raw-attack-version.bin`, the latest version's statement signed at slot
  `genesis + KEY_SLOTS`. The prover relabels that last one to version
  `KEY_SLOTS`, so the verifier corpus's `attack-version.bin` is slot-consistent
  and only check 2 rejects it, as in self-contained mode. `params.rs` asserts
  `N_UPDATES + 1 < KEY_SLOTS` so these three forgery slots never collide.

## Benchmarking

`benchmark.sh` is built for numbers that can be audited before a write-up: it captures the full
environment (`env.txt`), emits tidy raw data (`samples.csv`), per-run rows
(`runs.csv`) and aggregates with quartiles, sd, CV and t-based CI95
(`summary.csv` / `summary.txt`).
Both harnesses take those aggregates from one module, `tools/stats.awk`. Its
interval is the CI of the **mean** of per-run values (`mean_ci95_halfwidth`),
with the exact Student quantile for every df — the normal 1.960 is too narrow
at the 48-run publication size (df=47: 2.0117). A value that cannot be estimated is `NA` (an empty CSV cell,
`n/a` in `summary.txt`), never 0: with one run there is no sd, CV or interval,
and the scaling report can then confirm no verification advantage. The tests
are independent of the module — quantiles from numerical integration of the t
density — and cover n = 0, 1, 2, 31, 32, 48 and a mean at the edge of zero. `runs.csv` also records load, selected-CPU
frequency and the highest readable temperature before and after each process.
`drift.csv` flags an early/late median shift above 15% without deleting data.
Strict runs require a clean tree; exploratory dirty runs preserve
`source.patch` and `source-status.txt`, but untracked contents are omitted.

**Every figure belongs to a workload `(N, t, L)`.** A record carries the whole
list and every scheme reads it once to authenticate it, so list size enters
record size and verification time on all three paths. `LIST_ENTRIES=L` fixes
it (exported to the binaries as `BENCH_LIST_ENTRIES`; unset is the default
list growing 1..=`N_UPDATES`), and the fixtures draw quorums spread over the
whole committee (`spread-splitmix64-v1`). The workload is evidence, not a
label: each fixture writes `workload.txt`, each measured process prints
`list_min`/`list_max`, and `benchmark.sh` refuses a fixture built for another
workload and aborts, withholding every number, when a process handled other
list sizes than declared (`check_workload`). `OUTDIR/workload.txt` is bound by
`outputs.sha256`, and the scaling layer's `validate_campaign` requires it to
match the campaign's list size. The self-contained shape and `combined` build
their own lists and are refused with `LIST_ENTRIES`
(`tools/test_benchmark_workload.sh`). A sign row excludes hashing the list into
the signed message on both families (XMSS: BLAKE2s; ML-DSA: SHAKE256), which a
member does once either way.

**Two clocks, never merged.** Elapsed time is how long a caller waits; CPU time
is what the work costs. The prover and the SNARK verifier are multithreaded
(at `N=10`, `L=1000`, eight CPUs: one proof 0.48 s elapsed and 3.0 s CPU, one
SNARK verification 177 ms and 0.89 s), the raw verifiers are sequential, and
the XMSS signer waits for its device. `summary.csv` therefore has
`*_cpu_per_item`/`*_cpu_total` rows beside the elapsed ones, `setup_cpu`, and
for the three verifiers `ready`/`ready_cpu`: what a relying party pays once per
process before its first verification (anchor read and decode, verifier
construction, and `setup` on the SNARK path), bracketed identically in the
three binaries so that a cold start can be compared. `samples.csv` carries the
CPU readings as `*_cpu` phases and the validator recomputes the run statistics
from them. Do not add elapsed milliseconds of processes with different
parallelism, and do not present a CPU figure as latency.

**One OUTDIR, one campaign.** `benchmark.sh` refuses a non-empty `OUTDIR`: its
files are written phase by phase, so a failed run in a populated directory would
leave an earlier summary beside its own new samples, and a plotter would show
it as the new result. `status.txt` is `running`, `failed` or `complete`; summaries are
staged in `OUTDIR/.staging` and renamed in only after validation, with
`outputs.sha256` binding `env.txt`, `inputs.sha256` (the fixture inputs,
re-hashed after the last run), samples, runs and summaries. Consumers —
`tools/plot_benchmarks.py` for a fixed benchmark, `validate_campaign` in the
scaling script — require `complete` plus a matching `outputs.sha256`.
`tools/validate_benchmark_csv.awk` recomputes each run's median, mean, sd, min,
max, total and `artifact_med_bytes` from `samples.csv`; its tolerances are the
three-decimal print rounding of both files (0.002 ms, plus 0.0005 ms per
sample for totals), never a looser fit.

**Binaries are frozen, never run from `target/release`.** `tools/freeze_bins.sh`
builds a crate, asks Cargo where each executable actually is (the
`compiler-artifact` messages of `--message-format=json`), copies them into
`OUTDIR/bin` with `SHA256SUMS` and a `PROVENANCE` file (build parameters,
`CARGO_TARGET_DIR`/`CARGO_BUILD_TARGET`, source paths), and fails early on a
noexec filesystem. Every measured and support process runs from those copies,
and `benchmark.sh` re-verifies the hashes after the last run, withholding every
number if one changed. The fixed `target/release` path is wrong whenever Cargo
writes elsewhere (an old executable left there would be measured under the new
commit), and it lets a rebuild during a campaign swap binaries between runs. Copies, not links: Cargo
relinks its own outputs. The copies are byte-identical and the programs neither
start their timers before `main` nor locate anything through their own path, so
freezing changes no measurement. `BENCH_BIN_DIR` hands `benchmark.sh` a set
frozen earlier; it must contain every binary the selected targets can run and
must have been built with the same `DROT_BENCH_N`/`DROT_BENCH_T`.

The unit of analysis for per-update metrics is the **per-run median** (n = RUNS),
not the pooled sample: updates inside one process share allocator and cache state
and are not independent. Preserve that distinction if you touch the aggregation.

### One target per role

The default sweep has six isolated targets. ML-DSA signer timing is crypto-only
until a durable one-statement-per-version policy exists. What each one measures is
decided by **which role would run that process**, and no target is charged for
another role's work:

| target | role | reports |
|---|---|---|
| `signer` | one committee member | protocol sign, durable slot burn, crypto sign, 1 key, 1 counter |
| `prover` | the aggregator | `prove` per update, `setup`, complete `SnarkStatusList` size |
| `verifier` | a relying party | decode, verify-only, contiguous decode+verify, `setup` |
| `raw_agg` | the raw XMSS baseline | decode, verify-only, contiguous decode+verify + record size |
| `mldsa_signer` | one ML-DSA member | randomized crypto sign only, 1 key, no version state |
| `mldsa_raw_agg` | an ML-DSA relying party | separate decode, verify, total time + record size |

All three receivers share one timer boundary (`src/bench/timing.rs`): neither
`verify` nor the contiguous total includes releasing the decoded record.
Every receiver's `decode` covers everything needed before the checks can run:
the SSZ container and each signature on the raw paths, the SSZ container plus
the leanVM aggregate (deserialization and canonical re-encode) on the SNARK path.
SNARK runs made before that alignment billed the aggregate to `verify`; their
decode/verify-only columns are not comparable with later runs, while the
contiguous decode+verify total is.

`combined` (`main.rs`) is **not** in the default `TARGETS`. It measures a process
that proves and verifies at once — not a role anyone deploys. It stays available
as `TARGETS="... combined"` for one purpose: an independent second reading of
prove time. Do not add it back to the defaults for any other reason.

**Only `signer` and `mldsa_signer` report a `sign` row, and that is
deliberate.** In production nobody produces `t` signatures: each member signs
*once* per round on its own machine and broadcasts, and the aggregator receives
`t` and produces none. Timing
a loop that signs `t` times sums the work of `t` machines and bills it to one,
a process that does not exist. Unmeasured XMSS and ML-DSA fixture generators produce their respective
signed corpora before the sweep. `raw_agg`, `mldsa_raw_agg` and `prover`
therefore receive ready-made inputs and hold no committee secret keys.
`BENCH_SELF_CONTAINED=1` retains the former all-in-one process shape only for
diagnostic back-comparison; in that mode `prover`, `combined` and `raw_agg`
produce signatures outside their timed phase.

A member's signing cost is identical on both published forms — same key, same
32-byte message, same derived slot — so the `signer` row applies unchanged to the
SNARK and the raw path, and what separates the two paths is only how the quorum is
evidenced and what a relying party pays to check it.

**The signer's storage is part of its measurement.** `sign_protocol` and
`slot_burn` include one `sync_data` per signature on the filesystem holding the
slot journal. `SIGNER_STATE_DIR` (default `TMPDIR`, exported to the binaries as
`DROT_SIGNER_STATE_DIR`, read through `src/bench/state.rs`) names that
directory; `tools/storage_class.sh` classifies it as `ram`, `local`, `network`
or `other`, and `env.txt`, `summary.txt` and the scaling report carry the class
with filesystem, device and mount. Strict and publication runs refuse `ram`
unless `ALLOW_RAM_SIGNER_STATE=1` names that scenario; exploratory runs warn. On
the development host the burn is 0.57 ms on ext4 and 0.003 ms on tmpfs, so a
tmpfs run would understate it roughly 190-fold. Never weaken the barrier to
improve a number, and keep `slot_burn`, `sign_crypto` and `sign_protocol` apart.

`signer`'s `keygen` and `slot_state` are for **one** XMSS key and counter.
`mldsa_signer` reports one ML-DSA key and no durable version state. Its
crypto-only timing is not comparable to the complete XMSS protocol cost. In the default
fixture-shaped benchmark, `prover`, `raw_agg` and `mldsa_raw_agg` report no
signer-state cost because those measured roles do not own signer state. The
self-contained diagnostic mode reports the whole committee's `N`; do not read
those figures as the same quantity as the signer row.

The default schedule uses a Williams-style balanced target order and an idle
`COOLDOWN_SECONDS=2` before every process. Warm-ups form a separate phase, so
their count does not shift the measured design. Even target counts use N rows;
odd counts use N rotations plus their reversals. This balances position and
directed predecessor across complete designs and reduces thermal carry-over.
`balanced_row` reduces its row number modulo the design length first, so an
odd design repeats as a whole and every order runs equally often. `tools/test_balanced_order.sh` checks orders,
positions and within-row predecessors over repeated designs for 2..6 targets,
and the harness warns when `RUNS` is not a multiple of the design or
`RUNS_<target>` differ, because the balance then holds only in part. It
does not prove equal temperature, so retain the telemetry and inspect
`drift.csv` before publishing.
`INTERLEAVE=0` remains the contiguous legacy order.

`runs.csv` calls its shared size column `artifact_med_bytes`. In
`summary.csv`, the public metric name is `signature_size`, `record_size` or
`proof_size` according to the actual serialized object. `prover` and
`raw_agg` measure the complete published record; only `combined` measures the
proof body. All even-sized byte samples use the arithmetic mean of their two
central observations.

**A result can be traced to what was measured.** Besides the frozen binaries
and the hashes above, each `benchmark.sh` directory keeps `logs/` (stdout and
stderr of every process, warm-ups and failures included; stderr carries the
complete `time -v` report), the signed inputs it generated (`inputs/xmss`,
`inputs/mldsa`: public records, never keys), the verifier corpus when it is at
most `KEEP_CORPUS_MAX_MB` (64) and always `corpus.sha256`, re-checked after the
last run, and `prover-outputs.sha256`, the hash and size of every record each
accepted prover execution wrote (the proofs themselves are not kept).
`runs.csv` ends with per-process accounting — `wall_s`, `cpu_user_s`,
`cpu_sys_s`, `cpu_total_s`, page faults, context switches — and host-wide
deltas around the process: `swap_in_pages`, `swap_out_pages`,
`mem_pressure_us`, `oom_kills`. `summary.csv` carries `process_wall` and
`process_cpu` (whole process, every thread, setup included; 0.01 s
resolution), and `summary.txt` says whether any measured run paged. The scaling
layer checks free space on every filesystem it writes to (OUTDIR, `TMPDIR`,
`SIGNER_STATE_DIR`, Cargo's target directory), refuses to start below the
reserve, and writes `pressure.csv`, one line per guarded stage.

**Memory is reported as what it is, and a missing reading is never 0.** Every
RSS figure is KiB / 1024: MiB, named as such in every summary line and CSV
column (`*_mib`). A process peak has two independent
readings: the process's own `VmHWM` (whole MiB) and the kernel's `ru_maxrss`
from `time -v` (one decimal). `src/bench/mem.rs` stops a Linux process that
cannot read `/proc/self/status` instead of printing 0; without `time`
(`BENCH_TIME_BIN=` reproduces it) the kernel rows are absent, and the scaling
report and the plots fall back to `VmHWM` for the whole point or figure and
name the source (`peak_rss_source`), so an empty kernel series is never
published as a 0 MiB peak. A peak covers
the whole process — setup, the measured updates and, for the three verifiers,
the negative controls run after them — so it is not the memory of verifying
honest updates; `rss_max` (`*_work_rss_mib` in `scaling.csv`), the largest RSS
sampled after each honest update, is the figure without the controls, and it is
a set of samples, not a continuous peak. `scaling.csv` carries the median and
the largest observed peak per role. None of these is a capacity bound.

Nothing in the output is extrapolated to other hardware, and nothing should be
added that is: `target-cpu=native` makes the binaries host-specific, so the only
honest way to get numbers for another machine is to run `benchmark.sh` there. A
projection block existed once and was removed — do not reintroduce it.

### Committee-scaling orchestrator

`committee-scaling-benchmark.sh` must remain an orchestrator over
`benchmark.sh`, not a second measurement implementation. `benchmark.sh` remains
the authority for scheduling, raw samples, descriptive statistics, confidence
intervals, drift diagnostics and security failure gates. The scaling layer
measures `signer` and `mldsa_signer` once for the whole campaign, then chooses
`(N,t)`, prepares both unmeasured signature corpora, enforces resources, invokes
complete benchmark sessions and aggregates their run-level medians. Signer
results stay separate in `signer.csv`: each is a one-member cost, not a quantity
to multiply by `t` or repeat at every committee size.

The requested grid is `N = 5, 10, 100, 500, 1000, 1500`, with
`t = floor(2N/3) + 1`. This is a strict two-thirds authorization policy, not PBFT
or another consensus protocol. `N=5,10,100` is the base grid. At startup the script
derives a usable process budget as the smaller of 70% of physical RAM and
`MemAvailable - host reserve`; it admits `N=500`, `N=1000` and `N=1500` at 8,
12 and 20 GiB respectively. It prints and persists that decision before building
anything.

Each session freezes its own binary set into `session-XX/bin` and passes it as
`BENCH_BIN_DIR`, so the fixtures and every measured process of that session run
one hashed build; a retried session replaces its own set.

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
hard memory backend. Its run count must be a multiple of four, completing the
balanced design for the four per-point targets (`prover`, `verifier`,
`raw_agg`, `mldsa_raw_agg`). Its sweep count must be even and `INTERLEAVE=1`:
three sweeps are two ascending and one descending, and blocked roles confound
role with time, which a report describing a counterbalanced design must not
contain. The refusal happens before `OUTDIR` exists
(`tools/test_scaling_design.sh`), and the report states the design that
ran. `plan.csv` holds the planned sweep order and `schedule.csv` every stage
event as it happens (`started`, outcomes, `kept_complete`), across resumes;
each `benchmark.sh` directory adds its own `schedule.csv` of processes,
warm-ups and cooldowns. It withholds a session on a
drift warning. `RESUME=1` is accepted only when the recorded
source/configuration fingerprint matches and the current usable RAM cap still
meets the admission threshold for the largest originally selected N. A stop
during a resume never rewrites a session that an earlier invocation completed
(marking it `not_run_after_guard` would silently drop valid points from
`manifest.csv` and `scaling.csv`); the final validation alone may demote
one, and only the damaged one. `status-history.txt` keeps every outcome and
`memory-decision.txt` appends each resume's block instead of replacing it.
A retried signer or session benchmark moves its previous attempt to
`benchmark.attempt-*` beside it, because `benchmark.sh` needs an empty
directory; the aggregation globs never read those.

A campaign has one list size (`LIST_ENTRIES`, in the resume fingerprint and
in `scaling.csv` as `list_entries`): a sweep varies the committee, and list
sizes are compared by running one campaign per size. Besides `scaling.csv` the
layer writes three tidy files. `costs.csv`: per point, role, quantity
(`per_update`, `setup`, `ready`), clock and per-run statistic (`median` for the
typical update, `mean` for what a total is made of), with quartiles and the CI
of the mean. `comparisons.csv`: the three verifiers two at a time on both
clocks, with the paired delta, its CI, the confirmed sign and, against the
SNARK verifier, the descriptive break-even. `all-runs.csv`: every run with its
sweep, direction, position and start time. The report prints them as tables and
chooses no threshold, unit or deployment scenario: it states measured
quantities and the model `P + Sp/U + M(S + Sv/K) < M R` they feed.

The combined report derives quantities from run-level medians across complete
sweeps. A validator requires complete run IDs, metric fields and phase samples
before a session contributes; per-target run overrides are rejected. A verification crossover is reportable only when the paired 95% CI for
`raw_decode_verify - snark_decode_verify` is wholly positive. Speedup and break-even retain
quartiles. `ceil(prove / (raw_decode_verify - snark_decode_verify))` excludes process setup,
networking, signing and fixture generation; withhold it if any paired run has no
positive saving rather than deleting that run. It is a descriptive ratio of
typical per-update costs on one clock (`break_even_elapsed_*` in `scaling.csv`;
all four variants in `comparisons.csv`), not a cost, a budget, an interval or
an end-to-end latency, and the report says so. A "first observed point" is the
smallest completed `N` at which a condition held for that list size, host and
session: not the exact crossover, not a claim about larger or uncompleted `N`,
and one of several comparisons read off the same grid whose 95% intervals are
not simultaneous. Do not extrapolate between measured grid points; refine the
grid around the first observed point and confirm it independently.

`tools/analyze_scaling.py` is the analysis the report's interval leaves out. It
reads `all-runs.csv` of a finished campaign and writes `analysis/` (`blocks.csv`,
`trends.csv`, `comparisons.csv`, `report.txt`); it never touches the campaign's
own files and is not called by the harness. A session is one sweep's visit to a
committee size. Per role and clock it gives the session effect (one-way analysis
of variance: spread of session means, F test, intraclass correlation) and the
drift inside each session (slope against run order with its interval, lag-1
autocorrelation). Per paired comparison it gives three intervals: `pairs` (every
pair independent, identical to `tools/stats.awk`'s), `within_sessions`
(sessions as fixed blocks) and `sessions` (sessions as the unit, `S - 1` degrees
of freedom), then Holm-adjusted p-values and Bonferroni simultaneous intervals
over the whole family (committee sizes x verifier pairs x clocks). Its
distribution functions are pure Python (regularized incomplete beta) and are
tested against table values, a hand-computed analysis of variance and
`stats.awk` (`tools/test_analyze_scaling.py`). It refuses an unbalanced
campaign instead of analysing what is there. Like the report it chooses no
threshold: with two sweeps the `sessions` interval has one degree of freedom
and is wide unless the sessions agree, which is a statement about the design,
not a defect to work around by pooling runs.
