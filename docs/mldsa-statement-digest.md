# Why ML-DSA members sign a digest of the statement

This note records one design decision of the `mldsa/` crate, the reasoning
behind it, the standard text it relies on, and the measurement that supports
it. The measurement is reproducible with
[`tools/mldsa_statement_experiment.sh`](../tools/mldsa_statement_experiment.sh).

## The decision

An ML-DSA committee member does not sign the status-list statement. It signs
the 64-byte SHAKE256 digest of the statement, with ordinary ML-DSA-65:

```
statement = domain "…/ml-dsa-65/status-list/v2\0" || SSZ(alg, anchor_id, version, list)
digest    = SHAKE256(statement, 64 bytes)
signature = ML-DSA-65.Sign(sk, digest, ctx = "")
```

The digest covers the **whole** statement (domain, algorithm, anchor identifier,
version and every list entry), not only the list. Nothing else changes: same
keys, same record format, same signature size, same checks in the verifier.

## The two flows

The statement contains the whole list, 32 bytes per credential. ML-DSA does not
sign a message directly: its first step computes a 64-byte message
representative `mu = SHAKE256(tr || M', 64)`, where `tr` is a hash of the
signer's public key (FIPS 204, Algorithm 7 line 6 and Algorithm 8 line 7).
`tr` comes first and is different for every member, so this hash cannot be
shared between two signers: each signature needs its own pass over `M'`.

**Before (signing the statement).** `M` is the statement.

| who | work that depends on the list |
|---|---|
| each member, to sign | build the statement, then one SHAKE256 pass over it inside ML-DSA |
| a verifier, for `t` signatures | build the statement once, then **`t` SHAKE256 passes** over it, one per signature |

**Now (signing the digest).** `M` is the 64-byte digest.

| who | work that depends on the list |
|---|---|
| each member, to sign | build the statement, one SHAKE256 pass over it, then ML-DSA over 64 bytes |
| a verifier, for `t` signatures | build the statement once, **one SHAKE256 pass** over it, then `t` ML-DSA verifications over 64 bytes |

The only difference is where the list is hashed and how many times: once by
the application, instead of once per signature inside ML-DSA. A verifier of a
quorum of 334 signatures over a 10,000-credential list (320 KB) read 107 MB
before; it reads 320 KB now.

This is the same shape the XMSS path already has, where the application hashes
the list once into a 32-byte message (`status_list_message`) and every
signature covers that message.

## Is this inside the standard?

Yes. It is "hashing at the application level" followed by pure ML-DSA, which
FIPS 204 section 5.4 describes and conditions:

> If the content to be signed is large, hashing of the content is often
> performed at the application level. For example, in the Cryptographic Message
> Syntax, a digest of the content may be computed, and that digest is signed
> along with other attributes.

> In order to maintain the same level of security strength when the content is
> hashed at the application level or using HashML-DSA, the digest that is signed
> needs to be generated using an approved hash function or XOF (e.g., from
> FIPS 180 or FIPS 202) that provides at least λ bits of classical security
> strength against both collision and second preimage attacks.

with the footnote: "Obtaining at least λ bits of classical security strength
against collision attacks requires that the digest to be signed be at least 2λ
bits in length."

How this construction meets each condition:

| condition (FIPS 204 §5.4) | here |
|---|---|
| approved hash function or XOF | SHAKE256, FIPS 202 |
| at least λ bits against collisions and second preimages; λ = 192 for ML-DSA-65 | SHAKE256 with a 512-bit output gives 256 bits against collisions and 256 against second preimages |
| digest at least 2λ = 384 bits | 512 bits (64 bytes) |
| the verifier computes the digest "in the same way" | one function, `Committee::statement_for`, is the only place the digest is defined; signer and verifier both call it |

The signature itself is `ML-DSA.Sign` / `ML-DSA.Verify` (Algorithms 2 and 3)
unchanged, with the empty context string. The `ml-dsa` crate is called exactly
as before; only its input is shorter.

**A worked precedent.** RFC 9882 (ML-DSA in the Cryptographic Message Syntax)
is the example the standard itself names. With signed attributes, CMS computes
a digest of the content, places it in the `message-digest` attribute, and signs
the attributes with pure ML-DSA. For ML-DSA-65 it allows SHA-384, SHA-512,
SHA3-384, SHA3-512 and SHAKE256 for that digest, i.e. digests of at least 384
bits. This crate does the same thing with one of the same functions.

**What this is not.** It is not HashML-DSA (FIPS 204 section 5.4.1), the
separate "pre-hash" signing mode with its own domain separator byte and a hash
OID inside the signed message. The sentence "In general, the 'pure' ML-DSA
version is preferred" in section 5.4 compares pure ML-DSA with HashML-DSA; the
construction here is pure ML-DSA.

**Why 64 bytes and not 32.** A 32-byte digest would give 128 bits of collision
resistance, below the 192 required for ML-DSA-65: a collision between two
statements would be cheaper to find than breaking the signature, and one
signature would then authorize both. 64 bytes is also what ML-DSA uses for its
own message representative `mu`; FIPS 204 Appendix D records that `mu` was
lengthened from 384 to 512 bits to remove a collision weakness at the highest
security category. Do not shorten the digest.

**What the security now rests on.** Signing the statement directly, a forgery
needed a break of ML-DSA (whose `mu` already depends on SHAKE256 collision
resistance, with the public-key hash as a prefix). Signing the digest, a
forgery needs a break of ML-DSA or a SHAKE256 collision or second preimage on
the statement, at 256 bits. That is above the 192-bit target of ML-DSA-65, so
the security level claimed for the scheme is unchanged. One property is given
up: with `tr` as a prefix, a collision had to be found per public key; an
application-level digest has no such prefix, so one collision would serve
against every member. At 256-bit collision strength this does not lower the
level, and the anchor identifier inside the statement still binds the digest
to one committee.

**Two limits of this claim.** "Inside the standard" here means the algorithm
is used as FIPS 204 specifies. It does not mean FIPS 140 validation: section
5.4 also says the hash of the content "must be computed within a FIPS
140-validated cryptographic module", and neither the `ml-dsa` nor the `sha3`
crate is one. That applies to this prototype with or without the digest.
Second, a signature made over the old statement does not verify over the
digest and the reverse: the change is a signed-message break, marked by the
statement domain moving to generation `v2`.

## The experiment

**Question.** How much does signing the digest change quorum verification and
signing, and how does that depend on the quorum size `t` and the list size `L`?

**Hypotheses, written before measuring.**

- H1. Signing the statement: quorum verification grows with `t × L`.
- H2. Signing the digest: quorum verification depends on `t` but hardly on `L`
  (one pass over the list, once).
- H3. The two coincide for short lists and diverge as `L` grows.

**What is compared.** Both variants are measured by one program
(`mldsa/src/bin/mldsa_statement_experiment.rs`) on the same keys and lists.
Verification is timed from "the record is decoded" to "all `t` signatures are
verified", so both variants pay for building the statement. Signing is timed
from "the list is known" to "one signature exists". The program is not a
benchmark target and `benchmark.sh` does not run it.

**Method.**

- Quorum sizes `t` = 4, 67, 334, 1001 (the thresholds of committees of 5, 100,
  500 and 1500 under `t = floor(2N/3) + 1`). List sizes `L` = 20, 100, 1,000,
  10,000 credentials (750 bytes to 320 KB of statement).
- One process per `t` measures every `L` and both variants. Inside it the list
  sizes are interleaved, their order rotates at every repetition, and the two
  variants alternate which goes first; 15 quorum verifications per variant and
  list size, at least 64 signatures per variant and list size.
- Each process is repeated (10 times in the main run); the order of the quorum
  sizes rotates and reverses from run to run. The unit of analysis is the
  per-process median. Intervals are the Student-t 95% confidence interval of
  the mean of those per-process values (`tools/stats.awk`).
- Every ratio and difference is computed inside one process and then
  summarized across processes.
- The binary is built once, frozen and hashed. Every verification must
  succeed and four negative controls must fail (a signature over the statement
  must not verify over the digest, nor the reverse, nor either under another
  key), or the process stops and nothing is reported. Nothing is filtered or
  discarded.

**Why ratios inside one process.** Comparing one process per `(t, L)` with
another is not reliable. On the test host (a laptop, `schedutil` governor) the
same per-signature work takes 0.065 ms in one process and 0.109 ms in another,
depending on the CPU clock state while it runs, which is enough to make the
digest variant appear faster with longer lists. With every list size and both
variants in one process, a change of CPU state shifts both terms of a ratio
and cancels. The absolute milliseconds still belong to the host; the report
records the CPU clock and the power source (mains or battery) of every
process.

**A second effect, found while checking the results.** The two SHAKE256 passes
are not the same code. The application digest uses the `sha3` crate; ML-DSA
hashes its message with its own SHAKE256 (the `shake` crate inside `ml-dsa`
0.1.1). Their relative speed depends on the compiler. The experiment was first
run with Rust 1.90.0, which this repository pinned at the time: in that build
ML-DSA's pass absorbs a long message about four times slower than the
application's. With Rust 1.98.1, pinned since 2 October 2026, and with a 2026
nightly compiler, the two are equal:

| compiler | application pass (`sha3`) | ML-DSA's pass (`mu`) |
|---|---|---|
| Rust 1.90.0 (pinned until 2 October 2026) | 464 MiB/s | 119 MiB/s |
| Rust nightly 1.97 | 464 MiB/s | 471 MiB/s |
| Rust 1.98.1 (pinned now) | 466 MiB/s | 477 MiB/s |

So a measured gain can have two parts: a **structural** one (one pass over the
list instead of `t`), which is the design, and a **build-specific** one (each
of the `t` passes was also slower than the one that replaces them), which
belongs to a compiler and library version. The report separates them by
computation (the ratio the same measurements would give if each of ML-DSA's
passes cost one application pass), and the experiment was run under all three
compilers. With the compiler pinned now the build-specific part is absent:
the measured ratio is the structural one. That difference between builds is
one of the reasons the pin was moved.

## Results

Main run: Rust 1.98.1, 10 processes per quorum size, AMD Ryzen 7 4800H, one
pinned core, mains power, 2 October 2026. Data in
[`data/mldsa-statement-digest/rust-1.98.1/`](data/mldsa-statement-digest/rust-1.98.1/).

**Quorum verification, ms** (build the statement, verify `t` signatures;
median across processes, ratio with its 95% CI):

| t | L | statement bytes | signing the statement | signing the digest | ratio |
|---:|---:|---:|---:|---:|---:|
| 4 | 20 | 750 | 0.222 | 0.211 | 1.05× [1.05, 1.06] |
| 4 | 100 | 3,310 | 0.236 | 0.218 | 1.08× [1.08, 1.09] |
| 4 | 1,000 | 32,110 | 0.473 | 0.278 | 1.71× [1.70, 1.71] |
| 4 | 10,000 | 320,110 | 3.119 | 1.281 | 2.43× [2.43, 2.45] |
| 67 | 20 | 750 | 3.701 | 3.565 | 1.04× [1.04, 1.04] |
| 67 | 100 | 3,310 | 3.990 | 3.568 | 1.12× [1.12, 1.12] |
| 67 | 1,000 | 32,110 | 7.906 | 3.636 | 2.17× [2.17, 2.18] |
| 67 | 10,000 | 320,110 | 47.301 | 4.748 | 9.95× [9.93, 9.98] |
| 334 | 20 | 750 | 18.346 | 17.787 | 1.03× [1.03, 1.03] |
| 334 | 100 | 3,310 | 19.975 | 17.789 | 1.12× [1.12, 1.12] |
| 334 | 1,000 | 32,110 | 39.504 | 17.853 | 2.21× [2.21, 2.21] |
| 334 | 10,000 | 320,110 | 234.186 | 18.522 | 12.64× [12.62, 12.66] |
| 1001 | 20 | 750 | 55.094 | 53.456 | 1.03× [1.03, 1.03] |
| 1001 | 100 | 3,310 | 60.015 | 53.405 | 1.12× [1.12, 1.12] |
| 1001 | 1,000 | 32,110 | 118.687 | 53.534 | 2.22× [2.21, 2.22] |
| 1001 | 10,000 | 320,110 | 702.182 | 54.139 | 12.97× [12.95, 12.99] |

**Growth from 20 to 10,000 credentials, inside one process:**

| t | signing the statement | signing the digest |
|---:|---:|---:|
| 4 | ×14.1 (0.222 → 3.119 ms) | ×6.05 (+1.07 ms) |
| 67 | ×12.8 (3.70 → 47.3 ms) | ×1.33 (+1.18 ms) |
| 334 | ×12.8 (18.3 → 234.2 ms) | ×1.04 (+0.74 ms) |
| 1001 | ×12.7 (55.1 → 702.2 ms) | ×1.01 (+0.68 ms) |

Per signature verified, the statement variant goes from 0.055 ms at 20
credentials to 0.70 ms at 10,000, the same for every `t` from 67 up (0.78 ms
for a quorum of 4, where building the statement is shared by few signatures);
the digest variant stays at 0.053 to 0.055 ms once the single pass is spread
over a large quorum.

**The same ratio under three compilers, at 1,000 and 10,000 credentials.**
"Computed" is `(digest variant + (t − 1) application passes) / digest variant`
from the main run's own measurements: what the ratio would be if each of
ML-DSA's passes cost exactly one application pass. The other two columns are
the same experiment built with the compiler pinned earlier
([`data/mldsa-statement-digest/rust-1.90.0/`](data/mldsa-statement-digest/rust-1.90.0/),
10 processes per quorum size, 1 October 2026) and with a nightly compiler
([`data/mldsa-statement-digest/rust-nightly-1.97/`](data/mldsa-statement-digest/rust-nightly-1.97/),
5 processes per quorum size).

| t | L | Rust 1.98.1, measured | Rust 1.98.1, computed | nightly 1.97, measured | Rust 1.90.0, measured |
|---:|---:|---:|---:|---:|---:|
| 4 | 1,000 | 1.71× | 1.71× | 1.71× | 3.55× |
| 67 | 1,000 | 2.17× | 2.19× | 2.17× | 4.37× |
| 334 | 1,000 | 2.21× | 2.22× | 2.20× | 4.43× |
| 1001 | 1,000 | 2.22× | 2.22× | 2.21× | 4.43× |
| 4 | 10,000 | 2.43× | 2.53× | 2.46× | 7.20× |
| 67 | 10,000 | 9.95× | 10.08× | 9.94× | 27.84× |
| 334 | 10,000 | 12.64× | 12.80× | 12.56× | 34.20× |
| 1001 | 10,000 | 12.97× | 13.11× | 12.92× | 34.86× |

The measured and the computed ratios of the main run agree to within 5%, and
the two builds with equal hashing speed agree with each other to within 2%.
The Rust 1.90.0 build measured ratios two to almost three times larger; the
same computation applied to its own data gave 1.61× to 2.02× at 1,000
credentials and 2.49× to 10.92× at 10,000, a little lower than the first two
columns because that build also verified one signature more slowly (0.065
instead of 0.053 ms), so the hashing weighed less.

**Is the difference really the hashing of the statement?** The report compares
the time saved per quorum verification with what the building blocks predict:
`t × (ML-DSA's hashing step over the statement − over the digest) − one
application pass`. In the main run the saved time is 0.97 to 1.04 times the
prediction for lists of 1,000 and 10,000 credentials (0.96 to 1.04 in the
nightly run). In the Rust 1.90.0 run it was 0.85 to 0.88 times: ML-DSA's
hashing step timed alone was that much slower than the same step inside
verification. In every build the whole difference is accounted for by that
one step. For lists of 20 and 100 credentials the saved time is a few
hundredths of a millisecond per signature and the prediction is not reliable
(0.5 to 2.2 times).

**One member signing once, ms, 10,000 credentials:**

| t (members rotating) | Rust 1.98.1: statement | Rust 1.98.1: digest | ratio | Rust 1.90.0 ratio |
|---:|---:|---:|---:|---:|
| 4 | 1.36 | 1.45 | 0.95× [0.90, 0.98] | 1.97× [1.90, 2.02] |
| 67 | 1.35 | 1.46 | 0.93× [0.90, 0.95] | 1.87× [1.84, 1.93] |
| 334 | 1.07 | 1.09 | 0.97× [0.93, 0.98] | 2.25× [2.19, 2.33] |
| 1001 | 1.07 | 1.09 | 0.98× [0.97, 0.98] | 2.26× [2.24, 2.31] |

At 1,000 credentials or fewer the signing ratios are within noise of 1 in the
main run: eleven of the twelve intervals contain 1, and the twelfth (`t` = 4,
1,000 credentials: 1.23× [1.01, 1.34]) is the widest of the table and is not
repeated at any other quorum size.

## Evaluation

**H1 is supported.** Signing the statement, the per-signature cost follows the
statement size (0.055 → 0.70 ms) and does not depend on `t`, so quorum
verification is proportional to `t × L` once the list dominates: ×12.7 to
×14.1 from 20 to 10,000 credentials for every quorum size.

**H2 is supported in absolute terms, and needs one qualification.** Signing
the digest, 10,000 credentials add 0.7 to 1.2 ms to a quorum verification
whatever the quorum size: one statement to build (0.21 ms) and one SHAKE256
pass (0.66 ms). For a quorum of 334 or 1001 that is 1 to 4% of the total. For
a quorum of 4 the same millisecond is five times the rest of the work, so
"hardly depends on `L`" is true of the added time, not of the ratio, when the
quorum is very small.

**H3 is supported.** At 20 credentials the two variants are within about 5%
of each other; at 100, within 12%; at 1,000 credentials the statement variant
is 1.7 to 2.2 times slower, at 10,000 it is 2.4 to 13 times slower, and the
ratio never decreases as the list grows, for any `t`.

**How large the gain is.**

- With the compiler pinned now: ×2.4 for a quorum of 4, ×10 for 67, ×12.6 to
  ×13 for 334 and 1001, at 10,000 credentials; ×1.7 to ×2.2 at 1,000
  credentials; 12% or less at 100 or fewer. For large quorums it approaches
  `1 + (one pass over the statement) / (one signature verification)`: with a
  verification of 0.053 ms and a pass of 0.65 ms, about 13. This is the part
  that belongs to the design, and the figure to quote.
- With Rust 1.90.0 the gain was larger (×7 to ×35 at 10,000 credentials),
  because each of the `t` passes that were removed was about four times
  slower than the one that remains. That was real on that build and is not a
  property of the design.

A descriptive marker, not a threshold: one pass over the statement costs as
much as one ML-DSA-65 signature verification at roughly 800 credentials
(roughly 300 with the slower internal pass of the Rust 1.90.0 build). Below
that the lattice arithmetic dominates and the choice hardly matters; above it,
signing the statement would have made the list, not the signatures, the main
cost of verification.

**Signing is not where the gain is.** A member hashes the statement once in
either design. Signing the digest is not faster: at 10,000 credentials it is
2 to 7% slower (ratios 0.93 to 0.98, every interval below 1), and at 1,000 or
fewer the two are indistinguishable, apart from the one cell noted above. The ×2 measured with Rust 1.90.0 came
entirely from the slower internal pass. The decision is justified by
verification, where the list is read once instead of `t` times, and by anyone
else who checks signatures (an aggregator verifies each contribution before
counting it).

**A side effect on the benchmark.** With the digest, ML-DSA's own hashing
covers 64 bytes per signature, so the ML-DSA targets of `benchmark.sh` do not
depend on how fast that library hashes long messages under a given compiler.
The list is hashed by one function in this crate, as on the XMSS path, which
makes the two families comparable on the same footing. What remains
compiler-dependent is the signature verification itself: 0.065 ms under Rust
1.90.0 and 0.053 ms under 1.98.1 on this host. In `benchmark.sh` at `N=10`,
`t=7`, `L=1000`, moving the pin made decoding and verifying one ML-DSA record
14% faster (0.60 → 0.52 ms) and left the XMSS and SNARK figures unchanged
within session noise. Results obtained under different pins must not be mixed.

**Stability.** In a preliminary full run of the same size under Rust 1.90.0
(not part of the published data, made with an earlier version of the report
script), one of the ten runs measured the statement variant slower: by 27% in
every one of the 15 repetitions at `t` = 334 (975 instead of 769 ms), and by
10 to 27% in 14 of the 15 at `t` = 1001, while the digest variant in the same
processes was unchanged.
The cause was not investigated; the pattern is what a memory-layout effect on
the long hashing loop would produce. It did not recur in any of the three
published runs. Only the statement variant showed it.

## Limits

- One machine, one library version (`ml-dsa` 0.1.1, `sha3` 0.10.9), three
  compilers. SHAKE256 speed differs across CPUs (some have hardware support)
  and, as shown above, across compilers, and with it the size of the gain.
- Lists are synthetic fingerprints up to 10,000 entries. Nothing is
  extrapolated beyond the measured sizes.
- Verification here is "build the statement and verify `t` signatures". The
  SSZ decoding of the record, the bitmap and the freshness gate are the same
  in both designs and are not included; `benchmark.sh` measures them.
- The security statements above are an argument from FIPS 204 and FIPS 202,
  not a formal proof and not a certification.

## What should reproduce elsewhere, and what should not

The milliseconds, the ×13 and the equality of the two SHAKE256 passes belong
to this host, compiler and library version (with another compiler the ratio
was ×35). What should hold on any machine is the shape, which the report
checks at the end:

- S1. The statement/digest ratio does not decrease as the list grows, for
  every `t`.
- S2. At the largest list, the 95% CI of the ratio is wholly above 1, for
  every `t`.
- S3. From the smallest to the largest list, the statement variant grows more
  than the digest variant, in every process (40 of 40 in each of the two
  10-process runs, 20 of 20 in the nightly run).
- S4. At the largest list, the ratio is larger for the largest quorum than for
  the smallest.
- S5. At the largest list, the ratio stays above 1 with the SHAKE256 speed
  difference removed, for every `t`.

All five were reproduced in the three runs.

## How to rerun

```sh
tools/mldsa_statement_experiment.sh                       # 5 runs, about 4 minutes
RUNS=10 PIN_CPUS=2 tools/mldsa_statement_experiment.sh    # the main run above
RUSTUP_TOOLCHAIN=1.90.0 CARGO_TARGET_DIR=/tmp/mldsa-1.90 \
  RUNS=10 PIN_CPUS=2 tools/mldsa_statement_experiment.sh  # the earlier compiler
T_LIST="67 334" L_LIST="100 1000 10000" tools/mldsa_statement_experiment.sh
```

The script builds and freezes the binary, records the environment (compiler
included), and writes `env.txt`, `runs.csv` (one row per process and list
size), `summary.csv`, `report.txt` (the tables, H1 to H3 and the shape check),
`logs/` and `outputs.sha256` into a new directory. On a laptop, keep the power
source unchanged during a run: the report says which one each process ran on
and flags a change.

The data behind this note are kept in
[`data/mldsa-statement-digest/`](data/mldsa-statement-digest/): `env.txt`,
`runs.csv`, `summary.csv`, `report.txt` and the hashes of the three runs. The
per-process logs are not kept; `logs.sha256` records their hashes. The host
name and the absolute paths in `env.txt` and `report.txt` were replaced by
placeholders before publication, and `outputs.sha256` was regenerated over the
published files; the
[`README`](data/mldsa-statement-digest/README.md) there lists what was
replaced and the original hashes. No measured value was changed.
