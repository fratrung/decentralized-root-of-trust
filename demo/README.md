# Container demos

Three runs of the same ten-node topology, distinguished by signature scheme and
published quorum form.

* **raw** publishes `t` XMSS signatures and their signer bitmap.
* **snark** aggregates that XMSS quorum into one leanVM proof; only a configured
  prover subset may coordinate these rounds.
* **mldsa** publishes `t` raw FIPS 204 ML-DSA-65 signatures and their bitmap.

All modes use `N = 10`, `t = 7`, the same credential lifecycle, storage
fixture and relying-party anti-rollback rule. ML-DSA uses its own committee
anchor and signed-statement format; it is not fed into the XMSS SNARK path.

```
./demo.sh raw   up        # build, start 1 bootstrap + 10 members + node A
./demo.sh raw   round     # node A asks for a credential, then verifies it
./demo.sh raw   revoke    # remove its fingerprint, then verify that it is revoked
./demo.sh raw   verify    # re-check what is published, without a new round
./demo.sh raw   crash     # kill a member mid-protocol, watch it re-align
./demo.sh raw   down      # stop and delete the volumes

./demo.sh snark up        # XMSS quorum aggregated into one proof
./demo.sh snark round

./demo.sh mldsa up        # raw ML-DSA-65 quorum
./demo.sh mldsa round
./demo.sh mldsa revoke
./demo.sh mldsa verify
./demo.sh mldsa down
```

The three demos share the `172.28.0.0/24` subnet, so only one runs at a time.
`up` tears the other two down first.

## Topology

| container | address | role |
|---|---|---|
| `bootstrap` | 172.28.0.5 | assembles the anchor, then exits |
| `signer-0` … `signer-9` | 172.28.0.11 … .20 | committee members, `N = 10`, `t = 7`; raw and ML-DSA allow every member to aggregate, while SNARK restricts aggregation to `0`, `4`, `8` |
| `holder` | 172.28.0.30 | node A, the relying party; resident, verifies on demand |
| `trigger` | assigned | asks node A for one round; run on demand |
| `probe` | assigned | XMSS double-sign probe and shared-volume utility; run on demand |

Three volumes, and the split between them is the design:

* `committee/` is written once at start: the run identifier, ten public keys,
  and the anchor assembled from them in index order.
* `storage/` is a one-file orchestration fixture. It atomically exposes
  `status-current.ssz`, modelling only the single canonical record an external
  secure VDR would return. It does not implement distributed storage,
  replication, consensus or canonicality; the node still authenticates the
  record locally.
* `signer-<i>-state/` exists in the XMSS modes only and is **private to one
  member**: it holds the durable one-time-slot counter. ML-DSA is stateless and
  therefore has no corresponding slot-counter volume.

## What a round looks like

The status list is a complete snapshot of **valid credential fingerprints**.
Presence means valid; revocation is represented by absence. A new version may
add and remove any number of fingerprints in the same update; it may therefore
grow, shrink, or become empty. There is no one-entry transition rule.

1. Node A knows the committee a priori (it loads `anchor.bin`) and dials one
   aggregator. In raw mode every member is eligible. In SNARK mode only the
   configured prover subset (`0`, `4`, `8`) is eligible, and those nodes have
   already run `setup_prover()` during startup. `TARGET_MEMBER=<i>` can still pin
   the target manually, but in SNARK mode it must name one of those aggregator
   indices.
2. The aggregator constructs the next complete `(version, list)` snapshot and
   proposes it to all ten members. The protocol permits any number of additions
   and removals in the same version; `round` and `revoke` merely drive one simple
   operation each. In the XMSS modes the aggregator does **not** propose a slot:
   every member derives it through `Committee::slot_for`. ML-DSA has no slot.
3. Each member signs the exact canonical statement. XMSS members first burn the
   derived leaf slot durably and abstain if it is already spent. ML-DSA members
   use randomized FIPS 204 signing and need no one-time state. The demo approves
   every requested lifecycle operation; a deployment supplies its own policy.
   ML-DSA itself does not prevent a member from signing two different statements
   for one version. The demo does not implement a durable anti-equivocation rule;
   it assumes the external VDR supplies one canonical current record.
4. The aggregator counts signatures until the seventh arrives. Each one is
   verified against the anchor's key at that index before it is counted, so the
   address map decides *where* to look and never *whether* the signature is
   good.
5. It builds the selected record: raw XMSS, aggregated XMSS, or raw ML-DSA. It
   then atomically replaces the demo's single current-record fixture.
6. Node A fetches that record, decodes and verifies it against the mode's anchor,
   and only then lets the authenticated version move its anti-rollback mark.
   The ML-DSA node preserves the same verify-before-gate ordering as `RawNode`
   and `SnarkNode`. Node A requires the
   issued credential's fingerprint to be present, or the revoked credential's
   fingerprint to be absent.

## What the output is for

Node A prints the two figures worth comparing.

**Size.** Raw records grow linearly with `t`: 1208 bytes per XMSS signature
or 3309 bytes per ML-DSA-65 signature, plus bitmap and framing. The SNARK record
replaces the XMSS signatures with one aggregate proof. The printed breakdown
reports the complete serialized record rather than only its cryptographic body.

**Memory.** The raw verifier has no setup: it holds an anchor and calls
`leanvm::xmss::verify` `t` times; the ML-DSA raw verifier performs `t`
FIPS 204 verifications. In SNARK mode, node A loads the verifier once and the
aggregator subset loads the prover once per aggregator process. The first cost is
visible in node A's startup log; the second is visible in the selected members'
startup logs. Each round then prints proof generation and verification costs.

## Node A is resident

`up` starts node A along with the members, and it stays up. That is not a
convenience: `setup_verifier()` is a **per-process** cost, so a relying party
that exits after every check pays five seconds and several hundred megabytes for
every record it looks at, and what you would be measuring is process startup.
Resident, it pays once — the figures appear in `up`, not in front of every
verification — and from then on a round costs only the proof.

`round`, `revoke` and `verify` therefore do not build a verifier. They send
node A a trigger, and it answers with a one-line verdict; the report belongs in
the log of the node that did the checking, so `demo.sh` prints that log rather
than moving the text across the wire. The one-shot shape is still there
(`HOLDER_SERVE` unset), because it is the honest measurement of what a cold
verifier costs.

Staying up is also what makes the anti-rollback mark mean anything: node A
carries a high-water version across rounds, so `verify` twice in a row shows the
second answer refused as stale, which is exactly what a replayed record looks
like.

`demo.sh up` provisions that mark only when the mode's `holder-state` volume does
not yet exist. Every later start explicitly opens it and fails if it is missing,
corrupt, unreadable, or belongs to another anchor. `demo.sh down` removes the
volume, so a later `up` is a new explicit provisioning event.

## The crash scenario

`./demo.sh raw crash` and `./demo.sh snark crash` answer one question: does a
durable slot burn survive the machine that made it? In SNARK mode, the default
victim is also an aggregator, so restart includes a fresh `setup_prover()`.

1. A member signs a version, and nobody publishes the result.
2. The container is killed with `SIGKILL`. No shutdown hook, no flush.
3. It is restarted, and resumes from whatever is on its volume.
4. It is asked to sign the **same version with a different list**. Two
   signatures at one XMSS slot recover the secret key, so the only safe answer
   is no, and the demo asserts it gets one.
5. A normal round runs anyway: the committee reaches quorum without that
   member's signature, which is what `t < N` buys.
6. The next round is at a version the member has not signed, and it rejoins on
   its own. Nobody told it where it was; it derived the slot from the anchor.

The probe exits `0` when a member signs and `3` when it abstains, so the script
asserts each step rather than leaving it to be read out of a log.

This scenario is deliberately unavailable in `mldsa` mode. It tests the
stateful one-time-leaf safety property of XMSS; ML-DSA safely signs repeatedly
and has no durable leaf counter to recover. Treating a normal ML-DSA restart as
the same test would produce a meaningless security claim.

## Deliberate simplifications

These are demo shortcuts. The XMSS paths use the parent crate's node types; the
ML-DSA path uses the independent `drot-mldsa` signer, committee, record and
verifier APIs with the same external freshness gate.

* **Fixed addresses.** The aggregator turns a peer into a committee index by
  looking it up in a compile-time table. A real deployment authenticates peers
  by key. The map is not trusted on its own: every signature is verified against
  `members[index]` before it is counted, so a wrong entry costs a rejected
  contribution rather than a forged record.
* **Derived member keys.** A member's key comes from a per-container secret and
  the run identifier, so a restarted container comes back as the same member
  without a secret key ever being written to a volume. A production member
  generates its key from real entropy and keeps it in hardware.
* **One request per connection.** Members answer proposals on the connection
  that carried them. The aggregator therefore knows which member it is talking
  to from the address it dialled, and an unreachable member costs the round its
  read timeout and nothing else.
* **Lifecycle policy.** The demo members approve every well-formed issuance or
  revocation request. A production member applies the application's authorization
  policy before signing. The protocol deliberately permits arbitrary additions
  and removals, including both in one update; the durable slot counter
  independently prevents two different snapshots from being signed at one XMSS
  slot.

## Rebuilding

`up` rebuilds the image when the sources change. The demo is its own crate, so
nothing here can change what `benchmark.sh` measures.

The image is built with `-C target-cpu=native` inherited from the repository's
`.cargo/config.toml`, which makes it fast on the machine that built it and
unportable to a machine with a smaller instruction set.
