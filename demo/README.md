# Container demos

Two runs of the same ten-node network, differing in one decision: what the
aggregator publishes once it has a quorum.

* **raw** lets any member aggregate, then publishes the `t` XMSS signatures and a
  bitmap naming their signers.
* **snark** publishes one aggregated proof, produced by a configured aggregator subset.

The protocol flow is otherwise the same: same committee, same threshold, same
credential, same shared storage, same relying party. In SNARK mode the aggregator
role is restricted to a small prover subset, so only those members pay
`setup_prover()`; all ten members still sign proposals. The publication and
verification reports remain the comparison points the demo prints.

```
./demo.sh raw   up        # build, start 1 bootstrap + 10 members + node A
./demo.sh raw   round     # node A asks for a credential, then verifies it
./demo.sh raw   verify    # re-check what is published, without a new round
./demo.sh raw   crash     # kill a member mid-protocol, watch it re-align
./demo.sh raw   down      # stop and delete the volumes

./demo.sh snark up        # the same network, publishing one proof instead
./demo.sh snark round
```

The two demos share the `172.28.0.0/24` subnet, so only one runs at a time.
`up` tears the other one down first.

## Topology

| container | address | role |
|---|---|---|
| `bootstrap` | 172.28.0.5 | assembles the anchor, then exits |
| `signer-0` … `signer-9` | 172.28.0.11 … .20 | committee members, `N = 10`, `t = 7`; in SNARK mode `0`, `4`, `8` are also aggregators |
| `holder` | 172.28.0.30 | node A, the relying party; resident, verifies on demand |
| `trigger` | assigned | asks node A for one round; run on demand |
| `probe` | assigned | double-sign probe; run on demand |

Three volumes, and the split between them is the design:

* `committee/` is written once at start: the run identifier, ten public keys,
  and the anchor assembled from them in index order.
* `storage/` stands in for the DHT. Anyone can read it and, in the demo, anyone
  could write to it. A record's authority comes from the signatures inside it,
  never from where it was found.
* `signer-<i>-state/` is **private to one member**: its durable slot counter.
  Sharing it would destroy the property it exists to provide.

## What a round looks like

1. Node A knows the committee a priori (it loads `anchor.bin`) and dials one
   aggregator. In raw mode every member is eligible. In SNARK mode only the
   configured prover subset (`0`, `4`, `8`) is eligible, and those nodes have
   already run `setup_prover()` during startup. `TARGET_MEMBER=<i>` can still pin
   the target manually, but in SNARK mode it must name one of those aggregator
   indices.
2. The aggregator reads the published record, appends the new credential's
   fingerprint, and proposes `(version, list)` to all ten members. It does
   **not** propose a slot: every member derives that itself through
   `Committee::slot_for`, so an aggregator cannot have two versions signed at
   one XMSS slot.
3. Each member checks that the proposal is an append-only successor of the last
   authenticated record it signed, burns the slot durably, signs, and answers. A
   member whose slot is already spent abstains, which is a normal outcome.
4. The aggregator counts signatures until the seventh arrives. Each one is
   verified against the anchor's key at that index before it is counted, so the
   address map decides *where* to look and never *whether* the signature is
   good.
5. It builds the record (bitmap from those indices, or one aggregated proof),
   publishes it atomically to the shared volume, and only then hands over the
   credential. A credential whose fingerprint is not yet in a published record
   is one the holder could prove nothing about.
6. Node A fetches the freshest record from the volume and hands the bytes to a
   `RawNode` or a `SnarkNode`, which decodes, verifies against the anchor, and
   only then lets the version move its anti-rollback mark. Node A then checks
   that its own fingerprint is in the list the committee signed.

## What the output is for

Node A prints the two figures worth comparing.

**Size.** The raw record is `t` signatures and a rounding error, so it grows by
1208 bytes per additional signer. The SNARK record is a proof whose size does
not move with `t` at all. The breakdown makes that structural rather than
asserted.

**Memory.** The raw verifier has no setup: it holds an anchor and calls
`xmss_verify` `t` times. In SNARK mode, node A loads the verifier once and the
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

`round` and `verify` therefore do not build a verifier. They send node A a
trigger, and it answers with a one-line verdict; the report belongs in the log of
the node that did the checking, so `demo.sh` prints that log rather than moving
the text across the wire. The one-shot shape is still there (`HOLDER_SERVE`
unset), because it is the honest measurement of what a cold verifier costs.

Staying up is also what makes the anti-rollback mark mean anything: node A
carries a high-water version across rounds, so `verify` twice in a row shows the
second answer refused as stale, which is exactly what a replayed record looks
like.

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

## Deliberate simplifications

These are demo shortcuts. None of them weakens the protocol code, which is used
unmodified from the parent crate.

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
* **Structural extension check.** A member verifies that a proposal is an
  append-only successor of the last authenticated record it recovered, but does
  not verify the published record's own signatures before signing. Verifying a
  SNARK before every signature would put the aggregator's cost on all ten nodes;
  the member's real defence is the slot counter, which no proposal can talk it out of.

## Rebuilding

`up` rebuilds the image when the sources change. The demo is its own crate, so
nothing here can change what `benchmark.sh` measures.

The image is built with `-C target-cpu=native` inherited from the repository's
`.cargo/config.toml`, which makes it fast on the machine that built it and
unportable to a machine with a smaller instruction set.
