# Container demos

Two runs of the same ten-node network, differing in one decision: what the
aggregator publishes once it has a quorum.

* **raw** publishes the `t` XMSS signatures and a bitmap naming their signers.
* **snark** publishes one aggregated proof that such a quorum existed.

Everything else is identical, which is what makes the two runs comparable: same
committee, same threshold, same credential, same shared storage, same relying
party. The difference shows up in exactly two places, the aggregator's
publication step and node A's verification step, and the demo prints both.

```
./demo.sh raw   up        # build, start 1 bootstrap + 10 members
./demo.sh raw   round     # node A asks for a credential, then verifies it
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
| `signer-0` … `signer-9` | 172.28.0.11 … .20 | committee members, `N = 10`, `t = 7` |
| `holder` | assigned | node A, the relying party; run on demand |
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

1. Node A knows the committee a priori (it loads `anchor.bin`) and dials **one
   member at random**. That member becomes the aggregator for this round and for
   no longer.
2. The aggregator reads the published record, appends the new credential's
   fingerprint, and proposes `(version, list)` to all ten members. It does
   **not** propose a slot: every member derives that itself through
   `Committee::slot_for`, so an aggregator cannot have two versions signed at
   one XMSS slot.
3. Each member checks that the proposal appends exactly one entry to what is
   published, burns the slot durably, signs, and answers. A member whose slot is
   already spent abstains, which is a normal outcome and not a fault.
4. The aggregator counts signatures until the seventh arrives. Each one is
   verified against the anchor's key at that index before it is counted, so the
   address map decides *where* to look and never *whether* the signature is
   good.
5. It builds the record (bitmap from those indices, or one aggregated proof),
   publishes it atomically to the shared volume, and only then hands over the
   credential. A credential whose fingerprint is not yet in a published record
   is one the holder could prove nothing about.
6. Node A fetches the freshest record from the volume, verifies it against the
   anchor, checks its own fingerprint is in the signed list, and advances its
   anti-rollback mark.

## What the output is for

Node A prints the two figures worth comparing.

**Size.** The raw record is `t` signatures and a rounding error, so it grows by
1208 bytes per additional signer. The SNARK record is a proof whose size does
not move with `t` at all. The breakdown makes that structural rather than
asserted.

**Memory.** The raw verifier has no setup: it holds an anchor and calls
`xmss_verify` `t` times. The SNARK verifier must make the aggregation bytecode
resident before it can so much as deserialise a proof. Both demos print RSS
before and after that step, and the peak.

## The crash scenario

`./demo.sh raw crash` answers one question: does a durable slot burn survive the
machine that made it?

1. A member signs a version, and nobody publishes the result.
2. The container is killed with `SIGKILL`. No shutdown hook, no flush.
3. It is restarted, and resumes from whatever is on its volume.
4. It is asked to sign the **same version with a different list**. Two
   signatures at one XMSS slot recover the secret key, so the only safe answer
   is no, and the demo asserts it gets one.
5. A normal round runs anyway: the committee reaches quorum with seven of the
   other nine, which is what `t < N` buys.
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
* **Structural extension check.** A member verifies that a proposal appends one
  entry to the published record, but does not verify the published record's own
  signatures before signing. Verifying a SNARK before every signature would put
  the aggregator's cost on all ten nodes; the member's real defence against a
  hostile aggregator is the slot counter, which no proposal can talk it out of.

## Rebuilding

`up` rebuilds the image when the sources change. The demo is its own crate, so
nothing here can change what `benchmark.sh` measures.

The image is built with `-C target-cpu=native` inherited from the repository's
`.cargo/config.toml`, which makes it fast on the machine that built it and
unportable to a machine with a smaller instruction set.
