# Committee-controlled status list

How to replace a **single-key root of trust** with a **`t`-of-`N` committee**,
while keeping the property that *anyone* can verify the status list knowing a
single, fixed, embeddable trust object.

---

## Scenario

- The status list is stored in a **DHT**.
- A verifier retrieves it and considers it **valid only if the proof carried by
  the structure verifies** (the proof takes the place of a single signature).
- **Before:** there was a *root of trust* — every verifier embedded **one**
  public key and used it to verify the single signature on the list.
- **Now:** updating the list is controlled by a **committee** of `N` members,
  and it is enough that at least `t` of them sign.

The design constraint is unchanged: the verifier must trust a **single fixed
object**, embedded once, without fetching anything "in real time".

---

## The idea in one sentence

We do not pin the hash of the signers (that changes at every update: `t`
different members each time). We pin the **committee**. The signing subset can
vary freely, and the verifier validates it **against the fixed committee**,
outside the circuit, with a membership check.

| | Old model | New model |
|---|---|---|
| Embedded trust anchor | 1 public key | the **committee** (`N` public keys, or their root) + threshold `t` |
| Object in the struct | single signature | aggregated **proof** (leanVM) |
| Who signed this update | the sole signer | a subset `≥ t` of the committee (inside the proof) |
| What changes per update | the signature | the signing subset — **but the anchor stays fixed** |

---

## The (fixed) trust anchor

Instead of the single public key, each verifier embeds the **committee**:

```rust
/// FIXED trust anchor, embedded in every verifier (like the public key before).
struct Committee {
    members: Vec<XmssPublicKey>, // the N committee public keys
    threshold: usize,            // t: minimum number of distinct signers
}
```

This is the only datum the verifier must know a priori. Nothing else has to be
fetched "live": *who* signed a given update travels **inside** the proof.

---

## Status list structure

The `signature` field is replaced by the **aggregated proof** (serialized):

```rust
struct StatusList {
    status_list: Vec<[u8; 32]>, // the entries (e.g. revocation states)
    version: u32,               // slot/version, bound to the signature
    proof: Vec<u8>,             // <-- former "signature": the serialized leanVM aggregate
}
```

The **message signed** by the aggregate is the **status-list root** (a Poseidon2
merkleization of the entries → `[F; 8]`). The aggregate carries, inside itself,
the set of signers of *this* update (`info.pubkeys`).

---

## Verification (by anyone, starting from the DHT)

Four checks, three of them **outside the circuit** and negligible in cost:

```rust
fn verify_status_list(sl: &StatusList, committee: &Committee) -> bool {
    // The proof (former "signature") is a leanVM single-message aggregate.
    let agg: SingleMessageAggregateSignature = deserialize(&sl.proof);

    // 1) Are all signers members of the fixed committee? (membership test)
    if !agg.info.pubkeys.iter().all(|pk| committee.members.contains(pk)) {
        return false;
    }

    // 2) Is the proof bound to THIS exact status list?
    //    Without this, one could attach a valid proof of a DIFFERENT list.
    if agg.info.message != status_list_root_fe(&sl.status_list) {
        return false;
    }

    // 3) Quorum: at least t distinct members signed.
    if agg.info.pubkeys.len() < committee.threshold {
        return false;
    }

    // 4) Does the aggregate verify? (one SNARK verification, ~ms, independent of t)
    verify_single_message_aggregate(&agg).is_ok()
}
```

**Check (2) is the most important for security:** it binds the proof to this
specific list. `verify_single_message_aggregate` only attests "these listed
public keys signed *this* message"; it is up to the verifier to check that the
message is the root of the list it is holding.

---

## Why this solves the problem

- **"The hash of the signers always changes"** → not a problem, because we do
  **not** pin the signers' hash. We pin the **committee**, and check that the
  (variable) subset is `⊆ committee` with cardinality `≥ t`. Having the subset
  change at every update is normal and expected.
- **"Anyone must be able to verify"** → yes: the embedded `Committee` anchor and
  the struct fetched from the DHT are enough. No data to retrieve in real time.
- Verification costs **one SNARK verification** (independent of how many signed)
  plus a membership test against the committee.

---

## Committee rotation

When the committee changes (new members, periodic rotation), the **embedded
anchor** (`members`, `threshold`) is updated. This is a rare governance event,
exactly as rotating the old single-key root of trust would have been.

---

## Optional extensions (not required for the scenario)

- **Tiny anchor (32 bytes).** Instead of the `N` keys, embed only
  `committee_root = hash(members)`; the struct ships the member list and the
  verifier checks `hash(members) == committee_root` before steps 1/3. No change
  to the circuit.
- **Hiding *who* signed** (revealing only "`t`-of-`N` satisfied"). This requires
  moving participation into the *witness* and proving membership + threshold
  **inside** the circuit, in zero knowledge. Not needed for a status list: here
  we care that *the committee authorized*, not the identity of the signers.

---

## Implementation note

The base scheme requires **no changes to leanVM**: steps 1 and 3 (committee
membership and quorum) are cleartext checks run by the verifier, outside the
proof. The leanVM proof only attests the validity of the signatures on the
message; the trust link "those signers belong to my committee" is a local check
against the fixed anchor.
