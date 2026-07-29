# TODO

Open items from the security & correctness review of **2026-07-24**. Validate
each in the next session before marking done. Severity is relative to *this
component* (the verifier + versioning/anti-rollback slice), not the whole system.

---

## Verified sound — do not re-audit (audit baseline)

These were checked against source this session; record them so we don't re-derive.

- **The cleartext checks are bound to the SNARK.** `verify_single_message_aggregate`
  verifies the proof against `info.build_input_data()`, built from `message`,
  `slot`, `pubkeys`
  (leanVM `rec_aggregation/src/single_message_aggregation.rs:201-204`, `:104-118`).
  Tampering with any of those breaks verification, so `verify_proof` checks 1-3
  constrain exactly the values check 4 authenticates. The conjunction is sound.
- **Quorum distinctness is enforced at deserialize.** `check_single_message_pubkeys`
  (non-empty, strictly sorted, no duplicates) runs inside `SingleMessageInfo::deserialize`
  (`:55-70`, `:75-86`), so `verify_proof` check 3 (`pubkeys.len() >= t`) counts
  distinct members.
- **`bytecode_claim` is not forgeable.** `deserialize` takes only the `point` from
  the wire and *recomputes* the value from the process-global bytecode (`:39`,
  `:57-70`). Our `postcard::from_bytes` path goes through this, so no injected
  claim — and this is why `setup_*` must run before decoding a proof.
- **Version binding.** `status_list_root_fe(list, version)` folds the version into
  the signed message with 16-bit limbs (injective, no modular aliasing); no
  structural list/version collision without breaking Poseidon collision
  resistance. Security test C exercises it.
- **`(key, slot)` never reused** in the demo (updates `SLOT+0..9`, attacks
  `SLOT+10/11`, outsiders `SLOT`).

---

## Open items

### 1. Non-canonical decoding of the inner proof  — priority: MEDIUM
- **Where:** `src/status_list.rs`, `StatusList::proof()` (uses `postcard::from_bytes`).
- **Problem:** `from_bytes` ignores trailing bytes. The *outer* `StatusList` is
  canonical, but the inner `zk_proof: Vec<u8>` can carry trailing garbage after the
  aggregate, and `proof()` accepts it.
- **Failure scenario:** an attacker appends bytes to `zk_proof`, producing a
  different outer encoding (different content-address in the DHT) for a record that
  verifies identically — malleability / dedup-spam. Not a crypto break.
- **Fix:** decode with `postcard::take_from_bytes` and reject if `!rest.is_empty()`,
  mirroring the outer `StatusList::from_bytes` / `Committee::from_bytes`. Then the
  padded variant fails `proof()` → fails `verify_proof` → only the canonical
  encoding verifies.

### 2. High-water mark integrity & fail-open  — priority: MEDIUM
- **Where:** `src/freshness.rs` (`parse`, load path) and the state-file location.
- **Problem:** a missing/corrupt state file is treated as "no mark" → high-water
  resets to 0. That is **fail-open** for rollback protection.
- **Failure scenario:** anything that can truncate/corrupt `verifier-highwater.state`
  (local tampering, partial write, disk error) silently re-opens the full rollback
  window; a peer can then replay an old-but-valid authorization list.
- **Fix / decision needed:** on an ICS device keep the file on trusted/tamper-
  resistant storage; decide **fail-closed** (refuse to advance / alert if the state
  is unreadable but a mark was expected) vs the current fail-open. Consider an
  integrity tag (MAC) if the storage is not trusted.

### 3. High-water mark durability (`fsync`)  — priority: LOW
- **Where:** `src/freshness.rs`, `persist()`.
- **Problem:** write-tmp + rename is atomic but not `fsync`'d; the doc comment
  ("a crash right after cannot lose the advance") overstates this.
- **Failure scenario:** power loss right after `try_advance` returns can leave the
  new mark not durably on disk → on reboot the window is (partly) reopened.
- **Fix:** `fsync` the temp file before rename and `fsync` the directory after, and
  soften the comment.

### 4. `select_freshest` is linear in candidate count  — priority: LOW
- **Where:** `src/committee.rs`, `select_freshest`.
- **Problem:** candidates are verified newest-first until one passes; a flood of
  high-declared-version records forces one failed verification each (~28 ms).
- **Failure scenario:** a hostile set of K junk records costs K verifications before
  the real newest is reached — a mild DoS amplifier.
- **Fix:** cap the candidate set the caller passes (Kademlia's k is small anyway),
  or bound the number of failed verifications tried.

### 5. `Committee::new` does not validate distinct members  — priority: LOW
- **Where:** `src/committee.rs`, `Committee::new`.
- **Problem:** no dedup/sort of `members`. Not exploitable (quorum counts distinct
  *signers* from the proof, not `|committee|`), but a misconfigured anchor with a
  duplicate key silently has a smaller real N than it appears.
- **Fix:** defensively reject or dedup duplicates (and optionally require sorted) at
  construction.

---

## Deferred design work (its own session)

### Committee rotation / re-key protocol
Not a bug — the missing next layer. When the committee changes, the anchor changes,
and the high-water mark resets (by design, keyed to the anchor fingerprint). Open
questions to design deliberately:
- **Anchor hand-off:** how a verifier learns the new anchor without external trust.
  Leading idea: `old committee signs new committee's anchor` → a chain of
  generations a verifier can walk from the anchor it holds.
- **Freshness across the hand-off:** the version counter is decoupled from the XMSS
  slot precisely so it stays monotonic across a rotation; confirm the anti-rollback
  mark migrates cleanly to the new generation.
- **Governance:** who authorizes a rotation, threshold/membership changes, and
  compromise-driven emergency rotation.
