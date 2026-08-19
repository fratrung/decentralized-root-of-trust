#!/usr/bin/env python3
"""Mutation testing: delete a security check, confirm a test notices.

A green suite says nothing on its own. The question that matters is whether each
check is load-bearing *according to the tests* — and the only way to answer it is
to break the check and see who complains. This repository has been caught twice
by exactly that: `snark_verifier_node` had silently lost the slot check, and
`padding_bits_past_the_committee_are_refused` turned out never to reach the check
it was named after (it patched a byte in the middle of a signature, so the record
failed to verify for the wrong reason, and `verify_status_list`'s padding check
could be deleted with the whole suite still green).

    tools/mutate.py                     # every mutant, against the whole suite
    tools/mutate.py list                # names and targets
    tools/mutate.py check               # verify every pattern still matches
    tools/mutate.py run NAME [args...]  # one mutant; args go to `cargo test`

A mutant is EXPECTED TO FAIL. One that SURVIVES is the finding: either the check
is dead code, or nothing tests it.

Output: each mutant is named *before* it is applied and the verdict completes the
line, so the last line of the log always identifies the mutant currently live in
the working tree. This matters because a full run takes ~40 minutes with tracked
source modified throughout, and the obvious reaction to finding a mutated file is
to assume something has gone wrong.

Safety: every target file is backed up before the first edit and restored after
each mutant, with the restore verified by comparison. `finally` plus a signal
handler means Ctrl-C and a crashing `cargo` both still restore. If a restore ever
fails, the script says so loudly and names the file.

Why Python and not shell: the patterns are Rust source containing `|`, `;`, `{`
and newlines. Every shell-friendly field separator appears inside them. A first
version of this tool used `|` and silently truncated four patterns at the first
closure — `.filter(|sl| ...)` became `.filter(`, which still matched once, so the
tool reported "ok" while mutating something else entirely.
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Python block-buffers stdout when it is not a terminal, so a redirected run
# stayed mute for its full 40 minutes and only flushed at the end — exactly when
# the progress was no longer of any use. Line buffering costs nothing here.
sys.stdout.reconfigure(line_buffering=True)

GREEN, RED, YELLOW, DIM, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YELLOW = DIM = OFF = ""

# ---------------------------------------------------------------- the catalogue
#
# name -> (file, exact text to find, replacement)
#
# The text must appear EXACTLY ONCE; `check` enforces that, so a refactor that
# reformats a check fails loudly here instead of producing a mutant that patches
# nothing and "passes". Replacing with "" deletes the check outright.
#
# Keep this in step with what README/AGENTS.md call load-bearing. A check worth
# documenting is a check worth a mutant.

MUTANTS = {
    # --- PQSNARKVerifierModule::verify: the five checks of the SNARK path --
    "snark-1-membership": ("src/snark_verifier_node.rs", """        if !agg
            .info
            .pubkeys
            .iter()
            .all(|pk| self.committee.members().contains(pk))
        {
            return false;
        }""", "        if false { return false; }"),
    "snark-2-message": ("src/snark_verifier_node.rs", """        if agg.info.core.message != status_list_message(status_list.list(), status_list.version()) {
            return false;
        }""", "        if false { return false; }"),
    "snark-3-slot": ("src/snark_verifier_node.rs", """        if self.committee.slot_for(status_list.version()) != Some(agg.info.core.slot) {
            return false;
        }""", "        if false { return false; }"),
    "snark-4-quorum": ("src/snark_verifier_node.rs", """        if agg.info.pubkeys.len() < self.committee.threshold() {
            return false;
        }""", "        if false { return false; }"),
    "snark-5-proof": ("src/snark_verifier_node.rs", """        if verify_single_message_aggregate(&agg).is_err() {
            return false;
        }""", "        if false { return false; }"),

    # --- VerifierNode::verify_status_list: the raw path -------------------
    "raw-t-zero": ("src/verifier_node.rs", """        if self.committee.threshold() == 0 {
            return false;
        }""", "        if false { return false; }"),
    # Not merely canonicity: this is also what keeps `members[i]` in range, since
    # every index the bitmap yields is below the length it declares. There used to
    # be a second mutant here, "raw-padding-bits", deleting a sweep for set bits
    # above member n - 1. An SSZ BitList carries its length in a sentinel bit, so
    # those bits cannot exist and there is no longer a check to delete.
    "raw-bitmap-width": ("src/verifier_node.rs", """        if status_list.signer_slots() != n {
            return false;
        }""", "        if false { return false; }"),
    "raw-quorum": ("src/verifier_node.rs", """        if count < self.committee.threshold() || count != status_list.signatures().len() {
            return false;
        }""", "        if false { return false; }"),
    "raw-signatures": (
        "src/verifier_node.rs",
        "            .all(|(i, sig)| xmss_verify(&members[i], slot, &message, sig).is_ok())",
        "            .all(|(i, sig)| { let _ = (i, sig); true })",
    ),

    # --- the derivations the node types own -------------------------------
    #
    # The five checks above are the predicate; these are the two places a node
    # decides *what* to check against. Both are on the critical path of every
    # binary, and `snark_verifier_node` is where a check has actually been lost
    # before — it once held a second copy of the predicate with the slot check
    # missing.
    #
    # The prover mutant stands in for "the slot comes from the caller instead of the
    # anchor". That cannot be written as a text swap — the parameter does not exist —
    # so the derivation is made wrong instead, which fails in the same way.
    "snark-module-slot": (
        "src/snark_prover_node.rs",
        "            .slot_for(version)",
        "            .slot_for(version + 1)",
    ),
    "snark-module-is-newer": (
        "src/snark_verifier_node.rs",
        "        status_list.version() > self.status_list_last_version",
        "        status_list.version() >= self.status_list_last_version",
    ),
    "node-membership": (
        "src/verifier_node.rs",
        "        if !self.committee.members().contains(pub_key) {",
        "        if false {",
    ),

    # --- freshness --------------------------------------------------------
    "freshness-floor-strict": (
        "src/snark_verifier_node.rs",
        "            .filter(|sl| floor.is_none_or(|f| sl.version() > f))",
        "            .filter(|sl| floor.is_none_or(|f| sl.version() >= f))",
    ),
    "freshness-floor-off": (
        "src/snark_verifier_node.rs",
        "            .filter(|sl| floor.is_none_or(|f| sl.version() > f))\n",
        "",
    ),
    # The selection is the DHT layer choosing which record to trust. Returning the
    # newest *declared* version without verifying it hands the choice to whichever
    # peer lies hardest.
    "freshness-select-unverified": (
        "src/snark_verifier_node.rs",
        "        decoded.into_iter().find(|sl| self.verify(sl))",
        "        decoded.into_iter().next()",
    ),
    "hwm-strict": (
        "src/freshness.rs",
        "        if self.have && version <= self.current {",
        "        if self.have && version < self.current {",
    ),

    # --- the stateful-signature invariants --------------------------------
    "lock-off": (
        "src/atomic_slot_counter.rs",
        "    file.try_lock().map_err(|_| AtomicSlotCounterError::Busy)?;\n",
        "",
    ),
    "create-exists-check": (
        "src/atomic_slot_counter.rs",
        "        if path.exists() {",
        "        if false {",
    ),
    "dup-signer-guard": ("src/snark_prover_node.rs", "        duplicated.is_none(),", "        true,"),

    # --- wire format ------------------------------------------------------
    # Was "anchor-canonical", deleting the re-encode-and-compare that ruled out
    # postcard's padded varints. SSZ cannot express that ambiguity, so the check
    # is gone and there is nothing to mutate. What remains in `from_bytes` is the
    # invariant no wire format knows about: `t = 0` makes an unsigned record reach
    # quorum, `t > N` is unsatisfiable, and deserialization bypasses `new`.
    "anchor-threshold": ("src/committee.rs", """        if !(1..=value.members.len()).contains(&t) {""",
                         "        if false {"),
    "bitmap-population": (
        "src/status_list.rs",
        "        if value.signer_count() != value.signatures.len() {",
        "        if false {",
    ),

    # --- the numbers that reach the paper ---------------------------------
    "stats-bessel": ("src/stats.rs", "/ (n - 1) as f64", "/ n as f64"),
    "stats-median-even": (
        "src/stats.rs",
        "(self.0[n / 2 - 1] + self.0[n / 2]) / 2.0",
        "self.0[n / 2]",
    ),
    "stats-sort": (
        "src/stats.rs",
        '        v.sort_by(|a, b| a.partial_cmp(b).expect("NaN in measurement series"));\n',
        "",
    ),
}


class Workspace:
    """Pristine copies of every file the catalogue touches."""

    def __init__(self, files):
        self.dir = tempfile.mkdtemp(prefix="mutate-")
        self.files = sorted(files)
        for rel in self.files:
            shutil.copy2(os.path.join(ROOT, rel), os.path.join(self.dir, rel.replace("/", "_")))

    def _backup(self, rel):
        return os.path.join(self.dir, rel.replace("/", "_"))

    def original(self, rel):
        with open(self._backup(rel)) as f:
            return f.read()

    def apply(self, rel, old, new):
        """Returns the number of matches; writes only when it is exactly 1."""
        src = self.original(rel)
        n = src.count(old)
        if n == 1:
            with open(os.path.join(ROOT, rel), "w") as f:
                f.write(src.replace(old, new))
        return n

    def restore(self):
        """Puts every file back and proves it. Returns the files that did not.

        `shutil.copy` and an explicit `utime`, deliberately **not** `copy2`.
        `copy2` preserves the source's mtime, which is the pristine one from
        before the run — older than the artifacts cargo just built from the
        *mutated* source. cargo fingerprints on mtime, so it would consider the
        build current and hand the next `cargo test` a binary compiled from code
        that no longer exists on disk.

        That is not hypothetical: it is how this tool first went wrong. Every
        content check passed, `git diff` was clean, and `cargo test` failed with
        four sort-related errors in a file whose sort was demonstrably present.
        Stamping the restore with the current time makes the source strictly
        newer than anything built from the mutant, so the rebuild is forced.
        """
        bad = []
        for rel in self.files:
            live = os.path.join(ROOT, rel)
            shutil.copy(self._backup(rel), live)
            os.utime(live, None)
            with open(live) as a, open(self._backup(rel)) as b:
                if a.read() != b.read():
                    bad.append(rel)
        return bad

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def cargo_test(extra):
    p = subprocess.run(
        ["cargo", "test", "--release", *extra],
        cwd=ROOT, capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def uncommitted(files):
    """Which of `files` differ from the index/HEAD. Empty if git is unavailable."""
    try:
        p = subprocess.run(
            ["git", "diff", "--name-only", "HEAD", "--", *files],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [line for line in p.stdout.split() if line]


def who_failed(output):
    names = [
        line.split()[1]
        for line in output.splitlines()
        if line.startswith("test ") and line.rstrip().endswith("FAILED")
    ]
    seen = list(dict.fromkeys(names))
    return ", ".join(seen[:3]) + (f" (+{len(seen) - 3} more)" if len(seen) > 3 else "")


def run_one(ws, name, extra, position=""):
    """0 = caught (good), 1 = survived (finding), 2 = pattern stale.

    The name is printed *before* the mutant is applied, not after the verdict.
    A `cargo test` here takes a minute or more, during which the working tree is
    modified; without this the log is silent and the tree looks inexplicably
    dirty. The last line of the output now always names the mutant currently
    live, which is the first thing anyone asks when they open a mutated file.
    """
    rel, old, new = MUTANTS[name]
    print(f"  {position}{name:<24} ", end="", flush=True)

    matches = ws.apply(rel, old, new)
    if matches != 1:
        print(f"{YELLOW}PATTERN STALE{OFF} — {matches} matches in {rel}")
        ws.restore()
        return 2

    started = time.monotonic()
    rc, out = cargo_test(extra)
    elapsed = time.monotonic() - started
    bad = ws.restore()
    if bad:
        print(f"\n  !! RESTORE FAILED for {', '.join(bad)} — check `git diff` now", file=sys.stderr)
        sys.exit(3)

    if rc != 0:
        print(f"{GREEN}caught{OFF} ({elapsed:.0f}s) by {who_failed(out) or '(build failure)'}")
        return 0
    print(f"{RED}SURVIVED ({elapsed:.0f}s) — no test covers this check{OFF}")
    return 1


def main():
    argv = sys.argv[1:]
    cmd = argv[0] if argv else "all"

    if cmd == "list":
        width = max(len(n) for n in MUTANTS)
        for name, (rel, _, _) in MUTANTS.items():
            print(f"{name:<{width}}  {rel}")
        return 0

    ws = Workspace({rel for rel, _, _ in MUTANTS.values()})
    # A Ctrl-C during `cargo test` must not leave a mutated tree behind.
    #
    # SIGTERM matters just as much and used to be missing: Python's default for it
    # exits without unwinding, so `finally` never runs and the tree keeps whatever
    # mutant was applied. That is exactly what a plain `kill` or `pkill` sends, and
    # it happened — a killed run left `.slot_for(version + 1)` in
    # `snark_prover_node.rs` and a `>=` in `snark_verifier_node.rs`, staged, ready
    # to be committed as if they were real code.
    interrupt = lambda *_: (_ for _ in ()).throw(KeyboardInterrupt)
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    # The backups live in /tmp. A SIGKILL takes them with it, so uncommitted work
    # in a target file is at risk in a way committed work is not — say so first.
    if dirty := uncommitted(ws.files):
        print(f"{YELLOW}warning:{OFF} uncommitted changes in {', '.join(dirty)}. "
              f"The only copy is in {ws.dir}; commit or stash first.\n")
    try:
        if cmd == "check":
            print("verifying every pattern matches exactly once:")
            stale = 0
            for name, (rel, old, new) in MUTANTS.items():
                n = ws.apply(rel, old, new)
                ws.restore()
                if n == 1:
                    print(f"  {name:<24} ok")
                else:
                    print(f"  {name:<24} {RED}STALE{OFF} — {n} matches in {rel}")
                    stale += 1
            print(f"\n{len(MUTANTS)} patterns, {stale} stale")
            return 1 if stale else 0

        if cmd == "run":
            if len(argv) < 2 or argv[1] not in MUTANTS:
                print(f"usage: {sys.argv[0]} run NAME [cargo test args...]", file=sys.stderr)
                print(f"names: {', '.join(MUTANTS)}", file=sys.stderr)
                return 1
            return run_one(ws, argv[1], argv[2:])

        total = len(MUTANTS)
        print(f"mutation testing — {total} mutants, every line should say 'caught'")
        print(f"{DIM}the tree is modified while this runs: {', '.join(ws.files)}")
        print(f"do not commit until it finishes; `git show HEAD:<file>` for the real source{OFF}\n")

        started = time.monotonic()
        survived, stale = [], []
        for i, name in enumerate(MUTANTS, 1):
            r = run_one(ws, name, [], position=f"[{i:>2}/{total}] ")
            if r == 1:
                survived.append(name)
            elif r == 2:
                stale.append(name)

        caught = total - len(survived) - len(stale)
        mins = (time.monotonic() - started) / 60
        print(f"\n{total} mutants in {mins:.0f} min: "
              f"{caught} caught, {len(survived)} survived, {len(stale)} stale")
        if survived:
            print(f"{RED}survived (nothing tests these):{OFF} {', '.join(survived)}")
        if stale:
            print(f"{YELLOW}stale (pattern no longer matches):{OFF} {', '.join(stale)}")
        return 1 if survived or stale else 0
    finally:
        bad = ws.restore()
        ws.close()
        if bad:
            print(f"!! RESTORE FAILED for {', '.join(bad)}", file=sys.stderr)
        else:
            # Said out loud on purpose. A tool that rewrites tracked source owes
            # the reader an explicit "your tree is back", not silence.
            print(f"{DIM}tree restored: {len(ws.files)} files match their pre-run contents{OFF}")


if __name__ == "__main__":
    sys.exit(main())
