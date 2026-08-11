#!/usr/bin/env python3
"""Mutation testing: delete a security check, confirm a test notices.

A green suite says nothing on its own. The question that matters is whether each
check is load-bearing *according to the tests* — and the only way to answer it is
to break the check and see who complains. This repository has been caught twice
by exactly that: `snark_verifier_node` had silently lost the slot check, and
`padding_bits_past_the_committee_are_refused` turned out never to reach the check
it was named after (it patched a byte in the middle of a signature, so the record
failed to verify for the wrong reason, and `verify_quorum`'s padding check could
be deleted with the whole suite still green).

    tools/mutate.py                     # every mutant, against the whole suite
    tools/mutate.py list                # names and targets
    tools/mutate.py check               # verify every pattern still matches
    tools/mutate.py run NAME [args...]  # one mutant; args go to `cargo test`

A mutant is EXPECTED TO FAIL. One that SURVIVES is the finding: either the check
is dead code, or nothing tests it.

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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
# Keep this in step with what README/AGENT.md call load-bearing. A check worth
# documenting is a check worth a mutant.

MUTANTS = {
    # --- verify_proof: the five checks of the SNARK path -------------------
    "snark-1-membership": ("src/committee.rs", """    if !agg
        .info
        .pubkeys
        .iter()
        .all(|pk| committee.members.contains(pk))
    {
        return false;
    }""", "    if false { return false; }"),
    "snark-2-message": ("src/committee.rs", """    if agg.info.message != status_list_root_fe(status_list.list(), status_list.version()) {
        return false;
    }""", "    if false { return false; }"),
    "snark-3-slot": ("src/committee.rs", """    if committee.slot_for(status_list.version()) != Some(agg.info.slot) {
        return false;
    }""", "    if false { return false; }"),
    "snark-4-quorum": ("src/committee.rs", """    if agg.info.pubkeys.len() < committee.t {
        return false;
    }""", "    if false { return false; }"),
    "snark-5-proof": ("src/committee.rs", """    if verify_single_message_aggregate(&agg).is_err() {
        return false;
    }""", "    if false { return false; }"),

    # --- verify_quorum: the raw path --------------------------------------
    "raw-t-zero": ("src/committee.rs", """    if committee.t == 0 {
        return false;
    }""", "    if false { return false; }"),
    "raw-bitmap-width": ("src/committee.rs", """    if bitmap.len() != n.div_ceil(8) {
        return false;
    }""", "    if false { return false; }"),
    # Not merely canonicity: this is what keeps `members[i]` in range. Removing
    # it turns a two-bit edit of a genuine record into a remote panic.
    "raw-padding-bits": ("src/committee.rs", """    if !n.is_multiple_of(8)
        && let Some(last) = bitmap.last()
        && (last >> (n % 8)) != 0
    {
        return false;
    }
""", ""),
    "raw-quorum": ("src/committee.rs", """    if count < committee.t || count != status_list.signatures().len() {
        return false;
    }""", "    if false { return false; }"),
    "raw-signatures": (
        "src/committee.rs",
        "        .all(|(i, sig)| xmss_verify(&committee.members[i], &message, sig, slot).is_ok())",
        "        .all(|(i, sig)| { let _ = (i, sig); true })",
    ),

    # --- freshness --------------------------------------------------------
    "freshness-floor-strict": (
        "src/committee.rs",
        "        .filter(|sl| floor.is_none_or(|f| sl.version() > f))",
        "        .filter(|sl| floor.is_none_or(|f| sl.version() >= f))",
    ),
    "freshness-floor-off": (
        "src/committee.rs",
        "        .filter(|sl| floor.is_none_or(|f| sl.version() > f))\n",
        "",
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
    "dup-signer-guard": ("src/committee.rs", "        duplicated.is_none(),", "        true,"),

    # --- wire format ------------------------------------------------------
    "anchor-canonical": ("src/committee.rs", """        if value.to_bytes() != bytes {
            return Err("anchor is not canonically encoded".to_string());
        }
""", ""),
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


def who_failed(output):
    names = [
        line.split()[1]
        for line in output.splitlines()
        if line.startswith("test ") and line.rstrip().endswith("FAILED")
    ]
    seen = list(dict.fromkeys(names))
    return ", ".join(seen[:3]) + (f" (+{len(seen) - 3} more)" if len(seen) > 3 else "")


def run_one(ws, name, extra):
    """0 = caught (good), 1 = survived (finding), 2 = pattern stale."""
    rel, old, new = MUTANTS[name]
    matches = ws.apply(rel, old, new)
    if matches != 1:
        print(f"  {name:<24} {YELLOW}PATTERN STALE{OFF} — {matches} matches in {rel}")
        ws.restore()
        return 2

    rc, out = cargo_test(extra)
    bad = ws.restore()
    if bad:
        print(f"  !! RESTORE FAILED for {', '.join(bad)} — check `git diff` now", file=sys.stderr)
        sys.exit(3)

    if rc != 0:
        print(f"  {name:<24} {GREEN}caught{OFF} by {who_failed(out) or '(build failure)'}")
        return 0
    print(f"  {name:<24} {RED}SURVIVED — no test covers this check{OFF}")
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
    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
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

        print("mutation testing — every line should say 'caught'\n")
        survived, stale = [], []
        for name in MUTANTS:
            r = run_one(ws, name, [])
            if r == 1:
                survived.append(name)
            elif r == 2:
                stale.append(name)

        caught = len(MUTANTS) - len(survived) - len(stale)
        print(f"\n{len(MUTANTS)} mutants: {caught} caught, {len(survived)} survived, {len(stale)} stale")
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


if __name__ == "__main__":
    sys.exit(main())
