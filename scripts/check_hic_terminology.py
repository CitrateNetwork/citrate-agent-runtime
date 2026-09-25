#!/usr/bin/env python3
"""HIC terminology guard (PBA-L8-018).

Owner standard: the human-oversight model is HIC (Human In Control, graded
HIC-1 / HIC-2 / HIC-X). "HITL" and "human-in-the-loop" must not appear in
markdown prose. This check scans every *.md file and fails on either term.

Exceptions are explicit: `.hic-allowlist` at the repo root holds one
`path:substring` entry per line. A hit is allowed only when the line in that
file contains that substring (used for code identifiers such as crate names
or type names that cannot be renamed without breaking a build). Dated audit
records (audits/, .agentile/audits/) are immutable and are skipped.

Lowercase `hitl` is a crate/module/file-name token and is not matched.

Exit codes: 0 clean, 1 violations (listed as file:line).
"""
import os
import re
import sys

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
ROOT = os.path.abspath(ARGS[0] if ARGS else ".")
SKIP_DIRS = {".git", "node_modules", "target", ".next", "dist"}
SKIP_PREFIXES = ("audits/", ".agentile/audits/")
# Uppercase HITL as a word (so `nist-agent-hitl`, `HITLQuorum` do not match),
# or the phrase in any case with spaces or hyphens.
BANNED = re.compile(r"\bHITL\b|(?i:\bhuman[- ]in[- ]the[- ]loop\b)")


def load_allowlist(root):
    entries = []
    path = os.path.join(root, ".hic-allowlist")
    if os.path.exists(path):
        for raw in open(path, encoding="utf-8"):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            file_part, _, needle = line.partition(":")
            entries.append((file_part.strip(), needle))
    return entries


def scan(root):
    allow = load_allowlist(root)
    bad = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if not f.endswith(".md"):
                continue
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            if rel.startswith(SKIP_PREFIXES):
                continue
            for n, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
                if not BANNED.search(line):
                    continue
                if any(rel == fp and needle in line for fp, needle in allow):
                    continue
                bad.append(f"{rel}:{n}: {line.strip()[:160]}")
    return bad


def self_test():
    """Oracles that kill the obvious guard mutants (drop a pattern, ignore the
    allowlist path, always pass). Runs in CI before the real scan."""
    import tempfile

    cases = [
        ({"x.md": "an HITL gate\n"}, None, 1),
        ({"x.md": "a Human-in-the-Loop gate\n"}, None, 1),
        ({"x.md": "a human in the loop gate\n"}, None, 1),
        ({"x.md": "an HIC gate, crate `nist-agent-hitl`, spec HITLQuorum.tla\n"}, None, 0),
        ({"x.md": "HITL gate\n"}, "other.md:HITL gate\n", 1),
        ({"x.md": "HITL gate\n"}, "x.md:HITL gate\n", 0),
        ({"audits/2026-01-01.md": "HITL\n"}, None, 0),
    ]
    ok = True
    for i, (files, allow, want) in enumerate(cases):
        with tempfile.TemporaryDirectory() as t:
            for name, body in files.items():
                os.makedirs(os.path.dirname(os.path.join(t, name)), exist_ok=True)
                open(os.path.join(t, name), "w").write(body)
            if allow:
                open(os.path.join(t, ".hic-allowlist"), "w").write(allow)
            got = 1 if scan(t) else 0
            if got != want:
                ok = False
                print(f"self-test case {i} FAILED: want {want}, got {got}")
    print("HIC terminology guard self-test:", "ok" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return self_test()
    bad = scan(ROOT)
    if bad:
        print("HIC terminology guard: use HIC (Human In Control), never HITL / human-in-the-loop.")
        for b in bad:
            print("  " + b)
        print(f"{len(bad)} violation(s). Add a `path:substring` line to .hic-allowlist only for code identifiers.")
        return 1
    print("HIC terminology guard: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
