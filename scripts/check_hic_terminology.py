#!/usr/bin/env python3
"""HIC terminology guard (PBA-L8-018).

Owner standard: the human-oversight model is HIC (Human In Control, graded
HIC-1 / HIC-2 / HIC-X). "HITL" and "human-in-the-loop" must not appear in
anything a person reads: docs, Gherkin, UI markup, user-facing strings, doc
comments, and package descriptions.

Scanned: .md .mdx .markdown .feature .slint .ts .tsx .js .jsx .mjs .cjs .rs
.toml .yml .yaml and package.json (any extension case). The whole file is
scanned, so string literals and comments are both covered. Matching runs on
the whole text, so a phrase split across lines, comment markers or markdown
emphasis is still caught.

Not flagged (code identifiers that cannot be renamed without breaking a build):
  - lowercase `hitl` tokens: crate, module, file and path names
    (`nist-agent-hitl`, `nist_agent_hitl`, `hitl::`, `hitl/`)
  - CamelCase / SCREAMING_SNAKE identifiers that merely contain the letters
    (`HitlUiError`, `HITLQuorum`, `HITL_TIMEOUT_SECS`), and `::HITL` paths
  - words that contain the letters (`Whitlock`)

Exceptions are explicit: `.hic-allowlist` at the repo root holds one
`path:substring` entry per line. A hit is allowed only when the hit's line in
that exact file contains that non-empty substring. There is no directory skip:
an immutable dated audit record needs its own entry.

Exit codes: 0 clean, 1 violations (listed as file:line), 2 bad allowlist.
"""
import os
import re
import sys

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
ROOT = os.path.abspath(ARGS[0] if ARGS else ".")
SELF = "check_hic_terminology.py"
SKIP_DIRS = {".git", "node_modules", "target", ".next", "dist", "build", ".turbo", "vendor"}
EXTS = (".md", ".mdx", ".markdown", ".feature", ".slint", ".ts", ".tsx", ".js", ".jsx",
        ".mjs", ".cjs", ".rs", ".toml", ".yml", ".yaml")

# Separator between the words of the phrase: whitespace (incl. line breaks),
# ASCII and Unicode hyphens/dashes, comment markers, markdown emphasis.
SEP = r"(?:[\s\-‐-―−/*#!>]|&nbsp;)+"
BANNED = [
    # human in (the) loop, any case, any separator; not snake_case identifiers
    re.compile(r"(?<![A-Za-z0-9_])human" + SEP + r"in" + SEP + r"(?:the" + SEP + r")?loop(?![A-Za-z0-9])", re.I),
    # HITL / HITLs / HiTL / Hitl / HITL_gate as a word; not ::HITL paths,
    # not CamelCase continuations (HITLQuorum, HitlUiError), not SCREAMING_SNAKE
    # constants (HITL_TIMEOUT), not lowercase identifiers (hitl, nist-agent-hitl)
    re.compile(r"(?<![A-Za-z0-9_])(?<!::)H[Ii][Tt][Ll](?:s|_[a-z][a-z0-9]*)?(?![A-Za-z0-9_])"),
    # dotted / spaced spelling: H.I.T.L, H. I. T. L.
    re.compile(r"(?<![A-Za-z0-9])H\.\s*I\.\s*T\.\s*L\b", re.I),
]


class AllowlistError(Exception):
    pass


def load_allowlist(root):
    entries = []
    path = os.path.join(root, ".hic-allowlist")
    if os.path.exists(path):
        for n, raw in enumerate(open(path, encoding="utf-8"), 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            file_part, sep, needle = line.partition(":")
            if not sep or not file_part.strip() or not needle.strip():
                raise AllowlistError(f".hic-allowlist:{n}: entry must be `path:non-empty-substring`: {line!r}")
            entries.append((file_part.strip(), needle.strip()))
    return entries


def wanted(name):
    low = name.lower()
    return low.endswith(EXTS) or low == "package.json"


def scan(root):
    allow = load_allowlist(root)
    bad = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if f == SELF or not wanted(f):
                continue
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            lines = text.split("\n")
            seen = set()
            for rx in BANNED:
                for m in rx.finditer(text):
                    ln = text.count("\n", 0, m.start()) + 1
                    if ln in seen:
                        continue
                    end_ln = text.count("\n", 0, m.end()) + 1
                    span = "\n".join(lines[ln - 1:end_ln])
                    if any(rel == fp and needle in span for fp, needle in allow):
                        continue
                    seen.add(ln)
                    bad.append(f"{rel}:{ln}: {lines[ln - 1].strip()[:160]}")
    return sorted(bad)


def self_test():
    """Oracles: every bypass found in review must fail, every identifier must pass."""
    import tempfile

    must_fail = {
        "a.md": "an HITL gate\n",
        "b.md": "a Human-in-the-Loop gate\n",
        "c.md": "a human in the loop gate\n",
        "d.md": "two HITLs\n",
        "e.md": "a HiTL gate\n",
        "f.md": "the HITL_gate step\n",
        "g.md": "a human-in-loop check\n",
        "h.md": "a human–in–the–loop check\n",
        "i.md": "a human—in—the—loop check\n",
        "j.md": "a Human-in-\n  the-loop check\n",
        "k.mdx": "an HITL gate\n",
        "l.MD": "an HITL gate\n",
        "audits/2026-01-01-log.md": "an HITL gate\n",
        "m.feature": "  Then the HITL queue shows the call\n",
        "n.slint": 'Text { text: "awaiting HITL decision"; }\n',
        "o.rs": '#[error("HITL timeout")]\nTimeout,\n',
        "p.rs": "/// Human-in-the-loop approval queue.\npub mod q;\n",
        "q.rs": "// human in\n// the loop gate\nfn f() {}\n",
        "r.tsx": "// HITL ceremony view\nexport const X = 1;\n",
        "s/Cargo.toml": '[package]\nname = "x-hitl"\ndescription = "HITL approval queue"\n',
        "t/package.json": '{"name": "x", "description": "Human-in-the-loop review"}\n',
        "u.md": "the H.I.T.L gate\n",
        "v.md": "a human-*in*-the-loop gate\n",
        "w.yml": "name: HITL gate\n",
    }
    must_pass = {
        "a.md": "an HIC gate, crate `nist-agent-hitl`, spec HITLQuorum.tla, path `agent/core/src/hitl/`\n",
        "b.rs": "use nist_agent_hitl::Queue;\nuse crate::hitl::signing;\nenum E { HitlUiError }\nconst HITL_TIMEOUT_SECS: u64 = 1;\nlet x = Error::HITL;\n",
        "c.md": "Mr. Whitlock approved it; the human_in_the_loop field is legacy\n",
        "d/Cargo.toml": '[dependencies]\nnist-agent-hitl = { path = "../nist-agent-hitl" }\n',
        "e.tsx": "import { hitl } from './hitl/index';\n",
    }
    ok = True

    def run(files, allow=None):
        with tempfile.TemporaryDirectory() as t:
            for name, body in files.items():
                full = os.path.join(t, name)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                open(full, "w", encoding="utf-8").write(body)
            if allow is not None:
                open(os.path.join(t, ".hic-allowlist"), "w").write(allow)
            return scan(t)

    for name, body in must_fail.items():
        if not run({name: body}):
            ok = False
            print(f"self-test: bypass not caught: {name}: {body!r}")
    for name, body in must_pass.items():
        hits = run({name: body})
        if hits:
            ok = False
            print(f"self-test: false positive: {hits}")
    # allowlist scoping
    if run({"x.md": "HITL gate\n"}, "other.md:HITL gate\n") == []:
        ok = False
        print("self-test: allowlist for another file must not apply")
    if run({"x.md": "HITL gate\n"}, "x.md:HITL gate\n") != []:
        ok = False
        print("self-test: exact allowlist entry must apply")
    for bad_allow in ("x.md:\n", "x.md:   \n", ":HITL\n", "x.md\n"):
        try:
            run({"x.md": "HITL gate\n"}, bad_allow)
            ok = False
            print(f"self-test: malformed allowlist accepted: {bad_allow!r}")
        except AllowlistError:
            pass
    n = len(must_fail) + len(must_pass) + 2 + 4
    print(f"HIC terminology guard self-test ({n} oracles):", "ok" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return self_test()
    try:
        bad = scan(ROOT)
    except AllowlistError as e:
        print(f"HIC terminology guard: {e}")
        return 2
    if bad:
        print("HIC terminology guard: use HIC (Human In Control), never HITL / human-in-the-loop.")
        for b in bad:
            print("  " + b)
        print(f"{len(bad)} violation(s). Add a `path:substring` line to .hic-allowlist only for code identifiers or immutable dated records.")
        return 1
    print("HIC terminology guard: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
