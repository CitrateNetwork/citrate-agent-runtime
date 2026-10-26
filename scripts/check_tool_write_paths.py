#!/usr/bin/env python3
"""Tool-layer write-path guard.

The coding tools in `agent-code/src/tools/` write files at paths a model
chooses. Those writes must go through `safe_write.rs`, which opens every
component with `openat` + `O_NOFOLLOW` from the workspace root and refuses
multiply-linked files. A path-based write (`fs::write`, `File::create`,
`OpenOptions::new`, `create_dir_all`, `fs::copy`, `fs::rename`,
`symlink`, `hard_link`) anywhere else in that directory is flagged.

Exceptions are explicit and local: the flagged line, or the line directly
above it, must carry `// write-path-ok: <reason>` with a non-empty reason.
`safe_write.rs` itself is the one file not scanned for writes.

Scratch directories: a tool that needs a scratch directory (e.g. an isolated
HOME for a subprocess) must get it from `scratch_home.rs`, which creates it
fresh with a random name and mode 0700 and never reuses an existing path or
follows a link. Building a name under the temp dir by hand (`temp_dir()`,
`process::id()`) anywhere else in the directory is flagged; the exception
marker is `// scratch-path-ok: <reason>`.

Items under `#[cfg(test)]` / `#[cfg(all(test, ...))]` are test code and are
not scanned.

Usage: check_tool_write_paths.py [--self-test] [repo_root]
Exit codes: 0 clean, 1 violations (listed as file:line).
"""
import os
import re
import sys

TOOLS_DIR = os.path.join("agent-code", "src", "tools")
EXEMPT_FILE = "safe_write.rs"
SCRATCH_FILE = "scratch_home.rs"
PATTERN = re.compile(
    r"\b(?:fs::write|File::create(?:_new)?|OpenOptions::new|create_dir_all|"
    r"fs::copy|fs::rename|symlink|hard_link)\s*\("
)
MARKER = re.compile(r"//\s*write-path-ok:\s*\S")
SCRATCH_PATTERN = re.compile(r"\b(?:temp_dir|process::id)\s*\(")
SCRATCH_MARKER = re.compile(r"//\s*scratch-path-ok:\s*\S")
TEST_ATTR = re.compile(r"^\s*#\[cfg\((?:test|all\(test\b[^\]]*)\)\]")


def non_test_lines(lines):
    """Yield (index, line) for lines outside `#[cfg(test)]` items."""
    skipping = False
    depth = 0
    opened = False
    for i, line in enumerate(lines):
        if not skipping and TEST_ATTR.match(line):
            skipping, depth, opened = True, 0, False
            continue
        if skipping:
            code = line.split("//", 1)[0]
            depth += code.count("{") - code.count("}")
            opened = opened or "{" in code
            if (opened and depth <= 0) or (not opened and code.rstrip().endswith(";")):
                skipping = False
            continue
        yield i, line


def scan_text(text, pattern=PATTERN, marker=MARKER):
    """Return 1-based line numbers of unmarked matches of `pattern` in non-test code."""
    lines = text.splitlines()
    hits = []
    for i, line in non_test_lines(lines):
        code = line.split("//", 1)[0]
        if not pattern.search(code):
            continue
        if marker.search(line) or (i > 0 and marker.search(lines[i - 1])):
            continue
        hits.append(i + 1)
    return hits


def scan_scratch(text):
    return scan_text(text, SCRATCH_PATTERN, SCRATCH_MARKER)


def self_test():
    bad = "fn f(p: &Path) {\n    std::fs::write(p, b\"x\").unwrap();\n}\n"
    assert scan_text(bad) == [2], "negative control: an unmarked fs::write must be flagged"
    bad2 = "let f = std::fs::OpenOptions::new().write(true).open(p)?;\n"
    assert scan_text(bad2) == [1], "negative control: OpenOptions must be flagged"
    bad3 = "tokio::fs::create_dir_all(parent).await?;\n"
    assert scan_text(bad3) == [1], "negative control: create_dir_all must be flagged"
    empty_reason = "// write-path-ok:\nstd::fs::write(p, b\"x\")?;\n"
    assert scan_text(empty_reason) == [2], "an empty reason must not exempt"
    ok_above = "// write-path-ok: tool-owned scratch dir\nstd::fs::create_dir_all(&d);\n"
    assert scan_text(ok_above) == [], "marker on the line above exempts"
    ok_same = "std::fs::create_dir_all(&d); // write-path-ok: tool-owned scratch dir\n"
    assert scan_text(ok_same) == [], "marker on the same line exempts"
    comment = "// we used to call fs::write(p) here\n"
    assert scan_text(comment) == [], "comments are not code"
    test_mod = (
        "fn f() {}\n#[cfg(all(test, unix))]\nmod tests {\n    fn t() {\n"
        "        std::fs::write(p, b\"x\").unwrap();\n    }\n}\nfn g(p: &Path) {\n"
        "    std::fs::write(p, b\"x\").unwrap();\n}\n"
    )
    assert scan_text(test_mod) == [9], "test items are skipped; code after them is still scanned"
    test_fn = "#[cfg(test)]\nfn t() { std::fs::write(p, b\"x\").unwrap(); }\nstd::fs::write(q, b\"y\")?;\n"
    assert scan_text(test_fn) == [3], "a one-line test item ends at its closing brace"
    test_use = "#[cfg(test)]\nuse std::fs::write;\nstd::fs::write(q, b\"y\")?;\n"
    assert scan_text(test_use) == [3], "a test-only `use` ends at its semicolon"
    old_scratch = (
        "let scratch_home = std::env::temp_dir().join(format!(\n"
        "    \"citrate-gitops-home-{}-{}\",\n    std::process::id(),\n    SEQ.fetch_add(1, Relaxed)\n));\n"
    )
    assert scan_scratch(old_scratch) == [1, 3], "negative control: a hand-built temp-dir name must be flagged"
    ok_scratch = "// scratch-path-ok: logged only, never created\nlet pid = std::process::id();\n"
    assert scan_scratch(ok_scratch) == [], "scratch marker exempts"
    good_scratch = "let home = ScratchHome::create(\"citrate-gitops-home-\")?;\n"
    assert scan_scratch(good_scratch) == [], "the scratch_home helper is not flagged"
    print("check_tool_write_paths: self-test ok")


def main(argv):
    args = [a for a in argv if a != "--self-test"]
    if "--self-test" in argv:
        self_test()
        if not args:
            return 0
    root = args[0] if args else os.getcwd()
    tools = os.path.join(root, TOOLS_DIR)
    if not os.path.isdir(tools):
        print(f"check_tool_write_paths: {tools} not found", file=sys.stderr)
        return 1
    violations = []
    scratch_violations = []
    for name in sorted(os.listdir(tools)):
        if not name.endswith(".rs") or name == EXEMPT_FILE:
            continue
        path = os.path.join(tools, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for line in scan_text(text):
            violations.append(f"{os.path.join(TOOLS_DIR, name)}:{line}")
        if name != SCRATCH_FILE:
            for line in scan_scratch(text):
                scratch_violations.append(f"{os.path.join(TOOLS_DIR, name)}:{line}")
    if violations:
        print("path-based writes in the tool layer must go through safe_write.rs")
        print("(or carry `// write-path-ok: <reason>`):")
        for v in violations:
            print(f"  {v}")
    if scratch_violations:
        print("scratch directories in the tool layer must come from scratch_home.rs")
        print("(or carry `// scratch-path-ok: <reason>`):")
        for v in scratch_violations:
            print(f"  {v}")
    if violations or scratch_violations:
        return 1
    print("check_tool_write_paths: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
