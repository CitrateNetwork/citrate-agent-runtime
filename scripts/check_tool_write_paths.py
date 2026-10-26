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
`safe_write.rs` itself is the one file not scanned.

Usage: check_tool_write_paths.py [--self-test] [repo_root]
Exit codes: 0 clean, 1 violations (listed as file:line).
"""
import os
import re
import sys

TOOLS_DIR = os.path.join("agent-code", "src", "tools")
EXEMPT_FILE = "safe_write.rs"
PATTERN = re.compile(
    r"\b(?:fs::write|File::create(?:_new)?|OpenOptions::new|create_dir_all|"
    r"fs::copy|fs::rename|symlink|hard_link)\s*\("
)
MARKER = re.compile(r"//\s*write-path-ok:\s*\S")


def scan_text(text):
    """Return 1-based line numbers of unmarked path-based writes."""
    lines = text.splitlines()
    hits = []
    for i, line in enumerate(lines):
        code = line.split("//", 1)[0]
        if not PATTERN.search(code):
            continue
        if MARKER.search(line) or (i > 0 and MARKER.search(lines[i - 1])):
            continue
        hits.append(i + 1)
    return hits


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
    for name in sorted(os.listdir(tools)):
        if not name.endswith(".rs") or name == EXEMPT_FILE:
            continue
        path = os.path.join(tools, name)
        with open(path, encoding="utf-8") as fh:
            for line in scan_text(fh.read()):
                violations.append(f"{os.path.join(TOOLS_DIR, name)}:{line}")
    if violations:
        print("path-based writes in the tool layer must go through safe_write.rs")
        print("(or carry `// write-path-ok: <reason>`):")
        for v in violations:
            print(f"  {v}")
        return 1
    print("check_tool_write_paths: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
