# citrate-agent-code

Coding agent tools and bridge for the IDE/Studio tab.

## Overview

Six OpenCode-style tools for AI-assisted coding within the Citrate desktop
application. The `CodeAgentBridge` routes LLM tool calls to the appropriate
tool and gathers workspace context. All tools enforce path traversal prevention,
rejecting paths outside the workspace directory. Production use requires an
`ApprovalFlow`; an ungated constructor exists only behind `#[cfg(test)]`.

## Modules

- `tools` -- Six `AgentTool` implementations: `FileRead`, `FileWrite`, `FileEdit`, `ShellExec`, `GitOps`, `SearchCode`
- `bridge` -- `CodeAgentBridge` routing layer with mandatory `ApprovalFlow`, workspace context gathering, and tool dispatch

## Tools

| Tool | Risk | Description |
|------|------|-------------|
| `file_read` | Low | Read file contents with optional line ranges |
| `file_write` | Medium | Write content to a file, creating directories as needed |
| `file_edit` | Medium | Replace an exact unique string occurrence in a file |
| `shell_exec` | Medium | Execute a shell command with timeout |
| `git_ops` | Medium | Git status, diff, commit (validates non-empty message) |
| `search_code` | Low | Grep-like pattern search with optional file type filter |

## Usage

```rust
use citrate_agent_code::{register_tools, bridge::CodeAgentBridge};
use citrate_agent_core::tool::ToolRegistry;
use citrate_agent_core::approval::ApprovalFlow;
use std::sync::Arc;

let registry = Arc::new(ToolRegistry::new());
register_tools(&registry).await;

let bridge = CodeAgentBridge::with_approval(registry, approval_flow);
let result = bridge.execute_tool("file_read", params, &ctx).await?;
```

## Tests

```bash
cargo test -p citrate-agent-code
```

Test count: 34 tests covering tool registration, risk levels, file read/write/edit
operations, shell execution, git operations, code search, path traversal prevention,
bridge dispatch, and workspace context gathering.
