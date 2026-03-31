# citrate-agent-chain

Native blockchain tools for the Citrate chat agent.

## Overview

This crate provides seven `AgentTool` implementations that let the AI agent
interact with the Citrate blockchain. Tools cover wallet queries, transaction
building, contract deployment and interaction, AI model registry browsing,
and inference execution. Each tool registers with the shared `ToolRegistry`
from `citrate-agent-core`.

## Tools

| Tool | Description |
|------|-------------|
| `check_balance` | Query wallet balance |
| `send_tx` | Build and send a transaction (requires approval) |
| `deploy_contract` | Deploy compiled Solidity bytecode (requires approval) |
| `query_contract` | Read-only contract call |
| `list_models` | Browse the on-chain AI model registry |
| `run_inference` | Invoke an on-chain AI model |
| `explain_tx` | Decode and explain a transaction |

## Usage

```rust
use citrate_agent_chain::register_tools;
use citrate_agent_core::tool::ToolRegistry;

let registry = ToolRegistry::new();
register_tools(&registry).await;
assert_eq!(registry.count().await, 7);
```

## Tests

```bash
cargo test -p citrate-agent-chain
```

Test count: 2 tests covering tool registration and tool definition format
validation (all 7 tool names present with correct function-call schema).
