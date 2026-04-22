//! Citrate Agent Chain — native blockchain tools for the chat agent.
//!
//! These tools let the AI agent interact with the Citrate chain:
//! - check_balance: query wallet balance
//! - send_tx: build and send a transaction (requires approval)
//! - deploy_contract: deploy compiled Solidity (requires approval)
//! - query_contract: read-only contract call
//! - list_models: browse AI model registry
//! - run_inference: invoke an on-chain model
//! - explain_tx: decode and explain a transaction
//! - get_block_height: read current chain height
//! - get_peer_count: read P2P + mempool stats
//! - get_recent_blocks: list the N most recent blocks
//! - get_tx_history: list recent transactions for an address

pub mod tools;

use citrate_agent_core::tool::ToolRegistry;
use std::sync::Arc;

/// Register all chain tools with the given registry.
pub async fn register_tools(registry: &ToolRegistry) {
    registry.register(Arc::new(tools::CheckBalance)).await;
    registry.register(Arc::new(tools::SendTransaction)).await;
    registry.register(Arc::new(tools::DeployContract)).await;
    registry.register(Arc::new(tools::QueryContract)).await;
    registry.register(Arc::new(tools::ListModels)).await;
    registry.register(Arc::new(tools::RunInference)).await;
    registry.register(Arc::new(tools::ExplainTransaction)).await;
    // P960-A WP-A.2: read-only chain-state tools.
    registry.register(Arc::new(tools::GetBlockHeight)).await;
    registry.register(Arc::new(tools::GetPeerCount)).await;
    registry.register(Arc::new(tools::GetRecentBlocks)).await;
    registry.register(Arc::new(tools::GetTxHistory)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_all_tools() {
        let registry = ToolRegistry::new();
        register_tools(&registry).await;
        assert_eq!(registry.count().await, 11);
    }

    #[tokio::test]
    async fn test_tool_definitions_format() {
        let registry = ToolRegistry::new();
        register_tools(&registry).await;
        let defs = registry.tool_definitions().await;
        assert_eq!(defs.len(), 11);
        // Verify all tool names are present
        let names: Vec<String> = defs.iter()
            .map(|d| d["function"]["name"].as_str().expect("name").to_string())
            .collect();
        assert!(names.contains(&"check_balance".to_string()));
        assert!(names.contains(&"send_tx".to_string()));
        assert!(names.contains(&"deploy_contract".to_string()));
        assert!(names.contains(&"query_contract".to_string()));
        assert!(names.contains(&"list_models".to_string()));
        assert!(names.contains(&"run_inference".to_string()));
        assert!(names.contains(&"explain_tx".to_string()));
        // P960-A chain-state tools
        assert!(names.contains(&"get_block_height".to_string()));
        assert!(names.contains(&"get_peer_count".to_string()));
        assert!(names.contains(&"get_recent_blocks".to_string()));
        assert!(names.contains(&"get_tx_history".to_string()));
    }
}
