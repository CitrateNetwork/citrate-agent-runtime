//! HUP-S7.5: the model seam can report token usage, and a client that cannot see usage reports
//! none (unknown), never zero.

use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, TokenUsage};

struct Plain;
impl LlmClient for Plain {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        Ok(AssistantTurn::text("hi"))
    }
}

struct Reporting;
impl LlmClient for Reporting {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.complete_with_usage(req).map(|(t, _)| t)
    }
    fn complete_with_usage(
        &self,
        _req: &CompletionRequest,
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        Ok((
            AssistantTurn::text("hi"),
            Some(TokenUsage {
                prompt_tokens: 12,
                completion_tokens: 3,
                generation_ms: None,
            }),
        ))
    }
}

fn req() -> CompletionRequest {
    CompletionRequest {
        model: "m".into(),
        messages: vec![],
        tools: vec![],
        max_tokens: 16,
    }
}

#[test]
fn a_client_that_cannot_see_usage_reports_none() {
    let (turn, usage) = Plain.complete_with_usage(&req()).unwrap();
    assert_eq!(turn.content, "hi");
    assert_eq!(usage, None);
}

#[test]
fn a_reporting_client_passes_usage_through() {
    let (_, usage) = Reporting.complete_with_usage(&req()).unwrap();
    assert_eq!(
        usage,
        Some(TokenUsage {
            prompt_tokens: 12,
            completion_tokens: 3,
            generation_ms: None,
        })
    );
}
