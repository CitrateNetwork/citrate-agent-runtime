//! Manual smoke: hit the configured local LLM through the real client.
//! Run: `HERMES_LLM_MODEL=llama3.1:latest cargo run -p hermes-llm --example smoke`

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let c = hermes_llm::LlmClient::from_env();
    eprintln!("endpoint={} model={} health={}", c.endpoint(), c.model(), c.health().await);
    let reply = c
        .respond(&["In one sentence, who do you work for and what can't you do yet?".to_string()])
        .await?;
    println!("REPLY: {reply}");
    Ok(())
}
