use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProvider {
    OpenAi,
    Anthropic,
    Ollama,
}

pub struct AiClient {
    pub provider: AiProvider,
}

impl AiClient {
    pub fn new(provider: AiProvider) -> Self {
        Self { provider }
    }
}
