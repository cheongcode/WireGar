use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AiProvider {
    OpenAi,
    Anthropic,
    Ollama,
}

impl std::fmt::Display for AiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiProvider::OpenAi => write!(f, "openai"),
            AiProvider::Anthropic => write!(f, "anthropic"),
            AiProvider::Ollama => write!(f, "ollama"),
        }
    }
}

impl std::str::FromStr for AiProvider {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "openai" | "open_ai" => Ok(AiProvider::OpenAi),
            "anthropic" | "claude" => Ok(AiProvider::Anthropic),
            "ollama" | "local" => Ok(AiProvider::Ollama),
            _ => anyhow::bail!("unknown provider '{}': expected openai, anthropic, or ollama", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub provider: AiProvider,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::OpenAi,
            api_key: None,
            model: None,
            base_url: None,
            max_tokens: Some(4096),
            temperature: Some(0.3),
        }
    }
}

impl AiConfig {
    pub fn config_path() -> std::path::PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".wirehunt")
            .join("config.toml")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(Self::from_env());
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let mut config: AiConfig =
            toml::from_str(&contents).with_context(|| "invalid config.toml")?;
        config.apply_env_overrides();
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(&path, contents)?;
        Ok(())
    }

    fn from_env() -> Self {
        let mut config = Self::default();
        config.apply_env_overrides();
        config
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            if self.api_key.is_none() {
                self.api_key = Some(key);
                self.provider = AiProvider::OpenAi;
            }
        }
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            if self.api_key.is_none() {
                self.api_key = Some(key);
                self.provider = AiProvider::Anthropic;
            }
        }
        if let Ok(url) = std::env::var("OLLAMA_URL") {
            self.base_url = Some(url);
            if self.api_key.is_none() {
                self.provider = AiProvider::Ollama;
            }
        }
        if let Ok(model) = std::env::var("WIREHUNT_AI_MODEL") {
            self.model = Some(model);
        }
    }

    fn default_model(&self) -> &str {
        match self.provider {
            AiProvider::OpenAi => "gpt-4o",
            AiProvider::Anthropic => "claude-sonnet-4-20250514",
            AiProvider::Ollama => "llama3",
        }
    }

    fn base_url(&self) -> &str {
        self.base_url.as_deref().unwrap_or(match self.provider {
            AiProvider::OpenAi => "https://api.openai.com/v1",
            AiProvider::Anthropic => "https://api.anthropic.com/v1",
            AiProvider::Ollama => "http://localhost:11434",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

pub struct AiClient {
    config: AiConfig,
    http: reqwest::Client,
}

impl AiClient {
    pub fn new(config: AiConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        Ok(Self { config, http })
    }

    pub fn from_config() -> Result<Self> {
        let config = AiConfig::load()?;
        Self::new(config)
    }

    pub async fn chat(&self, messages: &[ChatMessage]) -> Result<String> {
        match self.config.provider {
            AiProvider::OpenAi => self.chat_openai(messages).await,
            AiProvider::Anthropic => self.chat_anthropic(messages).await,
            AiProvider::Ollama => self.chat_ollama(messages).await,
        }
    }

    async fn chat_openai(&self, messages: &[ChatMessage]) -> Result<String> {
        let api_key = self
            .config
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no API key configured. Run `wirehunt ai login` or set OPENAI_API_KEY"))?;

        let model = self
            .config
            .model
            .as_deref()
            .unwrap_or(self.config.default_model());

        let body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": self.config.max_tokens.unwrap_or(4096),
            "temperature": self.config.temperature.unwrap_or(0.3),
        });

        let url = format!("{}/chat/completions", self.config.base_url());
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("failed to reach OpenAI API")?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("OpenAI API error ({}): {}", status, text);
        }

        let json: serde_json::Value = serde_json::from_str(&text)?;
        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(content)
    }

    async fn chat_anthropic(&self, messages: &[ChatMessage]) -> Result<String> {
        let api_key = self
            .config
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no API key configured. Run `wirehunt ai login` or set ANTHROPIC_API_KEY"))?;

        let model = self
            .config
            .model
            .as_deref()
            .unwrap_or(self.config.default_model());

        let system_msg = messages
            .iter()
            .find(|m| m.role == "system")
            .map(|m| m.content.clone());

        let user_messages: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != "system")
            .map(|m| {
                serde_json::json!({
                    "role": m.role,
                    "content": m.content,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": model,
            "messages": user_messages,
            "max_tokens": self.config.max_tokens.unwrap_or(4096),
            "temperature": self.config.temperature.unwrap_or(0.3),
        });

        if let Some(sys) = system_msg {
            body["system"] = serde_json::Value::String(sys);
        }

        let url = format!("{}/messages", self.config.base_url());
        let resp = self
            .http
            .post(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("failed to reach Anthropic API")?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("Anthropic API error ({}): {}", status, text);
        }

        let json: serde_json::Value = serde_json::from_str(&text)?;
        let content = json["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(content)
    }

    async fn chat_ollama(&self, messages: &[ChatMessage]) -> Result<String> {
        let model = self
            .config
            .model
            .as_deref()
            .unwrap_or(self.config.default_model());

        let body = serde_json::json!({
            "model": model,
            "messages": messages,
            "stream": false,
        });

        let url = format!("{}/api/chat", self.config.base_url());
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("failed to reach Ollama (is it running?)")?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("Ollama error ({}): {}", status, text);
        }

        let json: serde_json::Value = serde_json::from_str(&text)?;
        let content = json["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(content)
    }
}
