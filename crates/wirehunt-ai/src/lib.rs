pub mod provider;
pub mod copilot;
pub mod decoder;
pub mod rulegen;

pub use provider::{AiClient, AiConfig, AiProvider, ChatMessage};
pub use copilot::{AnalystCopilot, summarize_report};
pub use decoder::DecodeAssistant;
pub use rulegen::RuleGenerator;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
