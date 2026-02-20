use anyhow::Result;

use crate::provider::{AiClient, ChatMessage};

const SYSTEM_PROMPT: &str = r#"You are WireHunt's decode assistant. Given binary or encoded data from a network capture, your job is to:

1. Identify the encoding or format (base64, hex, XOR, ROT13, custom cipher, compressed, etc.)
2. Suggest a decode chain to recover the plaintext
3. If the data looks like a known file format, identify it
4. Look for patterns that suggest CTF flags or sensitive data
5. Provide the WireHunt decode command to apply your suggested chain

WireHunt decode chain format: "base64 | xor:0x42 | gunzip"
Available operations: base64, base32, hex, url, rot13, gzip, zlib, xor:0xNN"#;

pub struct DecodeAssistant {
    client: AiClient,
}

impl DecodeAssistant {
    pub fn new(client: AiClient) -> Self {
        Self { client }
    }

    pub async fn analyze_data(&self, data: &str, context: &str) -> Result<String> {
        let messages = vec![
            ChatMessage {
                role: "system".into(),
                content: SYSTEM_PROMPT.into(),
            },
            ChatMessage {
                role: "user".into(),
                content: format!(
                    "Context: {}\n\nData to analyze:\n```\n{}\n```\n\nIdentify the encoding and suggest how to decode it.",
                    context,
                    data,
                ),
            },
        ];
        self.client.chat(&messages).await
    }
}
