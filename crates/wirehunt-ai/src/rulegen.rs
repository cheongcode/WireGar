use anyhow::Result;
use wirehunt_core::models::Finding;

use crate::provider::{AiClient, ChatMessage};

const SYSTEM_PROMPT: &str = r#"You are WireHunt's rule generator. Given a detection finding from network forensic analysis, generate detection rules in multiple formats:

1. **Suricata rule** - IDS/IPS rule that would detect similar traffic
2. **Sigma rule** - SIEM-agnostic detection rule in YAML format
3. **WireHunt query** - Query for the WireHunt search index

For each rule, include:
- A descriptive rule name and SID
- Relevant content matches, flow conditions, and metadata
- MITRE ATT&CK references
- Severity/priority mapping

Output the rules in fenced code blocks with the format name."#;

pub struct RuleGenerator {
    client: AiClient,
}

impl RuleGenerator {
    pub fn new(client: AiClient) -> Self {
        Self { client }
    }

    pub async fn generate_from_finding(&self, finding: &Finding) -> Result<String> {
        let finding_summary = format!(
            "Title: {}\nDescription: {}\nSeverity: {:?}\nConfidence: {:.0}%\nCategory: {:?}\nMITRE: {}\nTags: {}",
            finding.title,
            finding.description,
            finding.severity,
            finding.confidence * 100.0,
            finding.category,
            finding.mitre_attack.join(", "),
            finding.tags.join(", "),
        );

        let messages = vec![
            ChatMessage {
                role: "system".into(),
                content: SYSTEM_PROMPT.into(),
            },
            ChatMessage {
                role: "user".into(),
                content: format!(
                    "Generate detection rules for this finding:\n\n{}\n\nGenerate Suricata, Sigma, and WireHunt query rules.",
                    finding_summary,
                ),
            },
        ];
        self.client.chat(&messages).await
    }
}
