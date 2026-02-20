use anyhow::Result;
use wirehunt_core::models::*;

use crate::provider::{AiClient, ChatMessage};

const SYSTEM_PROMPT_EXPLAIN: &str = r#"You are WireHunt, an expert network forensic analyst. You are given a summary of a PCAP analysis report. Your job is to:

1. Explain what happened in the network capture in plain English
2. Identify the likely scenario (CTF challenge, attack, normal traffic, etc.)
3. Highlight the most significant findings
4. Describe attacker techniques if applicable (reference MITRE ATT&CK IDs when relevant)
5. Suggest next investigation steps

Be concise but thorough. Use bullet points for findings. If CTF flags were found, highlight them prominently."#;

const SYSTEM_PROMPT_SOLVE: &str = r#"You are WireHunt, an expert CTF player and network forensic analyst. You are given a summary of a PCAP analysis from a CTF challenge. Your job is to:

1. Analyze the findings and identify potential flag locations
2. Suggest decode strategies for obfuscated data (base64, XOR, ROT13, hex, etc.)
3. Identify encoding layers that may be hiding flags
4. Point out suspicious patterns that could contain flags
5. If flags were already found, explain how they were discovered
6. Suggest additional techniques to find more flags

Think step by step. Be creative about where flags might be hidden (DNS TXT records, HTTP headers, ICMP payloads, file metadata, etc.)."#;

pub struct AnalystCopilot {
    client: AiClient,
}

impl AnalystCopilot {
    pub fn new(client: AiClient) -> Self {
        Self { client }
    }

    pub async fn explain(&self, report: &Report, allow_raw: bool) -> Result<String> {
        let summary = summarize_report(report, allow_raw);
        let messages = vec![
            ChatMessage {
                role: "system".into(),
                content: SYSTEM_PROMPT_EXPLAIN.into(),
            },
            ChatMessage {
                role: "user".into(),
                content: format!("Analyze this network capture:\n\n{}", summary),
            },
        ];
        self.client.chat(&messages).await
    }

    pub async fn solve(&self, report: &Report) -> Result<String> {
        let summary = summarize_report(report, true);
        let messages = vec![
            ChatMessage {
                role: "system".into(),
                content: SYSTEM_PROMPT_SOLVE.into(),
            },
            ChatMessage {
                role: "user".into(),
                content: format!(
                    "Solve this CTF network challenge:\n\n{}\n\nFind all flags and explain the solution.",
                    summary
                ),
            },
        ];
        self.client.chat(&messages).await
    }

    pub async fn suggest_queries(&self, report: &Report) -> Result<String> {
        let summary = summarize_report(report, false);
        let messages = vec![
            ChatMessage {
                role: "system".into(),
                content: "You are WireHunt, a network forensic tool. Given a capture summary, suggest useful search queries the analyst should run using the WireHunt query DSL. Format each suggestion as: `query_string` - explanation. Suggest 5-10 queries.".into(),
            },
            ChatMessage {
                role: "user".into(),
                content: format!("Suggest queries for:\n\n{}", summary),
            },
        ];
        self.client.chat(&messages).await
    }
}

pub fn summarize_report(report: &Report, include_raw: bool) -> String {
    let mut out = String::with_capacity(8192);

    out.push_str(&format!("## Capture Metadata\n"));
    out.push_str(&format!("- File: {}\n", report.metadata.pcap_filename));
    out.push_str(&format!("- SHA256: {}\n", &report.metadata.pcap_sha256[..report.metadata.pcap_sha256.len().min(16)]));
    out.push_str(&format!("- Packets: {}\n", report.metadata.total_packets));
    out.push_str(&format!("- Duration: {:.1}s\n", report.metadata.capture_duration_secs));
    out.push_str(&format!("- Profile: {:?}\n\n", report.metadata.profile));

    out.push_str(&format!("## Statistics\n"));
    out.push_str(&format!("- Flows: {}\n", report.flows.len()));
    out.push_str(&format!("- Streams: {}\n", report.streams.len()));
    out.push_str(&format!("- Findings: {}\n", report.findings.len()));
    out.push_str(&format!("- Credentials: {}\n", report.credentials.len()));
    out.push_str(&format!("- Artifacts: {}\n", report.artifacts.len()));
    out.push_str(&format!("- DNS records: {}\n", report.dns_records.len()));
    out.push_str(&format!("- HTTP transactions: {}\n", report.http_transactions.len()));
    out.push_str(&format!("- TLS sessions: {}\n\n", report.tls_sessions.len()));

    if !report.statistics.protocol_breakdown.is_empty() {
        out.push_str("## Protocol Breakdown\n");
        let mut protos: Vec<_> = report.statistics.protocol_breakdown.iter().collect();
        protos.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in protos.iter().take(15) {
            out.push_str(&format!("- {}: {} flows\n", name, count));
        }
        out.push('\n');
    }

    if !report.findings.is_empty() {
        out.push_str("## Findings (sorted by severity)\n");
        for f in report.findings.iter().take(20) {
            let mitre = if f.mitre_attack.is_empty() {
                String::new()
            } else {
                format!(" [{}]", f.mitre_attack.join(", "))
            };
            out.push_str(&format!(
                "- [{:?}] {} (conf: {:.0}%){}\n  {}\n",
                f.severity,
                f.title,
                f.confidence * 100.0,
                mitre,
                f.description,
            ));
        }
        out.push('\n');
    }

    if !report.credentials.is_empty() {
        out.push_str("## Harvested Credentials\n");
        for c in report.credentials.iter().take(20) {
            out.push_str(&format!(
                "- {:?}: user={} secret={} svc={}\n",
                c.kind,
                c.username.as_deref().unwrap_or("-"),
                mask_secret(&c.secret),
                c.service.as_deref().unwrap_or("-"),
            ));
        }
        out.push('\n');
    }

    if !report.dns_records.is_empty() {
        out.push_str("## DNS Records (top 20)\n");
        for r in report.dns_records.iter().take(20) {
            let data = if r.response_data.is_empty() {
                String::new()
            } else {
                format!(" -> {}", r.response_data.join(", "))
            };
            out.push_str(&format!(
                "- {} {} {}{}\n",
                if r.is_response { "R" } else { "Q" },
                r.record_type,
                r.query_name,
                data,
            ));
        }
        out.push('\n');
    }

    if !report.http_transactions.is_empty() {
        out.push_str("## HTTP Transactions\n");
        for tx in report.http_transactions.iter().take(20) {
            out.push_str(&format!(
                "- {} {} {} [{}]\n",
                tx.method,
                tx.host.as_deref().unwrap_or("-"),
                tx.uri,
                tx.status_code.map(|c| c.to_string()).unwrap_or_default(),
            ));
        }
        out.push('\n');
    }

    if !report.tls_sessions.is_empty() {
        out.push_str("## TLS Sessions\n");
        for t in report.tls_sessions.iter().take(10) {
            out.push_str(&format!(
                "- {} SNI={} cipher={}\n",
                t.version,
                t.sni.as_deref().unwrap_or("-"),
                t.cipher_suite.as_deref().unwrap_or("-"),
            ));
        }
        out.push('\n');
    }

    if include_raw && !report.streams.is_empty() {
        out.push_str("## Stream Excerpts (first 500 bytes of text-like streams)\n");
        let mut shown = 0;
        for s in &report.streams {
            if shown >= 10 {
                break;
            }
            let all_data: Vec<u8> = s.segments.iter().flat_map(|seg| seg.data.iter().copied()).collect();
            if let Ok(text) = String::from_utf8(all_data.clone()) {
                let trimmed = if text.len() > 500 { &text[..500] } else { &text };
                if trimmed.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                    out.push_str(&format!(
                        "### Stream {} ({:?}, {} bytes)\n```\n{}\n```\n\n",
                        &s.id[..12],
                        s.protocol,
                        s.total_bytes,
                        trimmed,
                    ));
                    shown += 1;
                }
            }
        }
    }

    out
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 8 {
        return s.to_string();
    }
    format!("{}...{}", &s[..4], &s[s.len() - 4..])
}
