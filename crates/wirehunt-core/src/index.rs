use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use crate::models::*;

pub struct SearchIndex {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub table: String,
    pub id: String,
    pub snippet: String,
    pub rank: f64,
    pub metadata: std::collections::HashMap<String, String>,
}

impl SearchIndex {
    pub fn create(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("cannot create index at {}", path.display()))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        conn.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS fts_streams USING fts5(
                id UNINDEXED, flow_id UNINDEXED, protocol, content, summary,
                tokenize='unicode61'
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_dns USING fts5(
                query_name, record_type, response_data, response_code,
                is_response UNINDEXED,
                tokenize='unicode61'
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_http USING fts5(
                method, uri, host, status_code UNINDEXED,
                user_agent, content_type, cookies, headers,
                tokenize='unicode61'
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_credentials USING fts5(
                id UNINDEXED, kind, username, secret, service, host,
                tokenize='unicode61'
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_artifacts USING fts5(
                id UNINDEXED, kind, name, mime_type, sha256, md5,
                size_bytes UNINDEXED,
                tokenize='unicode61'
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_findings USING fts5(
                id UNINDEXED, title, description, severity, confidence UNINDEXED,
                category, mitre_attack, tags,
                tokenize='unicode61'
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_tls USING fts5(
                version, sni, cipher_suite, ja3_hash, ja3s_hash,
                cert_subject, cert_issuer,
                tokenize='unicode61'
            );
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;

        Ok(Self { conn })
    }

    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!("index not found at {}", path.display());
        }
        let conn = Connection::open(path)?;
        Ok(Self { conn })
    }

    pub fn build_from_report(&self, report: &Report) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        tx.execute("DELETE FROM fts_streams", [])?;
        tx.execute("DELETE FROM fts_dns", [])?;
        tx.execute("DELETE FROM fts_http", [])?;
        tx.execute("DELETE FROM fts_credentials", [])?;
        tx.execute("DELETE FROM fts_artifacts", [])?;
        tx.execute("DELETE FROM fts_findings", [])?;
        tx.execute("DELETE FROM fts_tls", [])?;

        for stream in &report.streams {
            let content = stream
                .segments
                .iter()
                .filter_map(|seg| String::from_utf8(seg.data.clone()).ok())
                .collect::<Vec<_>>()
                .join(" ");
            let content_trimmed = if content.len() > 100_000 {
                &content[..100_000]
            } else {
                &content
            };
            tx.execute(
                "INSERT INTO fts_streams (id, flow_id, protocol, content, summary)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    stream.id,
                    stream.flow_id,
                    format!("{:?}", stream.protocol),
                    content_trimmed,
                    stream.summary.as_deref().unwrap_or(""),
                ],
            )?;
        }

        for rec in &report.dns_records {
            tx.execute(
                "INSERT INTO fts_dns (query_name, record_type, response_data, response_code, is_response)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    rec.query_name,
                    rec.record_type,
                    rec.response_data.join(", "),
                    rec.response_code.as_deref().unwrap_or(""),
                    if rec.is_response { "true" } else { "false" },
                ],
            )?;
        }

        for tx_http in &report.http_transactions {
            let headers = tx_http
                .request_headers
                .iter()
                .chain(tx_http.response_headers.iter())
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n");
            tx.execute(
                "INSERT INTO fts_http (method, uri, host, status_code, user_agent, content_type, cookies, headers)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    tx_http.method,
                    tx_http.uri,
                    tx_http.host.as_deref().unwrap_or(""),
                    tx_http.status_code.map(|c| c.to_string()).unwrap_or_default(),
                    tx_http.user_agent.as_deref().unwrap_or(""),
                    tx_http.content_type.as_deref().unwrap_or(""),
                    tx_http.cookies.join("; "),
                    headers,
                ],
            )?;
        }

        for cred in &report.credentials {
            tx.execute(
                "INSERT INTO fts_credentials (id, kind, username, secret, service, host)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    cred.id,
                    format!("{:?}", cred.kind),
                    cred.username.as_deref().unwrap_or(""),
                    cred.secret,
                    cred.service.as_deref().unwrap_or(""),
                    cred.host.as_deref().unwrap_or(""),
                ],
            )?;
        }

        for art in &report.artifacts {
            tx.execute(
                "INSERT INTO fts_artifacts (id, kind, name, mime_type, sha256, md5, size_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    art.id,
                    format!("{:?}", art.kind),
                    art.name.as_deref().unwrap_or(""),
                    art.mime_type.as_deref().unwrap_or(""),
                    art.sha256,
                    art.md5,
                    art.size_bytes.to_string(),
                ],
            )?;
        }

        for finding in &report.findings {
            tx.execute(
                "INSERT INTO fts_findings (id, title, description, severity, confidence, category, mitre_attack, tags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    finding.id,
                    finding.title,
                    finding.description,
                    format!("{:?}", finding.severity),
                    format!("{:.0}", finding.confidence * 100.0),
                    format!("{:?}", finding.category),
                    finding.mitre_attack.join(", "),
                    finding.tags.join(", "),
                ],
            )?;
        }

        for tls in &report.tls_sessions {
            tx.execute(
                "INSERT INTO fts_tls (version, sni, cipher_suite, ja3_hash, ja3s_hash, cert_subject, cert_issuer)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    tls.version,
                    tls.sni.as_deref().unwrap_or(""),
                    tls.cipher_suite.as_deref().unwrap_or(""),
                    tls.ja3_hash.as_deref().unwrap_or(""),
                    tls.ja3s_hash.as_deref().unwrap_or(""),
                    tls.cert_subject.as_deref().unwrap_or(""),
                    tls.cert_issuer.as_deref().unwrap_or(""),
                ],
            )?;
        }

        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('pcap', ?1)",
            params![report.metadata.pcap_filename],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('version', ?1)",
            params![report.metadata.wirehunt_version],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('indexed_at', ?1)",
            params![chrono::Utc::now().to_rfc3339()],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn query(&self, dsl: &str, limit: usize) -> Result<Vec<QueryResult>> {
        let parsed = parse_query_dsl(dsl);
        let mut results = Vec::new();

        match &parsed {
            ParsedQuery::TableScoped { table, fts_expr } => {
                let tbl = table_alias(table);
                if let Some(tbl) = tbl {
                    let rows = self.search_table(tbl, fts_expr, limit)?;
                    results.extend(rows);
                } else {
                    anyhow::bail!("unknown table alias '{}'", table);
                }
            }
            ParsedQuery::FreeText(expr) => {
                let per_table = (limit / 7).max(5);
                for tbl in ALL_TABLES {
                    if let Ok(rows) = self.search_table(tbl, expr, per_table) {
                        results.extend(rows);
                    }
                }
                results.sort_by(|a, b| b.rank.partial_cmp(&a.rank).unwrap_or(std::cmp::Ordering::Equal));
                results.truncate(limit);
            }
        }

        Ok(results)
    }

    fn search_table(&self, table: &str, fts_expr: &str, limit: usize) -> Result<Vec<QueryResult>> {
        let sql = format!(
            "SELECT *, rank FROM {} WHERE {} MATCH ?1 ORDER BY rank LIMIT ?2",
            table, table
        );
        let mut stmt = self.conn.prepare(&sql)?;

        let col_count = stmt.column_count();
        let col_names: Vec<String> = (0..col_count)
            .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
            .collect();

        let mut results = Vec::new();
        let rows = stmt.query_map(params![fts_expr, limit as i64], |row| {
            let mut meta = std::collections::HashMap::new();
            let mut snippet = String::new();
            let mut id_val = String::new();

            for (i, name) in col_names.iter().enumerate() {
                if name == "rank" {
                    continue;
                }
                let val: String = row.get::<_, String>(i).unwrap_or_default();
                if name == "id" {
                    id_val = val.clone();
                }
                if !val.is_empty() {
                    if !snippet.is_empty() {
                        snippet.push_str(" | ");
                    }
                    let display = if val.len() > 120 {
                        format!("{}...", &val[..120])
                    } else {
                        val.clone()
                    };
                    snippet.push_str(&format!("{}={}", name, display));
                }
                meta.insert(name.clone(), val);
            }

            let rank: f64 = row.get::<_, f64>(col_count - 1).unwrap_or(0.0);

            Ok(QueryResult {
                table: table.to_string(),
                id: id_val,
                snippet,
                rank: -rank,
                metadata: meta,
            })
        })?;

        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }
}

const ALL_TABLES: &[&str] = &[
    "fts_streams",
    "fts_dns",
    "fts_http",
    "fts_credentials",
    "fts_artifacts",
    "fts_findings",
    "fts_tls",
];

fn table_alias(name: &str) -> Option<&'static str> {
    match name.to_lowercase().as_str() {
        "stream" | "streams" | "fts_streams" => Some("fts_streams"),
        "dns" | "fts_dns" => Some("fts_dns"),
        "http" | "fts_http" => Some("fts_http"),
        "cred" | "creds" | "credentials" | "fts_credentials" => Some("fts_credentials"),
        "artifact" | "artifacts" | "fts_artifacts" => Some("fts_artifacts"),
        "finding" | "findings" | "fts_findings" => Some("fts_findings"),
        "tls" | "fts_tls" => Some("fts_tls"),
        _ => None,
    }
}

#[derive(Debug)]
enum ParsedQuery {
    TableScoped { table: String, fts_expr: String },
    FreeText(String),
}

fn parse_query_dsl(dsl: &str) -> ParsedQuery {
    let trimmed = dsl.trim();

    if let Some(idx) = trimmed.find(':') {
        let before = &trimmed[..idx];
        if !before.contains(' ') && table_alias(before).is_some() {
            let after = trimmed[idx + 1..].trim().to_string();
            let fts_expr = dsl_to_fts5(&after);
            return ParsedQuery::TableScoped {
                table: before.to_string(),
                fts_expr,
            };
        }
    }

    ParsedQuery::FreeText(dsl_to_fts5(trimmed))
}

fn dsl_to_fts5(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len());
    let mut chars = expr.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                out.push('"');
                for inner in chars.by_ref() {
                    out.push(inner);
                    if inner == '"' {
                        break;
                    }
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_free_text() {
        let parsed = parse_query_dsl("evil.com");
        assert!(matches!(parsed, ParsedQuery::FreeText(_)));
    }

    #[test]
    fn test_parse_table_scoped() {
        let parsed = parse_query_dsl("dns:evil.com");
        match parsed {
            ParsedQuery::TableScoped { table, fts_expr } => {
                assert_eq!(table, "dns");
                assert_eq!(fts_expr, "evil.com");
            }
            _ => panic!("expected TableScoped"),
        }
    }

    #[test]
    fn test_create_and_query_index() -> Result<()> {
        let idx = SearchIndex::create(Path::new(":memory:"))?;

        let report = Report {
            metadata: ReportMetadata {
                wirehunt_version: "test".into(),
                generated_at: chrono::Utc::now(),
                pcap_filename: "test.pcap".into(),
                pcap_sha256: "abc".into(),
                pcap_size_bytes: 0,
                total_packets: 0,
                capture_start: None,
                capture_end: None,
                capture_duration_secs: 0.0,
                profile: AnalysisProfile::Ctf,
            },
            findings: vec![],
            flows: vec![],
            streams: vec![],
            artifacts: vec![],
            credentials: vec![],
            iocs: vec![],
            dns_records: vec![DnsRecord {
                query_name: "evil.example.com".into(),
                record_type: "A".into(),
                response_data: vec!["1.2.3.4".into()],
                ttl: Some(300),
                is_response: true,
                response_code: Some("NOERROR".into()),
            }],
            http_transactions: vec![],
            tls_sessions: vec![],
            host_profiles: vec![],
            timeline: vec![],
            statistics: AnalysisStatistics {
                protocol_breakdown: std::collections::HashMap::new(),
                top_talkers: vec![],
                top_ports: vec![],
                total_findings: 0,
                total_artifacts: 0,
                total_credentials: 0,
                analysis_duration_ms: 0,
            },
        };

        idx.build_from_report(&report)?;

        let results = idx.query("dns:evil", 10)?;
        assert!(!results.is_empty());
        assert_eq!(results[0].table, "fts_dns");

        let results2 = idx.query("evil", 10)?;
        assert!(!results2.is_empty());

        Ok(())
    }
}
