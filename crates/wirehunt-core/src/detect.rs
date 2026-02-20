use crate::models::*;

/// Run all detection rules and produce scored findings.
/// The report already contains all dissected protocol data and credentials.
/// `flag_values` are CTF flags found during extraction.
pub fn run_detection(
    report: &Report,
    flag_values: &[(String, String, Option<String>)],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // CTF flag findings
    for (value, stream_id, decode_chain) in flag_values {
        findings.push(
            Finding::new(
                format!("CTF Flag Found: {}", value),
                format!(
                    "Flag pattern detected{}",
                    decode_chain
                        .as_ref()
                        .map(|c| format!(" via decode chain: {}", c))
                        .unwrap_or_else(|| " in plaintext".to_string())
                ),
                Severity::Critical,
                1.0,
                FindingCategory::CtfFlag,
            )
            .with_evidence(EvidenceRef::from_stream(
                stream_id,
                format!("Flag '{}' found in stream", value),
            ))
            .with_mitre("T1020"),
        );
    }

    // Credential findings
    for cred in &report.credentials {
        let severity = match cred.kind {
            CredentialKind::HttpBasicAuth | CredentialKind::FtpLogin
            | CredentialKind::TelnetLogin | CredentialKind::SmtpAuth
            | CredentialKind::Pop3Login => Severity::High,
            CredentialKind::SshPrivateKey => Severity::Critical,
            CredentialKind::Jwt | CredentialKind::ApiKey => Severity::High,
            CredentialKind::SessionCookie | CredentialKind::BearerToken => Severity::Medium,
            _ => Severity::Medium,
        };

        let user = cred.username.as_deref().unwrap_or("unknown");
        findings.push(
            Finding::new(
                format!("{:?} credential: {}", cred.kind, user),
                format!(
                    "Credential of type {:?} harvested from network traffic",
                    cred.kind
                ),
                severity,
                0.95,
                FindingCategory::Credential,
            )
            .with_evidence(cred.evidence.clone())
            .with_mitre("T1552.001"),
        );
    }

    // Cleartext protocol findings
    for flow in &report.flows {
        let proto = flow.detected_protocol.unwrap_or(AppProtocol::Unknown);
        match proto {
            AppProtocol::Ftp | AppProtocol::Telnet => {
                findings.push(
                    Finding::new(
                        format!("Cleartext {:?} session detected", proto),
                        format!(
                            "{:?} transmits credentials and data in plaintext: {}:{} -> {}:{}",
                            proto,
                            flow.key.src_ip, flow.key.src_port,
                            flow.key.dst_ip, flow.key.dst_port,
                        ),
                        Severity::Medium,
                        0.9,
                        FindingCategory::ClearTextProtocol,
                    )
                    .with_mitre("T1071.001"),
                );
            }
            _ => {}
        }
    }

    // DNS anomaly detection
    for rec in &report.dns_records {
        // Long subdomain labels can indicate DNS tunneling
        if rec.query_name.len() > 60 {
            findings.push(
                Finding::new(
                    format!("Suspicious long DNS name: {}", &rec.query_name[..40]),
                    "Unusually long DNS query name may indicate DNS tunneling or data exfiltration".to_string(),
                    Severity::Medium,
                    0.7,
                    FindingCategory::SuspiciousDns,
                )
                .with_mitre("T1071.004")
                .with_pivot(Pivot {
                    description: "Search for all DNS queries to this domain".to_string(),
                    query: Some(format!("dns.qname~\"{}\"", &rec.query_name)),
                    command: None,
                }),
            );
        }

        // TXT records can carry exfiltrated data
        if rec.record_type == "TXT" && rec.is_response {
            for data in &rec.response_data {
                if data.len() > 100 {
                    findings.push(
                        Finding::new(
                            "Large DNS TXT record detected",
                            format!("TXT record with {} chars for {} -- possible data exfil", data.len(), rec.query_name),
                            Severity::Low,
                            0.5,
                            FindingCategory::Exfiltration,
                        )
                        .with_mitre("T1048.003"),
                    );
                }
            }
        }
    }

    // HTTP anomalies
    for tx in &report.http_transactions {
        // Suspicious user agents
        if let Some(ref ua) = tx.user_agent {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("python-requests")
                || ua_lower.contains("curl")
                || ua_lower.contains("wget")
                || ua_lower.contains("powershell")
                || ua_lower.contains("nmap")
            {
                findings.push(
                    Finding::new(
                        format!("Scripted/tool HTTP request: {}", ua),
                        format!(
                            "Non-browser user agent detected: {} {} {}",
                            tx.method,
                            tx.host.as_deref().unwrap_or("-"),
                            tx.uri
                        ),
                        Severity::Low,
                        0.6,
                        FindingCategory::ReconActivity,
                    )
                    .with_mitre("T1595"),
                );
            }
        }

        // Large file downloads
        if tx.response_body_size > 1_000_000 {
            findings.push(
                Finding::new(
                    format!(
                        "Large HTTP download: {:.1} MB",
                        tx.response_body_size as f64 / 1_048_576.0
                    ),
                    format!(
                        "{} {} {} -- {} bytes downloaded",
                        tx.method,
                        tx.host.as_deref().unwrap_or("-"),
                        tx.uri,
                        tx.response_body_size
                    ),
                    Severity::Info,
                    0.4,
                    FindingCategory::Anomaly,
                ),
            );
        }
    }

    // TLS anomalies
    for tls in &report.tls_sessions {
        if tls.is_self_signed == Some(true) {
            findings.push(
                Finding::new(
                    format!(
                        "Self-signed TLS certificate: {}",
                        tls.sni.as_deref().unwrap_or("-")
                    ),
                    "Self-signed certificates may indicate MITM or C2 infrastructure".to_string(),
                    Severity::Medium,
                    0.7,
                    FindingCategory::CertificateIssue,
                )
                .with_mitre("T1557.002"),
            );
        }
    }

    // ICMP flows with data may indicate covert channels
    for flow in &report.flows {
        if flow.detected_protocol == Some(AppProtocol::Icmp) && flow.byte_count > 500 {
            findings.push(
                Finding::new(
                    format!("ICMP traffic with {} bytes", flow.byte_count),
                    "Significant ICMP traffic volume may indicate covert channel or data exfiltration".to_string(),
                    Severity::Medium,
                    0.6,
                    FindingCategory::Exfiltration,
                )
                .with_mitre("T1095"),
            );
        }
    }

    // Sort by severity (critical first) then confidence
    findings.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(
            b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
        )
    });

    tracing::info!(count = findings.len(), "detection complete");
    findings
}
