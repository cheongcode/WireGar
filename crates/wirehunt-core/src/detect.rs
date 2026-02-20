use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::models::*;

const PRIVATE_PREFIXES: &[&str] = &[
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "0.0.0.0", "::1", "fe80:",
];

fn is_external(ip: IpAddr) -> bool {
    let s = ip.to_string();
    !PRIVATE_PREFIXES.iter().any(|p| s.starts_with(p))
}

const SUSPICIOUS_PORTS: &[u16] = &[
    4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321,
    3389, 5900, 5985, 5986, 2222, 8443, 8080, 1080, 9090,
];

const KNOWN_BAD_JA3: &[(&str, &str)] = &[
    ("51c64c77e60f3980eea90869b68c58a8", "CobaltStrike"),
    ("72a589da586844d7f0818ce684948eea", "CobaltStrike"),
    ("a0e9f5d64349fb13191bc781f81f42e1", "CobaltStrike"),
    ("e35df3e28c5ce5e11c2b726fad6d31ac", "Metasploit"),
    ("3b5074b1b5d032e5620f69f9f700ff0e", "TrickBot"),
    ("6734f37431670b3ab4292b8f60f29984", "Dridex"),
];

/// Run all detection rules and produce scored findings.
pub fn run_detection(
    report: &Report,
    flag_values: &[(String, String, Option<String>)],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    detect_ctf_flags(&mut findings, flag_values);
    detect_credentials(&mut findings, report);
    detect_data_exfiltration(&mut findings, report);
    detect_c2_indicators(&mut findings, report);
    detect_suspicious_connections(&mut findings, report);
    detect_tls_anomalies(&mut findings, report);
    detect_dns_anomalies(&mut findings, report);
    detect_http_anomalies(&mut findings, report);
    detect_cleartext_protocols(&mut findings, report);
    detect_icmp_anomalies(&mut findings, report);
    detect_lateral_movement(&mut findings, report);
    detect_recon_activity(&mut findings, report);
    generate_traffic_summary(&mut findings, report);

    findings.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    tracing::info!(count = findings.len(), "detection complete");
    findings
}

fn detect_ctf_flags(findings: &mut Vec<Finding>, flag_values: &[(String, String, Option<String>)]) {
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
            .with_evidence(EvidenceRef::from_stream(stream_id, format!("Flag '{}' found in stream", value)))
            .with_mitre("T1020"),
        );
    }
}

fn detect_credentials(findings: &mut Vec<Finding>, report: &Report) {
    for cred in &report.credentials {
        let severity = match cred.kind {
            CredentialKind::SshPrivateKey => Severity::Critical,
            CredentialKind::HttpBasicAuth | CredentialKind::FtpLogin
            | CredentialKind::TelnetLogin | CredentialKind::SmtpAuth
            | CredentialKind::Pop3Login => Severity::High,
            CredentialKind::Jwt | CredentialKind::ApiKey => Severity::High,
            CredentialKind::SessionCookie | CredentialKind::BearerToken => Severity::Medium,
            _ => Severity::Medium,
        };
        let user = cred.username.as_deref().unwrap_or("unknown");
        findings.push(
            Finding::new(
                format!("{:?} credential: {}", cred.kind, user),
                format!("Credential of type {:?} harvested from network traffic. Service: {}. Host: {}",
                    cred.kind,
                    cred.service.as_deref().unwrap_or("-"),
                    cred.host.as_deref().unwrap_or("-"),
                ),
                severity,
                0.95,
                FindingCategory::Credential,
            )
            .with_evidence(cred.evidence.clone())
            .with_mitre("T1552.001"),
        );
    }
}

fn detect_data_exfiltration(findings: &mut Vec<Finding>, report: &Report) {
    let mut external_outbound: HashMap<IpAddr, (u64, u64, u64)> = HashMap::new();

    for flow in &report.flows {
        let (ext_ip, bytes_to_ext) = if is_external(flow.key.dst_ip) && !is_external(flow.key.src_ip) {
            (flow.key.dst_ip, flow.fwd_bytes)
        } else if is_external(flow.key.src_ip) && !is_external(flow.key.dst_ip) {
            (flow.key.src_ip, flow.rev_bytes)
        } else {
            continue;
        };

        let entry = external_outbound.entry(ext_ip).or_insert((0, 0, 0));
        entry.0 += bytes_to_ext;
        entry.1 += flow.byte_count;
        entry.2 += 1;
    }

    for (ip, (bytes_out, total_bytes, flow_count)) in &external_outbound {
        if *bytes_out > 10_000 {
            let ratio = if *total_bytes > 0 { *bytes_out as f64 / *total_bytes as f64 } else { 0.0 };
            let mut severity = Severity::Info;
            let mut confidence: f64 = 0.3;

            if *bytes_out > 1_000_000 {
                severity = Severity::High;
                confidence = 0.8;
            } else if *bytes_out > 100_000 {
                severity = Severity::Medium;
                confidence = 0.6;
            } else if *bytes_out > 10_000 {
                severity = Severity::Low;
                confidence = 0.4;
            }

            if ratio > 0.7 {
                severity = std::cmp::max(severity, Severity::Medium);
                confidence = confidence.max(0.7);
            }

            findings.push(
                Finding::new(
                    format!("Data sent to external host {}: {} ({} flow{})",
                        ip, fmt_bytes(*bytes_out), flow_count, if *flow_count > 1 { "s" } else { "" }),
                    format!(
                        "{} bytes sent to {} across {} flow(s). Outbound ratio: {:.0}%. This could indicate data exfiltration.",
                        bytes_out, ip, flow_count, ratio * 100.0,
                    ),
                    severity,
                    confidence,
                    FindingCategory::Exfiltration,
                )
                .with_mitre("T1041")
                .with_pivot(Pivot {
                    description: format!("Investigate all traffic to {}", ip),
                    query: Some(format!("flows:\"{}\"", ip)),
                    command: None,
                }),
            );
        }
    }

    for flow in &report.flows {
        if flow.fwd_bytes > 0 && flow.rev_bytes > 0 {
            let outbound_ratio = flow.fwd_bytes as f64 / (flow.fwd_bytes + flow.rev_bytes) as f64;
            if outbound_ratio > 0.85 && flow.fwd_bytes > 50_000 && is_external(flow.key.dst_ip) {
                findings.push(
                    Finding::new(
                        format!("Asymmetric outbound flow to {}:{} ({:.0}% outbound)",
                            flow.key.dst_ip, flow.key.dst_port, outbound_ratio * 100.0),
                        format!(
                            "{}:{} -> {}:{}: {} sent, {} received ({:.0}% outbound). Highly asymmetric outbound flows may indicate data exfiltration.",
                            flow.key.src_ip, flow.key.src_port,
                            flow.key.dst_ip, flow.key.dst_port,
                            fmt_bytes(flow.fwd_bytes), fmt_bytes(flow.rev_bytes),
                            outbound_ratio * 100.0,
                        ),
                        Severity::Medium,
                        0.65,
                        FindingCategory::Exfiltration,
                    )
                    .with_mitre("T1048"),
                );
            }
        }
    }
}

fn detect_c2_indicators(findings: &mut Vec<Finding>, report: &Report) {
    let mut ext_conn_times: HashMap<IpAddr, Vec<i64>> = HashMap::new();
    for flow in &report.flows {
        if is_external(flow.key.dst_ip) && !is_external(flow.key.src_ip) {
            ext_conn_times
                .entry(flow.key.dst_ip)
                .or_default()
                .push(flow.start_time.timestamp());
        }
    }

    for (ip, times) in &ext_conn_times {
        if times.len() >= 3 {
            let mut sorted = times.clone();
            sorted.sort();
            let intervals: Vec<i64> = sorted.windows(2).map(|w| w[1] - w[0]).collect();
            if !intervals.is_empty() {
                let avg_interval = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
                let variance: f64 = intervals.iter().map(|i| (*i as f64 - avg_interval).powi(2)).sum::<f64>() / intervals.len() as f64;
                let cv = if avg_interval > 0.0 { variance.sqrt() / avg_interval } else { 1.0 };

                if cv < 0.3 && avg_interval < 300.0 {
                    findings.push(
                        Finding::new(
                            format!("Possible C2 beaconing to {} ({} connections, ~{:.0}s interval)",
                                ip, times.len(), avg_interval),
                            format!(
                                "{} periodic connections to {} with average interval {:.0}s (coefficient of variation: {:.2}). Regular periodic connections to external hosts are a strong indicator of C2 beaconing.",
                                times.len(), ip, avg_interval, cv,
                            ),
                            Severity::High,
                            0.8,
                            FindingCategory::C2Communication,
                        )
                        .with_mitre("T1071")
                        .with_mitre("T1573"),
                    );
                }
            }
        }
    }

    for (ip, times) in &ext_conn_times {
        if times.len() >= 2 {
            let ext_flows: Vec<&Flow> = report.flows.iter()
                .filter(|f| f.key.dst_ip == *ip && is_external(f.key.dst_ip))
                .collect();

            let uses_tls = ext_flows.iter().any(|f| matches!(f.detected_protocol, Some(AppProtocol::Tls | AppProtocol::Https)));
            let total_bytes: u64 = ext_flows.iter().map(|f| f.byte_count).sum();

            if uses_tls && total_bytes > 5000 {
                let has_sni = report.tls_sessions.iter().any(|t| t.sni.is_some());

                findings.push(
                    Finding::new(
                        format!("Encrypted connection to external host {} ({}, {} total)",
                            ip, fmt_bytes(total_bytes), ext_flows.len()),
                        format!(
                            "{} encrypted connection(s) to {} transferring {} total. {}. Encrypted channels to external hosts warrant investigation in incident response.",
                            ext_flows.len(), ip, fmt_bytes(total_bytes),
                            if has_sni { "SNI present" } else { "No SNI (connecting to IP directly)" },
                        ),
                        if has_sni { Severity::Low } else { Severity::Medium },
                        if has_sni { 0.4 } else { 0.7 },
                        FindingCategory::C2Communication,
                    )
                    .with_mitre("T1573")
                    .with_pivot(Pivot {
                        description: format!("Examine TLS sessions to {}", ip),
                        query: Some(format!("tls:\"{}\"", ip)),
                        command: None,
                    }),
                );
            }
        }
    }
}

fn detect_suspicious_connections(findings: &mut Vec<Finding>, report: &Report) {
    for flow in &report.flows {
        let dst_port = flow.key.dst_port;
        if is_external(flow.key.dst_ip) && SUSPICIOUS_PORTS.contains(&dst_port) {
            findings.push(
                Finding::new(
                    format!("Connection to suspicious port {}:{}", flow.key.dst_ip, dst_port),
                    format!(
                        "{}:{} -> {}:{} ({:?}, {} packets, {}). Port {} is commonly associated with malware, backdoors, or unauthorized services.",
                        flow.key.src_ip, flow.key.src_port,
                        flow.key.dst_ip, dst_port,
                        flow.key.protocol, flow.packet_count, fmt_bytes(flow.byte_count),
                        dst_port,
                    ),
                    Severity::Medium,
                    0.6,
                    FindingCategory::Anomaly,
                )
                .with_mitre("T1571"),
            );
        }
    }

    let mut dst_counts: HashMap<IpAddr, usize> = HashMap::new();
    for flow in &report.flows {
        if is_external(flow.key.dst_ip) {
            *dst_counts.entry(flow.key.dst_ip).or_insert(0) += 1;
        }
    }

    let unique_ext = dst_counts.len();
    if unique_ext > 0 {
        let total_ext_flows: usize = dst_counts.values().sum();
        let mut dest_summary: Vec<_> = dst_counts.iter().collect();
        dest_summary.sort_by(|a, b| b.1.cmp(a.1));
        let top_dests: String = dest_summary.iter().take(5)
            .map(|(ip, c)| format!("{} ({})", ip, c))
            .collect::<Vec<_>>().join(", ");

        findings.push(
            Finding::new(
                format!("External connections: {} unique IPs, {} flows", unique_ext, total_ext_flows),
                format!(
                    "Traffic observed to {} unique external IP addresses across {} flows. Top destinations: {}",
                    unique_ext, total_ext_flows, top_dests,
                ),
                Severity::Info,
                0.3,
                FindingCategory::Anomaly,
            )
            .with_mitre("T1071"),
        );
    }
}

fn detect_tls_anomalies(findings: &mut Vec<Finding>, report: &Report) {
    for tls in &report.tls_sessions {
        if tls.is_self_signed == Some(true) {
            findings.push(
                Finding::new(
                    format!("Self-signed TLS certificate: {}", tls.sni.as_deref().unwrap_or("-")),
                    format!("Self-signed certificate detected for {}. Issuer: {}. Self-signed certs may indicate C2 infrastructure, MITM attacks, or testing environments.",
                        tls.sni.as_deref().unwrap_or("(no SNI)"),
                        tls.cert_issuer.as_deref().unwrap_or("-"),
                    ),
                    Severity::Medium,
                    0.7,
                    FindingCategory::CertificateIssue,
                )
                .with_mitre("T1557.002"),
            );
        }

        if tls.sni.is_none() {
            findings.push(
                Finding::new(
                    "TLS connection without SNI (direct IP connection)",
                    format!("TLS handshake without Server Name Indication. Version: {}, Cipher: {}. Connecting to IPs directly via TLS (no domain) is unusual and may indicate C2 or tunneled traffic.",
                        tls.version,
                        tls.cipher_suite.as_deref().unwrap_or("-"),
                    ),
                    Severity::Medium,
                    0.6,
                    FindingCategory::C2Communication,
                )
                .with_mitre("T1573.002"),
            );
        }

        if let Some(ref ja3) = tls.ja3_hash {
            for (hash, malware) in KNOWN_BAD_JA3 {
                if ja3 == hash {
                    findings.push(
                        Finding::new(
                            format!("Known malware JA3 fingerprint: {} ({})", malware, &ja3[..12]),
                            format!("JA3 hash {} matches known {} fingerprint. SNI: {}",
                                ja3, malware, tls.sni.as_deref().unwrap_or("-")),
                            Severity::Critical,
                            0.95,
                            FindingCategory::C2Communication,
                        )
                        .with_mitre("T1071"),
                    );
                }
            }
        }
    }
}

fn detect_dns_anomalies(findings: &mut Vec<Finding>, report: &Report) {
    let mut domain_query_counts: HashMap<String, usize> = HashMap::new();
    for rec in &report.dns_records {
        let root = extract_root_domain(&rec.query_name);
        *domain_query_counts.entry(root).or_insert(0) += 1;

        if rec.query_name.len() > 60 {
            findings.push(
                Finding::new(
                    format!("Suspicious long DNS name: {}...", &rec.query_name[..40]),
                    format!("DNS query with {} character name. Long DNS names may indicate DNS tunneling, DGA domains, or data exfiltration via DNS.", rec.query_name.len()),
                    Severity::Medium,
                    0.7,
                    FindingCategory::SuspiciousDns,
                )
                .with_mitre("T1071.004"),
            );
        }

        if rec.record_type == "TXT" && rec.is_response {
            for data in &rec.response_data {
                if data.len() > 100 {
                    findings.push(
                        Finding::new(
                            "Large DNS TXT record",
                            format!("TXT record with {} chars for {} -- possible data exfiltration or C2", data.len(), rec.query_name),
                            Severity::Medium,
                            0.6,
                            FindingCategory::Exfiltration,
                        )
                        .with_mitre("T1048.003"),
                    );
                }
            }
        }

        if rec.response_code.as_deref() == Some("NXDOMAIN") {
            // Tracked for DGA detection below
        }
    }

    let nxdomain_count = report.dns_records.iter()
        .filter(|r| r.response_code.as_deref() == Some("NXDOMAIN"))
        .count();
    if nxdomain_count > 5 {
        findings.push(
            Finding::new(
                format!("{} NXDOMAIN DNS responses", nxdomain_count),
                format!("{} DNS queries resulted in NXDOMAIN (non-existent domain). High NXDOMAIN counts may indicate DGA malware attempting to reach C2 infrastructure.", nxdomain_count),
                Severity::Medium,
                0.7,
                FindingCategory::SuspiciousDns,
            )
            .with_mitre("T1568.002"),
        );
    }

    for (domain, count) in &domain_query_counts {
        if *count > 10 {
            findings.push(
                Finding::new(
                    format!("High DNS query volume: {} ({} queries)", domain, count),
                    format!("{} DNS queries to {} -- high query volume to a single domain may indicate DNS tunneling, beaconing, or data exfiltration.", count, domain),
                    Severity::Low,
                    0.5,
                    FindingCategory::SuspiciousDns,
                )
                .with_mitre("T1071.004"),
            );
        }
    }
}

fn detect_http_anomalies(findings: &mut Vec<Finding>, report: &Report) {
    for tx in &report.http_transactions {
        if let Some(ref ua) = tx.user_agent {
            let ua_lower = ua.to_lowercase();
            let suspicious_agents = [
                ("python-requests", "Python"), ("curl", "curl"), ("wget", "wget"),
                ("powershell", "PowerShell"), ("nmap", "Nmap"), ("nikto", "Nikto"),
                ("sqlmap", "SQLMap"), ("gobuster", "Gobuster"), ("dirbuster", "DirBuster"),
                ("masscan", "Masscan"), ("zgrab", "ZGrab"), ("httpx", "httpx"),
            ];
            for (pattern, name) in &suspicious_agents {
                if ua_lower.contains(pattern) {
                    findings.push(
                        Finding::new(
                            format!("Scripted HTTP request ({}): {} {}", name, tx.method, tx.uri),
                            format!("Non-browser user agent '{}' used for {} {} {}. Scripted tools may indicate reconnaissance, exploitation, or automated exfiltration.",
                                ua, tx.method, tx.host.as_deref().unwrap_or("-"), tx.uri),
                            Severity::Low,
                            0.6,
                            FindingCategory::ReconActivity,
                        )
                        .with_mitre("T1595"),
                    );
                    break;
                }
            }
        }

        if tx.response_body_size > 1_000_000 {
            findings.push(
                Finding::new(
                    format!("Large HTTP download: {} from {}{}", fmt_bytes(tx.response_body_size), tx.host.as_deref().unwrap_or("-"), tx.uri),
                    format!("{} {} {} -- {} downloaded. Large downloads may indicate payload delivery or staging.", tx.method, tx.host.as_deref().unwrap_or("-"), tx.uri, fmt_bytes(tx.response_body_size)),
                    Severity::Low,
                    0.4,
                    FindingCategory::Anomaly,
                )
                .with_mitre("T1105"),
            );
        }

        if tx.request_body_size > 100_000 && tx.method == "POST" {
            findings.push(
                Finding::new(
                    format!("Large HTTP POST: {} to {}{}", fmt_bytes(tx.request_body_size), tx.host.as_deref().unwrap_or("-"), tx.uri),
                    format!("POST request with {} body to {}{}. Large POST uploads may indicate data exfiltration.", fmt_bytes(tx.request_body_size), tx.host.as_deref().unwrap_or("-"), tx.uri),
                    Severity::Medium,
                    0.6,
                    FindingCategory::Exfiltration,
                )
                .with_mitre("T1041"),
            );
        }
    }
}

fn detect_cleartext_protocols(findings: &mut Vec<Finding>, report: &Report) {
    let mut ftp_seen = false;
    let mut telnet_seen = false;
    let mut smtp_seen = false;

    for flow in &report.flows {
        let proto = flow.detected_protocol.unwrap_or(AppProtocol::Unknown);
        match proto {
            AppProtocol::Ftp | AppProtocol::FtpData => {
                if !ftp_seen {
                    ftp_seen = true;
                    findings.push(
                        Finding::new(
                            format!("FTP traffic detected: {}:{} -> {}:{}", flow.key.src_ip, flow.key.src_port, flow.key.dst_ip, flow.key.dst_port),
                            format!("FTP transmits credentials and file data in cleartext. {}:{} -> {}:{} ({} packets, {}). In a malware context, FTP is commonly used for data exfiltration by threats like AgentTesla, FormBook, and SnakeKeylogger.",
                                flow.key.src_ip, flow.key.src_port, flow.key.dst_ip, flow.key.dst_port,
                                flow.packet_count, fmt_bytes(flow.byte_count)),
                            Severity::High,
                            0.9,
                            FindingCategory::ClearTextProtocol,
                        )
                        .with_mitre("T1048.003")
                        .with_mitre("T1071.002"),
                    );
                }
            }
            AppProtocol::Telnet => {
                if !telnet_seen {
                    telnet_seen = true;
                    findings.push(
                        Finding::new(
                            format!("Telnet session detected: {}:{} -> {}:{}", flow.key.src_ip, flow.key.src_port, flow.key.dst_ip, flow.key.dst_port),
                            "Telnet transmits all data including credentials in cleartext.".to_string(),
                            Severity::Medium,
                            0.9,
                            FindingCategory::ClearTextProtocol,
                        )
                        .with_mitre("T1021.005"),
                    );
                }
            }
            AppProtocol::Smtp => {
                if !smtp_seen {
                    smtp_seen = true;
                    findings.push(
                        Finding::new(
                            format!("SMTP traffic detected: {}:{} -> {}:{}", flow.key.src_ip, flow.key.src_port, flow.key.dst_ip, flow.key.dst_port),
                            format!("SMTP email traffic detected. In a malware context, SMTP is commonly used for data exfiltration and C2 by infostealers. {} packets, {}.",
                                flow.packet_count, fmt_bytes(flow.byte_count)),
                            Severity::Medium,
                            0.7,
                            FindingCategory::Exfiltration,
                        )
                        .with_mitre("T1048.003"),
                    );
                }
            }
            _ => {}
        }
    }
}

fn detect_icmp_anomalies(findings: &mut Vec<Finding>, report: &Report) {
    for flow in &report.flows {
        if flow.detected_protocol == Some(AppProtocol::Icmp) && flow.byte_count > 500 {
            findings.push(
                Finding::new(
                    format!("ICMP traffic: {} between {} and {} ", fmt_bytes(flow.byte_count), flow.key.src_ip, flow.key.dst_ip),
                    format!("ICMP traffic with {} across {} packets. Significant ICMP volume may indicate covert channel, tunneling, or exfiltration.", fmt_bytes(flow.byte_count), flow.packet_count),
                    Severity::Medium,
                    0.6,
                    FindingCategory::Exfiltration,
                )
                .with_mitre("T1095"),
            );
        }
    }
}

fn detect_lateral_movement(findings: &mut Vec<Finding>, report: &Report) {
    let internal_only: Vec<&Flow> = report.flows.iter()
        .filter(|f| !is_external(f.key.src_ip) && !is_external(f.key.dst_ip))
        .collect();

    let mut internal_targets: HashSet<(IpAddr, u16)> = HashSet::new();
    for flow in &internal_only {
        let port = flow.key.dst_port;
        if [445, 139, 3389, 22, 23, 5985, 5986, 135, 593].contains(&port) {
            internal_targets.insert((flow.key.dst_ip, port));
        }
    }

    if internal_targets.len() > 2 {
        let targets: String = internal_targets.iter().take(5)
            .map(|(ip, port)| format!("{}:{}", ip, port))
            .collect::<Vec<_>>().join(", ");
        findings.push(
            Finding::new(
                format!("Potential lateral movement: {} internal service targets", internal_targets.len()),
                format!("Internal connections to admin/remote-access services on {} hosts: {}. This pattern may indicate lateral movement.",
                    internal_targets.len(), targets),
                Severity::High,
                0.7,
                FindingCategory::LateralMovement,
            )
            .with_mitre("T1021"),
        );
    }
}

fn detect_recon_activity(findings: &mut Vec<Finding>, report: &Report) {
    let mut src_port_targets: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
    for flow in &report.flows {
        src_port_targets
            .entry(flow.key.src_ip)
            .or_default()
            .insert(flow.key.dst_port);
    }

    for (src_ip, ports) in &src_port_targets {
        if ports.len() > 15 {
            findings.push(
                Finding::new(
                    format!("Port scanning from {}: {} unique destination ports", src_ip, ports.len()),
                    format!("{} connected to {} unique destination ports. This volume of port diversity strongly suggests port scanning or service enumeration.",
                        src_ip, ports.len()),
                    Severity::Medium,
                    0.75,
                    FindingCategory::ReconActivity,
                )
                .with_mitre("T1046"),
            );
        }
    }
}

fn generate_traffic_summary(findings: &mut Vec<Finding>, report: &Report) {
    let total_bytes: u64 = report.flows.iter().map(|f| f.byte_count).sum();
    let total_packets: u64 = report.flows.iter().map(|f| f.packet_count).sum();
    let tcp_flows = report.flows.iter().filter(|f| f.key.protocol == TransportProtocol::Tcp).count();
    let udp_flows = report.flows.iter().filter(|f| f.key.protocol == TransportProtocol::Udp).count();

    let mut proto_summary: Vec<String> = Vec::new();
    let mut protos: Vec<_> = report.statistics.protocol_breakdown.iter().collect();
    protos.sort_by(|a, b| b.1.cmp(a.1));
    for (name, count) in protos.iter().take(5) {
        proto_summary.push(format!("{}: {}", name, count));
    }

    let ext_ips: HashSet<IpAddr> = report.flows.iter()
        .flat_map(|f| vec![f.key.src_ip, f.key.dst_ip])
        .filter(|ip| is_external(*ip))
        .collect();

    findings.push(
        Finding::new(
            format!("Traffic summary: {} flows, {}, {} external IPs", report.flows.len(), fmt_bytes(total_bytes), ext_ips.len()),
            format!(
                "Capture contains {} flows ({} TCP, {} UDP) with {} total across {} packets. {} unique external IP(s) observed. Protocols: {}.",
                report.flows.len(), tcp_flows, udp_flows,
                fmt_bytes(total_bytes), total_packets,
                ext_ips.len(),
                proto_summary.join(", "),
            ),
            Severity::Info,
            0.2,
            FindingCategory::Anomaly,
        ),
    );
}

fn extract_root_domain(name: &str) -> String {
    let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        name.to_string()
    }
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1_073_741_824 { format!("{:.1} GB", b as f64 / 1_073_741_824.0) }
    else if b >= 1_048_576 { format!("{:.1} MB", b as f64 / 1_048_576.0) }
    else if b >= 1024 { format!("{:.1} KB", b as f64 / 1024.0) }
    else { format!("{} B", b) }
}
