use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

use crate::models::*;

/// Extract IOCs from a fully assembled report.
pub fn extract_iocs(report: &Report) -> Vec<Ioc> {
    let mut iocs = Vec::new();
    let mut seen_values: HashSet<String> = HashSet::new();

    let private_nets = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "0.0.0.0", "::1", "fe80:",
    ];

    let is_private = |ip: &str| -> bool {
        private_nets.iter().any(|p| ip.starts_with(p))
    };

    for flow in &report.flows {
        for ip in [flow.key.src_ip, flow.key.dst_ip] {
            let ip_str = ip.to_string();
            if !is_private(&ip_str) && seen_values.insert(format!("ip:{}", ip_str)) {
                iocs.push(Ioc {
                    id: format!("IOC-{}", Uuid::new_v4().as_simple()),
                    kind: IocKind::IpAddress,
                    value: ip_str.clone(),
                    description: Some(format!("External IP observed in {} flows", count_ip_flows(&report.flows, ip))),
                    source: Some("flow_analysis".into()),
                    confidence: 0.5,
                    evidence: vec![],
                    mitre_attack: vec![],
                });
            }
        }
    }

    for dns in &report.dns_records {
        if !dns.query_name.is_empty() && seen_values.insert(format!("domain:{}", dns.query_name)) {
            let mut confidence: f64 = 0.3;
            let mut mitre = Vec::new();
            let name = &dns.query_name;

            if name.len() > 50 {
                confidence = 0.7;
                mitre.push("T1071.004".to_string());
            }
            if name.matches('.').count() > 5 {
                confidence = confidence.max(0.6);
            }
            if looks_like_dga(name) {
                confidence = 0.8;
                mitre.push("T1568.002".to_string());
            }

            iocs.push(Ioc {
                id: format!("IOC-{}", Uuid::new_v4().as_simple()),
                kind: IocKind::Domain,
                value: dns.query_name.clone(),
                description: Some(format!("{} record, response: {}", dns.record_type, dns.response_data.join(", "))),
                source: Some("dns_analysis".into()),
                confidence,
                evidence: vec![],
                mitre_attack: mitre,
            });
        }
    }

    for tx in &report.http_transactions {
        let uri = format!("{}{}",
            tx.host.as_deref().unwrap_or(""),
            &tx.uri,
        );
        if !uri.is_empty() && seen_values.insert(format!("url:{}", uri)) {
            let mut confidence: f64 = 0.3;
            let mut mitre = Vec::new();

            if tx.uri.contains("..") || tx.uri.contains("%2e%2e") {
                confidence = 0.9;
                mitre.push("T1083".to_string());
            }
            if tx.uri.contains("/admin") || tx.uri.contains("/shell") || tx.uri.contains("/cmd") || tx.uri.contains("/exec") {
                confidence = confidence.max(0.7);
                mitre.push("T1190".to_string());
            }
            if tx.method == "POST" && tx.request_body_size > 10000 {
                confidence = confidence.max(0.5);
                mitre.push("T1041".to_string());
            }

            iocs.push(Ioc {
                id: format!("IOC-{}", Uuid::new_v4().as_simple()),
                kind: IocKind::Url,
                value: uri,
                description: Some(format!("{} {} -> {}", tx.method, tx.uri, tx.status_code.map(|c| c.to_string()).unwrap_or_default())),
                source: Some("http_analysis".into()),
                confidence,
                evidence: vec![],
                mitre_attack: mitre,
            });
        }
    }

    for art in &report.artifacts {
        if seen_values.insert(format!("hash:{}", art.sha256)) {
            iocs.push(Ioc {
                id: format!("IOC-{}", Uuid::new_v4().as_simple()),
                kind: IocKind::FileHash,
                value: art.sha256.clone(),
                description: Some(format!("{:?} '{}' ({} bytes, {})",
                    art.kind,
                    art.name.as_deref().unwrap_or("-"),
                    art.size_bytes,
                    art.mime_type.as_deref().unwrap_or("?"),
                )),
                source: Some("artifact_extraction".into()),
                confidence: 0.4,
                evidence: vec![],
                mitre_attack: vec![],
            });
        }
    }

    for tls in &report.tls_sessions {
        if let Some(ref ja3) = tls.ja3_hash {
            if seen_values.insert(format!("ja3:{}", ja3)) {
                iocs.push(Ioc {
                    id: format!("IOC-{}", Uuid::new_v4().as_simple()),
                    kind: IocKind::Ja3Fingerprint,
                    value: ja3.clone(),
                    description: Some(format!("JA3 fingerprint, SNI: {}", tls.sni.as_deref().unwrap_or("-"))),
                    source: Some("tls_analysis".into()),
                    confidence: 0.4,
                    evidence: vec![],
                    mitre_attack: vec![],
                });
            }
        }
        if let Some(ref ja3s) = tls.ja3s_hash {
            if seen_values.insert(format!("ja3s:{}", ja3s)) {
                iocs.push(Ioc {
                    id: format!("IOC-{}", Uuid::new_v4().as_simple()),
                    kind: IocKind::Ja3sFingerprint,
                    value: ja3s.clone(),
                    description: Some(format!("JA3S fingerprint, SNI: {}", tls.sni.as_deref().unwrap_or("-"))),
                    source: Some("tls_analysis".into()),
                    confidence: 0.4,
                    evidence: vec![],
                    mitre_attack: vec![],
                });
            }
        }
    }

    let mut ua_counts: HashMap<String, usize> = HashMap::new();
    for tx in &report.http_transactions {
        if let Some(ref ua) = tx.user_agent {
            *ua_counts.entry(ua.clone()).or_insert(0) += 1;
        }
    }
    for (ua, count) in &ua_counts {
        if seen_values.insert(format!("ua:{}", ua)) {
            let mut confidence = 0.2;
            let mut mitre = Vec::new();
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("curl") || ua_lower.contains("wget") || ua_lower.contains("python") || ua_lower.contains("go-http") || ua_lower.contains("nikto") || ua_lower.contains("sqlmap") || ua_lower.contains("nmap") {
                confidence = 0.7;
                mitre.push("T1595".to_string());
            }
            iocs.push(Ioc {
                id: format!("IOC-{}", Uuid::new_v4().as_simple()),
                kind: IocKind::UserAgent,
                value: ua.clone(),
                description: Some(format!("Seen in {} HTTP request(s)", count)),
                source: Some("http_analysis".into()),
                confidence,
                evidence: vec![],
                mitre_attack: mitre,
            });
        }
    }

    iocs.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    iocs
}

fn count_ip_flows(flows: &[Flow], ip: IpAddr) -> usize {
    flows.iter().filter(|f| f.key.src_ip == ip || f.key.dst_ip == ip).count()
}

fn looks_like_dga(domain: &str) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 { return false; }
    let label = parts[0];
    if label.len() < 8 { return false; }

    let consonants = label.chars().filter(|c| "bcdfghjklmnpqrstvwxyz".contains(*c)).count();
    let vowels = label.chars().filter(|c| "aeiou".contains(*c)).count();
    let digits = label.chars().filter(|c| c.is_ascii_digit()).count();

    if vowels == 0 { return true; }
    let ratio = consonants as f64 / vowels.max(1) as f64;

    (ratio > 5.0) || (digits >= label.len() / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dga_detection() {
        assert!(looks_like_dga("xjfkqwrtzpls.evil.com"));
        assert!(looks_like_dga("8a3b2c1d9e0f7a4b.net"));
        assert!(!looks_like_dga("google.com"));
        assert!(!looks_like_dga("mail.example.org"));
    }
}
