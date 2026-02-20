use crate::models::*;

pub fn generate_executive_summary(report: &Report) -> String {
    let mut parts: Vec<String> = Vec::new();

    let m = &report.metadata;
    let tcp = report.flows.iter().filter(|f| f.key.protocol == TransportProtocol::Tcp).count();
    let udp = report.flows.iter().filter(|f| f.key.protocol == TransportProtocol::Udp).count();
    parts.push(format!(
        "This capture ({}) contains {} flows ({} TCP, {} UDP) across {} streams totaling {} packets over {:.1} seconds.",
        m.pcap_filename, report.flows.len(), tcp, udp, report.streams.len(),
        m.total_packets, m.capture_duration_secs,
    ));

    let ext_ips: std::collections::HashSet<std::net::IpAddr> = report.flows.iter()
        .flat_map(|f| vec![f.key.src_ip, f.key.dst_ip])
        .filter(|ip| is_external(*ip))
        .collect();
    let int_ips: std::collections::HashSet<std::net::IpAddr> = report.flows.iter()
        .flat_map(|f| vec![f.key.src_ip, f.key.dst_ip])
        .filter(|ip| !is_external(*ip))
        .collect();

    if !ext_ips.is_empty() || !int_ips.is_empty() {
        parts.push(format!(
            "{} internal and {} external unique IP addresses were observed.",
            int_ips.len(), ext_ips.len(),
        ));
    }

    let mut protos: Vec<_> = report.statistics.protocol_breakdown.iter().collect();
    protos.sort_by(|a, b| b.1.cmp(a.1));
    if !protos.is_empty() {
        let proto_str = protos.iter().take(4)
            .map(|(name, count)| format!("{} ({})", name, count))
            .collect::<Vec<_>>().join(", ");
        parts.push(format!("Application protocols detected: {}.", proto_str));
    }

    let critical = report.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = report.findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = report.findings.iter().filter(|f| f.severity == Severity::Medium).count();

    if critical > 0 || high > 0 || medium > 0 {
        let mut sev_parts = Vec::new();
        if critical > 0 { sev_parts.push(format!("{} critical", critical)); }
        if high > 0 { sev_parts.push(format!("{} high", high)); }
        if medium > 0 { sev_parts.push(format!("{} medium", medium)); }
        parts.push(format!(
            "Detection engine produced {} findings: {}.",
            report.findings.len(), sev_parts.join(", "),
        ));
    }

    let flags: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.category == FindingCategory::CtfFlag)
        .collect();
    if !flags.is_empty() {
        let flag_values: Vec<String> = flags.iter()
            .map(|f| f.title.replace("CTF Flag Found: ", ""))
            .collect();
        parts.push(format!(
            "CTF Flags found ({}): {}",
            flags.len(),
            flag_values.join(", "),
        ));
    }

    let exfil: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.category == FindingCategory::Exfiltration)
        .collect();
    if !exfil.is_empty() {
        parts.push(format!(
            "DATA EXFILTRATION INDICATORS: {} finding(s) suggest potential data exfiltration. {}",
            exfil.len(),
            exfil.first().map(|f| f.description.clone()).unwrap_or_default(),
        ));
    }

    let c2: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.category == FindingCategory::C2Communication)
        .collect();
    if !c2.is_empty() {
        parts.push(format!(
            "C2 INDICATORS: {} finding(s) suggest potential command-and-control activity. {}",
            c2.len(),
            c2.first().map(|f| f.description.clone()).unwrap_or_default(),
        ));
    }

    if !report.credentials.is_empty() {
        let kinds: Vec<String> = report.credentials.iter()
            .map(|c| format!("{:?}", c.kind))
            .collect::<std::collections::HashSet<_>>()
            .into_iter().collect();
        parts.push(format!(
            "{} credential(s) harvested from network traffic (types: {}).",
            report.credentials.len(), kinds.join(", "),
        ));
    }

    if !report.tls_sessions.is_empty() {
        let self_signed = report.tls_sessions.iter().filter(|t| t.is_self_signed == Some(true)).count();
        let no_sni = report.tls_sessions.iter().filter(|t| t.sni.is_none()).count();
        let mut tls_notes = vec![format!("{} TLS session(s)", report.tls_sessions.len())];
        if self_signed > 0 { tls_notes.push(format!("{} self-signed", self_signed)); }
        if no_sni > 0 { tls_notes.push(format!("{} without SNI", no_sni)); }
        parts.push(format!("TLS: {}.", tls_notes.join(", ")));
    }

    let cleartext: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.category == FindingCategory::ClearTextProtocol)
        .collect();
    if !cleartext.is_empty() {
        let protos: Vec<String> = cleartext.iter()
            .map(|f| f.title.split(':').next().unwrap_or("").trim().to_string())
            .collect();
        parts.push(format!(
            "WARNING: Cleartext protocol(s) detected: {}. Credentials and data transmitted in plaintext.",
            protos.join(", "),
        ));
    }

    let mut mitre_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &report.findings {
        for t in &f.mitre_attack {
            mitre_ids.insert(t.split('.').next().unwrap_or(t).to_string());
        }
    }
    if !mitre_ids.is_empty() {
        let mut sorted: Vec<_> = mitre_ids.into_iter().collect();
        sorted.sort();
        parts.push(format!("MITRE ATT&CK coverage: {}.", sorted.join(", ")));
    }

    if report.findings.is_empty() && report.credentials.is_empty() && flags.is_empty() {
        parts.push("No significant threats or anomalies detected in this capture.".into());
    }

    parts.join(" ")
}

fn is_external(ip: std::net::IpAddr) -> bool {
    let s = ip.to_string();
    !["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
      "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
      "172.29.", "172.30.", "172.31.", "192.168.", "127.", "0.0.0.0", "::1", "fe80:"]
        .iter().any(|p| s.starts_with(p))
}
