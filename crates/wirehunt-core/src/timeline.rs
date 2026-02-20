use crate::models::*;

pub struct TimelineBuilder;

impl TimelineBuilder {
    pub fn new() -> Self { Self }

    pub fn build(&self, report: &Report) -> Vec<TimelineEvent> {
        let mut events = Vec::new();

        for flow in &report.flows {
            let proto = flow.detected_protocol
                .map(|p| format!("{:?}", p))
                .unwrap_or_else(|| format!("{:?}", flow.key.protocol));
            events.push(TimelineEvent {
                timestamp: flow.start_time,
                event_type: "flow_start".into(),
                summary: format!("{} {}:{} -> {}:{} ({} pkts, {} bytes)",
                    proto, flow.key.src_ip, flow.key.src_port,
                    flow.key.dst_ip, flow.key.dst_port,
                    flow.packet_count, flow.byte_count),
                severity: Severity::Info,
                evidence_id: Some(flow.id.clone()),
                source_ip: Some(flow.key.src_ip),
                dest_ip: Some(flow.key.dst_ip),
                protocol: flow.detected_protocol,
            });
        }

        for finding in &report.findings {
            events.push(TimelineEvent {
                timestamp: finding.timestamp,
                event_type: format!("finding_{:?}", finding.severity).to_lowercase(),
                summary: finding.title.clone(),
                severity: finding.severity,
                evidence_id: Some(finding.id.clone()),
                source_ip: None,
                dest_ip: None,
                protocol: None,
            });
        }

        for tx in &report.http_transactions {
            let ts = report.metadata.generated_at;
            events.push(TimelineEvent {
                timestamp: ts,
                event_type: "http_transaction".into(),
                summary: format!("{} {} {} -> {}",
                    tx.method,
                    tx.host.as_deref().unwrap_or("-"),
                    tx.uri,
                    tx.status_code.map(|c| c.to_string()).unwrap_or_default()),
                severity: Severity::Info,
                evidence_id: None,
                source_ip: None,
                dest_ip: None,
                protocol: Some(AppProtocol::Http),
            });
        }

        for cred in &report.credentials {
            events.push(TimelineEvent {
                timestamp: report.metadata.generated_at,
                event_type: "credential_harvested".into(),
                summary: format!("{:?} user={} svc={}",
                    cred.kind,
                    cred.username.as_deref().unwrap_or("-"),
                    cred.service.as_deref().unwrap_or("-")),
                severity: Severity::High,
                evidence_id: Some(cred.id.clone()),
                source_ip: None,
                dest_ip: None,
                protocol: None,
            });
        }

        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        events
    }
}
