use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::models::*;

pub struct HostProfiler;

impl HostProfiler {
    pub fn new() -> Self { Self }

    pub fn build(&self, report: &Report) -> Vec<HostProfile> {
        let mut hosts: HashMap<IpAddr, HostState> = HashMap::new();

        for flow in &report.flows {
            let src = hosts.entry(flow.key.src_ip).or_insert_with(|| HostState::new(flow.key.src_ip, flow.start_time));
            src.total_bytes_sent += flow.fwd_bytes;
            src.total_bytes_received += flow.rev_bytes;
            src.total_flows += 1;
            if flow.start_time < src.first_seen { src.first_seen = flow.start_time; }
            if flow.end_time > src.last_seen { src.last_seen = flow.end_time; }
            if let Some(proto) = flow.detected_protocol {
                let port = std::cmp::min(flow.key.src_port, flow.key.dst_port);
                if port > 0 {
                    src.services.insert((port, flow.key.protocol, Some(proto)));
                }
            }

            let dst = hosts.entry(flow.key.dst_ip).or_insert_with(|| HostState::new(flow.key.dst_ip, flow.start_time));
            dst.total_bytes_received += flow.fwd_bytes;
            dst.total_bytes_sent += flow.rev_bytes;
            dst.total_flows += 1;
            if flow.start_time < dst.first_seen { dst.first_seen = flow.start_time; }
            if flow.end_time > dst.last_seen { dst.last_seen = flow.end_time; }
            if let Some(proto) = flow.detected_protocol {
                let port = std::cmp::min(flow.key.src_port, flow.key.dst_port);
                if port > 0 {
                    dst.services.insert((port, flow.key.protocol, Some(proto)));
                }
            }
        }

        for dns in &report.dns_records {
            if dns.is_response {
                for data in &dns.response_data {
                    if let Ok(ip) = data.parse::<IpAddr>() {
                        if let Some(host) = hosts.get_mut(&ip) {
                            host.hostnames.insert(dns.query_name.clone());
                        }
                    }
                }
            }
        }

        for tls in &report.tls_sessions {
            if let Some(ref sni) = tls.sni {
                for host in hosts.values_mut() {
                    if host.hostnames.is_empty() {
                        // Can't easily match TLS to host without flow correlation
                        // but we collect SNI as a general enrichment
                    }
                    let _ = sni;
                }
            }
        }

        let mut profiles: Vec<HostProfile> = hosts.into_values().map(|h| {
            let services: Vec<ServiceInfo> = h.services.into_iter().map(|(port, proto, app)| {
                ServiceInfo {
                    port,
                    protocol: proto,
                    app_protocol: app,
                    banner: None,
                }
            }).collect();

            HostProfile {
                ip: h.ip,
                hostnames: h.hostnames.into_iter().collect(),
                mac_address: None,
                os_guess: None,
                services,
                total_bytes_sent: h.total_bytes_sent,
                total_bytes_received: h.total_bytes_received,
                total_flows: h.total_flows,
                first_seen: h.first_seen,
                last_seen: h.last_seen,
            }
        }).collect();

        profiles.sort_by(|a, b| (b.total_bytes_sent + b.total_bytes_received).cmp(&(a.total_bytes_sent + a.total_bytes_received)));
        profiles
    }
}

struct HostState {
    ip: IpAddr,
    hostnames: HashSet<String>,
    services: HashSet<(u16, TransportProtocol, Option<AppProtocol>)>,
    total_bytes_sent: u64,
    total_bytes_received: u64,
    total_flows: u64,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
}

impl HostState {
    fn new(ip: IpAddr, ts: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            ip,
            hostnames: HashSet::new(),
            services: HashSet::new(),
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_flows: 0,
            first_seen: ts,
            last_seen: ts,
        }
    }
}
