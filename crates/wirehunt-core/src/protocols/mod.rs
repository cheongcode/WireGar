pub mod dns;
pub mod http;
pub mod tls;
pub mod icmp;
pub mod ftp;
pub mod smtp;

use crate::models::*;

/// Run all protocol dissectors against finalized streams.
/// Returns enriched protocol data for the report.
pub fn dissect_all(
    flows: &[Flow],
    streams: &[Stream],
) -> DissectionResults {
    let mut results = DissectionResults::default();

    for stream in streams {
        let _flow = flows.iter().find(|f| f.stream_ids.contains(&stream.id));
        let proto = stream.protocol;

        match proto {
            AppProtocol::Dns => {
                let records = dns::parse_dns_stream(&stream.segments);
                results.dns_records.extend(records);
            }
            AppProtocol::Http => {
                let txns = http::parse_http_stream(&stream.segments);
                let found_http = !txns.is_empty();
                results.http_transactions.extend(txns);

                // Also try TLS in case port-based guess was wrong
                if !found_http {
                    if let Some(tls) = tls::parse_tls_stream(&stream.segments) {
                        results.tls_sessions.push(tls);
                    }
                }
            }
            AppProtocol::Tls | AppProtocol::Https => {
                if let Some(tls) = tls::parse_tls_stream(&stream.segments) {
                    results.tls_sessions.push(tls);
                }
            }
            AppProtocol::Icmp => {
                let summary = icmp::parse_icmp_stream(&stream.segments);
                results.icmp_summaries.push(summary);
            }
            AppProtocol::Ftp => {
                let session = ftp::parse_ftp_stream(&stream.segments);
                results.ftp_sessions.push(session);
            }
            AppProtocol::Smtp => {
                let session = smtp::parse_smtp_stream(&stream.segments);
                results.smtp_sessions.push(session);
            }
            _ => {
                // For unknown protocols, try heuristic detection
                if let Some(detected) = heuristic_detect(stream) {
                    match detected {
                        AppProtocol::Http => {
                            let txns = http::parse_http_stream(&stream.segments);
                            results.http_transactions.extend(txns);
                        }
                        AppProtocol::Tls => {
                            if let Some(tls) = tls::parse_tls_stream(&stream.segments) {
                                results.tls_sessions.push(tls);
                            }
                        }
                        AppProtocol::Dns => {
                            let records = dns::parse_dns_stream(&stream.segments);
                            results.dns_records.extend(records);
                        }
                        AppProtocol::Ftp => {
                            let session = ftp::parse_ftp_stream(&stream.segments);
                            results.ftp_sessions.push(session);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    tracing::info!(
        dns = results.dns_records.len(),
        http = results.http_transactions.len(),
        tls = results.tls_sessions.len(),
        icmp = results.icmp_summaries.len(),
        ftp = results.ftp_sessions.len(),
        smtp = results.smtp_sessions.len(),
        "protocol dissection complete"
    );

    results
}

/// Heuristic protocol detection by inspecting the first bytes of a stream.
fn heuristic_detect(stream: &Stream) -> Option<AppProtocol> {
    let first_seg = stream.segments.first()?;
    let data = &first_seg.data;

    if data.is_empty() {
        return None;
    }

    // TLS: starts with 0x16 (handshake) or 0x17 (application data)
    if data.len() >= 3 && (data[0] == 0x16 || data[0] == 0x17) && data[1] == 0x03 {
        return Some(AppProtocol::Tls);
    }

    let text = String::from_utf8_lossy(&data[..data.len().min(64)]);

    // HTTP request
    if text.starts_with("GET ")
        || text.starts_with("POST ")
        || text.starts_with("PUT ")
        || text.starts_with("HEAD ")
        || text.starts_with("DELETE ")
        || text.starts_with("OPTIONS ")
        || text.starts_with("CONNECT ")
        || text.starts_with("HTTP/")
    {
        return Some(AppProtocol::Http);
    }

    // FTP
    if text.starts_with("220 ") || text.starts_with("USER ") || text.starts_with("230 ") {
        return Some(AppProtocol::Ftp);
    }

    // SMTP
    if text.starts_with("220 ") && text.contains("SMTP")
        || text.starts_with("EHLO ")
        || text.starts_with("HELO ")
    {
        return Some(AppProtocol::Smtp);
    }

    // DNS: check if first 2 bytes look like valid DNS (heuristic)
    if data.len() >= 12 {
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let opcode = (flags >> 11) & 0xF;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if opcode <= 2 && qdcount >= 1 && qdcount <= 10 {
            return Some(AppProtocol::Dns);
        }
    }

    // SSH
    if text.starts_with("SSH-") {
        return Some(AppProtocol::Ssh);
    }

    None
}

#[derive(Debug, Default)]
pub struct DissectionResults {
    pub dns_records: Vec<DnsRecord>,
    pub http_transactions: Vec<HttpTransaction>,
    pub tls_sessions: Vec<TlsInfo>,
    pub icmp_summaries: Vec<icmp::IcmpSummary>,
    pub ftp_sessions: Vec<ftp::FtpSession>,
    pub smtp_sessions: Vec<smtp::SmtpSession>,
}
