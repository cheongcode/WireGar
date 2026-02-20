pub mod dns;
pub mod http;
pub mod tls;
pub mod icmp;
pub mod ftp;
pub mod smtp;
pub mod ssh;
pub mod telnet;
pub mod dhcp;
pub mod smb;

use crate::models::*;

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
            AppProtocol::FtpData => {
                // FTP-DATA streams are raw file transfers
            }
            AppProtocol::Smtp => {
                let session = smtp::parse_smtp_stream(&stream.segments);
                results.smtp_sessions.push(session);
            }
            AppProtocol::Ssh => {
                let session = ssh::parse_ssh_stream(&stream.segments);
                results.ssh_sessions.push(session);
            }
            AppProtocol::Telnet => {
                let session = telnet::parse_telnet_stream(&stream.segments);
                results.telnet_sessions.push(session);
            }
            AppProtocol::Dhcp => {
                let leases = dhcp::parse_dhcp_stream(&stream.segments);
                results.dhcp_leases.extend(leases);
            }
            AppProtocol::Smb => {
                let session = smb::parse_smb_stream(&stream.segments);
                results.smb_sessions.push(session);
            }
            _ => {
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
                        AppProtocol::Ssh => {
                            let session = ssh::parse_ssh_stream(&stream.segments);
                            results.ssh_sessions.push(session);
                        }
                        AppProtocol::Smb => {
                            let session = smb::parse_smb_stream(&stream.segments);
                            results.smb_sessions.push(session);
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
        ssh = results.ssh_sessions.len(),
        telnet = results.telnet_sessions.len(),
        dhcp = results.dhcp_leases.len(),
        smb = results.smb_sessions.len(),
        "protocol dissection complete"
    );

    results
}

fn heuristic_detect(stream: &Stream) -> Option<AppProtocol> {
    let first_seg = stream.segments.first()?;
    let data = &first_seg.data;
    if data.is_empty() { return None; }

    // TLS
    if data.len() >= 3 && (data[0] == 0x16 || data[0] == 0x17) && data[1] == 0x03 {
        return Some(AppProtocol::Tls);
    }

    let text = String::from_utf8_lossy(&data[..data.len().min(128)]);

    // HTTP
    if text.starts_with("GET ") || text.starts_with("POST ") || text.starts_with("PUT ")
        || text.starts_with("HEAD ") || text.starts_with("DELETE ")
        || text.starts_with("OPTIONS ") || text.starts_with("CONNECT ") || text.starts_with("HTTP/")
    {
        return Some(AppProtocol::Http);
    }

    // SSH
    if text.starts_with("SSH-") {
        return Some(AppProtocol::Ssh);
    }

    // FTP
    if text.starts_with("220 ") && !text.contains("SMTP") {
        return Some(AppProtocol::Ftp);
    }
    if text.starts_with("USER ") || text.starts_with("230 ") {
        return Some(AppProtocol::Ftp);
    }

    // SMTP
    if (text.starts_with("220 ") && text.contains("SMTP"))
        || text.starts_with("EHLO ") || text.starts_with("HELO ")
    {
        return Some(AppProtocol::Smtp);
    }

    // SMB over NetBIOS
    if data.len() > 8 {
        let smb_offset = if data[0] == 0x00 && data.len() > 8 { 4 } else { 0 };
        if data[smb_offset..].starts_with(b"\xffSMB") || data[smb_offset..].starts_with(b"\xfeSMB") {
            return Some(AppProtocol::Smb);
        }
    }

    // Telnet (IAC commands)
    if data.len() >= 3 && data[0] == 0xFF && (data[1] >= 0xFB && data[1] <= 0xFE) {
        return Some(AppProtocol::Telnet);
    }

    // DHCP (magic cookie at offset 236 for full BOOTP message)
    if data.len() > 240 && data[236..240] == [99, 130, 83, 99] {
        return Some(AppProtocol::Dhcp);
    }

    // DNS heuristic
    if data.len() >= 12 {
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let opcode = (flags >> 11) & 0xF;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if opcode <= 2 && qdcount >= 1 && qdcount <= 10 {
            return Some(AppProtocol::Dns);
        }
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
    pub ssh_sessions: Vec<ssh::SshSession>,
    pub telnet_sessions: Vec<telnet::TelnetSession>,
    pub dhcp_leases: Vec<dhcp::DhcpLease>,
    pub smb_sessions: Vec<smb::SmbSession>,
}
