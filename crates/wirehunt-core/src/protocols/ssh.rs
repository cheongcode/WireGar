use crate::models::StreamSegment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSession {
    pub client_banner: Option<String>,
    pub server_banner: Option<String>,
    pub client_version: Option<String>,
    pub server_version: Option<String>,
    pub kex_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
}

pub fn parse_ssh_stream(segments: &[StreamSegment]) -> SshSession {
    let mut session = SshSession {
        client_banner: None,
        server_banner: None,
        client_version: None,
        server_version: None,
        kex_algorithms: Vec::new(),
        ciphers: Vec::new(),
        macs: Vec::new(),
    };

    for seg in segments {
        let text = String::from_utf8_lossy(&seg.data);
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("SSH-") {
                continue;
            }

            let is_client = seg.direction == crate::models::StreamDirection::ClientToServer;

            if is_client {
                session.client_banner = Some(line.to_string());
                session.client_version = extract_ssh_version(line);
            } else {
                session.server_banner = Some(line.to_string());
                session.server_version = extract_ssh_version(line);
            }
        }

        if seg.data.len() > 20 {
            if let Some(kex) = try_parse_kex_init(&seg.data) {
                if session.kex_algorithms.is_empty() {
                    session.kex_algorithms = kex.kex_algorithms;
                    session.ciphers = kex.ciphers;
                    session.macs = kex.macs;
                }
            }
        }
    }

    session
}

fn extract_ssh_version(banner: &str) -> Option<String> {
    let parts: Vec<&str> = banner.splitn(3, '-').collect();
    if parts.len() >= 3 {
        Some(parts[2].split_whitespace().next().unwrap_or(parts[2]).to_string())
    } else {
        None
    }
}

struct KexInit {
    kex_algorithms: Vec<String>,
    ciphers: Vec<String>,
    macs: Vec<String>,
}

fn try_parse_kex_init(data: &[u8]) -> Option<KexInit> {
    let msg_offset = if data.len() > 5 && data[5] == 20 { 6 } else {
        data.iter().position(|&b| b == 20)?
    };

    let payload = &data[msg_offset..];
    if payload.is_empty() || payload[0] != 20 {
        return None;
    }

    let mut offset = 17; // skip msg_type(1) + cookie(16)
    if offset >= payload.len() { return None; }

    let kex_algs = read_name_list(payload, &mut offset)?;
    let _server_host_key_algs = read_name_list(payload, &mut offset)?;
    let enc_client = read_name_list(payload, &mut offset)?;
    let _enc_server = read_name_list(payload, &mut offset)?;
    let mac_client = read_name_list(payload, &mut offset)?;

    Some(KexInit {
        kex_algorithms: kex_algs,
        ciphers: enc_client,
        macs: mac_client,
    })
}

fn read_name_list(data: &[u8], offset: &mut usize) -> Option<Vec<String>> {
    if *offset + 4 > data.len() { return None; }
    let len = u32::from_be_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]) as usize;
    *offset += 4;
    if *offset + len > data.len() { return None; }
    let s = String::from_utf8_lossy(&data[*offset..*offset + len]);
    *offset += len;
    Some(s.split(',').map(|s| s.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ssh_version() {
        assert_eq!(extract_ssh_version("SSH-2.0-OpenSSH_8.9"), Some("OpenSSH_8.9".into()));
        assert_eq!(extract_ssh_version("SSH-2.0-libssh2_1.10.0"), Some("libssh2_1.10.0".into()));
    }
}
