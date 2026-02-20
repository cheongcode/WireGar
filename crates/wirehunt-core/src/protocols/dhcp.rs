use crate::models::StreamSegment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub message_type: String,
    pub client_mac: String,
    pub assigned_ip: Option<String>,
    pub hostname: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub lease_secs: Option<u32>,
    pub server_ip: Option<String>,
    pub domain_name: Option<String>,
}

pub fn parse_dhcp_stream(segments: &[StreamSegment]) -> Vec<DhcpLease> {
    let mut leases = Vec::new();
    for seg in segments {
        if let Some(lease) = parse_dhcp_message(&seg.data) {
            leases.push(lease);
        }
    }
    leases
}

fn parse_dhcp_message(data: &[u8]) -> Option<DhcpLease> {
    if data.len() < 240 { return None; }

    let op = data[0]; // 1=request, 2=reply
    let _htype = data[1];
    let hlen = data[2] as usize;

    let client_mac = if hlen == 6 && data.len() > 34 {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[28], data[29], data[30], data[31], data[32], data[33])
    } else {
        "unknown".to_string()
    };

    let your_ip = if data[16..20] != [0, 0, 0, 0] {
        Some(format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]))
    } else {
        None
    };

    // Magic cookie check
    if data[236..240] != [99, 130, 83, 99] { return None; }

    let mut msg_type = String::new();
    let mut hostname = None;
    let mut gateway = None;
    let mut dns_servers = Vec::new();
    let mut lease_secs = None;
    let mut server_ip = None;
    let mut domain_name = None;

    let mut i = 240;
    while i < data.len() {
        let opt = data[i];
        if opt == 255 { break; } // end
        if opt == 0 { i += 1; continue; } // pad
        if i + 1 >= data.len() { break; }
        let len = data[i + 1] as usize;
        i += 2;
        if i + len > data.len() { break; }
        let val = &data[i..i + len];

        match opt {
            53 if len == 1 => {
                msg_type = match val[0] {
                    1 => "Discover", 2 => "Offer", 3 => "Request", 4 => "Decline",
                    5 => "ACK", 6 => "NAK", 7 => "Release", 8 => "Inform",
                    _ => "Unknown",
                }.to_string();
            }
            3 if len >= 4 => {
                gateway = Some(format!("{}.{}.{}.{}", val[0], val[1], val[2], val[3]));
            }
            6 => {
                let mut j = 0;
                while j + 3 < len {
                    dns_servers.push(format!("{}.{}.{}.{}", val[j], val[j+1], val[j+2], val[j+3]));
                    j += 4;
                }
            }
            12 => {
                hostname = Some(String::from_utf8_lossy(val).to_string());
            }
            15 => {
                domain_name = Some(String::from_utf8_lossy(val).to_string());
            }
            51 if len == 4 => {
                lease_secs = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
            }
            54 if len == 4 => {
                server_ip = Some(format!("{}.{}.{}.{}", val[0], val[1], val[2], val[3]));
            }
            _ => {}
        }
        i += len;
    }

    if msg_type.is_empty() {
        msg_type = if op == 1 { "Request".into() } else { "Reply".into() };
    }

    Some(DhcpLease {
        message_type: msg_type,
        client_mac,
        assigned_ip: your_ip,
        hostname,
        gateway,
        dns_servers,
        lease_secs,
        server_ip,
        domain_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dhcp_discover() {
        let mut data = vec![0u8; 240];
        data[0] = 1; // request
        data[2] = 6; // hlen
        data[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        data[236..240].copy_from_slice(&[99, 130, 83, 99]); // magic
        data.extend_from_slice(&[53, 1, 1]); // DHCP Discover
        data.extend_from_slice(&[12, 6]); // hostname opt
        data.extend_from_slice(b"myhost");
        data.push(255); // end

        let leases = parse_dhcp_stream(&[StreamSegment {
            direction: crate::models::StreamDirection::ClientToServer,
            data,
            timestamp: chrono::Utc::now(),
        }]);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].message_type, "Discover");
        assert_eq!(leases[0].hostname, Some("myhost".into()));
        assert_eq!(leases[0].client_mac, "aa:bb:cc:dd:ee:ff");
    }
}
