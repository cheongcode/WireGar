use crate::models::StreamSegment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpSummary {
    pub messages: Vec<IcmpMessage>,
    pub embedded_payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpMessage {
    pub icmp_type: u8,
    pub code: u8,
    pub type_name: String,
    pub payload_size: usize,
}

/// Parse ICMP messages from stream segments.
/// Useful for CTF: ICMP tunneling often hides data in payloads.
pub fn parse_icmp_stream(segments: &[StreamSegment]) -> IcmpSummary {
    let mut messages = Vec::new();
    let mut embedded_payload = Vec::new();

    for seg in segments {
        if seg.data.len() < 4 {
            continue;
        }

        let icmp_type = seg.data[0];
        let code = seg.data[1];
        let type_name = icmp_type_name(icmp_type, code);

        // Payload starts after type(1) + code(1) + checksum(2) + rest-of-header(4)
        let payload_offset = if seg.data.len() > 8 { 8 } else { 4 };
        let payload = &seg.data[payload_offset.min(seg.data.len())..];

        messages.push(IcmpMessage {
            icmp_type,
            code,
            type_name,
            payload_size: payload.len(),
        });

        // Collect embedded payloads for CTF exfil detection
        if !payload.is_empty() && (icmp_type == 8 || icmp_type == 0) {
            embedded_payload.extend_from_slice(payload);
        }
    }

    IcmpSummary {
        messages,
        embedded_payload,
    }
}

fn icmp_type_name(icmp_type: u8, code: u8) -> String {
    match (icmp_type, code) {
        (0, _) => "Echo Reply".to_string(),
        (3, 0) => "Destination Net Unreachable".to_string(),
        (3, 1) => "Destination Host Unreachable".to_string(),
        (3, 3) => "Destination Port Unreachable".to_string(),
        (3, _) => format!("Destination Unreachable (code {})", code),
        (4, _) => "Source Quench".to_string(),
        (5, _) => format!("Redirect (code {})", code),
        (8, _) => "Echo Request".to_string(),
        (9, _) => "Router Advertisement".to_string(),
        (10, _) => "Router Solicitation".to_string(),
        (11, 0) => "TTL Exceeded in Transit".to_string(),
        (11, 1) => "Fragment Reassembly Exceeded".to_string(),
        _ => format!("Type {} Code {}", icmp_type, code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_parse_icmp_echo() {
        let data = vec![
            8, 0,           // Type 8 (Echo Request), Code 0
            0x00, 0x00,     // Checksum
            0x00, 0x01,     // Identifier
            0x00, 0x01,     // Sequence number
            b'H', b'e', b'l', b'l', b'o', // Payload
        ];

        let segments = vec![StreamSegment {
            direction: crate::models::StreamDirection::Unknown,
            data,
            timestamp: Utc::now(),
        }];

        let summary = parse_icmp_stream(&segments);
        assert_eq!(summary.messages.len(), 1);
        assert_eq!(summary.messages[0].type_name, "Echo Request");
        assert_eq!(summary.embedded_payload, b"Hello");
    }
}
