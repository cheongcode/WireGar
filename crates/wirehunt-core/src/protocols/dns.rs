use crate::models::{DnsRecord, StreamSegment};

/// Parse DNS records from a stream's segments (typically single UDP datagrams).
pub fn parse_dns_stream(segments: &[StreamSegment]) -> Vec<DnsRecord> {
    let mut records = Vec::new();
    for seg in segments {
        if let Some(mut parsed) = parse_dns_message(&seg.data) {
            records.append(&mut parsed);
        }
    }
    records
}

fn parse_dns_message(data: &[u8]) -> Option<Vec<DnsRecord>> {
    if data.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = (flags & 0x8000) != 0;
    let rcode = flags & 0x000F;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let response_code = match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    };

    let mut offset = 12;
    let mut records = Vec::new();

    // Parse questions
    for _ in 0..qdcount {
        let (name, new_offset) = read_dns_name(data, offset)?;
        offset = new_offset;
        if offset + 4 > data.len() {
            return Some(records);
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 4; // skip qtype + qclass

        let record_type = dns_type_to_string(qtype);

        records.push(DnsRecord {
            query_name: name,
            record_type,
            response_data: Vec::new(),
            ttl: None,
            is_response,
            response_code: Some(response_code.to_string()),
        });
    }

    // Parse answers (only in responses)
    if is_response {
        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }
            let (name, new_offset) = read_dns_name(data, offset)?;
            offset = new_offset;

            if offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            let rdata = &data[offset..offset + rdlength];
            let response_str = parse_rdata(rtype, rdata, data);
            offset += rdlength;

            let record_type = dns_type_to_string(rtype);

            records.push(DnsRecord {
                query_name: name,
                record_type,
                response_data: vec![response_str],
                ttl: Some(ttl),
                is_response: true,
                response_code: Some(response_code.to_string()),
            });
        }
    }

    Some(records)
}

fn read_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut return_offset = 0;
    let mut seen = 0;

    loop {
        if offset >= data.len() || seen > 256 {
            return None;
        }
        seen += 1;

        let len = data[offset] as usize;

        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Pointer (compression)
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            if !jumped {
                return_offset = offset + 2;
            }
            offset = ptr;
            jumped = true;
            continue;
        }

        offset += 1;
        if offset + len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        parts.push(label);
        offset += len;
    }

    let name = if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join(".")
    };

    Some((name, return_offset))
}

fn parse_rdata(rtype: u16, rdata: &[u8], full_msg: &[u8]) -> String {
    match rtype {
        1 if rdata.len() == 4 => {
            // A record
            format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        28 if rdata.len() == 16 => {
            // AAAA record
            let addr: [u8; 16] = rdata.try_into().unwrap();
            std::net::Ipv6Addr::from(addr).to_string()
        }
        5 | 2 | 12 | 15 | 6 => {
            // CNAME, NS, PTR, MX, SOA -- contains a domain name
            read_dns_name(full_msg, rdata.as_ptr() as usize - full_msg.as_ptr() as usize)
                .map(|(name, _)| name)
                .unwrap_or_else(|| hex::encode(rdata))
        }
        16 => {
            // TXT record
            if !rdata.is_empty() {
                let txt_len = rdata[0] as usize;
                if txt_len + 1 <= rdata.len() {
                    return String::from_utf8_lossy(&rdata[1..1 + txt_len]).to_string();
                }
            }
            hex::encode(rdata)
        }
        _ => hex::encode(rdata),
    }
}

fn dns_type_to_string(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        41 => "OPT".to_string(),
        43 => "DS".to_string(),
        46 => "RRSIG".to_string(),
        47 => "NSEC".to_string(),
        48 => "DNSKEY".to_string(),
        65 => "HTTPS".to_string(),
        255 => "ANY".to_string(),
        _ => format!("TYPE{}", qtype),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query() {
        // Minimal DNS query for example.com A record
        let data: Vec<u8> = vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, 0x00, 0x00, // Authority + Additional
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // Root label
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let records = parse_dns_message(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].query_name, "example.com");
        assert_eq!(records[0].record_type, "A");
        assert!(!records[0].is_response);
    }

    #[test]
    fn test_parse_dns_response_with_a_record() {
        let data: Vec<u8> = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response, no error
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answers: 1
            0x00, 0x00, 0x00, 0x00,
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
            // Answer: pointer to offset 12, A, IN, TTL=300, 4 bytes, 93.184.216.34
            0xC0, 0x0C, // Name pointer
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x01, 0x2C, // TTL = 300
            0x00, 0x04, // RDLength = 4
            93, 184, 216, 34, // IP address
        ];

        let records = parse_dns_message(&data).unwrap();
        assert_eq!(records.len(), 2); // 1 question + 1 answer
        assert_eq!(records[1].query_name, "example.com");
        assert_eq!(records[1].response_data[0], "93.184.216.34");
        assert_eq!(records[1].ttl, Some(300));
    }
}
