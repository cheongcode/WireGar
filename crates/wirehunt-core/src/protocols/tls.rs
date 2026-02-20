use crate::models::{StreamDirection, StreamSegment, TlsInfo};
use md5::{Digest, Md5};

/// Parse TLS handshake metadata from a stream's segments.
pub fn parse_tls_stream(segments: &[StreamSegment]) -> Option<TlsInfo> {
    let mut client_data = Vec::new();
    let mut server_data = Vec::new();

    for seg in segments {
        match seg.direction {
            StreamDirection::ClientToServer => client_data.extend_from_slice(&seg.data),
            StreamDirection::ServerToClient => server_data.extend_from_slice(&seg.data),
            _ => {}
        }
    }

    let client_hello = parse_client_hello(&client_data);
    let server_hello = parse_server_hello(&server_data);

    if client_hello.is_none() && server_hello.is_none() {
        return None;
    }

    let mut info = TlsInfo {
        version: String::new(),
        sni: None,
        alpn: Vec::new(),
        cipher_suite: None,
        ja3_hash: None,
        ja3s_hash: None,
        cert_subject: None,
        cert_issuer: None,
        cert_not_before: None,
        cert_not_after: None,
        cert_fingerprint_sha256: None,
        is_self_signed: None,
    };

    if let Some(ch) = client_hello {
        info.version = format_tls_version(ch.version);
        info.ja3_hash = Some(compute_ja3(&ch));
        info.sni = ch.sni;
        info.alpn = ch.alpn;
    }

    if let Some(sh) = server_hello {
        if info.version.is_empty() {
            info.version = format_tls_version(sh.version);
        }
        info.cipher_suite = Some(format!("0x{:04x}", sh.cipher_suite));
        info.ja3s_hash = Some(compute_ja3s(&sh));
    }

    Some(info)
}

struct ClientHello {
    version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    elliptic_curves: Vec<u16>,
    ec_point_formats: Vec<u8>,
    sni: Option<String>,
    alpn: Vec<String>,
}

struct ServerHello {
    version: u16,
    cipher_suite: u16,
    extensions: Vec<u16>,
}

fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    if data.len() < 5 {
        return None;
    }
    if data[0] != 0x16 {
        return None; // Not a handshake record
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }
    let hs = &data[5..5 + record_len];

    if hs.is_empty() || hs[0] != 0x01 {
        return None; // Not ClientHello
    }

    if hs.len() < 38 {
        return None;
    }

    let version = u16::from_be_bytes([hs[4], hs[5]]);
    // Skip random (32 bytes): hs[6..38]
    let mut offset = 38;

    // Session ID
    if offset >= hs.len() {
        return None;
    }
    let session_id_len = hs[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suites
    if offset + 2 > hs.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
    offset += 2;
    if offset + cs_len > hs.len() {
        return None;
    }

    let mut ciphers = Vec::new();
    let mut cs_offset = offset;
    while cs_offset + 2 <= offset + cs_len {
        let cs = u16::from_be_bytes([hs[cs_offset], hs[cs_offset + 1]]);
        // Skip GREASE values (0x?a?a pattern)
        if !is_grease(cs) {
            ciphers.push(cs);
        }
        cs_offset += 2;
    }
    offset += cs_len;

    // Compression methods
    if offset >= hs.len() {
        return None;
    }
    let comp_len = hs[offset] as usize;
    offset += 1 + comp_len;

    // Extensions
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut sni = None;
    let mut alpn = Vec::new();

    if offset + 2 <= hs.len() {
        let ext_total_len = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
        offset += 2;
        let ext_end = (offset + ext_total_len).min(hs.len());

        while offset + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
            let ext_len = u16::from_be_bytes([hs[offset + 2], hs[offset + 3]]) as usize;
            offset += 4;

            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }

            let ext_data = if offset + ext_len <= ext_end {
                &hs[offset..offset + ext_len]
            } else {
                break;
            };

            match ext_type {
                0x0000 => {
                    // SNI
                    sni = parse_sni_extension(ext_data);
                }
                0x000a => {
                    // Supported groups / elliptic curves
                    elliptic_curves = parse_supported_groups(ext_data);
                }
                0x000b => {
                    // EC point formats
                    ec_point_formats = parse_ec_point_formats(ext_data);
                }
                0x0010 => {
                    // ALPN
                    alpn = parse_alpn_extension(ext_data);
                }
                _ => {}
            }

            offset += ext_len;
        }
    }

    Some(ClientHello {
        version,
        ciphers,
        extensions,
        elliptic_curves,
        ec_point_formats,
        sni,
        alpn,
    })
}

fn parse_server_hello(data: &[u8]) -> Option<ServerHello> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }
    let hs = &data[5..5 + record_len];

    if hs.is_empty() || hs[0] != 0x02 {
        return None; // Not ServerHello
    }

    if hs.len() < 40 {
        return None;
    }

    let version = u16::from_be_bytes([hs[4], hs[5]]);
    let mut offset = 38;

    // Session ID
    if offset >= hs.len() {
        return None;
    }
    let session_id_len = hs[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suite (single)
    if offset + 2 > hs.len() {
        return None;
    }
    let cipher_suite = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
    offset += 2;

    // Compression method (single byte)
    offset += 1;

    // Extensions
    let mut extensions = Vec::new();
    if offset + 2 <= hs.len() {
        let ext_total_len = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
        offset += 2;
        let ext_end = (offset + ext_total_len).min(hs.len());

        while offset + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
            let ext_len = u16::from_be_bytes([hs[offset + 2], hs[offset + 3]]) as usize;
            offset += 4;

            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }
            offset += ext_len;
        }
    }

    Some(ServerHello {
        version,
        cipher_suite,
        extensions,
    })
}

/// JA3 = md5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
fn compute_ja3(ch: &ClientHello) -> String {
    let version = ch.version.to_string();
    let ciphers = ch.ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");
    let extensions = ch.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
    let curves = ch.elliptic_curves.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");
    let formats = ch.ec_point_formats.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("-");

    let ja3_string = format!("{},{},{},{},{}", version, ciphers, extensions, curves, formats);

    let mut hasher = Md5::new();
    hasher.update(ja3_string.as_bytes());
    hex::encode(hasher.finalize())
}

/// JA3S = md5(TLSVersion,CipherSuite,Extensions)
fn compute_ja3s(sh: &ServerHello) -> String {
    let version = sh.version.to_string();
    let cipher = sh.cipher_suite.to_string();
    let extensions = sh.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");

    let ja3s_string = format!("{},{},{}", version, cipher, extensions);

    let mut hasher = Md5::new();
    hasher.update(ja3s_string.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let _list_len = u16::from_be_bytes([data[0], data[1]]);
    let _name_type = data[2];
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len {
        return None;
    }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut groups = Vec::new();
    let mut offset = 2;
    while offset + 2 <= (2 + list_len).min(data.len()) {
        let g = u16::from_be_bytes([data[offset], data[offset + 1]]);
        if !is_grease(g) {
            groups.push(g);
        }
        offset += 2;
    }
    groups
}

fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let len = data[0] as usize;
    data[1..(1 + len).min(data.len())].to_vec()
}

fn parse_alpn_extension(data: &[u8]) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let _total_len = u16::from_be_bytes([data[0], data[1]]);
    let mut offset = 2;
    let mut protocols = Vec::new();

    while offset < data.len() {
        let proto_len = data[offset] as usize;
        offset += 1;
        if offset + proto_len > data.len() {
            break;
        }
        if let Ok(s) = String::from_utf8(data[offset..offset + proto_len].to_vec()) {
            protocols.push(s);
        }
        offset += proto_len;
    }
    protocols
}

fn format_tls_version(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0304 => "TLS 1.3".to_string(),
        _ => format!("0x{:04x}", v),
    }
}

fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0035)); // AES-256-CBC
        assert!(!is_grease(0x00ff));
    }

    #[test]
    fn test_format_tls_version() {
        assert_eq!(format_tls_version(0x0303), "TLS 1.2");
        assert_eq!(format_tls_version(0x0304), "TLS 1.3");
    }
}
