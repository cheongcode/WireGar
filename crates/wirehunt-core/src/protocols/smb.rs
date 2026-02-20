use crate::models::StreamSegment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbSession {
    pub version: String,
    pub dialect: Option<String>,
    pub commands: Vec<String>,
    pub shares_accessed: Vec<String>,
    pub ntlm_domains: Vec<String>,
    pub ntlm_users: Vec<String>,
    pub files_accessed: Vec<String>,
}

pub fn parse_smb_stream(segments: &[StreamSegment]) -> SmbSession {
    let mut session = SmbSession {
        version: String::new(),
        dialect: None,
        commands: Vec::new(),
        shares_accessed: Vec::new(),
        ntlm_domains: Vec::new(),
        ntlm_users: Vec::new(),
        files_accessed: Vec::new(),
    };

    for seg in &*segments {
        let data = &seg.data;
        let mut offset = 0;

        while offset + 4 < data.len() {
            // NetBIOS session header (4 bytes) before SMB
            let nb_len = if offset + 4 < data.len() && data[offset] == 0x00 {
                let len = ((data[offset + 1] as usize) << 16)
                    | ((data[offset + 2] as usize) << 8)
                    | (data[offset + 3] as usize);
                offset += 4;
                len
            } else {
                data.len() - offset
            };

            if offset + 4 > data.len() { break; }

            // SMB1: \xFFSMB
            if data[offset..].starts_with(b"\xffSMB") && offset + 36 < data.len() {
                session.version = "SMB1".to_string();
                let cmd = data[offset + 4];
                let cmd_name = smb1_command_name(cmd);
                if !session.commands.contains(&cmd_name) {
                    session.commands.push(cmd_name.clone());
                }

                // Session Setup (0x73) may contain NTLM
                if cmd == 0x73 {
                    extract_ntlm_from_slice(&data[offset..], &mut session);
                }
                // Tree Connect (0x75)
                if cmd == 0x75 {
                    extract_share_from_smb1(&data[offset..], &mut session);
                }
            }
            // SMB2/3: \xFESMB
            else if data[offset..].starts_with(b"\xfeSMB") && offset + 68 < data.len() {
                if session.version.is_empty() || session.version == "SMB1" {
                    session.version = "SMB2+".to_string();
                }
                let cmd = u16::from_le_bytes([data[offset + 12], data[offset + 13]]);
                let cmd_name = smb2_command_name(cmd);
                if !session.commands.contains(&cmd_name) {
                    session.commands.push(cmd_name.clone());
                }

                // Session Setup (0x01) may contain NTLM
                if cmd == 1 {
                    extract_ntlm_from_slice(&data[offset..], &mut session);
                }
                // Tree Connect (0x03)
                if cmd == 3 {
                    extract_share_from_smb2(&data[offset..], &mut session);
                }
            } else {
                break;
            }

            offset += nb_len;
            if nb_len == 0 { break; }
        }
    }

    session
}

fn extract_ntlm_from_slice(data: &[u8], session: &mut SmbSession) {
    if let Some(pos) = find_subsequence(data, b"NTLMSSP\x00") {
        let ntlm_data = &data[pos..];
        if ntlm_data.len() < 12 { return; }
        let msg_type = u32::from_le_bytes([ntlm_data[8], ntlm_data[9], ntlm_data[10], ntlm_data[11]]);

        if msg_type == 3 && ntlm_data.len() > 36 {
            // Type 3 (Authentication) -- extract domain and user
            if let Some(domain) = extract_ntlm_field(ntlm_data, 28) {
                if !domain.is_empty() && !session.ntlm_domains.contains(&domain) {
                    session.ntlm_domains.push(domain);
                }
            }
            if let Some(user) = extract_ntlm_field(ntlm_data, 36) {
                if !user.is_empty() && !session.ntlm_users.contains(&user) {
                    session.ntlm_users.push(user);
                }
            }
        }
    }
}

fn extract_ntlm_field(data: &[u8], field_offset: usize) -> Option<String> {
    if field_offset + 4 > data.len() { return None; }
    let len = u16::from_le_bytes([data[field_offset], data[field_offset + 1]]) as usize;
    let off = u32::from_le_bytes([data[field_offset + 4], data[field_offset + 5],
        data.get(field_offset + 6).copied().unwrap_or(0),
        data.get(field_offset + 7).copied().unwrap_or(0)]) as usize;
    if off + len > data.len() || len == 0 { return None; }
    // UTF-16LE decode
    let slice = &data[off..off + len];
    let chars: Vec<u16> = slice.chunks(2)
        .filter_map(|c| if c.len() == 2 { Some(u16::from_le_bytes([c[0], c[1]])) } else { None })
        .collect();
    Some(String::from_utf16_lossy(&chars))
}

fn extract_share_from_smb1(data: &[u8], session: &mut SmbSession) {
    if let Some(text) = find_utf16_or_ascii_string(data, b"\\\\") {
        if !session.shares_accessed.contains(&text) {
            session.shares_accessed.push(text);
        }
    }
}

fn extract_share_from_smb2(data: &[u8], session: &mut SmbSession) {
    if let Some(text) = find_utf16_or_ascii_string(data, b"\\\\") {
        if !session.shares_accessed.contains(&text) {
            session.shares_accessed.push(text);
        }
    }
}

fn find_utf16_or_ascii_string(data: &[u8], prefix: &[u8]) -> Option<String> {
    // Try ASCII
    if let Some(pos) = find_subsequence(data, prefix) {
        let end = data[pos..].iter().position(|&b| b == 0).unwrap_or(data.len() - pos);
        let s = String::from_utf8_lossy(&data[pos..pos + end]).to_string();
        if s.len() > 4 { return Some(s); }
    }
    // Try UTF-16LE (\\  = 0x5C 0x00 0x5C 0x00)
    let utf16_prefix = [0x5C, 0x00, 0x5C, 0x00];
    if let Some(pos) = find_subsequence(data, &utf16_prefix) {
        let slice = &data[pos..];
        let chars: Vec<u16> = slice.chunks(2).take(128)
            .filter_map(|c| if c.len() == 2 { Some(u16::from_le_bytes([c[0], c[1]])) } else { None })
            .take_while(|&c| c != 0)
            .collect();
        let s = String::from_utf16_lossy(&chars);
        if s.len() > 4 { return Some(s); }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn smb1_command_name(cmd: u8) -> String {
    match cmd {
        0x72 => "Negotiate".into(),
        0x73 => "SessionSetup".into(),
        0x75 => "TreeConnect".into(),
        0x71 => "TreeDisconnect".into(),
        0x2e => "Read".into(),
        0x2f => "Write".into(),
        0x32 => "Trans2".into(),
        0xa2 => "NtCreate".into(),
        0x04 => "Close".into(),
        _ => format!("SMB1_CMD_{:02x}", cmd),
    }
}

fn smb2_command_name(cmd: u16) -> String {
    match cmd {
        0 => "Negotiate".into(),
        1 => "SessionSetup".into(),
        2 => "Logoff".into(),
        3 => "TreeConnect".into(),
        4 => "TreeDisconnect".into(),
        5 => "Create".into(),
        6 => "Close".into(),
        8 => "Read".into(),
        9 => "Write".into(),
        14 => "Find".into(),
        16 => "GetInfo".into(),
        17 => "SetInfo".into(),
        _ => format!("SMB2_CMD_{:02x}", cmd),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb1_command_names() {
        assert_eq!(smb1_command_name(0x72), "Negotiate");
        assert_eq!(smb1_command_name(0x73), "SessionSetup");
    }

    #[test]
    fn test_smb2_command_names() {
        assert_eq!(smb2_command_name(0), "Negotiate");
        assert_eq!(smb2_command_name(1), "SessionSetup");
        assert_eq!(smb2_command_name(3), "TreeConnect");
    }
}
