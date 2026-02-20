use crate::models::{StreamDirection, StreamSegment};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetSession {
    pub content: String,
    pub credentials_seen: Vec<TelnetCredential>,
    pub negotiation_options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetCredential {
    pub username: Option<String>,
    pub password: Option<String>,
}

pub fn parse_telnet_stream(segments: &[StreamSegment]) -> TelnetSession {
    let mut session = TelnetSession {
        content: String::new(),
        credentials_seen: Vec::new(),
        negotiation_options: Vec::new(),
    };

    let mut last_prompt = String::new();
    let mut pending_username: Option<String> = None;

    for seg in segments {
        let cleaned = strip_iac(&seg.data);
        let text = String::from_utf8_lossy(&cleaned);

        for iac_opt in extract_iac_options(&seg.data) {
            session.negotiation_options.push(iac_opt);
        }

        let text_str = text.to_string();
        session.content.push_str(&text_str);

        let is_server = seg.direction == StreamDirection::ServerToClient;

        if is_server {
            let lower = text_str.to_lowercase();
            if lower.contains("login:") || lower.contains("username:") {
                last_prompt = "login".to_string();
            } else if lower.contains("password:") {
                last_prompt = "password".to_string();
            }
        } else {
            let input = text_str.trim().to_string();
            if !input.is_empty() {
                match last_prompt.as_str() {
                    "login" => {
                        pending_username = Some(input);
                        last_prompt.clear();
                    }
                    "password" => {
                        session.credentials_seen.push(TelnetCredential {
                            username: pending_username.take(),
                            password: Some(input),
                        });
                        last_prompt.clear();
                    }
                    _ => {}
                }
            }
        }
    }

    if session.content.len() > 10000 {
        session.content.truncate(10000);
        session.content.push_str("...[truncated]");
    }

    session
}

fn strip_iac(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0xFF && i + 1 < data.len() {
            let cmd = data[i + 1];
            if cmd >= 0xFB && cmd <= 0xFE && i + 2 < data.len() {
                i += 3; // WILL/WONT/DO/DONT + option
            } else if cmd == 0xFA {
                // Subnegotiation - skip until IAC SE
                i += 2;
                while i + 1 < data.len() && !(data[i] == 0xFF && data[i + 1] == 0xF0) {
                    i += 1;
                }
                if i + 1 < data.len() { i += 2; }
            } else {
                i += 2;
            }
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

fn extract_iac_options(data: &[u8]) -> Vec<String> {
    let mut opts = Vec::new();
    let mut i = 0;
    while i + 2 < data.len() {
        if data[i] == 0xFF {
            let cmd = data[i + 1];
            let cmd_name = match cmd {
                0xFB => "WILL",
                0xFC => "WONT",
                0xFD => "DO",
                0xFE => "DONT",
                _ => { i += 2; continue; }
            };
            if i + 2 < data.len() {
                let opt = data[i + 2];
                let opt_name = match opt {
                    0 => "Binary", 1 => "Echo", 3 => "SGA",
                    5 => "Status", 24 => "TermType", 31 => "WindowSize",
                    32 => "TermSpeed", 33 => "RemoteFlowCtrl", 34 => "Linemode",
                    36 => "EnvVars", 39 => "NewEnv",
                    _ => "",
                };
                if !opt_name.is_empty() {
                    opts.push(format!("{} {}", cmd_name, opt_name));
                } else {
                    opts.push(format!("{} opt:{}", cmd_name, opt));
                }
                i += 3;
            } else { break; }
        } else {
            i += 1;
        }
    }
    opts
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn seg(dir: StreamDirection, data: &[u8]) -> StreamSegment {
        StreamSegment { direction: dir, data: data.to_vec(), timestamp: Utc::now() }
    }

    #[test]
    fn test_parse_telnet_login() {
        let segs = vec![
            seg(StreamDirection::ServerToClient, b"\xff\xfd\x01\xff\xfd\x1flogin: "),
            seg(StreamDirection::ClientToServer, b"admin\r\n"),
            seg(StreamDirection::ServerToClient, b"Password: "),
            seg(StreamDirection::ClientToServer, b"secret123\r\n"),
            seg(StreamDirection::ServerToClient, b"Welcome!\r\n"),
        ];
        let session = parse_telnet_stream(&segs);
        assert_eq!(session.credentials_seen.len(), 1);
        assert_eq!(session.credentials_seen[0].username, Some("admin".into()));
        assert_eq!(session.credentials_seen[0].password, Some("secret123".into()));
        assert!(!session.negotiation_options.is_empty());
    }
}
