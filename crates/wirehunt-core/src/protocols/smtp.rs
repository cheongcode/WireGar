use crate::models::{StreamDirection, StreamSegment};

#[derive(Debug, Clone)]
pub struct SmtpSession {
    pub commands: Vec<SmtpExchange>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub data_content: Option<String>,
    pub subject: Option<String>,
    pub ehlo_domain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SmtpExchange {
    pub direction: StreamDirection,
    pub line: String,
    pub response_code: Option<u16>,
}

/// Parse an SMTP session from reassembled stream segments.
pub fn parse_smtp_stream(segments: &[StreamSegment]) -> SmtpSession {
    let mut session = SmtpSession {
        commands: Vec::new(),
        mail_from: None,
        rcpt_to: Vec::new(),
        auth_username: None,
        auth_password: None,
        data_content: None,
        subject: None,
        ehlo_domain: None,
    };

    let mut in_data = false;
    let mut data_buf = String::new();
    let mut auth_state = AuthState::None;

    for seg in segments {
        let text = String::from_utf8_lossy(&seg.data);
        for line in text.lines() {
            let line = line.trim();

            match seg.direction {
                StreamDirection::ClientToServer => {
                    let upper = line.to_uppercase();

                    if in_data {
                        if line == "." {
                            in_data = false;
                            session.data_content = Some(data_buf.clone());
                            // Extract subject from email headers
                            for email_line in data_buf.lines() {
                                if let Some(subj) = email_line.strip_prefix("Subject: ") {
                                    session.subject = Some(subj.to_string());
                                    break;
                                }
                            }
                            data_buf.clear();
                        } else {
                            data_buf.push_str(line);
                            data_buf.push('\n');
                        }
                        continue;
                    }

                    match auth_state {
                        AuthState::WaitingUsername => {
                            // Base64-encoded username
                            if let Ok(decoded) = base64_decode_lossy(line) {
                                session.auth_username = Some(decoded);
                            }
                            auth_state = AuthState::WaitingPassword;
                            continue;
                        }
                        AuthState::WaitingPassword => {
                            if let Ok(decoded) = base64_decode_lossy(line) {
                                session.auth_password = Some(decoded);
                            }
                            auth_state = AuthState::None;
                            continue;
                        }
                        AuthState::None => {}
                    }

                    if upper.starts_with("EHLO ") || upper.starts_with("HELO ") {
                        session.ehlo_domain =
                            line.split_whitespace().nth(1).map(|s| s.to_string());
                    } else if upper.starts_with("MAIL FROM:") {
                        session.mail_from = extract_angle_bracket(line);
                    } else if upper.starts_with("RCPT TO:") {
                        if let Some(addr) = extract_angle_bracket(line) {
                            session.rcpt_to.push(addr);
                        }
                    } else if upper == "DATA" {
                        in_data = true;
                    } else if upper.starts_with("AUTH LOGIN") {
                        auth_state = AuthState::WaitingUsername;
                    } else if upper.starts_with("AUTH PLAIN ") {
                        // AUTH PLAIN with inline credentials (base64 of \0user\0pass)
                        let b64 = line.trim_start_matches("AUTH PLAIN ")
                            .trim_start_matches("auth plain ");
                        if let Ok(decoded) = base64_decode_lossy(b64) {
                            let parts: Vec<&str> = decoded.splitn(3, '\0').collect();
                            if parts.len() >= 3 {
                                session.auth_username = Some(parts[1].to_string());
                                session.auth_password = Some(parts[2].to_string());
                            }
                        }
                    }

                    session.commands.push(SmtpExchange {
                        direction: StreamDirection::ClientToServer,
                        line: line.to_string(),
                        response_code: None,
                    });
                }
                StreamDirection::ServerToClient => {
                    let code = line
                        .split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|s| s.parse::<u16>().ok());

                    session.commands.push(SmtpExchange {
                        direction: StreamDirection::ServerToClient,
                        line: line.to_string(),
                        response_code: code,
                    });
                }
                _ => {}
            }
        }
    }

    session
}

#[derive(Debug)]
enum AuthState {
    None,
    WaitingUsername,
    WaitingPassword,
}

fn extract_angle_bracket(s: &str) -> Option<String> {
    let start = s.find('<')?;
    let end = s.find('>')?;
    if end > start {
        Some(s[start + 1..end].to_string())
    } else {
        None
    }
}

fn base64_decode_lossy(s: &str) -> Result<String, ()> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| ())?;
    String::from_utf8(bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn seg(dir: StreamDirection, data: &[u8]) -> StreamSegment {
        StreamSegment {
            direction: dir,
            data: data.to_vec(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_parse_smtp_session() {
        let segments = vec![
            seg(StreamDirection::ServerToClient, b"220 mail.example.com ESMTP\r\n"),
            seg(StreamDirection::ClientToServer, b"EHLO client.local\r\n"),
            seg(StreamDirection::ServerToClient, b"250-mail.example.com\r\n250 AUTH LOGIN PLAIN\r\n"),
            seg(StreamDirection::ClientToServer, b"MAIL FROM:<user@example.com>\r\n"),
            seg(StreamDirection::ClientToServer, b"RCPT TO:<victim@target.com>\r\n"),
            seg(StreamDirection::ClientToServer, b"DATA\r\n"),
            seg(StreamDirection::ServerToClient, b"354 Start mail input\r\n"),
            seg(StreamDirection::ClientToServer, b"Subject: Secret Flag\r\nflag{smtp_exfil}\r\n.\r\n"),
        ];

        let session = parse_smtp_stream(&segments);
        assert_eq!(session.mail_from, Some("user@example.com".to_string()));
        assert_eq!(session.rcpt_to, vec!["victim@target.com"]);
        assert_eq!(session.ehlo_domain, Some("client.local".to_string()));
        assert_eq!(session.subject, Some("Secret Flag".to_string()));
        assert!(session.data_content.unwrap().contains("flag{smtp_exfil}"));
    }
}
