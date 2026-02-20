use crate::models::{StreamDirection, StreamSegment};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpSession {
    pub commands: Vec<FtpCommand>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub files_transferred: Vec<String>,
    pub data_channel_ports: Vec<u16>,
    pub auth_tls: bool,
    pub passive_mode: bool,
    pub transfer_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpCommand {
    pub direction: StreamDirection,
    pub command: String,
    pub argument: Option<String>,
    pub response_code: Option<u16>,
}

pub fn parse_ftp_stream(segments: &[StreamSegment]) -> FtpSession {
    let mut session = FtpSession {
        commands: Vec::new(),
        username: None,
        password: None,
        files_transferred: Vec::new(),
        data_channel_ports: Vec::new(),
        auth_tls: false,
        passive_mode: false,
        transfer_bytes: 0,
    };

    for seg in segments {
        let text = String::from_utf8_lossy(&seg.data);
        session.transfer_bytes += seg.data.len() as u64;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }

            match seg.direction {
                StreamDirection::ClientToServer => {
                    let (cmd, arg) = split_ftp_command(line);
                    let cmd_upper = cmd.to_uppercase();

                    match cmd_upper.as_str() {
                        "USER" => session.username = arg.clone(),
                        "PASS" => session.password = arg.clone(),
                        "RETR" | "STOR" | "STOU" | "APPE" => {
                            if let Some(ref filename) = arg {
                                session.files_transferred.push(filename.clone());
                            }
                        }
                        "AUTH" => {
                            if arg.as_deref().map(|a| a.to_uppercase()) == Some("TLS".into())
                                || arg.as_deref().map(|a| a.to_uppercase()) == Some("SSL".into())
                            {
                                session.auth_tls = true;
                            }
                        }
                        "PORT" => {
                            if let Some(ref a) = arg {
                                if let Some(port) = parse_port_command(a) {
                                    session.data_channel_ports.push(port);
                                }
                            }
                        }
                        "EPRT" => {
                            if let Some(ref a) = arg {
                                if let Some(port) = parse_eprt_command(a) {
                                    session.data_channel_ports.push(port);
                                }
                            }
                        }
                        "PASV" | "EPSV" => {
                            session.passive_mode = true;
                        }
                        _ => {}
                    }

                    session.commands.push(FtpCommand {
                        direction: StreamDirection::ClientToServer,
                        command: cmd_upper,
                        argument: arg,
                        response_code: None,
                    });
                }
                StreamDirection::ServerToClient => {
                    let code = line.split_whitespace().next()
                        .and_then(|s| s.parse::<u16>().ok());

                    // Parse PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
                    if code == Some(227) {
                        if let Some(port) = parse_pasv_response(line) {
                            session.data_channel_ports.push(port);
                        }
                    }
                    // Parse EPSV response: 229 Entering Extended Passive Mode (|||port|)
                    if code == Some(229) {
                        if let Some(port) = parse_epsv_response(line) {
                            session.data_channel_ports.push(port);
                        }
                    }

                    session.commands.push(FtpCommand {
                        direction: StreamDirection::ServerToClient,
                        command: line.to_string(),
                        argument: None,
                        response_code: code,
                    });
                }
                _ => {}
            }
        }
    }

    session
}

fn split_ftp_command(line: &str) -> (String, Option<String>) {
    if let Some((cmd, arg)) = line.split_once(' ') {
        (cmd.to_string(), Some(arg.to_string()))
    } else {
        (line.to_string(), None)
    }
}

fn parse_port_command(arg: &str) -> Option<u16> {
    let parts: Vec<u8> = arg.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    if parts.len() == 6 {
        Some((parts[4] as u16) * 256 + parts[5] as u16)
    } else {
        None
    }
}

fn parse_eprt_command(arg: &str) -> Option<u16> {
    let parts: Vec<&str> = arg.split('|').collect();
    if parts.len() >= 4 {
        parts[3].parse().ok()
    } else {
        None
    }
}

fn parse_pasv_response(line: &str) -> Option<u16> {
    let start = line.find('(')?;
    let end = line.find(')')?;
    let inner = &line[start + 1..end];
    let parts: Vec<u8> = inner.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    if parts.len() == 6 {
        Some((parts[4] as u16) * 256 + parts[5] as u16)
    } else {
        None
    }
}

fn parse_epsv_response(line: &str) -> Option<u16> {
    let start = line.find("|||")?;
    let rest = &line[start + 3..];
    let end = rest.find('|')?;
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn seg(dir: StreamDirection, data: &[u8]) -> StreamSegment {
        StreamSegment { direction: dir, data: data.to_vec(), timestamp: Utc::now() }
    }

    #[test]
    fn test_parse_ftp_login() {
        let segments = vec![
            seg(StreamDirection::ServerToClient, b"220 Welcome to FTP\r\n"),
            seg(StreamDirection::ClientToServer, b"USER admin\r\n"),
            seg(StreamDirection::ServerToClient, b"331 Password required\r\n"),
            seg(StreamDirection::ClientToServer, b"PASS secret123\r\n"),
            seg(StreamDirection::ServerToClient, b"230 Login successful\r\n"),
            seg(StreamDirection::ClientToServer, b"RETR flag.txt\r\n"),
        ];
        let session = parse_ftp_stream(&segments);
        assert_eq!(session.username, Some("admin".to_string()));
        assert_eq!(session.password, Some("secret123".to_string()));
        assert_eq!(session.files_transferred, vec!["flag.txt"]);
    }

    #[test]
    fn test_parse_pasv_response() {
        assert_eq!(parse_pasv_response("227 Entering Passive Mode (192,168,1,1,4,1)"), Some(1025));
        assert_eq!(parse_pasv_response("227 Entering Passive Mode (10,0,0,1,195,149)"), Some(50069));
    }

    #[test]
    fn test_parse_epsv_response() {
        assert_eq!(parse_epsv_response("229 Entering Extended Passive Mode (|||6446|)"), Some(6446));
    }

    #[test]
    fn test_parse_port_command() {
        assert_eq!(parse_port_command("192,168,1,1,4,1"), Some(1025));
    }

    #[test]
    fn test_auth_tls_detection() {
        let segments = vec![
            seg(StreamDirection::ServerToClient, b"220 FTP Server Ready\r\n"),
            seg(StreamDirection::ClientToServer, b"AUTH TLS\r\n"),
            seg(StreamDirection::ServerToClient, b"234 Proceed with TLS\r\n"),
        ];
        let session = parse_ftp_stream(&segments);
        assert!(session.auth_tls);
    }
}
