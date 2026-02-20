use crate::models::{StreamDirection, StreamSegment};

#[derive(Debug, Clone)]
pub struct FtpSession {
    pub commands: Vec<FtpCommand>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub files_transferred: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FtpCommand {
    pub direction: StreamDirection,
    pub command: String,
    pub argument: Option<String>,
    pub response_code: Option<u16>,
}

/// Parse an FTP control channel session from reassembled stream segments.
pub fn parse_ftp_stream(segments: &[StreamSegment]) -> FtpSession {
    let mut session = FtpSession {
        commands: Vec::new(),
        username: None,
        password: None,
        files_transferred: Vec::new(),
    };

    for seg in segments {
        let text = String::from_utf8_lossy(&seg.data);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match seg.direction {
                StreamDirection::ClientToServer => {
                    let (cmd, arg) = split_ftp_command(line);
                    let cmd_upper = cmd.to_uppercase();

                    if cmd_upper == "USER" {
                        session.username = arg.clone();
                    } else if cmd_upper == "PASS" {
                        session.password = arg.clone();
                    } else if cmd_upper == "RETR" || cmd_upper == "STOR" {
                        if let Some(ref filename) = arg {
                            session.files_transferred.push(filename.clone());
                        }
                    }

                    session.commands.push(FtpCommand {
                        direction: StreamDirection::ClientToServer,
                        command: cmd_upper,
                        argument: arg,
                        response_code: None,
                    });
                }
                StreamDirection::ServerToClient => {
                    let code = line
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse::<u16>().ok());

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
}
