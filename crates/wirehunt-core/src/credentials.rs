use regex::Regex;
use std::sync::LazyLock;

use crate::models::*;
use crate::protocols::DissectionResults;

/// Harvest credentials from all dissected protocol data.
pub fn harvest_credentials(dissection: &DissectionResults, streams: &[Stream]) -> Vec<Credential> {
    let mut creds = Vec::new();

    // HTTP Basic Auth, cookies, form data
    for tx in &dissection.http_transactions {
        if let Some(auth) = tx.request_headers.get("authorization") {
            if let Some(basic) = auth.strip_prefix("Basic ") {
                if let Some((user, pass)) = decode_basic_auth(basic.trim()) {
                    creds.push(Credential {
                        id: cred_id(),
                        kind: CredentialKind::HttpBasicAuth,
                        username: Some(user),
                        secret: pass,
                        service: tx.host.clone(),
                        host: tx.host.clone(),
                        evidence: EvidenceRef::from_stream("http", format!(
                            "HTTP Basic Auth in {} {}",
                            tx.method, tx.uri
                        )),
                        metadata: Default::default(),
                    });
                }
            }
            if let Some(bearer) = auth.strip_prefix("Bearer ") {
                creds.push(Credential {
                    id: cred_id(),
                    kind: CredentialKind::BearerToken,
                    username: None,
                    secret: bearer.trim().to_string(),
                    service: tx.host.clone(),
                    host: tx.host.clone(),
                    evidence: EvidenceRef::from_stream("http", format!(
                        "Bearer token in {} {}",
                        tx.method, tx.uri
                    )),
                    metadata: Default::default(),
                });
            }
        }

        // Session cookies
        for cookie in &tx.cookies {
            if looks_like_session_cookie(cookie) {
                creds.push(Credential {
                    id: cred_id(),
                    kind: CredentialKind::SessionCookie,
                    username: None,
                    secret: cookie.clone(),
                    service: tx.host.clone(),
                    host: tx.host.clone(),
                    evidence: EvidenceRef::from_stream("http", format!(
                        "Session cookie in {} {}",
                        tx.method, tx.uri
                    )),
                    metadata: Default::default(),
                });
            }
        }
    }

    // FTP credentials
    for ftp in &dissection.ftp_sessions {
        if let (Some(user), Some(pass)) = (&ftp.username, &ftp.password) {
            creds.push(Credential {
                id: cred_id(),
                kind: CredentialKind::FtpLogin,
                username: Some(user.clone()),
                secret: pass.clone(),
                service: Some("ftp".to_string()),
                host: None,
                evidence: EvidenceRef::from_stream("ftp", "FTP USER/PASS login"),
                metadata: Default::default(),
            });
        }
    }

    // SMTP credentials
    for smtp in &dissection.smtp_sessions {
        if let (Some(user), Some(pass)) = (&smtp.auth_username, &smtp.auth_password) {
            creds.push(Credential {
                id: cred_id(),
                kind: CredentialKind::SmtpAuth,
                username: Some(user.clone()),
                secret: pass.clone(),
                service: Some("smtp".to_string()),
                host: None,
                evidence: EvidenceRef::from_stream("smtp", "SMTP AUTH credentials"),
                metadata: Default::default(),
            });
        }
    }

    // Scan all stream content for tokens, keys, JWTs
    for stream in streams {
        let full_text = stream_to_text(stream);
        creds.extend(scan_for_tokens(&full_text, &stream.id));
    }

    creds
}

fn decode_basic_auth(b64: &str) -> Option<(String, String)> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

fn looks_like_session_cookie(cookie: &str) -> bool {
    let lower = cookie.to_lowercase();
    lower.contains("session") || lower.contains("sid=") || lower.contains("token=")
        || lower.contains("auth") || lower.contains("jwt=") || lower.contains("phpsessid")
}

fn stream_to_text(stream: &Stream) -> String {
    let mut text = String::new();
    for seg in &stream.segments {
        text.push_str(&String::from_utf8_lossy(&seg.data));
    }
    text
}

static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap()
});

static AWS_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()
});

static GITHUB_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap()
});

static SLACK_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"xox[bpsar]-[0-9A-Za-z\-]{24,}").unwrap()
});

static GENERIC_API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{16,})['"]?"#).unwrap()
});

static PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap()
});

static PASSWORD_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(password|passwd|pass|pwd)\s*[=:]\s*([^\s&]{3,})").unwrap()
});

fn scan_for_tokens(text: &str, stream_id: &str) -> Vec<Credential> {
    let mut creds = Vec::new();

    // JWTs
    for m in JWT_RE.find_iter(text) {
        creds.push(Credential {
            id: cred_id(),
            kind: CredentialKind::Jwt,
            username: None,
            secret: m.as_str().to_string(),
            service: None,
            host: None,
            evidence: EvidenceRef::from_stream(stream_id, "JWT token found in stream content"),
            metadata: Default::default(),
        });
    }

    // AWS access keys
    for m in AWS_KEY_RE.find_iter(text) {
        creds.push(Credential {
            id: cred_id(),
            kind: CredentialKind::ApiKey,
            username: None,
            secret: m.as_str().to_string(),
            service: Some("AWS".to_string()),
            host: None,
            evidence: EvidenceRef::from_stream(stream_id, "AWS access key found in stream"),
            metadata: Default::default(),
        });
    }

    // GitHub tokens
    for m in GITHUB_TOKEN_RE.find_iter(text) {
        creds.push(Credential {
            id: cred_id(),
            kind: CredentialKind::ApiKey,
            username: None,
            secret: m.as_str().to_string(),
            service: Some("GitHub".to_string()),
            host: None,
            evidence: EvidenceRef::from_stream(stream_id, "GitHub token found in stream"),
            metadata: Default::default(),
        });
    }

    // Slack tokens
    for m in SLACK_TOKEN_RE.find_iter(text) {
        creds.push(Credential {
            id: cred_id(),
            kind: CredentialKind::ApiKey,
            username: None,
            secret: m.as_str().to_string(),
            service: Some("Slack".to_string()),
            host: None,
            evidence: EvidenceRef::from_stream(stream_id, "Slack token found in stream"),
            metadata: Default::default(),
        });
    }

    // Generic API keys (key=value patterns)
    for cap in GENERIC_API_KEY_RE.captures_iter(text) {
        if let Some(val) = cap.get(2) {
            creds.push(Credential {
                id: cred_id(),
                kind: CredentialKind::ApiKey,
                username: None,
                secret: val.as_str().to_string(),
                service: None,
                host: None,
                evidence: EvidenceRef::from_stream(stream_id, "API key pattern found in stream"),
                metadata: Default::default(),
            });
        }
    }

    // Private keys
    for _m in PRIVATE_KEY_RE.find_iter(text) {
        creds.push(Credential {
            id: cred_id(),
            kind: CredentialKind::SshPrivateKey,
            username: None,
            secret: "[PRIVATE KEY DETECTED]".to_string(),
            service: None,
            host: None,
            evidence: EvidenceRef::from_stream(stream_id, "Private key block found in stream"),
            metadata: Default::default(),
        });
    }

    // Password fields in form data / query strings
    for cap in PASSWORD_FIELD_RE.captures_iter(text) {
        if let Some(val) = cap.get(2) {
            creds.push(Credential {
                id: cred_id(),
                kind: CredentialKind::HttpFormLogin,
                username: None,
                secret: val.as_str().to_string(),
                service: None,
                host: None,
                evidence: EvidenceRef::from_stream(stream_id, "Password field found in stream"),
                metadata: Default::default(),
            });
        }
    }

    creds
}

fn cred_id() -> String {
    format!("CR-{}", uuid::Uuid::new_v4().as_simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_basic_auth() {
        // base64("admin:password123") = "YWRtaW46cGFzc3dvcmQxMjM="
        let (user, pass) = decode_basic_auth("YWRtaW46cGFzc3dvcmQxMjM=").unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "password123");
    }

    #[test]
    fn test_scan_for_jwt() {
        let text = "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dummysignaturevalue12345";
        let creds = scan_for_tokens(text, "test-stream");
        assert!(!creds.is_empty());
        assert_eq!(creds[0].kind, CredentialKind::Jwt);
    }

    #[test]
    fn test_scan_for_aws_key() {
        let text = "access_key=AKIAIOSFODNN7EXAMPLE";
        let creds = scan_for_tokens(text, "test-stream");
        let aws_creds: Vec<_> = creds.iter().filter(|c| c.service == Some("AWS".to_string())).collect();
        assert!(!aws_creds.is_empty());
    }

    #[test]
    fn test_scan_for_password_field() {
        let text = "username=admin&password=sup3rs3cret&submit=login";
        let creds = scan_for_tokens(text, "test-stream");
        let pass_creds: Vec<_> = creds.iter().filter(|c| c.kind == CredentialKind::HttpFormLogin).collect();
        assert!(!pass_creds.is_empty());
        assert_eq!(pass_creds[0].secret, "sup3rs3cret");
    }
}
