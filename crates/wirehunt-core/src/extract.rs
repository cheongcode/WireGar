use std::collections::HashMap;
use std::path::Path;

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::crypto;
use crate::models::*;
use crate::protocols::DissectionResults;

/// Run all extraction passes and return artifacts + decoded content.
pub fn run_extraction(
    streams: &[Stream],
    dissection: &DissectionResults,
    output_dir: &Path,
) -> ExtractionResults {
    let mut results = ExtractionResults::default();

    // 1. String sweep across all stream content
    for stream in streams {
        let text = stream_text(stream);
        let mut found = sweep_strings(&text, &stream.id);
        results.interesting_strings.append(&mut found);
    }

    // 2. Auto-decode interesting strings
    for s in &results.interesting_strings {
        let decoded = crypto::auto_decode(s.value.as_bytes(), 3);
        for dec in decoded {
            if let Some(ref printable) = dec.printable_text {
                if printable != &s.value && printable.len() > 3 {
                    results.decoded_strings.push(DecodedString {
                        original: s.value.clone(),
                        decoded: printable.clone(),
                        chain: dec.chain.join(" | "),
                        stream_id: s.stream_id.clone(),
                    });
                }
            }
        }
    }

    // 3. HTTP response body extraction
    let artifacts_dir = output_dir.join("artifacts");
    for (i, tx) in dissection.http_transactions.iter().enumerate() {
        if tx.response_body_size > 0 {
            if let Some(artifact) = extract_http_body(streams, tx, i, &artifacts_dir) {
                results.artifacts.push(artifact);
            }
        }
    }

    // 4. Flag pattern sweep
    for stream in streams {
        let text = stream_text(stream);
        let mut flags = find_flag_patterns(&text, &stream.id);
        results.flag_candidates.append(&mut flags);
    }

    // Also sweep decoded strings for flags
    for dec in &results.decoded_strings {
        let mut flags = find_flag_patterns(&dec.decoded, &dec.stream_id);
        for f in &mut flags {
            f.decode_chain = Some(dec.chain.clone());
        }
        results.flag_candidates.append(&mut flags);
    }

    // Deduplicate flags by value (same flag in multiple streams = 1 finding)
    {
        let mut seen = std::collections::HashSet::new();
        results.flag_candidates.retain(|f| seen.insert(f.value.clone()));
    }

    // Deduplicate artifacts by SHA256
    {
        let mut seen = std::collections::HashSet::new();
        results.artifacts.retain(|a| seen.insert(a.sha256.clone()));
    }

    tracing::info!(
        strings = results.interesting_strings.len(),
        decoded = results.decoded_strings.len(),
        artifacts = results.artifacts.len(),
        flags = results.flag_candidates.len(),
        "extraction complete"
    );

    results
}

// ---------------------------------------------------------------------------
// String sweep
// ---------------------------------------------------------------------------

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s<>"']+"#).unwrap()
});

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
});

static IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap()
});

static BASE64_BLOB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap()
});

static HEX_BLOB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap()
});

fn sweep_strings(text: &str, stream_id: &str) -> Vec<InterestingString> {
    let mut results = Vec::new();

    for m in URL_RE.find_iter(text) {
        results.push(InterestingString {
            kind: StringKind::Url,
            value: m.as_str().to_string(),
            stream_id: stream_id.to_string(),
        });
    }

    for m in EMAIL_RE.find_iter(text) {
        results.push(InterestingString {
            kind: StringKind::Email,
            value: m.as_str().to_string(),
            stream_id: stream_id.to_string(),
        });
    }

    for m in BASE64_BLOB_RE.find_iter(text) {
        if m.as_str().len() >= 24 {
            results.push(InterestingString {
                kind: StringKind::Base64Blob,
                value: m.as_str().to_string(),
                stream_id: stream_id.to_string(),
            });
        }
    }

    for m in HEX_BLOB_RE.find_iter(text) {
        results.push(InterestingString {
            kind: StringKind::HexBlob,
            value: m.as_str().to_string(),
            stream_id: stream_id.to_string(),
        });
    }

    results
}

// ---------------------------------------------------------------------------
// Flag pattern detection
// ---------------------------------------------------------------------------

static FLAG_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)flag\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)ctf\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)ctfa\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)ctfb\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)picoctf\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)htb\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)thm\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)hack\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)key\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)secret\{[^\}]{1,200}\}").unwrap(),
        Regex::new(r"(?i)flg\{[^\}]{1,200}\}").unwrap(),
        // Catch-all: any word followed by {}, common CTF format
        Regex::new(r"[a-zA-Z]{2,12}\{[^\}]{1,200}\}").unwrap(),
    ]
});

fn find_flag_patterns(text: &str, stream_id: &str) -> Vec<FlagCandidate> {
    let mut seen = std::collections::HashSet::new();
    let mut flags = Vec::new();
    for re in FLAG_PATTERNS.iter() {
        for m in re.find_iter(text) {
            let val = m.as_str().to_string();
            if seen.insert(val.clone()) {
                flags.push(FlagCandidate {
                    value: val,
                    stream_id: stream_id.to_string(),
                    decode_chain: None,
                });
            }
        }
    }
    flags
}

// ---------------------------------------------------------------------------
// HTTP body extraction
// ---------------------------------------------------------------------------

fn extract_http_body(
    streams: &[Stream],
    tx: &HttpTransaction,
    tx_index: usize,
    _artifacts_dir: &Path,
) -> Option<Artifact> {
    // Find the server-to-client data in streams
    for stream in streams {
        if stream.protocol != AppProtocol::Http {
            continue;
        }
        let server_data: Vec<u8> = stream
            .segments
            .iter()
            .filter(|s| s.direction == StreamDirection::ServerToClient)
            .flat_map(|s| s.data.iter().copied())
            .collect();

        if server_data.is_empty() {
            continue;
        }

        // Find the body after headers
        let text = String::from_utf8_lossy(&server_data);
        if let Some(body_start) = text.find("\r\n\r\n") {
            let body = &server_data[body_start + 4..];
            if body.is_empty() {
                continue;
            }

            let sha256 = hex::encode(Sha256::digest(body));
            let md5_hash = {
                use md5::Digest as _;
                hex::encode(md5::Md5::digest(body))
            };

            let mime = tx.content_type.clone().unwrap_or_else(|| guess_mime(body));
            let kind = mime_to_artifact_kind(&mime);
            let ext = mime_to_extension(&mime);
            let name = format!("http_response_{}_{}.{}", tx_index, &sha256[..8], ext);

            return Some(Artifact {
                id: format!("AR-{}", uuid::Uuid::new_v4().as_simple()),
                kind,
                name: Some(name),
                mime_type: Some(mime),
                size_bytes: body.len() as u64,
                sha256,
                md5: md5_hash,
                path: None,
                source_stream_id: Some(stream.id.clone()),
                source_evidence: EvidenceRef::from_stream(
                    &stream.id,
                    format!("HTTP response body from {} {}", tx.method, tx.uri),
                ),
                metadata: HashMap::new(),
            });
        }
    }
    None
}

fn guess_mime(data: &[u8]) -> String {
    if data.len() >= 4 {
        match &data[..4] {
            [0x89, b'P', b'N', b'G'] => return "image/png".to_string(),
            [0xFF, 0xD8, 0xFF, _] => return "image/jpeg".to_string(),
            [b'G', b'I', b'F', b'8'] => return "image/gif".to_string(),
            [b'P', b'K', 0x03, 0x04] => return "application/zip".to_string(),
            [0x7F, b'E', b'L', b'F'] => return "application/x-elf".to_string(),
            [b'M', b'Z', _, _] => return "application/x-pe".to_string(),
            [0x25, b'P', b'D', b'F'] => return "application/pdf".to_string(),
            _ => {}
        }
    }
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        return "application/gzip".to_string();
    }
    if is_mostly_text(data) {
        return "text/plain".to_string();
    }
    "application/octet-stream".to_string()
}

fn is_mostly_text(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    let printable = data.iter()
        .filter(|&&b| (b >= 0x20 && b < 0x7f) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    (printable as f64 / data.len() as f64) > 0.85
}

fn mime_to_artifact_kind(mime: &str) -> ArtifactKind {
    if mime.starts_with("image/") { return ArtifactKind::Image; }
    if mime.contains("zip") || mime.contains("tar") || mime.contains("gzip") {
        return ArtifactKind::Archive;
    }
    if mime.contains("pdf") || mime.contains("document") {
        return ArtifactKind::Document;
    }
    if mime.contains("elf") || mime.contains("pe") || mime.contains("executable") {
        return ArtifactKind::Executable;
    }
    if mime.contains("certificate") || mime.contains("x509") {
        return ArtifactKind::Certificate;
    }
    ArtifactKind::File
}

fn mime_to_extension(mime: &str) -> &'static str {
    match mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "application/zip" => "zip",
        "application/gzip" => "gz",
        "application/pdf" => "pdf",
        "application/x-elf" => "elf",
        "application/x-pe" => "exe",
        "text/html" => "html",
        "text/plain" => "txt",
        _ => "bin",
    }
}

fn stream_text(stream: &Stream) -> String {
    let mut text = String::new();
    for seg in &stream.segments {
        text.push_str(&String::from_utf8_lossy(&seg.data));
    }
    text
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ExtractionResults {
    pub artifacts: Vec<Artifact>,
    pub interesting_strings: Vec<InterestingString>,
    pub decoded_strings: Vec<DecodedString>,
    pub flag_candidates: Vec<FlagCandidate>,
}

#[derive(Debug, Clone)]
pub struct InterestingString {
    pub kind: StringKind,
    pub value: String,
    pub stream_id: String,
}

#[derive(Debug, Clone)]
pub enum StringKind {
    Url,
    Email,
    Base64Blob,
    HexBlob,
    IpAddress,
}

#[derive(Debug, Clone)]
pub struct DecodedString {
    pub original: String,
    pub decoded: String,
    pub chain: String,
    pub stream_id: String,
}

#[derive(Debug, Clone)]
pub struct FlagCandidate {
    pub value: String,
    pub stream_id: String,
    pub decode_chain: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_flag_patterns() {
        let text = "some data flag{test_flag_123} more data CTF{another}";
        let flags = find_flag_patterns(text, "s1");
        assert_eq!(flags.len(), 2);
        assert_eq!(flags[0].value, "flag{test_flag_123}");
        assert_eq!(flags[1].value, "CTF{another}");
    }

    #[test]
    fn test_sweep_urls() {
        let text = "visit https://evil.com/malware.exe for more info";
        let results = sweep_strings(text, "s1");
        let urls: Vec<_> = results.iter().filter(|r| matches!(r.kind, StringKind::Url)).collect();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].value, "https://evil.com/malware.exe");
    }

    #[test]
    fn test_guess_mime() {
        assert_eq!(guess_mime(&[0x89, b'P', b'N', b'G']), "image/png");
        assert_eq!(guess_mime(&[0xFF, 0xD8, 0xFF, 0xE0]), "image/jpeg");
        assert_eq!(guess_mime(&[b'P', b'K', 0x03, 0x04]), "application/zip");
        assert_eq!(guess_mime(b"Hello world\n"), "text/plain");
    }
}
