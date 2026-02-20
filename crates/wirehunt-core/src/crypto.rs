use base64::Engine;
use std::io::Read;

/// Result of a decode attempt: the decoded bytes plus the chain of transforms applied.
#[derive(Debug, Clone)]
pub struct DecodeResult {
    pub data: Vec<u8>,
    pub chain: Vec<String>,
    pub printable_text: Option<String>,
}

/// Try all single-layer decodings on the input data.
/// Returns all successful results.
pub fn try_all_decodings(data: &[u8]) -> Vec<DecodeResult> {
    let mut results = Vec::new();
    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim();

    // Base64
    if let Some(decoded) = try_base64(trimmed.as_bytes()) {
        results.push(DecodeResult {
            printable_text: to_printable(&decoded),
            data: decoded,
            chain: vec!["base64".to_string()],
        });
    }

    // Base32
    if let Some(decoded) = try_base32(trimmed) {
        results.push(DecodeResult {
            printable_text: to_printable(&decoded),
            data: decoded,
            chain: vec!["base32".to_string()],
        });
    }

    // Hex decode
    if let Some(decoded) = try_hex_decode(trimmed) {
        results.push(DecodeResult {
            printable_text: to_printable(&decoded),
            data: decoded,
            chain: vec!["hex".to_string()],
        });
    }

    // URL decode
    if trimmed.contains('%') {
        if let Some(decoded) = try_url_decode(trimmed) {
            results.push(DecodeResult {
                printable_text: Some(decoded.clone()),
                data: decoded.into_bytes(),
                chain: vec!["url_decode".to_string()],
            });
        }
    }

    // ROT13
    let rot13 = apply_rot13(trimmed);
    if rot13 != trimmed {
        results.push(DecodeResult {
            printable_text: Some(rot13.clone()),
            data: rot13.into_bytes(),
            chain: vec!["rot13".to_string()],
        });
    }

    // Gzip/zlib inflate
    if data.len() >= 2 {
        if let Some(decoded) = try_gunzip(data) {
            results.push(DecodeResult {
                printable_text: to_printable(&decoded),
                data: decoded,
                chain: vec!["gunzip".to_string()],
            });
        }
        if let Some(decoded) = try_zlib_inflate(data) {
            results.push(DecodeResult {
                printable_text: to_printable(&decoded),
                data: decoded,
                chain: vec!["zlib".to_string()],
            });
        }
    }

    // XOR brute force (single byte key, only if data is short enough)
    if data.len() <= 4096 {
        for key in 1u8..=255 {
            let xored: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            if is_mostly_printable(&xored) && !is_mostly_printable(data) {
                results.push(DecodeResult {
                    printable_text: to_printable(&xored),
                    data: xored,
                    chain: vec![format!("xor:0x{:02x}", key)],
                });
                break; // only report first hit
            }
        }
    }

    results
}

/// Multi-layer automatic decoding: tries chaining decodings up to `max_depth` levels.
pub fn auto_decode(data: &[u8], max_depth: usize) -> Vec<DecodeResult> {
    let mut all_results = Vec::new();
    auto_decode_recursive(data, &[], max_depth, &mut all_results);
    // Deduplicate by final data content
    all_results.sort_by(|a, b| b.chain.len().cmp(&a.chain.len()));
    all_results.dedup_by(|a, b| a.data == b.data);
    all_results
}

fn auto_decode_recursive(
    data: &[u8],
    chain_so_far: &[String],
    depth_remaining: usize,
    results: &mut Vec<DecodeResult>,
) {
    if depth_remaining == 0 || data.is_empty() {
        return;
    }

    let decodings = try_all_decodings(data);
    for dec in decodings {
        let mut full_chain = chain_so_far.to_vec();
        full_chain.extend(dec.chain.clone());

        results.push(DecodeResult {
            data: dec.data.clone(),
            chain: full_chain.clone(),
            printable_text: dec.printable_text.clone(),
        });

        // Recurse only if we got something different
        if dec.data != data && depth_remaining > 1 {
            auto_decode_recursive(&dec.data, &full_chain, depth_remaining - 1, results);
        }
    }
}

/// Apply a named decode pipeline: "base64 | xor:0x42 | gunzip"
pub fn apply_chain(data: &[u8], chain: &str) -> Result<Vec<u8>, String> {
    let mut current = data.to_vec();

    for step in chain.split('|').map(|s| s.trim()) {
        current = match step {
            "base64" => try_base64(&current).ok_or("base64 decode failed")?,
            "hex" => try_hex_decode(&String::from_utf8_lossy(&current))
                .ok_or("hex decode failed")?,
            "url" | "url_decode" => {
                let text = String::from_utf8_lossy(&current);
                try_url_decode(&text)
                    .map(|s| s.into_bytes())
                    .ok_or("url decode failed")?
            }
            "rot13" => apply_rot13(&String::from_utf8_lossy(&current)).into_bytes(),
            "gunzip" | "gzip" => try_gunzip(&current).ok_or("gunzip failed")?,
            "zlib" => try_zlib_inflate(&current).ok_or("zlib inflate failed")?,
            s if s.starts_with("xor:") => {
                let key_str = s.strip_prefix("xor:").unwrap();
                let key = if let Some(hex_str) = key_str.strip_prefix("0x") {
                    u8::from_str_radix(hex_str, 16).map_err(|e| e.to_string())?
                } else {
                    key_str.parse::<u8>().map_err(|e| e.to_string())?
                };
                current.iter().map(|b| b ^ key).collect()
            }
            other => return Err(format!("unknown transform: {}", other)),
        };
    }

    Ok(current)
}

// ---------------------------------------------------------------------------
// Individual decoders
// ---------------------------------------------------------------------------

fn try_base64(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let trimmed = text.trim();
    if trimmed.len() < 4 {
        return None;
    }
    // Strict: must look like base64
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r') {
        return None;
    }
    let cleaned: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .ok()
        .filter(|d| !d.is_empty())
}

fn try_base32(text: &str) -> Option<Vec<u8>> {
    if text.len() < 8 {
        return None;
    }
    if !text.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '=' || c == ' ') {
        return None;
    }
    // Simple base32 decode (RFC 4648)
    let cleaned: String = text.chars().filter(|c| *c != '=' && *c != ' ').collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut bits = 0u64;
    let mut bit_count = 0u32;
    let mut result = Vec::new();

    for ch in cleaned.bytes() {
        let val = alphabet.iter().position(|&b| b == ch)? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    if result.is_empty() { None } else { Some(result) }
}

fn try_hex_decode(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 4 || cleaned.len() % 2 != 0 {
        return None;
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(&cleaned).ok()
}

fn try_url_decode(text: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(text)
        .decode_utf8()
        .ok()?
        .to_string();
    if decoded == text {
        return None; // no change
    }
    Some(decoded)
}

fn apply_rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn try_gunzip(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        return None;
    }
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    if result.is_empty() { None } else { Some(result) }
}

fn try_zlib_inflate(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    // zlib magic: first byte is usually 0x78
    if data[0] != 0x78 {
        return None;
    }
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    if result.is_empty() { None } else { Some(result) }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_printable(data: &[u8]) -> Option<String> {
    if is_mostly_printable(data) {
        Some(String::from_utf8_lossy(data).to_string())
    } else {
        None
    }
}

fn is_mostly_printable(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| (b >= 0x20 && b < 0x7f) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    (printable as f64 / data.len() as f64) > 0.85
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let encoded = b"SGVsbG8gV29ybGQ=";
        let result = try_base64(encoded).unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_hex_decode() {
        let result = try_hex_decode("48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_rot13() {
        assert_eq!(apply_rot13("Hello"), "Uryyb");
        assert_eq!(apply_rot13("Uryyb"), "Hello");
    }

    #[test]
    fn test_url_decode() {
        let result = try_url_decode("hello%20world%21").unwrap();
        assert_eq!(result, "hello world!");
    }

    #[test]
    fn test_apply_chain() {
        // base64 encode "Hello" -> "SGVsbG8="
        let result = apply_chain(b"SGVsbG8=", "base64").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_xor_roundtrip() {
        let original = b"flag{secret}";
        let xored: Vec<u8> = original.iter().map(|b| b ^ 0x42).collect();
        let result = apply_chain(&xored, "xor:0x42").unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_auto_decode_base64() {
        // base64("flag{found}") = "ZmxhZ3tmb3VuZH0="
        let results = auto_decode(b"ZmxhZ3tmb3VuZH0=", 3);
        let found = results.iter().any(|r| {
            r.printable_text.as_deref() == Some("flag{found}")
        });
        assert!(found, "should auto-decode base64 to find flag");
    }

    #[test]
    fn test_multi_layer_decode() {
        // hex(base64("test")) = hex("dGVzdA==") = "6447567a64413d3d"
        let result = apply_chain(b"6447567a64413d3d", "hex | base64").unwrap();
        assert_eq!(result, b"test");
    }
}
