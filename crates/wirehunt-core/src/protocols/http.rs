use std::collections::HashMap;

use crate::models::{HttpTransaction, StreamDirection, StreamSegment};

/// Parse HTTP transactions from a reassembled TCP stream.
/// Returns a list of request/response pairs.
pub fn parse_http_stream(segments: &[StreamSegment]) -> Vec<HttpTransaction> {
    let mut client_data = Vec::new();
    let mut server_data = Vec::new();

    for seg in segments {
        match seg.direction {
            StreamDirection::ClientToServer => client_data.extend_from_slice(&seg.data),
            StreamDirection::ServerToClient => server_data.extend_from_slice(&seg.data),
            StreamDirection::Unknown => {}
        }
    }

    let requests = parse_http_requests(&client_data);
    let responses = parse_http_responses(&server_data);

    let mut transactions = Vec::new();

    for (i, req) in requests.iter().enumerate() {
        let mut tx = req.clone();
        if let Some(resp) = responses.get(i) {
            tx.status_code = resp.status_code;
            tx.response_headers = resp.response_headers.clone();
            tx.response_body_size = resp.response_body_size;
            if tx.content_type.is_none() {
                tx.content_type = resp.content_type.clone();
            }
        }
        transactions.push(tx);
    }

    // If there are more responses than requests (e.g., pipelined), add them
    for resp in responses.iter().skip(requests.len()) {
        transactions.push(resp.clone());
    }

    // If no structured parsing worked but data looks like HTTP, try best-effort
    if transactions.is_empty() && (!client_data.is_empty() || !server_data.is_empty()) {
        if let Some(tx) = try_best_effort_parse(&client_data, &server_data) {
            transactions.push(tx);
        }
    }

    transactions
}

fn parse_http_requests(data: &[u8]) -> Vec<HttpTransaction> {
    let mut results = Vec::new();
    let text = String::from_utf8_lossy(data);
    let mut remaining = text.as_ref();

    while !remaining.is_empty() {
        let (tx, rest) = match parse_one_request(remaining) {
            Some(r) => r,
            None => break,
        };
        results.push(tx);
        remaining = rest;
    }

    results
}

fn parse_one_request(text: &str) -> Option<(HttpTransaction, &str)> {
    let header_end = text.find("\r\n\r\n")?;
    let header_section = &text[..header_end];
    let after_headers = &text[header_end + 4..];

    let mut lines = header_section.lines();
    let request_line = lines.next()?;

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    let method = parts[0].to_string();
    if !is_http_method(&method) {
        return None;
    }
    let uri = parts[1].to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(
                key.trim().to_lowercase(),
                value.trim().to_string(),
            );
        }
    }

    let host = headers.get("host").cloned();
    let user_agent = headers.get("user-agent").cloned();
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let cookies: Vec<String> = headers
        .get("cookie")
        .map(|c| c.split(';').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let request_body_size = content_length.min(after_headers.len()) as u64;

    let rest_start = content_length.min(after_headers.len());
    let rest = &after_headers[rest_start..];

    let request_headers: HashMap<String, String> = headers
        .into_iter()
        .map(|(k, v)| (k, v))
        .collect();

    Some((
        HttpTransaction {
            method,
            uri,
            host,
            status_code: None,
            request_headers,
            response_headers: HashMap::new(),
            request_body_size,
            response_body_size: 0,
            content_type: None,
            user_agent,
            cookies,
        },
        rest,
    ))
}

fn parse_http_responses(data: &[u8]) -> Vec<HttpTransaction> {
    let mut results = Vec::new();
    let text = String::from_utf8_lossy(data);
    let mut remaining = text.as_ref();

    while !remaining.is_empty() {
        let (tx, rest) = match parse_one_response(remaining) {
            Some(r) => r,
            None => break,
        };
        results.push(tx);
        remaining = rest;
    }

    results
}

fn parse_one_response(text: &str) -> Option<(HttpTransaction, &str)> {
    let header_end = text.find("\r\n\r\n")?;
    let header_section = &text[..header_end];
    let after_headers = &text[header_end + 4..];

    let mut lines = header_section.lines();
    let status_line = lines.next()?;

    if !status_line.starts_with("HTTP/") {
        return None;
    }

    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let status_code: u16 = parts.get(1)?.parse().ok()?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(
                key.trim().to_lowercase(),
                value.trim().to_string(),
            );
        }
    }

    let content_type = headers.get("content-type").cloned();
    let is_chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false);

    let (response_body_size, rest) = if is_chunked {
        // Chunked: decode until "0\r\n"
        let decoded_size = decode_chunked_length(after_headers);
        (decoded_size as u64, "")
    } else {
        let content_length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(after_headers.len());
        let actual = content_length.min(after_headers.len());
        (actual as u64, &after_headers[actual..])
    };

    let set_cookies: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.as_str() == "set-cookie")
        .map(|(_, v)| v.clone())
        .collect();

    let response_headers: HashMap<String, String> = headers
        .into_iter()
        .map(|(k, v)| (k, v))
        .collect();

    Some((
        HttpTransaction {
            method: String::new(),
            uri: String::new(),
            host: None,
            status_code: Some(status_code),
            request_headers: HashMap::new(),
            response_headers,
            request_body_size: 0,
            response_body_size,
            content_type,
            user_agent: None,
            cookies: set_cookies,
        },
        rest,
    ))
}

fn try_best_effort_parse(client: &[u8], server: &[u8]) -> Option<HttpTransaction> {
    let client_str = String::from_utf8_lossy(client);
    let server_str = String::from_utf8_lossy(server);

    let first_line = client_str.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() >= 2 && is_http_method(parts[0]) {
        let status_code = server_str
            .lines()
            .next()
            .and_then(|l| l.splitn(3, ' ').nth(1))
            .and_then(|s| s.parse::<u16>().ok());

        return Some(HttpTransaction {
            method: parts[0].to_string(),
            uri: parts[1].to_string(),
            host: None,
            status_code,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            request_body_size: client.len() as u64,
            response_body_size: server.len() as u64,
            content_type: None,
            user_agent: None,
            cookies: Vec::new(),
        });
    }

    None
}

fn decode_chunked_length(body: &str) -> usize {
    let mut total = 0;
    let mut remaining = body;
    loop {
        let line_end = match remaining.find("\r\n") {
            Some(pos) => pos,
            None => break,
        };
        let size_str = &remaining[..line_end];
        let chunk_size = match usize::from_str_radix(size_str.trim(), 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        if chunk_size == 0 { break; }
        total += chunk_size;
        let skip = line_end + 2 + chunk_size + 2; // \r\n + data + \r\n
        if skip > remaining.len() { break; }
        remaining = &remaining[skip..];
    }
    total
}

fn is_http_method(s: &str) -> bool {
    matches!(
        s,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_seg(dir: StreamDirection, data: &[u8]) -> StreamSegment {
        StreamSegment {
            direction: dir,
            data: data.to_vec(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_parse_http_request_response() {
        let segments = vec![
            make_seg(
                StreamDirection::ClientToServer,
                b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: WireHunt/1.0\r\n\r\n",
            ),
            make_seg(
                StreamDirection::ServerToClient,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html>hi</html>",
            ),
        ];

        let txns = parse_http_stream(&segments);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].method, "GET");
        assert_eq!(txns[0].uri, "/index.html");
        assert_eq!(txns[0].host, Some("example.com".to_string()));
        assert_eq!(txns[0].user_agent, Some("WireHunt/1.0".to_string()));
        assert_eq!(txns[0].status_code, Some(200));
        assert_eq!(txns[0].content_type, Some("text/html".to_string()));
    }

    #[test]
    fn test_parse_http_with_cookies() {
        let segments = vec![
            make_seg(
                StreamDirection::ClientToServer,
                b"GET / HTTP/1.1\r\nHost: evil.com\r\nCookie: session=abc123; user=admin\r\n\r\n",
            ),
        ];

        let txns = parse_http_stream(&segments);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].cookies.len(), 2);
        assert_eq!(txns[0].cookies[0], "session=abc123");
        assert_eq!(txns[0].cookies[1], "user=admin");
    }
}
