//! RTSP/1.0 wire encode/decode.

use super::{Headers, Request, Response, VERSION};
use crate::error::{Error, Result};

const CRLF: &[u8] = b"\r\n";
const HEAD_END: &[u8] = b"\r\n\r\n";

/// Encode a request. `Content-Length` is always written from the actual body
/// length, so callers must not set it themselves.
pub(crate) fn encode_request(req: &Request) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + req.body.len());
    out.extend_from_slice(format!("{} {} {}\r\n", req.method, req.uri, VERSION).as_bytes());
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("Content-Length") {
            continue; // authoritative length is appended below
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
    out.extend_from_slice(CRLF);
    out.extend_from_slice(&req.body);
    out
}

/// Parse one response from `buf`.
///
/// Returns `Ok(None)` when more bytes are needed (headers or body incomplete),
/// or `Ok(Some((response, consumed)))` where `consumed` is the total byte count
/// of this message so the caller can advance its buffer.
pub fn parse_response(buf: &[u8]) -> Result<Option<(Response, usize)>> {
    let Some(head_end) = find(buf, HEAD_END) else {
        return Ok(None);
    };
    let head = &buf[..head_end];
    let mut lines = split_crlf(head);

    let status_line = lines
        .next()
        .ok_or_else(|| Error::Rtsp("empty response".into()))?;
    let (status, reason) = parse_status_line(status_line)?;

    let mut headers = Headers::new();
    for line in lines {
        let text = std::str::from_utf8(line).map_err(|_| Error::Rtsp("non-utf8 header".into()))?;
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| Error::Rtsp("malformed header".into()))?;
        headers.push(name.trim(), value.trim().to_string());
    }

    let body_start = head_end + HEAD_END.len();
    let content_len = content_length(&headers)?;
    let end = body_start
        .checked_add(content_len)
        .ok_or_else(|| Error::Rtsp("content-length overflow".into()))?;
    if buf.len() < end {
        return Ok(None);
    }
    let body = buf[body_start..end].to_vec();

    Ok(Some((
        Response {
            status,
            reason,
            headers,
            body,
        },
        end,
    )))
}

/// Resolve the message body length. Absent means zero, but a present header must
/// be strictly numeric and non-conflicting — otherwise framing desyncs the TCP
/// stream, so we error instead of guessing.
fn content_length(headers: &Headers) -> Result<usize> {
    let mut found: Option<usize> = None;
    for (name, value) in headers.iter() {
        if !name.eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        let text = value.trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Rtsp("invalid content-length".into()));
        }
        let n: usize = text
            .parse()
            .map_err(|_| Error::Rtsp("content-length too large".into()))?;
        match found {
            Some(prev) if prev != n => {
                return Err(Error::Rtsp("conflicting content-length".into()));
            }
            _ => found = Some(n),
        }
    }
    Ok(found.unwrap_or(0))
}

fn parse_status_line(line: &[u8]) -> Result<(u16, String)> {
    let text = std::str::from_utf8(line).map_err(|_| Error::Rtsp("non-utf8 status".into()))?;
    let mut parts = text.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != VERSION {
        return Err(Error::Rtsp(format!("bad version: {version}")));
    }
    let code = parts
        .next()
        .ok_or_else(|| Error::Rtsp("missing status code".into()))?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Rtsp(format!("bad status code: {code}")));
    }
    let status = code
        .parse::<u16>()
        .map_err(|_| Error::Rtsp("bad status code".into()))?;
    let reason = parts.next().unwrap_or("").to_string();
    Ok((status, reason))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn split_crlf(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_request_with_length() {
        let req = Request::new("GET", "/info")
            .header("CSeq", "1")
            .header("User-Agent", "openplay/0")
            .body(b"xy".to_vec());
        let wire = req.encode();
        let text = String::from_utf8_lossy(&wire);
        assert!(text.starts_with("GET /info RTSP/1.0\r\n"));
        assert!(text.contains("CSeq: 1\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\nxy"));
    }

    #[test]
    fn caller_content_length_is_overridden() {
        let req = Request::new("POST", "/x")
            .header("Content-Length", "999")
            .body(b"abcd".to_vec());
        let wire = req.encode();
        let text = String::from_utf8_lossy(&wire);
        assert!(text.contains("Content-Length: 4\r\n"));
        assert!(!text.contains("999"));
    }

    #[test]
    fn parses_response_with_body() {
        let raw = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: 3\r\n\r\nabc";
        let (resp, used) = parse_response(raw).expect("ok").expect("complete");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert!(resp.is_success());
        assert_eq!(resp.headers.get("cseq"), Some("1"));
        assert_eq!(resp.body, b"abc");
        assert_eq!(used, raw.len());
    }

    #[test]
    fn incomplete_returns_none() {
        assert!(parse_response(b"RTSP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nab")
            .expect("ok")
            .is_none());
        assert!(parse_response(b"RTSP/1.0 200 OK\r\nCSeq: 1")
            .expect("ok")
            .is_none());
    }

    #[test]
    fn reports_consumed_for_pipelined_messages() {
        let mut raw =
            b"RTSP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nA".to_vec();
        let tail = b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        raw.extend_from_slice(tail);
        let (_, used) = parse_response(&raw).expect("ok").expect("complete");
        assert_eq!(&raw[used..], tail);
    }

    #[test]
    fn rejects_non_rtsp_version() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_malformed_status_codes() {
        assert!(parse_response(b"RTSP/1.0 20 OK\r\n\r\n").is_err());
        assert!(parse_response(b"RTSP/1.0 2000 OK\r\n\r\n").is_err());
        assert!(parse_response(b"RTSP/1.0 +20 OK\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_invalid_and_conflicting_content_length() {
        assert!(parse_response(b"RTSP/1.0 200 OK\r\nContent-Length: abc\r\n\r\n").is_err());
        assert!(parse_response(
            b"RTSP/1.0 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nAB"
        )
        .is_err());
    }

    #[test]
    fn duplicate_but_equal_content_length_is_ok() {
        let raw = b"RTSP/1.0 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nA";
        let (resp, _) = parse_response(raw).expect("ok").expect("complete");
        assert_eq!(resp.body, b"A");
    }
}
