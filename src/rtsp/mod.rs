//! RTSP/1.0 message types for the AirPlay control channel.
//!
//! AirPlay speaks RTSP/1.0 over TCP:7000 — even `GET /info` is an RTSP request,
//! not HTTP. Bodies are opaque bytes (usually binary plists or TLV8). This
//! module models a client request and a parsed server response; the wire
//! encode/decode lives in [`codec`].

mod codec;
mod headers;

pub use codec::parse_response;
pub use headers::Headers;

/// RTSP version literal used on every line.
pub(crate) const VERSION: &str = "RTSP/1.0";

/// A request we send to the receiver.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Request {
    /// Start a request with the given method and URI (e.g. `GET`, `/info`).
    pub fn new(method: &str, uri: &str) -> Self {
        Request {
            method: method.to_string(),
            uri: uri.to_string(),
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    /// Add a header (builder style).
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push(name, value);
        self
    }

    /// Attach a body (builder style). `Content-Length` is emitted at encode time.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Serialize to the RTSP wire format.
    pub fn encode(&self) -> Vec<u8> {
        codec::encode_request(self)
    }
}

/// A response parsed from the receiver.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Response {
    /// True for a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}
