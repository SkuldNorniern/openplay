//! The AirPlay `GET /info` endpoint.
//!
//! `/info` is served unencrypted before pairing and returns a binary plist
//! describing the receiver: capability bits, supported audio formats, its
//! public key, and identifiers. We parse the fields the sender needs to decide
//! how to pair and stream.

use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};

use plist::{Dictionary, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

use crate::error::{Error, Result};
use crate::rtsp::{Request, Response, parse_response};

/// Receiver description parsed from `/info`.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub model: String,
    pub device_id: String,
    pub source_version: String,
    /// 64-bit capability bitmask (`features`); bit 48 = transient pairing.
    pub features: u64,
    pub status_flags: u64,
    /// Receiver Ed25519 public key (`pk`).
    pub public_key: Vec<u8>,
}

impl DeviceInfo {
    /// Whether the receiver advertises HomeKit transient pairing (feature 48).
    pub fn supports_transient_pairing(&self) -> bool {
        self.features & (1 << 48) != 0
    }

    /// Parse a `/info` binary plist body.
    pub fn from_plist(bytes: &[u8]) -> Result<DeviceInfo> {
        let value =
            Value::from_reader(Cursor::new(bytes)).map_err(|e| Error::Protocol(e.to_string()))?;
        let dict = value
            .as_dictionary()
            .ok_or_else(|| Error::Protocol("info: not a dictionary".into()))?;

        Ok(DeviceInfo {
            name: string_field(dict, "name")?,
            model: string_field(dict, "model")?,
            device_id: string_field(dict, "deviceID")?,
            source_version: string_field(dict, "sourceVersion")?,
            features: u64_field(dict, "features")?,
            status_flags: match dict.get("statusFlags") {
                Some(v) => plist_uint(v)
                    .ok_or_else(|| Error::Protocol("info: bad statusFlags".into()))?,
                None => 0,
            },
            public_key: public_key(dict)?,
        })
    }
}

fn public_key(dict: &Dictionary) -> Result<Vec<u8>> {
    let data = dict
        .get("pk")
        .and_then(Value::as_data)
        .ok_or_else(|| Error::Protocol("info: missing pk".into()))?;
    if data.len() != 32 {
        return Err(Error::Protocol(format!("info: pk is {} bytes", data.len())));
    }
    Ok(data.to_vec())
}

/// Accept a plist integer as `u64`, trying the unsigned representation first so
/// masks with bit 63 set (beyond `i64::MAX`) survive, and rejecting negatives.
fn plist_uint(value: &Value) -> Option<u64> {
    if let Some(u) = value.as_unsigned_integer() {
        return Some(u);
    }
    value
        .as_signed_integer()
        .filter(|s| *s >= 0)
        .map(|s| s as u64)
}

fn string_field(dict: &Dictionary, key: &str) -> Result<String> {
    dict.get(key)
        .and_then(Value::as_string)
        .map(str::to_string)
        .ok_or_else(|| Error::Protocol(format!("info: missing {key}")))
}

fn u64_field(dict: &Dictionary, key: &str) -> Result<u64> {
    dict.get(key)
        .and_then(plist_uint)
        .ok_or_else(|| Error::Protocol(format!("info: missing {key}")))
}

/// Connect to `addr` (optionally from local `bind`) and fetch `/info`.
pub async fn fetch(addr: SocketAddr, bind: Option<Ipv4Addr>, user_agent: &str) -> Result<DeviceInfo> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(ip) = bind {
        if !addr.is_ipv4() {
            return Err(Error::Protocol("cannot bind IPv4 to an IPv6 target".into()));
        }
        socket.bind(SocketAddr::from((ip, 0)))?;
    }
    let mut stream = socket.connect(addr).await?;
    fetch_on(&mut stream, user_agent).await
}

/// Fetch `/info` over an already-connected stream.
pub async fn fetch_on(stream: &mut TcpStream, user_agent: &str) -> Result<DeviceInfo> {
    let request = Request::new("GET", "/info")
        .header("CSeq", "0")
        .header("User-Agent", user_agent);
    stream.write_all(&request.encode()).await?;

    let response = read_response(stream).await?;
    if !response.is_success() {
        return Err(Error::Protocol(format!("/info status {}", response.status)));
    }
    DeviceInfo::from_plist(&response.body)
}

/// Upper bound on a `/info` response; the real one is ~1.5 KiB. Guards against a
/// broken or hostile receiver streaming without end.
const MAX_INFO_RESPONSE: usize = 64 * 1024;

async fn read_response(stream: &mut TcpStream) -> Result<Response> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some((response, _)) = parse_response(&buf)? {
            return Ok(response);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Protocol("/info connection closed".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_INFO_RESPONSE {
            return Err(Error::Protocol("/info response too large".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real `GET /info` response body captured from HomePod mini "Bedroom".
    const INFO: &[u8] = include_bytes!("../../tests/fixtures/info.plist");

    #[test]
    fn parses_real_homepod_info() {
        let info = DeviceInfo::from_plist(INFO).expect("parse");
        assert_eq!(info.name, "Bedroom");
        assert_eq!(info.model, "AudioAccessory5,1");
        assert_eq!(info.source_version, "950.7.1");
        assert_eq!(info.public_key.len(), 32);
        assert_eq!(info.features, 0x3c354bd04a7fca00);
    }

    #[test]
    fn detects_transient_pairing_support() {
        let info = DeviceInfo::from_plist(INFO).expect("parse");
        assert!(info.supports_transient_pairing());
    }

    #[test]
    fn rejects_non_dictionary_plist() {
        // A bare bplist integer, not a dictionary.
        let bytes = b"bplist00\x10\x2a\x08\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a";
        assert!(DeviceInfo::from_plist(bytes).is_err());
    }
}
