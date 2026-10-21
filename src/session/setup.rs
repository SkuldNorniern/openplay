//! Sans-IO builders and parsers for the RTSP session setup sequence.
//!
//! SETUP first establishes session-wide timing and event channels, then
//! describes the realtime audio stream and its already-bound UDP ports.
//! RECORD is kept separate because it must be sent immediately before media
//! starts flowing.

use std::io::Cursor;

use plist::{Dictionary, Value};
use rand::{fill, random};

use crate::error::{Error, Result};
use crate::rtsp::Request;

const PLIST_CONTENT_TYPE: &str = "application/x-apple-binary-plist";

/// Identifier used as the RTSP path for one streaming session.
pub struct SessionId(String);

impl SessionId {
    /// Generate a fresh session id: a random u64 formatted as 16 uppercase hex characters.
    pub fn generate() -> Self {
        Self(format!("{:016X}", random::<u64>()))
    }

    /// The RTSP request path for this session, e.g. "/1A2B3C4D5E6F7890".
    pub fn path(&self) -> String {
        format!("/{}", self.0)
    }
}

/// Key material the session- and stream-level SETUP requests must both present
/// to the receiver.
///
/// The two requests are separate RTSP round trips, but the receiver expects
/// the exact same key and IV in both; presenting different values is accepted
/// at the RTSP layer and only surfaces later as a rejected or garbled audio
/// stream. Bundling both fields in one type, constructed once per session,
/// makes that divergence impossible rather than merely documented.
pub struct AudioStreamSecret {
    key: [u8; 32],
    iv: [u8; 16],
}

impl AudioStreamSecret {
    /// Derive the audio stream secret for this session.
    ///
    /// `session_key` is the raw SRP pairing session key (the 64-byte SHA-512
    /// output); its first 32 bytes seed the audio stream's own encryption,
    /// independent of the HKDF-derived control channel keys. The IV is fresh
    /// random for this session.
    pub fn derive(session_key: &[u8]) -> Self {
        let mut key = [0_u8; 32];
        let take = session_key.len().min(key.len());
        key[..take].copy_from_slice(&session_key[..take]);

        let mut iv = [0_u8; 16];
        fill(&mut iv);

        Self { key, iv }
    }

    /// Key that encrypts the RTP audio payloads.
    pub fn audio_key(&self) -> [u8; 32] {
        self.key
    }
}

/// Build the session-level SETUP request.
///
/// `timing_port` is our bound NTP timing port. The receiver starts sending
/// timing requests to it right after this exchange, before stream SETUP.
pub fn session_setup_request(
    session: &SessionId,
    secret: &AudioStreamSecret,
    timing_port: u16,
) -> Result<Request> {
    let mut body = Dictionary::new();
    body.insert("timingProtocol".into(), Value::String("NTP".into()));
    body.insert("timingPort".into(), Value::from(timing_port));
    body.insert("ekey".into(), Value::Data(secret.key.to_vec()));
    body.insert("eiv".into(), Value::Data(secret.iv.to_vec()));
    body.insert("et".into(), Value::from(4_i64));

    Ok(Request::new("SETUP", &session.path())
        .header("Content-Type", PLIST_CONTENT_TYPE)
        .body(encode_plist(body)?))
}

/// Receiver port established by the session-level SETUP exchange.
///
/// A HomePod answers with `eventPort` and `skipRecord` only. It sends timing
/// requests to our `timingPort` instead of giving one of its own.
pub struct SessionSetupResponse {
    pub event_port: u16,
}

/// Parse the session-level SETUP response body.
pub fn parse_session_setup_response(body: &[u8]) -> Result<SessionSetupResponse> {
    let plist = parse_dictionary(body, "session setup")?;

    Ok(SessionSetupResponse {
        event_port: port_field(&plist, "eventPort", "session setup")?,
    })
}

/// Ports already bound by the sender and advertised to the receiver.
pub struct LocalStreamPorts {
    pub audio: u16,
    pub control: u16,
    pub timing: u16,
}

/// Build the realtime ALAC stream SETUP request.
///
/// A stream packet carries 352 stereo frames. At 44.1 kHz this keeps packet
/// cadence and the rest of the sender's ALAC packetization in lockstep.
/// `secret` must be the same value passed to [`session_setup_request`] for
/// this session.
pub fn stream_setup_request(
    session: &SessionId,
    ports: &LocalStreamPorts,
    secret: &AudioStreamSecret,
) -> Result<Request> {
    let mut stream = Dictionary::new();
    stream.insert("type".into(), Value::from(96_i64));
    stream.insert("ct".into(), Value::from(2_i64));
    stream.insert("audioFormat".into(), Value::from(0x40000_i64));
    stream.insert("spf".into(), Value::from(352_i64));
    stream.insert("audioType".into(), Value::String("default".into()));
    stream.insert("shk".into(), Value::Data(secret.key.to_vec()));
    stream.insert("shiv".into(), Value::Data(secret.iv.to_vec()));
    stream.insert("controlPort".into(), Value::from(ports.control));
    stream.insert("timingPort".into(), Value::from(ports.timing));
    stream.insert("latencyMin".into(), Value::from(11025_i64));
    stream.insert("latencyMax".into(), Value::from(88200_i64));

    let mut body = Dictionary::new();
    body.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(stream)]),
    );

    let transport = format!(
        "RTP/AVP/UDP;unicast;mode=record;client_port={};control_port={};timing_port={}",
        ports.audio, ports.control, ports.timing
    );
    Ok(Request::new("SETUP", &session.path())
        .header("Content-Type", PLIST_CONTENT_TYPE)
        .header("Transport", transport)
        .body(encode_plist(body)?))
}

/// Receiver ports established by the stream-level SETUP exchange.
pub struct StreamSetupResponse {
    pub data_port: u16,
    pub control_port: u16,
}

/// Parse the stream-level SETUP response body.
///
/// Receivers use both a flat response and a response mirroring the request's
/// `streams` array, so the nested form is used when the flat pair is incomplete.
pub fn parse_stream_setup_response(body: &[u8]) -> Result<StreamSetupResponse> {
    let plist = parse_dictionary(body, "stream setup")?;
    let source = if plist.get("dataPort").is_some() && plist.get("controlPort").is_some() {
        &plist
    } else {
        plist
            .get("streams")
            .and_then(Value::as_array)
            .and_then(|streams| streams.first())
            .and_then(Value::as_dictionary)
            .ok_or_else(|| {
                Error::Protocol(
                    "stream setup: missing dataPort or controlPort at both locations".into(),
                )
            })?
    };

    Ok(StreamSetupResponse {
        data_port: port_field(source, "dataPort", "stream setup")?,
        control_port: port_field(source, "controlPort", "stream setup")?,
    })
}

/// Build the RECORD request.
///
/// Callers must send this immediately before starting audio. An unbounded gap
/// between RECORD and the first packet can make the receiver expire the
/// session; this builder intentionally leaves sequencing to the caller.
pub fn record_request(session: &SessionId) -> Request {
    Request::new("RECORD", &session.path())
}

fn encode_plist(dictionary: Dictionary) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    Value::Dictionary(dictionary)
        .to_writer_binary(&mut body)
        .map_err(|error| Error::Protocol(format!("plist encoding failed: {error}")))?;
    Ok(body)
}

fn parse_dictionary(body: &[u8], context: &str) -> Result<Dictionary> {
    Value::from_reader(Cursor::new(body))
        .map_err(|error| Error::Protocol(format!("{context}: invalid plist: {error}")))?
        .into_dictionary()
        .ok_or_else(|| Error::Protocol(format!("{context}: not a dictionary")))
}

fn port_field(dictionary: &Dictionary, key: &str, context: &str) -> Result<u16> {
    let value = dictionary
        .get(key)
        .ok_or_else(|| Error::Protocol(format!("{context}: missing {key}")))?;
    let wide = value
        .as_unsigned_integer()
        .or_else(|| {
            value
                .as_signed_integer()
                .and_then(|signed| u64::try_from(signed).ok())
        })
        .ok_or_else(|| Error::Protocol(format!("{context}: bad {key}")))?;

    u16::try_from(wide)
        .map_err(|_| Error::Protocol(format!("{context}: {key} out of range: {wide}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_session() -> SessionId {
        SessionId("1A2B3C4D5E6F7890".into())
    }

    fn plist_body(dictionary: Dictionary) -> Vec<u8> {
        encode_plist(dictionary).expect("encode plist")
    }

    fn decode_dictionary(body: &[u8]) -> Dictionary {
        Value::from_reader(Cursor::new(body))
            .expect("decode plist")
            .into_dictionary()
            .expect("plist dictionary")
    }

    fn integer(dictionary: &Dictionary, key: &str) -> i64 {
        dictionary
            .get(key)
            .and_then(Value::as_signed_integer)
            .expect("integer field")
    }

    #[test]
    fn generates_random_uppercase_hex_session_ids() {
        let first = SessionId::generate().path();
        let second = SessionId::generate().path();

        assert_eq!(first.len(), 17);
        assert_eq!(&first[..1], "/");
        assert!(
            first[1..]
                .chars()
                .all(|character| character.is_ascii_digit() || ('A'..='F').contains(&character))
        );
        assert_ne!(first, second);
    }

    fn fixed_session_key() -> Vec<u8> {
        (0_u8..64).collect()
    }

    #[test]
    fn derives_key_from_the_first_32_bytes_of_the_session_key() {
        let session_key = fixed_session_key();
        let secret = AudioStreamSecret::derive(&session_key);
        let session = fixed_session();
        let request = session_setup_request(&session, &secret, 5002).expect("build request");
        let body = decode_dictionary(&request.body);

        assert_eq!(
            body.get("ekey").and_then(Value::as_data),
            Some(&session_key[..32])
        );
    }

    #[test]
    fn derive_produces_a_fresh_iv_each_call() {
        let session_key = fixed_session_key();
        let first = AudioStreamSecret::derive(&session_key);
        let second = AudioStreamSecret::derive(&session_key);
        let session = fixed_session();
        let first_iv = decode_dictionary(
            &session_setup_request(&session, &first, 5002)
                .expect("build request")
                .body,
        )
        .get("eiv")
        .and_then(Value::as_data)
        .expect("eiv present")
        .to_vec();
        let second_iv = decode_dictionary(
            &session_setup_request(&session, &second, 5002)
                .expect("build request")
                .body,
        )
        .get("eiv")
        .and_then(Value::as_data)
        .expect("eiv present")
        .to_vec();

        assert_eq!(first_iv.len(), 16);
        assert_ne!(first_iv, second_iv);
    }

    #[test]
    fn builds_session_setup_request() {
        let session = fixed_session();
        let secret = AudioStreamSecret::derive(&fixed_session_key());
        let request = session_setup_request(&session, &secret, 5002).expect("build request");
        let body = decode_dictionary(&request.body);

        assert_eq!(request.method, "SETUP");
        assert_eq!(request.uri, session.path());
        assert_eq!(
            body.get("timingProtocol").and_then(Value::as_string),
            Some("NTP")
        );
        assert_eq!(integer(&body, "et"), 4);
        assert_eq!(integer(&body, "timingPort"), 5002);
        assert_eq!(body.len(), 5);
    }

    #[test]
    fn session_and_stream_setup_present_identical_key_material() {
        // The whole point of bundling key+iv into one AudioStreamSecret: both
        // requests built from the same instance must carry the same bytes.
        let secret = AudioStreamSecret::derive(&fixed_session_key());
        let session = fixed_session();
        let ports = LocalStreamPorts {
            audio: 5000,
            control: 5001,
            timing: 5002,
        };

        let session_body = decode_dictionary(
            &session_setup_request(&session, &secret, 5002)
                .expect("build session setup")
                .body,
        );
        let stream_body = decode_dictionary(
            &stream_setup_request(&session, &ports, &secret)
                .expect("build stream setup")
                .body,
        );
        let stream = stream_body
            .get("streams")
            .and_then(Value::as_array)
            .and_then(|streams| streams.first())
            .and_then(Value::as_dictionary)
            .expect("stream dictionary");

        assert_eq!(
            session_body.get("ekey").and_then(Value::as_data),
            stream.get("shk").and_then(Value::as_data)
        );
        assert_eq!(
            session_body.get("eiv").and_then(Value::as_data),
            stream.get("shiv").and_then(Value::as_data)
        );
    }

    #[test]
    fn parses_and_validates_session_setup_ports() {
        // Shape of a real HomePod response.
        let mut valid = Dictionary::new();
        valid.insert("eventPort".into(), Value::from(49266_i64));
        valid.insert("skipRecord".into(), Value::Boolean(true));
        let parsed = parse_session_setup_response(&plist_body(valid)).expect("parse session setup");
        assert_eq!(parsed.event_port, 49266);

        let mut missing = Dictionary::new();
        missing.insert("skipRecord".into(), Value::Boolean(true));
        assert!(parse_session_setup_response(&plist_body(missing)).is_err());

        for invalid in [-1_i64, 70_000] {
            let mut out_of_range = Dictionary::new();
            out_of_range.insert("eventPort".into(), Value::from(invalid));
            assert!(parse_session_setup_response(&plist_body(out_of_range)).is_err());
        }
    }

    #[test]
    fn builds_stream_setup_request() {
        let session = fixed_session();
        let ports = LocalStreamPorts {
            audio: 5000,
            control: 5001,
            timing: 5002,
        };
        let secret = AudioStreamSecret::derive(&fixed_session_key());
        let request = stream_setup_request(&session, &ports, &secret).expect("build request");
        let body = decode_dictionary(&request.body);
        let streams = body
            .get("streams")
            .and_then(Value::as_array)
            .expect("streams array");
        let stream = streams[0].as_dictionary().expect("stream dictionary");

        assert_eq!(request.method, "SETUP");
        assert_eq!(request.uri, session.path());
        assert_eq!(
            request.headers.get("Transport"),
            Some(
                "RTP/AVP/UDP;unicast;mode=record;client_port=5000;\
                 control_port=5001;timing_port=5002"
            )
        );
        assert_eq!(body.len(), 1);
        assert_eq!(streams.len(), 1);
        assert_eq!(stream.len(), 11);
        assert_eq!(integer(stream, "type"), 96);
        assert_eq!(integer(stream, "ct"), 2);
        assert_eq!(integer(stream, "audioFormat"), 0x40000);
        assert_eq!(integer(stream, "spf"), 352);
        assert_eq!(
            stream.get("audioType").and_then(Value::as_string),
            Some("default")
        );
        let session_key = fixed_session_key();
        assert_eq!(
            stream.get("shk").and_then(Value::as_data),
            Some(&session_key[..32])
        );
        assert_eq!(
            stream.get("shiv").and_then(Value::as_data).map(<[u8]>::len),
            Some(16)
        );
        assert_eq!(integer(stream, "controlPort"), 5001);
        assert_eq!(integer(stream, "timingPort"), 5002);
        assert_eq!(integer(stream, "latencyMin"), 11025);
        assert_eq!(integer(stream, "latencyMax"), 88200);
    }

    #[test]
    fn parses_flat_and_nested_stream_setup_ports() {
        let mut flat = Dictionary::new();
        flat.insert("dataPort".into(), Value::from(7000_i64));
        flat.insert("controlPort".into(), Value::from(7001_i64));
        let parsed = parse_stream_setup_response(&plist_body(flat)).expect("parse flat setup");
        assert_eq!(parsed.data_port, 7000);
        assert_eq!(parsed.control_port, 7001);

        let mut stream = Dictionary::new();
        stream.insert("dataPort".into(), Value::from(7100_i64));
        stream.insert("controlPort".into(), Value::from(7101_i64));
        let mut nested = Dictionary::new();
        nested.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(stream)]),
        );
        let parsed = parse_stream_setup_response(&plist_body(nested)).expect("parse nested setup");
        assert_eq!(parsed.data_port, 7100);
        assert_eq!(parsed.control_port, 7101);

        assert!(parse_stream_setup_response(&plist_body(Dictionary::new())).is_err());
    }

    #[test]
    fn builds_empty_record_request() {
        let session = fixed_session();
        let request = record_request(&session);

        assert_eq!(request.method, "RECORD");
        assert_eq!(request.uri, session.path());
        assert!(request.body.is_empty());
    }
}
