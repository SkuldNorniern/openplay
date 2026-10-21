//! RTSP requests for buffered streams timed by PTP.
//!
//! Buffered streams (type 103) carry audio ahead of time over TCP, and the
//! receiver plays it at the PTP time set by SETRATEANCHORTIME. The bodies
//! follow jburnhams/airplay2-rs and the receiver's advertised formats; they
//! are not yet confirmed against a live HomePod.

use std::net::IpAddr;

use plist::{Dictionary, Value};

use super::setup::{AudioStreamSecret, LocalStreamPorts, SessionId, encode_plist};
use crate::error::{Error, Result};
use crate::ptp::Timestamp;
use crate::rtsp::Request;

const PLIST_CONTENT_TYPE: &str = "application/x-apple-binary-plist";
const STREAM_TYPE_BUFFERED: i64 = 103;
const COMPRESSION_ALAC: i64 = 2;
/// ALAC 44.1 kHz/24-bit stereo. A HomePod's `bufferStream` formats list
/// the 24-bit ALAC variants and AAC, but not the 16-bit ALAC realtime uses.
pub const AUDIO_FORMAT_ALAC_44100_24: i64 = 1 << 19;
const FRAMES_PER_PACKET: i64 = 352;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Our PTP identity as the receiver needs it to answer our Delay_Req.
pub struct PtpPeer {
    /// Our addresses on the receiver's network.
    pub addresses: Vec<IpAddr>,
    pub clock_id: u64,
    /// Port our Delay_Req leaves from, where Delay_Resp must come back.
    pub clock_port: u16,
}

/// Session SETUP for a PTP-timed session.
///
/// `ClockPorts` with `SupportsClockPortMatchingOverride` tells the receiver
/// which port to send Delay_Resp to, so the follower can run on an
/// ephemeral port instead of the privileged 319.
pub fn ptp_session_setup_request(
    session: &SessionId,
    secret: &AudioStreamSecret,
    peer: &PtpPeer,
    group_uuid: &str,
) -> Result<Request> {
    let mut clock_ports = Dictionary::new();
    clock_ports.insert(
        format!("{:016X}", peer.clock_id),
        Value::from(peer.clock_port),
    );

    let mut timing_peer = Dictionary::new();
    timing_peer.insert(
        "Addresses".into(),
        Value::Array(
            peer.addresses
                .iter()
                .map(|address| Value::String(address.to_string()))
                .collect(),
        ),
    );
    timing_peer.insert("ID".into(), Value::String(session_id(session)));
    // Integer bit pattern, the form the receiver uses for its own ClockID.
    timing_peer.insert("ClockID".into(), Value::from(peer.clock_id as i64));
    timing_peer.insert(
        "SupportsClockPortMatchingOverride".into(),
        Value::Boolean(true),
    );
    timing_peer.insert("ClockPorts".into(), Value::Dictionary(clock_ports));

    let mut body = Dictionary::new();
    body.insert("timingProtocol".into(), Value::String("PTP".into()));
    body.insert("timingPeerInfo".into(), Value::Dictionary(timing_peer));
    body.insert("groupUUID".into(), Value::String(group_uuid.into()));
    body.insert("isAudioReceiver".into(), Value::Boolean(false));
    body.insert("ekey".into(), Value::Data(secret.audio_key().to_vec()));
    body.insert("eiv".into(), Value::Data(secret.iv().to_vec()));
    body.insert("et".into(), Value::from(4_i64));

    Ok(Request::new("SETUP", &session.path())
        .header("Content-Type", PLIST_CONTENT_TYPE)
        .body(encode_plist(body)?))
}

/// Stream SETUP for buffered 24-bit ALAC.
pub fn buffered_stream_setup_request(
    session: &SessionId,
    ports: &LocalStreamPorts,
    secret: &AudioStreamSecret,
) -> Result<Request> {
    let mut stream = Dictionary::new();
    stream.insert("type".into(), Value::from(STREAM_TYPE_BUFFERED));
    stream.insert("ct".into(), Value::from(COMPRESSION_ALAC));
    stream.insert(
        "audioFormat".into(),
        Value::from(AUDIO_FORMAT_ALAC_44100_24),
    );
    stream.insert("spf".into(), Value::from(FRAMES_PER_PACKET));
    stream.insert("audioType".into(), Value::String("default".into()));
    stream.insert("shk".into(), Value::Data(secret.audio_key().to_vec()));
    stream.insert("controlPort".into(), Value::from(ports.control));
    stream.insert("timingPort".into(), Value::from(ports.timing));

    let mut body = Dictionary::new();
    body.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(stream)]),
    );
    Ok(Request::new("SETUP", &session.path())
        .header("Content-Type", PLIST_CONTENT_TYPE)
        .body(encode_plist(body)?))
}

/// SETPEERS: the timing peers, as a plain array of address strings. The
/// receiver drops the connection on dictionary-style peer lists.
pub fn set_peers_request(session: &SessionId, peers: &[IpAddr]) -> Result<Request> {
    let body = Value::Array(
        peers
            .iter()
            .map(|peer| Value::String(peer.to_string()))
            .collect(),
    );
    let mut bytes = Vec::new();
    body.to_writer_binary(&mut bytes)
        .map_err(|error| Error::Protocol(format!("plist encoding failed: {error}")))?;
    Ok(Request::new("SETPEERS", &session.path())
        .header("Content-Type", PLIST_CONTENT_TYPE)
        .body(bytes))
}

/// Where on the receiver's PTP timeline playback is anchored.
pub struct Anchor {
    /// RTP timestamp that plays at `network_time`.
    pub rtp_time: u32,
    pub network_time: Timestamp,
    /// Clock identity of the PTP leader whose timeline `network_time` is on.
    pub timeline_id: u64,
}

/// SETRATEANCHORTIME: start (rate 1) or pause (rate 0) playback.
///
/// `networkTimeFrac` is a 64-bit binary fraction of a second. The 64-bit
/// values go out as the bit pattern of a signed integer, which is how the
/// receiver writes its own clock IDs.
pub fn set_rate_anchor_time_request(
    session: &SessionId,
    rate: f64,
    anchor: Option<&Anchor>,
) -> Result<Request> {
    let mut body = Dictionary::new();
    body.insert("rate".into(), Value::Real(rate));
    if let Some(anchor) = anchor {
        body.insert("rtpTime".into(), Value::from(i64::from(anchor.rtp_time)));
        body.insert(
            "networkTimeSecs".into(),
            Value::from(anchor.network_time.seconds as i64),
        );
        body.insert(
            "networkTimeFrac".into(),
            Value::from(nanos_to_fraction(anchor.network_time.nanoseconds) as i64),
        );
        body.insert(
            "networkTimeTimelineID".into(),
            Value::from(anchor.timeline_id as i64),
        );
    }
    Ok(Request::new("SETRATEANCHORTIME", &session.path())
        .header("Content-Type", PLIST_CONTENT_TYPE)
        .body(encode_plist(body)?))
}

/// Nanoseconds as a fraction of a second scaled by 2^64.
fn nanos_to_fraction(nanoseconds: u32) -> u64 {
    ((u128::from(nanoseconds) << 64) / NANOS_PER_SECOND) as u64
}

fn session_id(session: &SessionId) -> String {
    session.path().trim_start_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    use super::*;

    fn session() -> SessionId {
        SessionId::from_hex("1A2B3C4D5E6F7890")
    }

    fn secret() -> AudioStreamSecret {
        AudioStreamSecret::derive(&[7_u8; 64])
    }

    fn dictionary(body: &[u8]) -> Dictionary {
        Value::from_reader(Cursor::new(body))
            .expect("plist")
            .into_dictionary()
            .expect("dictionary")
    }

    #[test]
    fn ptp_session_setup_registers_clock_port() {
        let peer = PtpPeer {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            clock_id: 0x0102_0304_0506_0708,
            clock_port: 51_234,
        };
        let request =
            ptp_session_setup_request(&session(), &secret(), &peer, "D67B1696").expect("build");
        let body = dictionary(&request.body);

        assert_eq!(
            body.get("timingProtocol").and_then(Value::as_string),
            Some("PTP")
        );
        let timing = body
            .get("timingPeerInfo")
            .and_then(Value::as_dictionary)
            .expect("timingPeerInfo");
        assert_eq!(
            timing.get("ID").and_then(Value::as_string),
            Some("1A2B3C4D5E6F7890")
        );
        let ports = timing
            .get("ClockPorts")
            .and_then(Value::as_dictionary)
            .expect("ClockPorts");
        assert_eq!(
            ports
                .get("0102030405060708")
                .and_then(Value::as_signed_integer),
            Some(51_234)
        );
        assert_eq!(
            body.get("ekey").and_then(Value::as_data),
            Some(&[7_u8; 32][..])
        );
    }

    #[test]
    fn buffered_stream_uses_type_103_and_24_bit_alac() {
        let ports = LocalStreamPorts {
            audio: 1,
            control: 6001,
            timing: 6002,
        };
        let request = buffered_stream_setup_request(&session(), &ports, &secret()).expect("build");
        let body = dictionary(&request.body);
        let stream = body
            .get("streams")
            .and_then(Value::as_array)
            .and_then(|streams| streams.first())
            .and_then(Value::as_dictionary)
            .expect("stream");

        assert_eq!(
            stream.get("type").and_then(Value::as_signed_integer),
            Some(103)
        );
        assert_eq!(
            stream.get("audioFormat").and_then(Value::as_signed_integer),
            Some(0x80000)
        );
        assert!(request.headers.get("Transport").is_none());
    }

    #[test]
    fn set_peers_is_a_plain_address_array() {
        let peers = [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
        ];
        let request = set_peers_request(&session(), &peers).expect("build");
        let body = Value::from_reader(Cursor::new(&request.body)).expect("plist");

        assert_eq!(request.method, "SETPEERS");
        assert_eq!(
            body,
            Value::Array(vec![
                Value::String("192.0.2.10".into()),
                Value::String("192.0.2.20".into()),
            ])
        );
    }

    #[test]
    fn anchor_carries_network_time_fraction() {
        let anchor = Anchor {
            rtp_time: 352,
            network_time: Timestamp {
                seconds: 1_000,
                nanoseconds: 500_000_000,
            },
            timeline_id: 0xffff_0000_0000_0001,
        };
        let request = set_rate_anchor_time_request(&session(), 1.0, Some(&anchor)).expect("build");
        let body = dictionary(&request.body);

        assert_eq!(body.get("rate").and_then(Value::as_real), Some(1.0));
        assert_eq!(
            body.get("networkTimeFrac")
                .and_then(Value::as_signed_integer),
            Some(i64::MIN)
        );
        assert_eq!(
            body.get("networkTimeTimelineID")
                .and_then(Value::as_signed_integer),
            Some(0xffff_0000_0000_0001_u64 as i64)
        );
    }

    #[test]
    fn pause_has_rate_only() {
        let request = set_rate_anchor_time_request(&session(), 0.0, None).expect("build");
        let body = dictionary(&request.body);
        assert_eq!(body.len(), 1);
    }

    #[test]
    fn fraction_of_half_and_whole_seconds() {
        assert_eq!(nanos_to_fraction(0), 0);
        assert_eq!(nanos_to_fraction(500_000_000), 1 << 63);
        assert_eq!(nanos_to_fraction(999_999_999), u64::MAX - 18_446_744_073);
    }
}
