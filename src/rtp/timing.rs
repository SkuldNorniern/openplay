//! Unencrypted RAOP NTP timing: the receiver asks, the sender answers.
//!
//! After SETUP advertises `timingProtocol: NTP` and our timing port, the
//! receiver periodically sends 0xd2 requests carrying its transmit time. The
//! sender must echo that time back in a 0xd3 reply stamped with its own
//! receive and transmit times, which lets the receiver estimate our clock.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use crate::error::{Error, Result};

pub const TIMING_PACKET_LEN: usize = 32;

const RTP_VERSION: u8 = 0x80;
const TIMING_REQUEST_TYPE: u8 = 0xd2;
const TIMING_RESPONSE_TYPE: u8 = 0xd3;
const NTP_UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const NTP_FRACTION_BITS: u32 = 32;

const RTP_VERSION_INDEX: usize = 0;
const RTP_PACKET_TYPE_INDEX: usize = 1;
const SEQUENCE_START: usize = 2;
const SEQUENCE_END: usize = 4;
const REFERENCE_TIME_START: usize = 8;
const REFERENCE_TIME_END: usize = 16;
const RECEIVE_TIME_START: usize = 16;
const RECEIVE_TIME_END: usize = 24;
const SEND_TIME_START: usize = 24;
const SEND_TIME_END: usize = 32;
const NTP_TIMESTAMP_LEN: usize = 8;
const NTP_SECONDS_END: usize = 4;
/// Large enough that an oversized datagram is seen as oversized rather than
/// silently truncated to a plausible 32 bytes.
const RECEIVE_BUFFER_LEN: usize = 64;

/// A 64-bit NTP timestamp: seconds since 1900-01-01 plus a 1/2^32-second fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpTimestamp {
    seconds: u32,
    fraction: u32,
}

impl NtpTimestamp {
    /// Capture wall-clock time in the epoch and fixed-point format used on the wire.
    pub fn now() -> Result<Self> {
        Self::from_unix(SystemTime::now())
    }

    /// Convert a Unix wall-clock instant without silently accepting pre-epoch times
    /// or timestamps whose NTP seconds field cannot fit on the wire.
    pub fn from_unix(time: SystemTime) -> Result<Self> {
        let since_unix_epoch = time.duration_since(UNIX_EPOCH).map_err(|error| {
            Error::Protocol(format!("timing timestamp precedes the Unix epoch: {error}"))
        })?;
        let seconds = since_unix_epoch
            .as_secs()
            .checked_add(NTP_UNIX_EPOCH_OFFSET)
            .and_then(|seconds| u32::try_from(seconds).ok())
            .ok_or_else(|| Error::Protocol("timing timestamp exceeds the NTP era".to_owned()))?;
        let fraction = ((u64::from(since_unix_epoch.subsec_nanos()) << NTP_FRACTION_BITS)
            / NANOS_PER_SECOND) as u32;

        Ok(Self { seconds, fraction })
    }

    /// Preserve the protocol's seconds-then-fraction big-endian field order.
    pub fn to_bytes(self) -> [u8; NTP_TIMESTAMP_LEN] {
        let mut bytes = [0_u8; NTP_TIMESTAMP_LEN];
        bytes[..NTP_SECONDS_END].copy_from_slice(&self.seconds.to_be_bytes());
        bytes[NTP_SECONDS_END..].copy_from_slice(&self.fraction.to_be_bytes());
        bytes
    }

    /// Decode the fixed-width field after the enclosing packet has been validated.
    pub fn from_bytes(bytes: [u8; NTP_TIMESTAMP_LEN]) -> Self {
        let [
            seconds_0,
            seconds_1,
            seconds_2,
            seconds_3,
            fraction_0,
            fraction_1,
            fraction_2,
            fraction_3,
        ] = bytes;
        let seconds = u32::from_be_bytes([seconds_0, seconds_1, seconds_2, seconds_3]);
        let fraction = u32::from_be_bytes([fraction_0, fraction_1, fraction_2, fraction_3]);

        Self { seconds, fraction }
    }
}

/// The parts of a receiver's timing request that the reply must echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingRequest {
    pub sequence: u16,
    /// The receiver's transmit time; it becomes the reply's reference time.
    pub send_time: NtpTimestamp,
}

/// Parse a 32-byte RAOP timing request sent by the receiver.
///
/// Exact length and header validation prevents unrelated, truncated, or
/// extended UDP datagrams from being answered as clock requests.
pub fn parse_timing_request(bytes: &[u8]) -> Result<TimingRequest> {
    if bytes.len() != TIMING_PACKET_LEN {
        return Err(Error::Protocol(format!(
            "timing request must be exactly {TIMING_PACKET_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    if bytes[RTP_VERSION_INDEX] != RTP_VERSION {
        return Err(Error::Protocol(format!(
            "timing request byte 0 must be 0x{RTP_VERSION:02x}, got 0x{:02x}",
            bytes[RTP_VERSION_INDEX]
        )));
    }
    if bytes[RTP_PACKET_TYPE_INDEX] != TIMING_REQUEST_TYPE {
        return Err(Error::Protocol(format!(
            "timing request byte 1 must be 0x{TIMING_REQUEST_TYPE:02x}, got 0x{:02x}",
            bytes[RTP_PACKET_TYPE_INDEX]
        )));
    }

    let mut sequence = [0_u8; 2];
    sequence.copy_from_slice(&bytes[SEQUENCE_START..SEQUENCE_END]);
    let mut send_time = [0_u8; NTP_TIMESTAMP_LEN];
    send_time.copy_from_slice(&bytes[SEND_TIME_START..SEND_TIME_END]);

    Ok(TimingRequest {
        sequence: u16::from_be_bytes(sequence),
        send_time: NtpTimestamp::from_bytes(send_time),
    })
}

/// Build the 0xd3 reply to `request`.
///
/// Field layout matches what a HomePod accepts: sequence echoed, bytes 4..8
/// zero, the request's transmit time as reference, then our receive and
/// transmit times.
pub fn build_timing_response(
    request: TimingRequest,
    receive_time: NtpTimestamp,
    send_time: NtpTimestamp,
) -> [u8; TIMING_PACKET_LEN] {
    let mut packet = [0_u8; TIMING_PACKET_LEN];
    packet[RTP_VERSION_INDEX] = RTP_VERSION;
    packet[RTP_PACKET_TYPE_INDEX] = TIMING_RESPONSE_TYPE;
    packet[SEQUENCE_START..SEQUENCE_END].copy_from_slice(&request.sequence.to_be_bytes());
    packet[REFERENCE_TIME_START..REFERENCE_TIME_END].copy_from_slice(&request.send_time.to_bytes());
    packet[RECEIVE_TIME_START..RECEIVE_TIME_END].copy_from_slice(&receive_time.to_bytes());
    packet[SEND_TIME_START..SEND_TIME_END].copy_from_slice(&send_time.to_bytes());
    packet
}

/// Answers the receiver's timing requests on the port advertised in SETUP.
pub struct TimingResponder {
    socket: UdpSocket,
    receiver_ip: IpAddr,
}

impl TimingResponder {
    /// Bind the timing UDP socket to an ephemeral local port.
    ///
    /// The returned port goes into the session's `timingPort` during SETUP,
    /// and [`Self::run`] must already be running by the time SETUP completes,
    /// since the receiver starts asking immediately afterwards.
    ///
    /// Only datagrams from `receiver_ip` are answered; the receiver picks its
    /// own source port, so the port is not checked.
    pub async fn bind(receiver_ip: IpAddr, bind: Option<Ipv4Addr>) -> Result<(Self, u16)> {
        let local_addr = match receiver_ip {
            IpAddr::V4(_) => SocketAddr::from((bind.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)),
            IpAddr::V6(_) => {
                if bind.is_some() {
                    return Err(Error::Protocol("cannot bind IPv4 to an IPv6 target".into()));
                }
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            }
        };

        let socket = UdpSocket::bind(local_addr).await?;
        let local_port = socket.local_addr()?.port();

        Ok((
            Self {
                socket,
                receiver_ip,
            },
            local_port,
        ))
    }

    /// Wait for one datagram and answer it if it is a valid request from the
    /// receiver.
    ///
    /// Returns whether a reply was sent. Stray or malformed datagrams are
    /// ignored rather than treated as errors, so one bad packet on an open
    /// UDP port cannot tear down the session.
    pub async fn respond_once(&self) -> Result<bool> {
        let mut buffer = [0_u8; RECEIVE_BUFFER_LEN];
        let (length, peer) = self.socket.recv_from(&mut buffer).await?;
        // Stamp before any parsing so our processing time is not counted as
        // network delay by the receiver.
        let receive_time = NtpTimestamp::now()?;
        if peer.ip() != self.receiver_ip {
            return Ok(false);
        }
        let Ok(request) = parse_timing_request(&buffer[..length]) else {
            return Ok(false);
        };

        let reply = build_timing_response(request, receive_time, NtpTimestamp::now()?);
        let sent = self.socket.send_to(&reply, peer).await?;
        if sent != reply.len() {
            return Err(Error::Protocol(format!(
                "timing: sent {sent} of {} UDP packet bytes",
                reply.len()
            )));
        }

        Ok(true)
    }

    /// Answer requests until a socket error occurs. To stop it normally,
    /// callers can spawn this future and abort its Tokio task.
    pub async fn run(&self) -> Result<()> {
        loop {
            self.respond_once().await?;
        }
    }
}

impl fmt::Debug for TimingResponder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TimingResponder(..)")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    /// First request/reply pair from the captured working HomePod session.
    const CAPTURED_REQUEST: [u8; TIMING_PACKET_LEN] = [
        0x80, 0xd2, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0xaa, 0x7e, 0x80, 0xc4, 0x89,
        0x4c, 0xf7,
    ];
    const CAPTURED_REPLY: [u8; TIMING_PACKET_LEN] = [
        0x80, 0xd3, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x83, 0xaa, 0x7e, 0x80, 0xc4, 0x89, 0x4c,
        0xf7, 0xee, 0x08, 0xca, 0x51, 0x43, 0xc0, 0x1a, 0x36, 0xee, 0x08, 0xca, 0x51, 0x43, 0xc0,
        0x24, 0x47,
    ];

    fn assert_protocol_error(bytes: &[u8], expected: &str) {
        match parse_timing_request(bytes) {
            Err(Error::Protocol(message)) => assert_eq!(message, expected),
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    fn timestamp_at(bytes: &[u8]) -> NtpTimestamp {
        NtpTimestamp::from_bytes(bytes.try_into().expect("timestamp bytes"))
    }

    #[test]
    fn captured_request_parses_sequence_and_send_time() {
        let request = parse_timing_request(&CAPTURED_REQUEST).expect("parse captured request");

        assert_eq!(request.sequence, 0x0007);
        assert_eq!(
            request.send_time,
            NtpTimestamp {
                seconds: 0x83aa_7e80,
                fraction: 0xc489_4cf7,
            }
        );
    }

    #[test]
    fn reply_reproduces_captured_wire_bytes() {
        let request = parse_timing_request(&CAPTURED_REQUEST).expect("parse captured request");
        let receive_time = timestamp_at(&CAPTURED_REPLY[RECEIVE_TIME_START..RECEIVE_TIME_END]);
        let send_time = timestamp_at(&CAPTURED_REPLY[SEND_TIME_START..SEND_TIME_END]);

        assert_eq!(
            build_timing_response(request, receive_time, send_time),
            CAPTURED_REPLY
        );
    }

    #[test]
    fn ntp_timestamp_bytes_round_trip_in_field_order() {
        let timestamp = NtpTimestamp {
            seconds: 0x0102_0304,
            fraction: 0xa0b0_c0d0,
        };
        let expected = [0x01, 0x02, 0x03, 0x04, 0xa0, 0xb0, 0xc0, 0xd0];

        assert_eq!(timestamp.to_bytes(), expected);
        assert_eq!(NtpTimestamp::from_bytes(expected), timestamp);
    }

    #[test]
    fn unix_epoch_converts_to_ntp_epoch() {
        let epoch = NtpTimestamp::from_unix(UNIX_EPOCH).expect("convert Unix epoch");
        assert_eq!(
            epoch,
            NtpTimestamp {
                seconds: 2_208_988_800,
                fraction: 0,
            }
        );

        let half_second = NtpTimestamp::from_unix(UNIX_EPOCH + Duration::from_millis(500))
            .expect("convert half second after Unix epoch");
        assert_eq!(half_second.seconds, 2_208_988_800);
        assert_eq!(half_second.fraction, 0x8000_0000);
    }

    #[test]
    fn timing_request_rejects_wrong_lengths() {
        assert_protocol_error(
            &[0_u8; 31],
            "timing request must be exactly 32 bytes, got 31",
        );
        assert_protocol_error(
            &[0_u8; 33],
            "timing request must be exactly 32 bytes, got 33",
        );
        assert_protocol_error(&[], "timing request must be exactly 32 bytes, got 0");
    }

    #[test]
    fn timing_request_rejects_wrong_version() {
        let mut packet = CAPTURED_REQUEST;
        packet[RTP_VERSION_INDEX] = 0x00;

        assert_protocol_error(&packet, "timing request byte 0 must be 0x80, got 0x00");
    }

    #[test]
    fn timing_request_rejects_response_packet_type() {
        assert_protocol_error(
            &CAPTURED_REPLY,
            "timing request byte 1 must be 0xd2, got 0xd3",
        );
    }

    async fn responder_and_peer() -> (TimingResponder, UdpSocket, SocketAddr) {
        let (responder, port) =
            TimingResponder::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(Ipv4Addr::LOCALHOST))
                .await
                .expect("bind responder");
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        (
            responder,
            peer,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        )
    }

    #[tokio::test]
    async fn responder_answers_receiver_request() {
        let (responder, peer, responder_addr) = responder_and_peer().await;
        peer.send_to(&CAPTURED_REQUEST, responder_addr)
            .await
            .expect("send request");

        assert!(responder.respond_once().await.expect("respond"));
        let mut buffer = [0_u8; RECEIVE_BUFFER_LEN];
        let (length, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
            .await
            .expect("reply before timeout")
            .expect("receive reply");
        let reply = &buffer[..length];

        assert_eq!(length, TIMING_PACKET_LEN);
        assert_eq!(&reply[..SEQUENCE_END], &CAPTURED_REPLY[..SEQUENCE_END]);
        assert_eq!(
            &reply[REFERENCE_TIME_START..REFERENCE_TIME_END],
            &CAPTURED_REQUEST[SEND_TIME_START..SEND_TIME_END]
        );
        let receive_time = timestamp_at(&reply[RECEIVE_TIME_START..RECEIVE_TIME_END]);
        let send_time = timestamp_at(&reply[SEND_TIME_START..SEND_TIME_END]);
        assert!(receive_time.seconds > 0);
        assert!(
            (send_time.seconds, send_time.fraction)
                >= (receive_time.seconds, receive_time.fraction)
        );
    }

    #[tokio::test]
    async fn responder_ignores_malformed_datagram_and_keeps_serving() {
        let (responder, peer, responder_addr) = responder_and_peer().await;
        peer.send_to(&[0_u8; 33], responder_addr)
            .await
            .expect("send junk");
        peer.send_to(&CAPTURED_REQUEST, responder_addr)
            .await
            .expect("send request");

        assert!(!responder.respond_once().await.expect("skip junk"));
        assert!(responder.respond_once().await.expect("answer request"));
    }

    #[tokio::test]
    async fn responder_ignores_requests_from_other_hosts() {
        let (responder, _port) =
            TimingResponder::bind(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), None)
                .await
                .expect("bind responder");
        let port = responder.socket.local_addr().expect("address").port();
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        peer.send_to(&CAPTURED_REQUEST, (Ipv4Addr::LOCALHOST, port))
            .await
            .expect("send request");

        assert!(!responder.respond_once().await.expect("ignore stranger"));
    }
}
