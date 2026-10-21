//! IEEE 1588-2008 (PTPv2) message encoding and decoding.
//!
//! Only what a clock follower exchanges with an AirPlay receiver: Sync,
//! Follow_Up, Delay_Req, Delay_Resp and Announce. Other message types decode
//! to [`Body::Other`] so a socket loop can skip them.

use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 34;
const TIMESTAMP_LEN: usize = 10;
const PORT_IDENTITY_LEN: usize = 10;
const PTP_VERSION: u8 = 2;
const NANOS_PER_SECOND: u32 = 1_000_000_000;
const MAX_SECONDS: u64 = (1 << 48) - 1;

/// Flag bit: a Follow_Up carries this Sync's precise origin time.
pub const FLAG_TWO_STEP: u16 = 0x0200;
/// Flag bit: messages are sent unicast.
pub const FLAG_UNICAST: u16 = 0x0400;

/// Message type nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Sync = 0x0,
    DelayReq = 0x1,
    FollowUp = 0x8,
    DelayResp = 0x9,
    Announce = 0xb,
}

impl MessageType {
    fn from_nibble(nibble: u8) -> Option<Self> {
        match nibble {
            0x0 => Some(Self::Sync),
            0x1 => Some(Self::DelayReq),
            0x8 => Some(Self::FollowUp),
            0x9 => Some(Self::DelayResp),
            0xb => Some(Self::Announce),
            _ => None,
        }
    }

    /// Legacy PTPv1 control field, still required on the wire.
    fn control(self) -> u8 {
        match self {
            Self::Sync => 0,
            Self::DelayReq => 1,
            Self::FollowUp => 2,
            Self::DelayResp => 3,
            Self::Announce => 5,
        }
    }

    fn body_len(self) -> usize {
        match self {
            Self::Sync | Self::DelayReq | Self::FollowUp => TIMESTAMP_LEN,
            Self::DelayResp => TIMESTAMP_LEN + PORT_IDENTITY_LEN,
            Self::Announce => ANNOUNCE_BODY_LEN,
        }
    }
}

/// PTP time: 48-bit seconds and nanoseconds since the clock's epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub seconds: u64,
    pub nanoseconds: u32,
}

impl Timestamp {
    pub fn from_nanos(nanos: u128) -> Self {
        Self {
            seconds: (nanos / u128::from(NANOS_PER_SECOND)) as u64 & MAX_SECONDS,
            nanoseconds: (nanos % u128::from(NANOS_PER_SECOND)) as u32,
        }
    }

    pub fn to_nanos(self) -> u128 {
        u128::from(self.seconds) * u128::from(NANOS_PER_SECOND) + u128::from(self.nanoseconds)
    }

    fn encode(self, out: &mut [u8]) {
        out[..6].copy_from_slice(&self.seconds.to_be_bytes()[2..]);
        out[6..10].copy_from_slice(&self.nanoseconds.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut seconds = [0_u8; 8];
        seconds[2..].copy_from_slice(&bytes[..6]);
        let nanoseconds = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        if nanoseconds >= NANOS_PER_SECOND {
            return Err(Error::Protocol(format!(
                "ptp: nanoseconds field {nanoseconds} out of range"
            )));
        }
        Ok(Self {
            seconds: u64::from_be_bytes(seconds),
            nanoseconds,
        })
    }
}

/// A clock identity plus port number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortIdentity {
    pub clock_identity: u64,
    pub port_number: u16,
}

impl PortIdentity {
    fn encode(self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.clock_identity.to_be_bytes());
        out[8..10].copy_from_slice(&self.port_number.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut clock = [0_u8; 8];
        clock.copy_from_slice(&bytes[..8]);
        Self {
            clock_identity: u64::from_be_bytes(clock),
            port_number: u16::from_be_bytes([bytes[8], bytes[9]]),
        }
    }
}

/// Fields of the common header that matter to a follower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub domain: u8,
    pub flags: u16,
    /// Correction in nanoseconds scaled by 2^16, to add to timestamps.
    pub correction: i64,
    pub source: PortIdentity,
    pub sequence_id: u16,
    pub log_message_interval: i8,
}

const ANNOUNCE_BODY_LEN: usize = 30;

/// Grandmaster description carried by Announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announce {
    pub priority1: u8,
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
    pub priority2: u8,
    pub grandmaster_identity: u64,
    pub steps_removed: u16,
    pub time_source: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    Sync {
        origin: Timestamp,
    },
    DelayReq {
        origin: Timestamp,
    },
    FollowUp {
        precise_origin: Timestamp,
    },
    DelayResp {
        receive: Timestamp,
        requesting: PortIdentity,
    },
    Announce(Announce),
    /// Signaling, management, peer delay and other types a follower ignores.
    Other {
        message_type: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub body: Body,
}

impl Message {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Protocol(format!(
                "ptp: message too short: {} bytes",
                bytes.len()
            )));
        }
        let version = bytes[1] & 0x0f;
        if version != PTP_VERSION {
            return Err(Error::Protocol(format!(
                "ptp: unsupported version {version}"
            )));
        }
        let declared = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if declared < HEADER_LEN || declared > bytes.len() {
            return Err(Error::Protocol(format!(
                "ptp: declared length {declared} does not fit {} bytes",
                bytes.len()
            )));
        }

        let mut correction = [0_u8; 8];
        correction.copy_from_slice(&bytes[8..16]);
        let header = Header {
            domain: bytes[4],
            flags: u16::from_be_bytes([bytes[6], bytes[7]]),
            correction: i64::from_be_bytes(correction),
            source: PortIdentity::decode(&bytes[20..30]),
            sequence_id: u16::from_be_bytes([bytes[30], bytes[31]]),
            log_message_interval: bytes[33] as i8,
        };

        let nibble = bytes[0] & 0x0f;
        let Some(message_type) = MessageType::from_nibble(nibble) else {
            return Ok(Self {
                header,
                body: Body::Other {
                    message_type: nibble,
                },
            });
        };
        let body = &bytes[HEADER_LEN..declared];
        if body.len() < message_type.body_len() {
            return Err(Error::Protocol(format!(
                "ptp: {message_type:?} body too short: {} bytes",
                body.len()
            )));
        }

        let body = match message_type {
            MessageType::Sync => Body::Sync {
                origin: Timestamp::decode(body)?,
            },
            MessageType::DelayReq => Body::DelayReq {
                origin: Timestamp::decode(body)?,
            },
            MessageType::FollowUp => Body::FollowUp {
                precise_origin: Timestamp::decode(body)?,
            },
            MessageType::DelayResp => Body::DelayResp {
                receive: Timestamp::decode(body)?,
                requesting: PortIdentity::decode(&body[TIMESTAMP_LEN..]),
            },
            MessageType::Announce => Body::Announce(Announce {
                priority1: body[13],
                clock_class: body[14],
                clock_accuracy: body[15],
                offset_scaled_log_variance: u16::from_be_bytes([body[16], body[17]]),
                priority2: body[18],
                grandmaster_identity: u64::from_be_bytes([
                    body[19], body[20], body[21], body[22], body[23], body[24], body[25], body[26],
                ]),
                steps_removed: u16::from_be_bytes([body[27], body[28]]),
                time_source: body[29],
            }),
        };
        Ok(Self { header, body })
    }
}

/// Encode a Delay_Req, the one message a follower sends. Its origin time is
/// zero on the wire; the sender keeps its own precise send time.
pub fn encode_delay_req(source: PortIdentity, domain: u8, sequence_id: u16) -> Vec<u8> {
    encode(
        MessageType::DelayReq,
        source,
        domain,
        sequence_id,
        0x7f,
        |_| {},
    )
}

/// Encode a Sync with an origin time. Used by tests and a future leader role.
pub fn encode_sync(
    source: PortIdentity,
    domain: u8,
    sequence_id: u16,
    origin: Timestamp,
) -> Vec<u8> {
    encode(MessageType::Sync, source, domain, sequence_id, 0, |body| {
        origin.encode(body)
    })
}

/// Encode a Follow_Up. Used by tests and a future leader role.
pub fn encode_follow_up(
    source: PortIdentity,
    domain: u8,
    sequence_id: u16,
    precise_origin: Timestamp,
) -> Vec<u8> {
    encode(
        MessageType::FollowUp,
        source,
        domain,
        sequence_id,
        0,
        |body| precise_origin.encode(body),
    )
}

/// Encode a Delay_Resp. Used by tests and a future leader role.
pub fn encode_delay_resp(
    source: PortIdentity,
    domain: u8,
    sequence_id: u16,
    receive: Timestamp,
    requesting: PortIdentity,
) -> Vec<u8> {
    encode(
        MessageType::DelayResp,
        source,
        domain,
        sequence_id,
        0,
        |body| {
            receive.encode(body);
            requesting.encode(&mut body[TIMESTAMP_LEN..]);
        },
    )
}

fn encode(
    message_type: MessageType,
    source: PortIdentity,
    domain: u8,
    sequence_id: u16,
    log_message_interval: u8,
    write_body: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let length = HEADER_LEN + message_type.body_len();
    let mut out = vec![0_u8; length];
    out[0] = message_type as u8;
    out[1] = PTP_VERSION;
    out[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    out[4] = domain;
    if message_type == MessageType::Sync {
        out[6..8].copy_from_slice(&FLAG_TWO_STEP.to_be_bytes());
    }
    source.encode(&mut out[20..30]);
    out[30..32].copy_from_slice(&sequence_id.to_be_bytes());
    out[32] = message_type.control();
    out[33] = log_message_interval;
    write_body(&mut out[HEADER_LEN..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEADER: PortIdentity = PortIdentity {
        clock_identity: 0x96_9b_5f_ff_fe_c7_5f_9d,
        port_number: 1,
    };
    const FOLLOWER: PortIdentity = PortIdentity {
        clock_identity: 0x0102_0304_0506_0708,
        port_number: 0x8001,
    };

    fn time(seconds: u64, nanoseconds: u32) -> Timestamp {
        Timestamp {
            seconds,
            nanoseconds,
        }
    }

    #[test]
    fn delay_req_has_exact_header_layout() {
        let bytes = encode_delay_req(FOLLOWER, 0, 0x1234);

        assert_eq!(bytes.len(), 44);
        assert_eq!(&bytes[..4], &[0x01, 0x02, 0x00, 0x2c]);
        assert_eq!(&bytes[20..30], &[1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0x01]);
        assert_eq!(&bytes[30..34], &[0x12, 0x34, 0x01, 0x7f]);
        assert!(bytes[34..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sync_and_follow_up_round_trip() {
        let origin = time(0x0000_1234_5678, 999_999_999);
        let sync = Message::decode(&encode_sync(LEADER, 0, 7, origin)).expect("sync");
        assert_eq!(sync.body, Body::Sync { origin });
        assert_eq!(sync.header.flags & FLAG_TWO_STEP, FLAG_TWO_STEP);
        assert_eq!(sync.header.source, LEADER);
        assert_eq!(sync.header.sequence_id, 7);

        let follow_up =
            Message::decode(&encode_follow_up(LEADER, 0, 7, origin)).expect("follow up");
        assert_eq!(
            follow_up.body,
            Body::FollowUp {
                precise_origin: origin
            }
        );
    }

    #[test]
    fn delay_resp_round_trips_requesting_port() {
        let receive = time(42, 5);
        let bytes = encode_delay_resp(LEADER, 0, 9, receive, FOLLOWER);
        let message = Message::decode(&bytes).expect("delay resp");

        assert_eq!(
            message.body,
            Body::DelayResp {
                receive,
                requesting: FOLLOWER
            }
        );
    }

    #[test]
    fn decodes_announce_grandmaster_fields() {
        let mut bytes = encode_sync(LEADER, 0, 1, Timestamp::default());
        bytes[0] = 0x0b;
        bytes[2..4].copy_from_slice(&64_u16.to_be_bytes());
        bytes.truncate(HEADER_LEN);
        let mut body = [0_u8; ANNOUNCE_BODY_LEN];
        body[13] = 248;
        body[14] = 248;
        body[15] = 0xfe;
        body[16..18].copy_from_slice(&0xffff_u16.to_be_bytes());
        body[18] = 248;
        body[19..27].copy_from_slice(&LEADER.clock_identity.to_be_bytes());
        body[29] = 0xa0;
        bytes.extend_from_slice(&body);

        let Body::Announce(announce) = Message::decode(&bytes).expect("announce").body else {
            panic!("expected announce");
        };
        assert_eq!(announce.priority1, 248);
        assert_eq!(announce.grandmaster_identity, LEADER.clock_identity);
        assert_eq!(announce.time_source, 0xa0);
    }

    #[test]
    fn unknown_types_decode_as_other() {
        let mut bytes = encode_delay_req(FOLLOWER, 0, 1);
        bytes[0] = 0x0c;
        assert_eq!(
            Message::decode(&bytes).expect("signaling").body,
            Body::Other { message_type: 0xc }
        );
    }

    #[test]
    fn rejects_malformed_messages() {
        let good = encode_sync(LEADER, 0, 1, time(1, 1));
        assert!(Message::decode(&good[..HEADER_LEN - 1]).is_err());

        let mut v1 = good.clone();
        v1[1] = 1;
        assert!(Message::decode(&v1).is_err());

        let mut overlong = good.clone();
        overlong[2..4].copy_from_slice(&100_u16.to_be_bytes());
        assert!(Message::decode(&overlong).is_err());

        let mut short_body = good.clone();
        short_body[2..4].copy_from_slice(&(HEADER_LEN as u16 + 4).to_be_bytes());
        assert!(Message::decode(&short_body).is_err());

        let mut bad_nanos = good;
        bad_nanos[40..44].copy_from_slice(&NANOS_PER_SECOND.to_be_bytes());
        assert!(Message::decode(&bad_nanos).is_err());
    }

    #[test]
    fn timestamp_nanos_round_trip() {
        let stamp = time(1_700_000_000, 123_456_789);
        assert_eq!(Timestamp::from_nanos(stamp.to_nanos()), stamp);
    }
}
