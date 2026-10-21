//! Retransmission of lost audio packets on the control channel.
//!
//! When the receiver notices a sequence gap it sends a 0xd5 request naming
//! the first missing sequence number and a count. The sender answers each
//! missing packet it still holds with a 0xd6 reply: a 4-byte header followed
//! by the original, already encrypted RTP packet.

use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use log::debug;
use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// About four seconds of packets at 352 frames per packet, longer than the
/// receiver's two-second buffer, so any packet it can still use is kept.
pub const HISTORY_PACKETS: usize = 512;

const RTP_VERSION: u8 = 0x80;
const MARKER_BIT: u8 = 0x80;
const RESEND_REQUEST_TYPE: u8 = 0x55;
const RESEND_REPLY_TYPE: u8 = 0xd6;
const RESEND_REQUEST_LEN: usize = 8;
/// A request for more than this is malformed or hostile; real gaps are short.
const MAX_RESEND_COUNT: u16 = HISTORY_PACKETS as u16;
const RECEIVE_BUFFER_LEN: usize = 64;

/// Sent packets in send order, each with its RTP sequence number.
type SentPackets = VecDeque<(u16, Vec<u8>)>;

/// Recently sent audio packets, keyed by RTP sequence number. Cheap to clone;
/// the sender and the resend responder share one history.
#[derive(Clone)]
pub struct PacketHistory {
    packets: Arc<Mutex<SentPackets>>,
    capacity: usize,
}

impl PacketHistory {
    pub fn new(capacity: usize) -> Self {
        Self {
            packets: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Remember a sent packet, dropping the oldest once full.
    pub fn push(&self, sequence: u16, packet: Vec<u8>) {
        if self.capacity == 0 {
            return;
        }
        let mut packets = self.lock();
        if packets.len() == self.capacity {
            packets.pop_front();
        }
        packets.push_back((sequence, packet));
    }

    pub fn get(&self, sequence: u16) -> Option<Vec<u8>> {
        self.lock()
            .iter()
            .rev()
            .find(|(stored, _)| *stored == sequence)
            .map(|(_, packet)| packet.clone())
    }

    fn lock(&self) -> MutexGuard<'_, SentPackets> {
        // Only plain pushes and lookups happen under the lock, so a panic
        // elsewhere cannot leave the queue half-updated.
        self.packets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for PacketHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PacketHistory({} packets)", self.lock().len())
    }
}

/// Missing range named by one resend request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendRequest {
    pub first: u16,
    pub count: u16,
}

impl ResendRequest {
    /// Sequence numbers asked for, wrapping past 65535.
    pub fn sequences(self) -> impl Iterator<Item = u16> {
        (0..self.count).map(move |offset| self.first.wrapping_add(offset))
    }
}

/// Parse a resend request: `80 d5 <seq> <first missing> <count>`.
pub fn parse_resend_request(bytes: &[u8]) -> Result<ResendRequest> {
    if bytes.len() < RESEND_REQUEST_LEN {
        return Err(Error::Protocol(format!(
            "resend request too short: {} bytes",
            bytes.len()
        )));
    }
    if bytes[0] & 0xc0 != RTP_VERSION || bytes[1] & !MARKER_BIT != RESEND_REQUEST_TYPE {
        return Err(Error::Protocol(format!(
            "not a resend request: {:02x} {:02x}",
            bytes[0], bytes[1]
        )));
    }

    let first = u16::from_be_bytes([bytes[4], bytes[5]]);
    let count = u16::from_be_bytes([bytes[6], bytes[7]]);
    if count == 0 || count > MAX_RESEND_COUNT {
        return Err(Error::Protocol(format!(
            "resend count out of range: {count}"
        )));
    }
    Ok(ResendRequest { first, count })
}

/// Wrap a stored packet in the 0xd6 retransmission header.
pub fn build_resend_reply(sequence: u16, packet: &[u8]) -> Vec<u8> {
    let mut reply = Vec::with_capacity(4 + packet.len());
    reply.extend_from_slice(&[RTP_VERSION, RESEND_REPLY_TYPE]);
    reply.extend_from_slice(&sequence.to_be_bytes());
    reply.extend_from_slice(packet);
    reply
}

/// Answers resend requests arriving on the control socket.
pub struct ResendResponder {
    socket: Arc<UdpSocket>,
    receiver_ip: IpAddr,
    history: PacketHistory,
}

impl ResendResponder {
    /// `socket` is the control socket shared with [`super::SyncSender`].
    pub fn new(socket: Arc<UdpSocket>, receiver_ip: IpAddr, history: PacketHistory) -> Self {
        Self {
            socket,
            receiver_ip,
            history,
        }
    }

    /// Handle one datagram. Returns how many packets were resent.
    ///
    /// Stray or malformed datagrams are skipped, and packets no longer in
    /// the history are left for the receiver to conceal.
    pub async fn respond_once(&self) -> Result<usize> {
        let mut buffer = [0_u8; RECEIVE_BUFFER_LEN];
        let (length, peer) = self.socket.recv_from(&mut buffer).await?;
        if peer.ip() != self.receiver_ip {
            debug!("resend: ignored datagram from {peer}");
            return Ok(0);
        }
        let request = match parse_resend_request(&buffer[..length]) {
            Ok(request) => request,
            Err(error) => {
                debug!("resend: ignored datagram: {error}");
                return Ok(0);
            }
        };

        let mut resent = 0;
        for sequence in request.sequences() {
            if let Some(packet) = self.history.get(sequence) {
                self.socket
                    .send_to(&build_resend_reply(sequence, &packet), peer)
                    .await?;
                resent += 1;
            }
        }
        debug!(
            "resend: {resent} of {} packets from {}",
            request.count, request.first
        );
        Ok(resent)
    }

    /// Answer requests until a socket error occurs.
    pub async fn run(&self) -> Result<()> {
        loop {
            self.respond_once().await?;
        }
    }
}

impl fmt::Debug for ResendResponder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResendResponder(..)")
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::rtp::bind_udp;

    fn request(first: u16, count: u16) -> Vec<u8> {
        let mut bytes = vec![0x80, 0xd5, 0x00, 0x01];
        bytes.extend_from_slice(&first.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_request_with_or_without_marker_bit() {
        let expected = ResendRequest {
            first: 0xfffe,
            count: 3,
        };
        assert_eq!(
            parse_resend_request(&request(0xfffe, 3)).expect("parse"),
            expected
        );
        let mut unmarked = request(0xfffe, 3);
        unmarked[1] = 0x55;
        assert_eq!(parse_resend_request(&unmarked).expect("parse"), expected);
        assert_eq!(
            expected.sequences().collect::<Vec<_>>(),
            [0xfffe, 0xffff, 0x0000]
        );
    }

    #[test]
    fn rejects_short_foreign_and_oversized_requests() {
        assert!(parse_resend_request(&request(1, 1)[..7]).is_err());
        assert!(parse_resend_request(&[0x80, 0xd4, 0, 0, 0, 0, 0, 1]).is_err());
        assert!(parse_resend_request(&request(1, 0)).is_err());
        assert!(parse_resend_request(&request(1, MAX_RESEND_COUNT + 1)).is_err());
    }

    #[test]
    fn reply_prefixes_original_packet() {
        assert_eq!(
            build_resend_reply(0x1234, &[0x80, 0x60, 0x12, 0x34]),
            [0x80, 0xd6, 0x12, 0x34, 0x80, 0x60, 0x12, 0x34]
        );
    }

    #[test]
    fn history_keeps_only_newest_packets() {
        let history = PacketHistory::new(2);
        history.push(1, vec![1]);
        history.push(2, vec![2]);
        history.push(3, vec![3]);

        assert_eq!(history.get(1), None);
        assert_eq!(history.get(2), Some(vec![2]));
        assert_eq!(history.get(3), Some(vec![3]));
    }

    #[tokio::test]
    async fn responder_resends_held_packets_only() {
        let (socket, port) = bind_udp(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(Ipv4Addr::LOCALHOST))
            .await
            .expect("bind control");
        let history = PacketHistory::new(HISTORY_PACKETS);
        history.push(10, vec![0x80, 0x60, 0x00, 0x0a]);
        let responder =
            ResendResponder::new(Arc::new(socket), IpAddr::V4(Ipv4Addr::LOCALHOST), history);
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        peer.send_to(
            &request(10, 2),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        )
        .await
        .expect("send request");

        assert_eq!(responder.respond_once().await.expect("respond"), 1);
        let mut buffer = [0_u8; 64];
        let (length, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
            .await
            .expect("reply before timeout")
            .expect("receive reply");
        assert_eq!(
            &buffer[..length],
            &[0x80, 0xd6, 0x00, 0x0a, 0x80, 0x60, 0x00, 0x0a]
        );
    }
}
