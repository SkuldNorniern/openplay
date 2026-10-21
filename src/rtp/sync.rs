//! Control-channel sync packets that tie RTP timestamps to NTP wall time.
//!
//! The receiver uses them to place audio on its own clock. One goes out right
//! before the first audio packet, with the RTP extension bit set, and then one
//! about every second, each just before the audio packet it describes.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use log::debug;
use tokio::net::UdpSocket;

use crate::error::{Error, Result};

use super::is_transient;
use super::timing::NtpTimestamp;

pub const SYNC_PACKET_LEN: usize = 20;
/// 126 packets of 352 frames is about one second at 44.1 kHz.
pub const SYNC_INTERVAL_PACKETS: u32 = 126;

const RTP_VERSION: u8 = 0x80;
const RTP_EXTENSION_BIT: u8 = 0x10;
const SYNC_PACKET_TYPE: u8 = 0xd4;

/// Build one sync packet.
///
/// Bytes 16..20 carry the timestamp of the audio packet sent right after
/// this one, and bytes 4..8 the timestamp playing now: that one less
/// `latency_frames`. The receiver reads the gap as how far ahead audio is
/// sent. The working HomePod capture used no gap, leaving the receiver to
/// pick its own latency.
pub fn build_sync_packet(
    sequence: u16,
    first: bool,
    rtp_timestamp: u32,
    latency_frames: u32,
    now: NtpTimestamp,
) -> [u8; SYNC_PACKET_LEN] {
    let mut packet = [0_u8; SYNC_PACKET_LEN];
    packet[0] = if first {
        RTP_VERSION | RTP_EXTENSION_BIT
    } else {
        RTP_VERSION
    };
    packet[1] = SYNC_PACKET_TYPE;
    packet[2..4].copy_from_slice(&sequence.to_be_bytes());
    packet[4..8].copy_from_slice(&rtp_timestamp.wrapping_sub(latency_frames).to_be_bytes());
    packet[8..16].copy_from_slice(&now.to_bytes());
    packet[16..20].copy_from_slice(&rtp_timestamp.to_be_bytes());
    packet
}

/// Sends sync packets from the control port advertised in SETUP to the
/// receiver's control port.
pub struct SyncSender {
    socket: Arc<UdpSocket>,
    receiver_addr: SocketAddr,
    sequence: u16,
    /// Flipped only after a successful send, so a failed first sync is
    /// retried with the extension bit still set.
    first_sent: bool,
    packets_until_sync: u32,
    latency_frames: u32,
}

impl SyncSender {
    /// Use a control socket already bound with [`super::bind_udp`], shared
    /// with the resend responder that reads from it.
    ///
    /// The socket's port is the `controlPort` and `control_port` advertised
    /// during stream SETUP, and `receiver_addr` is the receiver's
    /// `controlPort` from the response.
    pub fn new(socket: Arc<UdpSocket>, receiver_addr: SocketAddr) -> Self {
        Self {
            socket,
            receiver_addr,
            sequence: 0,
            first_sent: false,
            packets_until_sync: 0,
            latency_frames: 0,
        }
    }

    /// Announce a playout latency in each sync packet.
    pub fn with_latency(mut self, latency_frames: u32) -> Self {
        self.latency_frames = latency_frames;
        self
    }

    /// Call right before each audio packet with that packet's RTP timestamp.
    ///
    /// Sends a sync packet when one is due and returns whether it did.
    pub async fn before_audio_packet(&mut self, rtp_timestamp: u32) -> Result<bool> {
        if self.packets_until_sync > 0 {
            self.packets_until_sync -= 1;
            return Ok(false);
        }

        let packet = build_sync_packet(
            self.sequence,
            !self.first_sent,
            rtp_timestamp,
            self.latency_frames,
            NtpTimestamp::now()?,
        );
        let sent = match self.socket.send_to(&packet, self.receiver_addr).await {
            Ok(sent) => sent,
            // Try again before the next audio packet; nothing advances.
            Err(error) if is_transient(&error) => {
                debug!("sync: send failed, retrying: {error}");
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if sent != packet.len() {
            return Err(Error::Protocol(format!(
                "sync: sent {sent} of {} UDP packet bytes",
                packet.len()
            )));
        }
        self.sequence = self.sequence.wrapping_add(1);
        self.first_sent = true;
        self.packets_until_sync = SYNC_INTERVAL_PACKETS - 1;

        Ok(true)
    }
}

impl fmt::Debug for SyncSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SyncSender(..)")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::rtp::bind_udp;

    async fn peer_and_sync() -> (UdpSocket, SyncSender) {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        let receiver_addr = peer.local_addr().expect("peer address");
        let (socket, _) = bind_udp(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(Ipv4Addr::LOCALHOST))
            .await
            .expect("bind control socket");
        (peer, SyncSender::new(Arc::new(socket), receiver_addr))
    }

    async fn receive_sync(peer: &UdpSocket) -> Vec<u8> {
        let mut buffer = [0_u8; 64];
        let (length, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
            .await
            .expect("receive before timeout")
            .expect("receive sync");
        buffer[..length].to_vec()
    }

    fn timestamp(bytes: [u8; 8]) -> NtpTimestamp {
        NtpTimestamp::from_bytes(bytes)
    }

    #[test]
    fn first_sync_reproduces_captured_wire_bytes() {
        let captured = [
            0x90, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee, 0x08, 0xca, 0x56, 0xdd, 0x7f,
            0x62, 0xb6, 0x00, 0x00, 0x00, 0x00,
        ];
        let now = timestamp([0xee, 0x08, 0xca, 0x56, 0xdd, 0x7f, 0x62, 0xb6]);

        assert_eq!(build_sync_packet(0, true, 0, 0, now), captured);
    }

    #[test]
    fn later_sync_reproduces_captured_wire_bytes() {
        let captured = [
            0x80, 0xd4, 0x00, 0x02, 0x00, 0x00, 0xae, 0xa0, 0xee, 0x08, 0xca, 0x57, 0xcc, 0xb1,
            0xb8, 0x74, 0x00, 0x00, 0xae, 0xa0,
        ];
        let now = timestamp([0xee, 0x08, 0xca, 0x57, 0xcc, 0xb1, 0xb8, 0x74]);

        assert_eq!(build_sync_packet(2, false, 0xaea0, 0, now), captured);
    }

    #[test]
    fn latency_moves_playing_timestamp_back() {
        let packet = build_sync_packet(1, false, 1_000, 4_410, NtpTimestamp::from_bytes([0; 8]));
        assert_eq!(
            &packet[4..8],
            &(1_000_u32.wrapping_sub(4_410)).to_be_bytes()
        );
        assert_eq!(&packet[16..20], &1_000_u32.to_be_bytes());
    }

    #[tokio::test]
    async fn first_audio_packet_gets_extension_sync() {
        let (peer, mut sync) = peer_and_sync().await;

        assert!(sync.before_audio_packet(0).await.expect("first sync"));
        let packet = receive_sync(&peer).await;

        assert_eq!(packet.len(), SYNC_PACKET_LEN);
        assert_eq!(&packet[..4], &[0x90, 0xd4, 0x00, 0x00]);
    }

    #[tokio::test]
    async fn sync_repeats_every_interval_with_next_sequence() {
        let (peer, mut sync) = peer_and_sync().await;

        let mut sent_at = Vec::new();
        for index in 0..=SYNC_INTERVAL_PACKETS * 2 {
            if sync
                .before_audio_packet(index * 352)
                .await
                .expect("maybe sync")
            {
                sent_at.push(index);
            }
        }
        assert_eq!(
            sent_at,
            [0, SYNC_INTERVAL_PACKETS, SYNC_INTERVAL_PACKETS * 2]
        );

        let _first = receive_sync(&peer).await;
        let second = receive_sync(&peer).await;
        let expected_timestamp = (SYNC_INTERVAL_PACKETS * 352).to_be_bytes();
        assert_eq!(&second[..4], &[0x80, 0xd4, 0x00, 0x01]);
        assert_eq!(&second[4..8], &expected_timestamp);
        assert_eq!(&second[16..20], &expected_timestamp);
    }
}
