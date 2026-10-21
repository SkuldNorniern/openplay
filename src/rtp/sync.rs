//! Control-channel sync packets that tie RTP timestamps to NTP wall time.
//!
//! The receiver uses them to place audio on its own clock. One goes out right
//! before the first audio packet, with the RTP extension bit set, and then one
//! about every second, each just before the audio packet it describes.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;

use crate::error::{Error, Result};

use super::timing::NtpTimestamp;

pub const SYNC_PACKET_LEN: usize = 20;
/// 126 packets of 352 frames is about one second at 44.1 kHz.
pub const SYNC_INTERVAL_PACKETS: u32 = 126;

const RTP_VERSION: u8 = 0x80;
const RTP_EXTENSION_BIT: u8 = 0x10;
const SYNC_PACKET_TYPE: u8 = 0xd4;

/// Build one sync packet.
///
/// The RTP timestamp appears twice, matching a working HomePod session:
/// bytes 4..8 and 16..20 both carry the timestamp of the audio packet sent
/// right after this one.
pub fn build_sync_packet(
    sequence: u16,
    first: bool,
    rtp_timestamp: u32,
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
    packet[4..8].copy_from_slice(&rtp_timestamp.to_be_bytes());
    packet[8..16].copy_from_slice(&now.to_bytes());
    packet[16..20].copy_from_slice(&rtp_timestamp.to_be_bytes());
    packet
}

/// Sends sync packets from the control port advertised in SETUP to the
/// receiver's control port.
pub struct SyncSender {
    socket: UdpSocket,
    receiver_addr: SocketAddr,
    sequence: u16,
    /// Flipped only after a successful send, so a failed first sync is
    /// retried with the extension bit still set.
    first_sent: bool,
    packets_until_sync: u32,
}

impl SyncSender {
    /// Bind the control UDP socket to an ephemeral local port.
    ///
    /// The returned port is the `controlPort` and `control_port` the sender
    /// advertises during stream SETUP.
    pub async fn bind(receiver_addr: SocketAddr, bind: Option<Ipv4Addr>) -> Result<(Self, u16)> {
        let local_addr = match receiver_addr {
            SocketAddr::V4(_) => SocketAddr::from((bind.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)),
            SocketAddr::V6(_) => {
                if bind.is_some() {
                    return Err(Error::Protocol("cannot bind IPv4 to an IPv6 target".into()));
                }
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            }
        };

        let socket = UdpSocket::bind(local_addr).await?;
        let local_port = socket.local_addr()?.port();
        let sender = Self {
            socket,
            receiver_addr,
            sequence: 0,
            first_sent: false,
            packets_until_sync: 0,
        };

        Ok((sender, local_port))
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
            NtpTimestamp::now()?,
        );
        let sent = self.socket.send_to(&packet, self.receiver_addr).await?;
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

    use super::*;

    async fn peer_and_sync() -> (UdpSocket, SyncSender) {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        let receiver_addr = peer.local_addr().expect("peer address");
        let (sync, _) = SyncSender::bind(receiver_addr, Some(Ipv4Addr::LOCALHOST))
            .await
            .expect("bind sync");
        (peer, sync)
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

        assert_eq!(build_sync_packet(0, true, 0, now), captured);
    }

    #[test]
    fn later_sync_reproduces_captured_wire_bytes() {
        let captured = [
            0x80, 0xd4, 0x00, 0x02, 0x00, 0x00, 0xae, 0xa0, 0xee, 0x08, 0xca, 0x57, 0xcc, 0xb1,
            0xb8, 0x74, 0x00, 0x00, 0xae, 0xa0,
        ];
        let now = timestamp([0xee, 0x08, 0xca, 0x57, 0xcc, 0xb1, 0xb8, 0x74]);

        assert_eq!(build_sync_packet(2, false, 0xaea0, now), captured);
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
