//! Paced UDP transport for encrypted realtime AirPlay audio.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::random;
use tokio::net::UdpSocket;
use tokio::time::interval;

use crate::audio::{AlacEncoder, AudioSource, Frame};
use crate::error::{Error, Result};

use super::{RtpPacketBuilder, SyncSender};

const FRAMES_PER_PACKET: usize = 352;
const SAMPLE_RATE: f64 = 44_100.0;

/// Sends realtime ALAC audio to an AirPlay receiver over UDP, pulling PCM
/// frames from an [`AudioSource`] at a steady approximately 8 ms cadence.
pub struct RtpSender {
    socket: UdpSocket,
    receiver_addr: SocketAddr,
    source: AudioSource,
    encoder: AlacEncoder,
    packet_builder: RtpPacketBuilder,
    /// Whether a packet has been confirmed sent yet. The RTP marker bit
    /// belongs on the first one — tracked here, not inside
    /// `RtpPacketBuilder`, and only flipped after `send_to` actually
    /// succeeds: if the marked packet's send fails, the next attempt must
    /// still carry the marker, since a failed send never reached the
    /// receiver at all.
    first_packet_sent: bool,
    sync: Option<SyncSender>,
}

impl RtpSender {
    /// Bind the audio UDP socket to an ephemeral local port and prepare it for
    /// sending to `receiver_addr`.
    ///
    /// When `bind` is supplied, the socket is bound to that specific local
    /// IPv4 interface, matching [`crate::info::fetch`]. An IPv4 bind address
    /// cannot be used with an IPv6 receiver.
    ///
    /// The returned port must be included in the session's local stream ports
    /// during SETUP. The caller is responsible for completing that SETUP
    /// before starting [`Self::send_one`] or [`Self::run`], so queued real
    /// audio is not pulled before the receiver is ready.
    pub async fn bind(
        receiver_addr: SocketAddr,
        bind: Option<Ipv4Addr>,
        source: AudioSource,
        audio_key: [u8; 32],
    ) -> Result<(Self, u16)> {
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
            source,
            encoder: AlacEncoder::new(),
            packet_builder: RtpPacketBuilder::new(random(), audio_key),
            first_packet_sent: false,
            sync: None,
        };

        Ok((sender, local_port))
    }

    /// Send control-channel sync packets alongside audio, as the receiver
    /// needs them to place audio on its clock.
    pub fn with_sync(mut self, sync: SyncSender) -> Self {
        self.sync = Some(sync);
        self
    }

    /// Pull, encode, encrypt, and transmit exactly one audio packet.
    ///
    /// Returns the actual number of PCM frames represented by the packet.
    #[allow(clippy::infallible_destructuring_match)]
    pub async fn send_one(&mut self) -> Result<usize> {
        // Keep this as a match so another Frame variant cannot be routed into
        // the ALAC encoder accidentally when the audio source grows.
        let samples = match self.source.next_or_silence(FRAMES_PER_PACKET) {
            Frame::Pcm(samples) => samples,
        };
        let alac_packet = self.encoder.encode_packet(&samples)?;
        let frame_count = alac_packet.frame_count;
        let marker = !self.first_packet_sent;
        if let Some(sync) = &mut self.sync {
            sync.before_audio_packet(self.packet_builder.next_timestamp())
                .await?;
        }
        let packet =
            self.packet_builder
                .build_packet(&alac_packet.data, frame_count as u32, marker)?;
        let sent = self.socket.send_to(&packet, self.receiver_addr).await?;
        if sent != packet.len() {
            return Err(Error::Protocol(format!(
                "rtp: sent {sent} of {} UDP packet bytes",
                packet.len()
            )));
        }
        self.first_packet_sent = true;

        Ok(frame_count)
    }

    /// Send packets forever at the cadence of 352 frames at 44.1 kHz.
    ///
    /// The first packet is sent on Tokio interval's immediate first tick.
    /// The loop returns as soon as sending fails. To stop it normally, callers
    /// can spawn this future and abort its Tokio task.
    pub async fn run(&mut self) -> Result<()> {
        let packet_interval = Duration::from_secs_f64(FRAMES_PER_PACKET as f64 / SAMPLE_RATE);
        let mut ticker = interval(packet_interval);
        loop {
            ticker.tick().await;
            // Keep Tokio's default Burst behavior: missed ticks catch up to
            // the original schedule instead of accumulating timing drift.
            self.send_one().await?;
        }
    }
}

impl fmt::Debug for RtpSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RtpSender(..)")
    }
}

#[cfg(test)]
mod tests {
    use tokio::spawn;
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::audio::WriteOutcome;

    const KEY: [u8; 32] = [0x42; 32];

    async fn peer_and_sender(source: AudioSource) -> (UdpSocket, RtpSender, u16) {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        let receiver_addr = peer.local_addr().expect("peer address");
        let (sender, local_port) =
            RtpSender::bind(receiver_addr, Some(Ipv4Addr::LOCALHOST), source, KEY)
                .await
                .expect("bind sender");
        (peer, sender, local_port)
    }

    async fn receive_packet(peer: &UdpSocket) -> Vec<u8> {
        let mut buffer = vec![0; 65_535];
        let (length, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
            .await
            .expect("receive before timeout")
            .expect("receive packet");
        buffer.truncate(length);
        buffer
    }

    fn sequence(packet: &[u8]) -> u16 {
        u16::from_be_bytes(packet[2..4].try_into().expect("sequence bytes"))
    }

    #[tokio::test]
    async fn bind_returns_the_bound_ephemeral_port() {
        let (_peer, sender, local_port) = peer_and_sender(AudioSource::new(1)).await;

        assert_ne!(local_port, 0);
        assert_eq!(
            local_port,
            sender.socket.local_addr().expect("sender address").port()
        );
    }

    #[tokio::test]
    async fn send_one_emits_an_encrypted_rtp_datagram() {
        let (peer, mut sender, _) = peer_and_sender(AudioSource::new(1)).await;

        assert_eq!(
            sender.send_one().await.expect("send silence packet"),
            FRAMES_PER_PACKET
        );
        let packet = receive_packet(&peer).await;

        assert_eq!(packet[0], 0x80);
        assert!(packet.len() > 12);
    }

    #[tokio::test]
    async fn consecutive_sends_advance_the_rtp_sequence() {
        let (peer, mut sender, _) = peer_and_sender(AudioSource::new(1)).await;

        let mut packets = Vec::new();
        for _ in 0..3 {
            sender.send_one().await.expect("send packet");
            packets.push(receive_packet(&peer).await);
        }

        let sequences: Vec<_> = packets.iter().map(|packet| sequence(packet)).collect();
        assert_eq!(sequences, [0, 1, 2]);
    }

    #[tokio::test]
    async fn marker_bit_moves_to_the_first_successfully_sent_packet_only() {
        // The marker belongs on the first packet the receiver actually gets,
        // not the first one merely built -- send_one only commits
        // first_packet_sent after a confirmed successful send, so a build
        // whose send failed would leave the marker available for the retry
        // that does reach the receiver. A real forced network-level send
        // failure isn't reliably triggerable over loopback UDP in a test
        // (EMSGSIZE can't be reached through legitimate ALAC-sized payloads,
        // and there's no mockable socket layer here by design, matching how
        // EventChannel is tested against real sockets only) -- this test
        // instead confirms the policy's observable outcome on the wire across
        // ordinary successful sends.
        let (peer, mut sender, _) = peer_and_sender(AudioSource::new(1)).await;

        let mut marker_bytes = Vec::new();
        for _ in 0..3 {
            sender.send_one().await.expect("send packet");
            let packet = receive_packet(&peer).await;
            marker_bytes.push(packet[1]);
        }

        assert_eq!(marker_bytes, [0xe0, 0x60, 0x60]);
    }

    #[tokio::test]
    async fn send_one_syncs_first_packet_on_control_port() {
        let (peer, sender, _) = peer_and_sender(AudioSource::new(1)).await;
        let control_peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind control peer");
        let (sync, _) = SyncSender::bind(
            control_peer.local_addr().expect("control address"),
            Some(Ipv4Addr::LOCALHOST),
        )
        .await
        .expect("bind sync");
        let mut sender = sender.with_sync(sync);

        sender.send_one().await.expect("send packet");
        sender.send_one().await.expect("send packet");
        let sync_packet = receive_packet(&control_peer).await;
        let _audio = receive_packet(&peer).await;
        let second_audio = receive_packet(&peer).await;

        assert_eq!(&sync_packet[..8], &[0x90, 0xd4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sequence(&second_audio), 1);
        let mut buffer = [0_u8; 64];
        assert!(
            timeout(
                Duration::from_millis(20),
                control_peer.recv_from(&mut buffer)
            )
            .await
            .is_err(),
            "only one sync is due in first interval"
        );
    }

    #[tokio::test]
    async fn send_one_consumes_a_queued_partial_pcm_frame() {
        let source = AudioSource::new(1);
        assert_eq!(source.write(Frame::Pcm(vec![7; 50 * 2])), WriteOutcome::Ok);
        let (peer, mut sender, _) = peer_and_sender(source).await;

        assert_eq!(sender.send_one().await.expect("send real PCM packet"), 50);
        let _packet = receive_packet(&peer).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_paces_multiple_packets_with_increasing_sequences() {
        let (peer, mut sender, _) = peer_and_sender(AudioSource::new(1)).await;
        let task = spawn(async move { sender.run().await });

        sleep(Duration::from_millis(60)).await;
        task.abort();
        let _cancelled = task.await;

        let mut sequences = Vec::new();
        let mut buffer = vec![0; 65_535];
        while let Ok(result) = timeout(Duration::from_millis(5), peer.recv_from(&mut buffer)).await
        {
            let (length, _) = result.expect("receive paced packet");
            sequences.push(sequence(&buffer[..length]));
        }

        assert!(
            sequences.len() >= 3,
            "expected several paced packets, received {}",
            sequences.len()
        );
        assert!(
            sequences
                .windows(2)
                .all(|pair| pair[1] == pair[0].wrapping_add(1))
        );
    }
}
