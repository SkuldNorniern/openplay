//! Buffered audio over TCP: audio sent ahead of its play time.
//!
//! Each packet is the same encrypted RTP packet realtime audio uses, here
//! carrying 24-bit ALAC, framed on the stream by a 2-byte big-endian length
//! that counts itself. The receiver buffers what arrives and plays it on
//! the PTP timeline set by SETRATEANCHORTIME, so the sender only has to stay
//! a steady lead ahead.

use std::fmt;
use std::time::Duration;

use rand::random;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, sleep_until};

use crate::audio::{AudioSource, alac24};
use crate::error::{Error, Result};

use super::RtpPacketBuilder;

const SAMPLE_RATE: u64 = 44_100;
const LENGTH_PREFIX: usize = 2;
const NANOS_PER_SECOND: u128 = 1_000_000_000;
/// 16-bit samples move to the top of the 24-bit range.
const I16_TO_I24_SHIFT: u32 = 8;

/// Prefix a packet with its framed length.
pub fn frame_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let total = u16::try_from(packet.len() + LENGTH_PREFIX)
        .map_err(|_| Error::Protocol(format!("buffered: {} byte packet too long", packet.len())))?;
    let mut framed = Vec::with_capacity(packet.len() + LENGTH_PREFIX);
    framed.extend_from_slice(&total.to_be_bytes());
    framed.extend_from_slice(packet);
    Ok(framed)
}

/// Sends audio from an [`AudioSource`] over the buffered data connection.
pub struct BufferedSender<W> {
    stream: W,
    source: AudioSource,
    packet_builder: RtpPacketBuilder,
    first_packet_sent: bool,
    frames_sent: u64,
}

impl<W: AsyncWrite + Unpin> BufferedSender<W> {
    /// `stream` is connected to the receiver's buffered `dataPort`.
    pub fn new(stream: W, source: AudioSource, audio_key: [u8; 32]) -> Self {
        Self {
            stream,
            source,
            packet_builder: RtpPacketBuilder::new(random(), audio_key),
            first_packet_sent: false,
            frames_sent: 0,
        }
    }

    /// RTP timestamp of the next packet, for anchoring playback.
    pub fn next_rtp_time(&self) -> u32 {
        self.packet_builder.next_timestamp()
    }

    /// Encode and send one full packet.
    pub async fn send_one(&mut self) -> Result<()> {
        let samples = self.source.read(alac24::FRAMES_PER_PACKET);
        let frames: Vec<[i32; 2]> = samples
            .chunks_exact(2)
            .map(|frame| {
                [
                    i32::from(frame[0]) << I16_TO_I24_SHIFT,
                    i32::from(frame[1]) << I16_TO_I24_SHIFT,
                ]
            })
            .collect();
        let payload = alac24::encode_packet(&frames)?;
        let marker = !self.first_packet_sent;
        let packet =
            self.packet_builder
                .build_packet(&payload, alac24::FRAMES_PER_PACKET as u32, marker)?;
        self.stream.write_all(&frame_packet(&packet)?).await?;
        self.first_packet_sent = true;
        self.frames_sent += alac24::FRAMES_PER_PACKET as u64;
        Ok(())
    }

    /// Send continuously, keeping `lead` of audio ahead of the playback
    /// position, which starts at `start`.
    pub async fn run(&mut self, start: Instant, lead: Duration) -> Result<()> {
        let lead_frames = frames_in(lead);
        loop {
            let played = frames_in(start.elapsed());
            if u128::from(self.frames_sent) < played + lead_frames {
                self.send_one().await?;
                continue;
            }
            self.stream.flush().await?;
            // Sleep until playback has advanced enough to allow one more packet.
            let resume_at = (u128::from(self.frames_sent) + 1).saturating_sub(lead_frames);
            sleep_until(start + duration_of(resume_at)).await;
        }
    }
}

fn frames_in(duration: Duration) -> u128 {
    duration.as_nanos() * u128::from(SAMPLE_RATE) / NANOS_PER_SECOND
}

fn duration_of(frames: u128) -> Duration {
    let nanos = frames * NANOS_PER_SECOND / u128::from(SAMPLE_RATE);
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

impl<W> fmt::Debug for BufferedSender<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BufferedSender({} frames sent)",
            self.frames_sent
        )
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, duplex};
    use tokio::spawn;
    use tokio::time::{sleep, timeout};

    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn frame_length_counts_its_own_prefix() {
        assert_eq!(
            frame_packet(&[0xaa, 0xbb]).expect("frame"),
            [0, 4, 0xaa, 0xbb]
        );
        assert!(frame_packet(&vec![0; 65_534]).is_err());
    }

    #[tokio::test]
    async fn sends_framed_marked_rtp_packets() {
        let (writer, mut reader) = duplex(1 << 20);
        let source = AudioSource::new(1_000);
        source.write(&[1_000, -1_000]);
        let mut sender = BufferedSender::new(writer, source, KEY);

        sender.send_one().await.expect("first");
        sender.send_one().await.expect("second");
        assert_eq!(sender.next_rtp_time(), 704);

        let mut headers = Vec::new();
        for _ in 0..2 {
            let mut length = [0_u8; 2];
            reader.read_exact(&mut length).await.expect("length");
            let mut packet = vec![0_u8; usize::from(u16::from_be_bytes(length)) - 2];
            reader.read_exact(&mut packet).await.expect("packet");
            headers.push((packet[1], u16::from_be_bytes([packet[2], packet[3]])));
        }
        assert_eq!(headers, [(0xe0, 0), (0x60, 1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn run_keeps_lead_ahead_of_playback() {
        let (writer, mut reader) = duplex(1 << 24);
        let mut sender = BufferedSender::new(writer, AudioSource::new(1), KEY);
        let start = Instant::now();
        let task = spawn(async move {
            let _ = sender.run(start, Duration::from_secs(1)).await;
        });

        // With time paused, sleeping advances the clock instantly.
        sleep(Duration::from_secs(2)).await;
        task.abort();
        let mut bytes = Vec::new();
        let _ = timeout(Duration::from_millis(10), reader.read_to_end(&mut bytes)).await;

        let mut packets = 0;
        let mut position = 0;
        while position + 2 <= bytes.len() {
            position += usize::from(u16::from_be_bytes([bytes[position], bytes[position + 1]]));
            packets += 1;
        }
        // Three seconds of audio (2 played + 1 lead) is about 376 packets.
        assert!((370..=380).contains(&packets), "{packets} packets");
    }
}
