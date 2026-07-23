//! Stateful ALAC packet encoding for the crate's fixed audio format.

use alac_encoder::{AlacEncoder as InnerEncoder, FormatDescription};

use super::wav::PcmSamples;
use crate::error::{Error, Result};

const SAMPLE_RATE: f64 = 44_100.0;
const CHANNELS: u32 = 2;
const FRAMES_PER_PACKET: usize = 352;
const SAMPLES_PER_PACKET: usize = FRAMES_PER_PACKET * CHANNELS as usize;

/// One encoded ALAC packet and the number of audio frames it covers.
///
/// Callers use the frame count to advance the RTP timestamp.
pub struct AlacPacket {
    pub data: Vec<u8>,
    pub frame_count: usize,
}

/// Encodes interleaved 16-bit PCM into ALAC packets of up to 352 frames each.
///
/// Reuse one encoder across an entire stream: its prediction state is retained
/// between packets, improving compression.
///
/// Two soundness caveats live in the underlying `alac_encoder` crate itself,
/// not in this wrapper, and cannot be fixed from calling code:
/// - Its 16-bit encode path reinterprets a `Vec<u8>`-backed byte buffer as
///   `&[i16]` via a raw pointer cast (`from_raw_parts`), which formally
///   requires 2-byte alignment that a byte-vector allocation does not
///   guarantee. In practice this holds on every mainstream allocator (they
///   over-align small/medium allocations), but it is undefined behavior per
///   the Rust abstract machine regardless.
/// - Its bit writer performs unaligned 4-byte reads/writes at `position >> 3`
///   without reserving slack for the last write, so encoding a full,
///   poorly-compressible packet can write a few bytes past the logical
///   packet length. `OUTPUT_SLACK` below exists specifically to give that
///   overwrite real backing memory so it cannot corrupt unrelated heap data;
///   `written` (the crate's own reported length) is still used to trim the
///   returned packet, so the extra bytes never leak into `AlacPacket::data`.
pub struct AlacEncoder {
    encoder: InnerEncoder,
    input_format: FormatDescription,
    output_format: FormatDescription,
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
}

/// Extra bytes allocated beyond `max_packet_size()` to absorb the dependency's
/// unaligned 4-byte bit-writer overrun (observed up to 2 bytes; this leaves
/// comfortable margin without being a meaningful cost per packet).
const OUTPUT_SLACK: usize = 8;

impl AlacEncoder {
    pub fn new() -> Self {
        let input_format = FormatDescription::pcm::<i16>(SAMPLE_RATE, CHANNELS);
        let output_format =
            FormatDescription::alac(SAMPLE_RATE, FRAMES_PER_PACKET as u32, CHANNELS);
        let encoder = InnerEncoder::new(&output_format);
        let output_buffer = vec![0; output_format.max_packet_size() + OUTPUT_SLACK];
        Self {
            encoder,
            input_format,
            output_format,
            input_buffer: Vec::with_capacity(SAMPLES_PER_PACKET * size_of::<i16>()),
            output_buffer,
        }
    }

    /// Encode at most 352 stereo frames into one ALAC packet.
    ///
    /// A shorter final chunk is valid and is encoded without silence padding.
    pub fn encode_packet(&mut self, interleaved: &[i16]) -> Result<AlacPacket> {
        if interleaved.len() > SAMPLES_PER_PACKET {
            return Err(Error::Protocol(format!(
                "alac: packet has {} samples, maximum is {SAMPLES_PER_PACKET}",
                interleaved.len()
            )));
        }
        if !interleaved.len().is_multiple_of(CHANNELS as usize) {
            return Err(Error::Protocol(
                "alac: interleaved input does not contain whole stereo frames".into(),
            ));
        }

        self.input_buffer.clear();
        // Native, not little, endian: the underlying encoder reinterprets
        // this buffer as `&[i16]` via a raw pointer cast rather than parsing
        // each sample's byte order, so it expects whatever layout the
        // platform's native i16 representation has.
        for sample in interleaved {
            self.input_buffer.extend_from_slice(&sample.to_ne_bytes());
        }

        debug_assert_eq!(
            self.output_buffer.len(),
            self.output_format.max_packet_size() + OUTPUT_SLACK
        );
        let written = self.encoder.encode(
            &self.input_format,
            &self.input_buffer,
            &mut self.output_buffer,
        );
        Ok(AlacPacket {
            data: self.output_buffer[..written].to_vec(),
            frame_count: interleaved.len() / CHANNELS as usize,
        })
    }
}

impl Default for AlacEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a complete in-memory PCM buffer using one stateful encoder.
pub fn encode_all(samples: &PcmSamples) -> Result<Vec<AlacPacket>> {
    let mut encoder = AlacEncoder::new();
    samples
        .interleaved
        .chunks(SAMPLES_PER_PACKET)
        .map(|chunk| encoder.encode_packet(chunk))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::wav::parse_wav;

    const TONE: &[u8] = include_bytes!("../../tests/fixtures/tone.wav");

    #[test]
    fn encodes_fixture_with_partial_tail() {
        let pcm = parse_wav(TONE).expect("parse fixture");
        let packets = encode_all(&pcm).expect("encode fixture");
        let counts: Vec<_> = packets.iter().map(|packet| packet.frame_count).collect();
        assert_eq!(counts, [352, 352, 352, 100]);
        assert_eq!(counts.iter().sum::<usize>(), 1156);
        assert!(packets.iter().all(|packet| !packet.data.is_empty()));
        assert!(
            packets
                .iter()
                .all(|packet| packet.data.len() < packet.frame_count * 4)
        );
    }

    #[test]
    fn reuses_encoder_for_consecutive_packets() {
        let mut encoder = AlacEncoder::new();
        let samples = vec![0; SAMPLES_PER_PACKET];
        assert!(encoder.encode_packet(&samples).is_ok());
        assert!(encoder.encode_packet(&samples).is_ok());
    }

    #[test]
    fn rejects_oversized_packet() {
        let mut encoder = AlacEncoder::new();
        let samples = vec![0; SAMPLES_PER_PACKET + 2];
        assert!(encoder.encode_packet(&samples).is_err());
    }

    #[test]
    fn encodes_exact_packet_boundary() {
        let mut encoder = AlacEncoder::new();
        let packet = encoder
            .encode_packet(&vec![0; SAMPLES_PER_PACKET])
            .expect("encode full packet");
        assert_eq!(packet.frame_count, FRAMES_PER_PACKET);
        assert!(!packet.data.is_empty());
    }

    #[test]
    fn encodes_high_entropy_full_packet() {
        let mut state = 0x9e37_79b9u32;
        let samples: Vec<i16> = (0..SAMPLES_PER_PACKET)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as i16
            })
            .collect();

        let packet = AlacEncoder::new()
            .encode_packet(&samples)
            .expect("encode high-entropy full packet");
        assert_eq!(packet.frame_count, FRAMES_PER_PACKET);
        assert!(!packet.data.is_empty());
    }
}
