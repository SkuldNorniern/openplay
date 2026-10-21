//! 24-bit stereo ALAC as uncompressed ("escape") packets.
//!
//! Buffered AirPlay streams accept 24-bit ALAC but not the 16-bit flavour
//! realtime uses, and the `alac-encoder` crate only produces 16-bit. ALAC's
//! escape packets store samples verbatim, so they need no predictor: about
//! 2.1 Mbit/s for 44.1 kHz stereo, which buffered audio's TCP link carries
//! easily on a LAN.
//!
//! Packet layout, MSB first: element tag `CPE` (3 bits), instance 0 (4),
//! 12 unused bits, then partial-frame flag, two bytes-shifted bits and the
//! escape flag (4), a 32-bit frame count if partial, each frame's left and
//! right samples (24 bits each), the `END` tag (3 bits), and zero padding to
//! a byte boundary.

use crate::error::{Error, Result};

pub const FRAMES_PER_PACKET: usize = 352;
const ELEMENT_CPE: u32 = 1;
const ELEMENT_END: u32 = 7;
const ESCAPE_FLAG: u32 = 1;
const PARTIAL_FLAG: u32 = 1 << 3;
const SAMPLE_BITS: u32 = 24;
const SAMPLE_MASK: u32 = (1 << SAMPLE_BITS) - 1;

/// Encode up to 352 stereo frames of 24-bit samples (held in `i32`, range
/// −2^23..2^23) into one ALAC packet.
pub fn encode_packet(frames: &[[i32; 2]]) -> Result<Vec<u8>> {
    if frames.len() > FRAMES_PER_PACKET {
        return Err(Error::Protocol(format!(
            "alac24: packet has {} frames, maximum is {FRAMES_PER_PACKET}",
            frames.len()
        )));
    }
    let partial = frames.len() < FRAMES_PER_PACKET;

    let mut bits = BitWriter::with_capacity(8 + frames.len() * 6);
    bits.write(ELEMENT_CPE, 3);
    bits.write(0, 4);
    bits.write(0, 12);
    bits.write(if partial { PARTIAL_FLAG } else { 0 } | ESCAPE_FLAG, 4);
    if partial {
        bits.write(frames.len() as u32, 32);
    }
    for [left, right] in frames {
        bits.write(*left as u32 & SAMPLE_MASK, SAMPLE_BITS);
        bits.write(*right as u32 & SAMPLE_MASK, SAMPLE_BITS);
    }
    bits.write(ELEMENT_END, 3);
    Ok(bits.finish())
}

struct BitWriter {
    bytes: Vec<u8>,
    /// Bits used in the last byte, 0 when it is full or absent.
    used: u32,
}

impl BitWriter {
    fn with_capacity(bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes),
            used: 0,
        }
    }

    /// Append the low `count` bits of `value`, most significant first.
    fn write(&mut self, value: u32, count: u32) {
        for shift in (0..count).rev() {
            if self.used == 0 {
                self.bytes.push(0);
            }
            let bit = ((value >> shift) & 1) as u8;
            if let Some(last) = self.bytes.last_mut() {
                *last |= bit << (7 - self.used);
            }
            self.used = (self.used + 1) % 8;
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read back what `encode_packet` wrote, as a decoder would.
    fn decode(packet: &[u8]) -> Vec<[i32; 2]> {
        let mut position = 0_usize;
        let mut read = |count: usize| -> u32 {
            let mut value = 0_u32;
            for _ in 0..count {
                let bit = (packet[position / 8] >> (7 - position % 8)) & 1;
                value = (value << 1) | u32::from(bit);
                position += 1;
            }
            value
        };
        assert_eq!(read(3), ELEMENT_CPE);
        assert_eq!(read(4), 0);
        assert_eq!(read(12), 0);
        let flags = read(4);
        assert_eq!(flags & ESCAPE_FLAG, ESCAPE_FLAG);
        let frames = if flags & PARTIAL_FLAG != 0 {
            read(32) as usize
        } else {
            FRAMES_PER_PACKET
        };
        let sign_extend = |value: u32| ((value << 8) as i32) >> 8;
        let samples = (0..frames)
            .map(|_| [sign_extend(read(24)), sign_extend(read(24))])
            .collect();
        assert_eq!(read(3), ELEMENT_END);
        samples
    }

    #[test]
    fn single_frame_has_exact_bytes() {
        let packet = encode_packet(&[[1, -1]]).expect("encode");
        // 001 0000 000000000000 1001, frame count 1, 0x000001, 0xffffff, 111.
        assert_eq!(
            packet,
            [
                0x20, 0x00, 0x12, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03, 0xff, 0xff, 0xff, 0xc0
            ]
        );
    }

    #[test]
    fn full_packet_round_trips_extremes() {
        let frames: Vec<[i32; 2]> = (0..FRAMES_PER_PACKET as i32)
            .map(|index| match index % 3 {
                0 => [8_388_607, -8_388_608],
                1 => [0, -1],
                _ => [index * 1_000, -index * 1_000],
            })
            .collect();
        let packet = encode_packet(&frames).expect("encode");

        // Header 23 bits, samples 352 × 48, END 3 bits, padded.
        assert_eq!(packet.len(), (23 + 352 * 48 + 3_usize).div_ceil(8));
        assert_eq!(decode(&packet), frames);
    }

    #[test]
    fn partial_packet_records_frame_count() {
        let frames = vec![[123_456, -654_321]; 100];
        assert_eq!(decode(&encode_packet(&frames).expect("encode")), frames);
    }

    #[test]
    fn rejects_oversized_packet() {
        assert!(encode_packet(&vec![[0, 0]; FRAMES_PER_PACKET + 1]).is_err());
    }
}
