//! Encrypted realtime-audio RTP packet construction.

use std::fmt;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};

use crate::{
    crypto::nonce::NonceCounter,
    error::{Error, Result},
};

const RTP_HEADER_LEN: usize = 12;
const RTP_VERSION: u8 = 0x80;
const RTP_PAYLOAD_TYPE: u8 = 0x60;
const RTP_MARKER_BIT: u8 = 0x80;
const TRANSMITTED_NONCE_LEN: usize = 8;

/// Builds encrypted realtime-audio RTP packets from ALAC payload bytes.
///
/// Owns the sequence/timestamp counters and the audio-channel nonce sequence
/// for one session; construct once and reuse for every packet sent, the same
/// way `audio::alac::AlacEncoder` must be reused across a stream.
pub struct RtpPacketBuilder {
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    cipher: ChaCha20Poly1305,
    nonces: NonceCounter,
}

impl RtpPacketBuilder {
    /// Begin a new session with a fixed SSRC. Sequence and timestamp start at 0.
    ///
    /// `audio_key` is the 32-byte AirPlay audio stream secret (the same value
    /// already sent to the receiver as `ekey`/`shk` during SETUP).
    pub fn new(ssrc: u32, audio_key: [u8; 32]) -> Self {
        Self {
            sequence: 0,
            timestamp: 0,
            ssrc,
            cipher: ChaCha20Poly1305::new(&Key::from(audio_key)),
            nonces: NonceCounter::new(),
        }
    }

    /// Build one RTP packet carrying an ALAC payload and advance session state.
    ///
    /// `frame_count` is the actual number of audio frames represented by the
    /// payload. RTP counters intentionally wrap, while the cryptographic nonce
    /// sequence never wraps: reusing an audio `(key, nonce)` pair would break
    /// both confidentiality and authentication.
    ///
    /// `marker` sets the RTP marker bit — the receiver's signal that a new
    /// stream segment is starting (e.g. reset its jitter buffer), meant for
    /// exactly the first packet sent after `RECORD` (or a future `FLUSH`).
    /// This is a caller-supplied flag rather than internal state here on
    /// purpose: only the caller (which owns the socket) knows whether a given
    /// packet was ever actually transmitted. Deciding "first packet" inside
    /// this builder would consume the marker at construction time even if the
    /// send that packet depended on later failed, permanently losing the
    /// segment-start signal on a retry — sequence/timestamp gaps from a failed
    /// send are normal, recoverable RTP loss, but the marker is a one-shot
    /// signal that can't be inferred from a later gap.
    ///
    /// RTP travels over lossy, unordered UDP, so each packet transmits the
    /// eight-byte counter tail needed to reconstruct its AEAD nonce. Timestamp
    /// and SSRC remain visible for routing but are authenticated as AAD.
    pub fn build_packet(&mut self, payload: &[u8], frame_count: u32, marker: bool) -> Result<Vec<u8>> {
        let mut header = [0_u8; RTP_HEADER_LEN];
        header[0] = RTP_VERSION;
        header[1] = if marker {
            RTP_MARKER_BIT | RTP_PAYLOAD_TYPE
        } else {
            RTP_PAYLOAD_TYPE
        };
        header[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        header[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        header[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        let nonce_bytes = self.nonces.next()?;
        let nonce = Nonce::from(nonce_bytes);
        let encrypted = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: payload,
                    aad: &header[4..12],
                },
            )
            .map_err(|_| Error::Crypto("aead: RTP audio encryption failed".to_owned()))?;

        let mut packet =
            Vec::with_capacity(RTP_HEADER_LEN + encrypted.len() + TRANSMITTED_NONCE_LEN);
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&encrypted);
        packet.extend_from_slice(&nonce_bytes[4..12]);

        self.sequence = self.sequence.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(frame_count);

        Ok(packet)
    }
}

impl fmt::Debug for RtpPacketBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RtpPacketBuilder(..)")
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::{Aead, Result as AeadResult};

    use super::*;

    const KEY: [u8; 32] = [0x42; 32];
    const SSRC: u32 = 0x1234_abcd;

    fn decrypt_payload(packet: &[u8], key: [u8; 32]) -> AeadResult<Vec<u8>> {
        let encrypted_end = packet.len() - TRANSMITTED_NONCE_LEN;
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes[4..].copy_from_slice(&packet[encrypted_end..]);
        let cipher = ChaCha20Poly1305::new(&Key::from(key));

        cipher.decrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: &packet[RTP_HEADER_LEN..encrypted_end],
                aad: &packet[4..12],
            },
        )
    }

    fn sequence(packet: &[u8]) -> u16 {
        u16::from_be_bytes(packet[2..4].try_into().expect("sequence bytes"))
    }

    fn timestamp(packet: &[u8]) -> u32 {
        u32::from_be_bytes(packet[4..8].try_into().expect("timestamp bytes"))
    }

    fn ssrc(packet: &[u8]) -> u32 {
        u32::from_be_bytes(packet[8..12].try_into().expect("SSRC bytes"))
    }

    #[test]
    fn first_packet_has_exact_rtp_header() {
        let packet = RtpPacketBuilder::new(SSRC, KEY)
            .build_packet(b"alac", 100, true)
            .expect("build first packet");

        assert_eq!(packet[0], 0x80);
        assert_eq!(packet[1], 0xe0);
        assert_eq!(sequence(&packet), 0);
        assert_eq!(timestamp(&packet), 0);
        assert_eq!(ssrc(&packet), SSRC);
    }

    #[test]
    fn second_packet_advances_by_actual_frame_count() {
        let mut builder = RtpPacketBuilder::new(SSRC, KEY);
        let _first = builder
            .build_packet(b"partial packet", 100, true)
            .expect("build first packet");
        let second = builder
            .build_packet(b"next packet", 7, false)
            .expect("build second packet");

        assert_eq!(sequence(&second), 1);
        assert_eq!(timestamp(&second), 100);
    }

    #[test]
    fn marker_bit_reflects_the_caller_supplied_flag() {
        // The marker signals "new stream segment" to the receiver (e.g. reset
        // its jitter buffer). Whether a given packet is the segment start is
        // the caller's decision (see build_packet's doc comment for why) --
        // this builder only needs to write whatever it's told correctly.
        let mut builder = RtpPacketBuilder::new(SSRC, KEY);
        let marked = builder.build_packet(b"first", 100, true).expect("build marked");
        let unmarked = builder
            .build_packet(b"second", 100, false)
            .expect("build unmarked");

        assert_eq!(marked[1], 0xe0, "marker set, PT 0x60");
        assert_eq!(unmarked[1], 0x60, "marker cleared, PT 0x60");
    }

    #[test]
    fn sequence_wraps_to_zero() {
        let mut builder = RtpPacketBuilder::new(SSRC, KEY);
        builder.sequence = u16::MAX;

        let last = builder
            .build_packet(b"last sequence", 1, false)
            .expect("build maximum-sequence packet");
        let wrapped = builder
            .build_packet(b"wrapped sequence", 1, false)
            .expect("build wrapped-sequence packet");

        assert_eq!(sequence(&last), u16::MAX);
        assert_eq!(sequence(&wrapped), 0);
    }

    #[test]
    fn timestamp_wraps_to_zero() {
        let mut builder = RtpPacketBuilder::new(SSRC, KEY);
        builder.timestamp = u32::MAX;

        let last = builder
            .build_packet(b"last timestamp", 1, false)
            .expect("build maximum-timestamp packet");
        let wrapped = builder
            .build_packet(b"wrapped timestamp", 1, false)
            .expect("build wrapped-timestamp packet");

        assert_eq!(timestamp(&last), u32::MAX);
        assert_eq!(timestamp(&wrapped), 0);
    }

    #[test]
    fn encrypted_payload_round_trips_with_transmitted_nonce_and_header_aad() {
        let payload = b"\0encoded ALAC payload\xff";
        let packet = RtpPacketBuilder::new(SSRC, KEY)
            .build_packet(payload, 100, true)
            .expect("build packet");

        assert_eq!(
            decrypt_payload(&packet, KEY).expect("decrypt packet"),
            payload
        );
    }

    #[test]
    fn tampering_with_authenticated_header_is_detected() {
        let mut packet = RtpPacketBuilder::new(SSRC, KEY)
            .build_packet(b"authenticated ALAC", 100, true)
            .expect("build packet");
        packet[4] ^= 0x01;

        assert!(decrypt_payload(&packet, KEY).is_err());
    }

    #[test]
    fn consecutive_packets_use_different_nonces() {
        let mut builder = RtpPacketBuilder::new(SSRC, KEY);
        let first = builder
            .build_packet(b"first", 100, true)
            .expect("build first packet");
        let second = builder
            .build_packet(b"second", 100, false)
            .expect("build second packet");

        assert_ne!(
            &first[first.len() - TRANSMITTED_NONCE_LEN..],
            &second[second.len() - TRANSMITTED_NONCE_LEN..]
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", RtpPacketBuilder::new(SSRC, KEY)),
            "RtpPacketBuilder(..)"
        );
    }
}
