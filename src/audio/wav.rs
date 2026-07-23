//! Minimal RIFF/WAVE parsing for the fixed PCM format streamed by openplay.

use crate::error::{Error, Result};

const CHANNELS: u16 = 2;
const SAMPLE_RATE: u32 = 44_100;
const BITS_PER_SAMPLE: u16 = 16;
const BYTES_PER_FRAME: usize = 4;

/// Upper bound on a WAV file's `data` chunk: about 1.7 hours of 44100/16/2
/// audio, generously beyond anything this crate streams in one file. Rejects
/// a corrupt or absurd declared length before allocating PCM storage
/// proportional to it, the same defense-in-depth this crate already applies
/// to other parsed-input-driven allocations (see e.g. `info::MAX_INFO_RESPONSE`).
const MAX_DATA_LEN: usize = 1 << 30;

/// Interleaved 16-bit PCM samples decoded from a WAV file, already validated
/// as 44100 Hz / 16-bit / stereo -- the only format this crate streams.
pub struct PcmSamples {
    /// Interleaved i16 samples: `[L0, R0, L1, R1, ...]`.
    pub interleaved: Vec<i16>,
}

impl PcmSamples {
    /// Number of stereo frames (`interleaved.len() / 2`).
    pub fn frame_count(&self) -> usize {
        self.interleaved.len() / usize::from(CHANNELS)
    }
}

/// Parse a WAV file's bytes and validate it matches this crate's fixed audio
/// format (44100 Hz, 16-bit, stereo).
///
/// Any other format is rejected rather than resampled or reinterpreted.
pub fn parse_wav(bytes: &[u8]) -> Result<PcmSamples> {
    if bytes.get(0..4) != Some(b"RIFF") || bytes.get(8..12) != Some(b"WAVE") {
        return Err(Error::Protocol("wav: missing RIFF/WAVE header".into()));
    }
    let riff_size = read_u32(bytes, 4, "RIFF size")? as usize;
    // The declared size excludes the 8-byte "RIFF"+size header itself, so the
    // container's chunks end at offset 8 + riff_size. A parser that instead
    // scanned to the end of the buffer would happily decode trailing bytes
    // appended after a (possibly truncated or polyglot) WAV container.
    let riff_end = 8usize
        .checked_add(riff_size)
        .ok_or_else(|| Error::Protocol("wav: RIFF size overflow".into()))?
        .min(bytes.len());

    let mut cursor = 12usize;
    let mut format = None;
    let mut data = None;

    while cursor < riff_end {
        let header_end = cursor
            .checked_add(8)
            .ok_or_else(|| Error::Protocol("wav: chunk header offset overflow".into()))?;
        let header = bytes
            .get(cursor..header_end)
            .ok_or_else(|| Error::Protocol("wav: truncated chunk header".into()))?;
        let chunk_id = header
            .get(0..4)
            .ok_or_else(|| Error::Protocol("wav: truncated chunk id".into()))?;
        let chunk_size = read_u32(header, 4, "chunk size")? as usize;
        if chunk_id == b"data" && chunk_size > MAX_DATA_LEN {
            return Err(Error::Protocol(format!(
                "wav: data chunk length {chunk_size} exceeds maximum {MAX_DATA_LEN}"
            )));
        }
        let data_start = header_end;
        let data_end = data_start
            .checked_add(chunk_size)
            .ok_or_else(|| Error::Protocol("wav: chunk size overflow".into()))?;
        let chunk = bytes
            .get(data_start..data_end)
            .ok_or_else(|| Error::Protocol("wav: chunk extends past end of file".into()))?;

        match chunk_id {
            b"fmt " if format.is_none() => format = Some(parse_format(chunk)?),
            b"data" if data.is_none() => data = Some(chunk),
            _ => {}
        }

        let padding = chunk_size % 2;
        cursor = data_end
            .checked_add(padding)
            .ok_or_else(|| Error::Protocol("wav: chunk padding offset overflow".into()))?;
        if cursor > bytes.len() {
            return Err(Error::Protocol("wav: missing chunk padding byte".into()));
        }
    }

    let format = format.ok_or_else(|| Error::Protocol("wav: missing fmt chunk".into()))?;
    validate_format(format)?;
    let data = data.ok_or_else(|| Error::Protocol("wav: missing data chunk".into()))?;
    if data.len() % BYTES_PER_FRAME != 0 {
        return Err(Error::Protocol(
            "wav: data length is not a whole stereo frame".into(),
        ));
    }

    let mut interleaved = Vec::with_capacity(data.len() / 2);
    for sample in data.chunks_exact(2) {
        let bytes = [sample[0], sample[1]];
        interleaved.push(i16::from_le_bytes(bytes));
    }

    Ok(PcmSamples { interleaved })
}

#[derive(Clone, Copy)]
struct WaveFormat {
    audio_format: u16,
    channels: u16,
    sample_rate: u32,
    bits_per_sample: u16,
}

fn parse_format(chunk: &[u8]) -> Result<WaveFormat> {
    if chunk.len() < 16 {
        return Err(Error::Protocol(
            "wav: fmt chunk is shorter than 16 bytes".into(),
        ));
    }
    Ok(WaveFormat {
        audio_format: read_u16(chunk, 0, "audio format")?,
        channels: read_u16(chunk, 2, "channel count")?,
        sample_rate: read_u32(chunk, 4, "sample rate")?,
        bits_per_sample: read_u16(chunk, 14, "bits per sample")?,
    })
}

fn validate_format(format: WaveFormat) -> Result<()> {
    if format.audio_format != 1 {
        return Err(Error::Protocol(format!(
            "wav: unsupported audio format {} (expected PCM format 1)",
            format.audio_format
        )));
    }
    if format.channels != CHANNELS {
        return Err(Error::Protocol(format!(
            "wav: unsupported channel count {} (expected {CHANNELS})",
            format.channels
        )));
    }
    if format.sample_rate != SAMPLE_RATE {
        return Err(Error::Protocol(format!(
            "wav: unsupported sample rate {} (expected {SAMPLE_RATE})",
            format.sample_rate
        )));
    }
    if format.bits_per_sample != BITS_PER_SAMPLE {
        return Err(Error::Protocol(format!(
            "wav: unsupported bit depth {} (expected {BITS_PER_SAMPLE})",
            format.bits_per_sample
        )));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize, field: &str) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| Error::Protocol(format!("wav: {field} offset overflow")))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| Error::Protocol(format!("wav: truncated {field}")))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::Protocol(format!("wav: {field} offset overflow")))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| Error::Protocol(format!("wav: truncated {field}")))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TONE: &[u8] = include_bytes!("../../tests/fixtures/tone.wav");

    fn wave(audio_format: u16, channels: u16, sample_rate: u32, bits: u16) -> Vec<u8> {
        let block_align = channels * (bits / 8);
        let byte_rate = sample_rate * u32::from(block_align);
        let mut bytes = b"RIFF".to_vec();
        bytes.extend_from_slice(&36u32.to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&audio_format.to_le_bytes());
        bytes.extend_from_slice(&channels.to_le_bytes());
        bytes.extend_from_slice(&sample_rate.to_le_bytes());
        bytes.extend_from_slice(&byte_rate.to_le_bytes());
        bytes.extend_from_slice(&block_align.to_le_bytes());
        bytes.extend_from_slice(&bits.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_tone_fixture() {
        let pcm = parse_wav(TONE).expect("parse fixture");
        assert_eq!(pcm.frame_count(), 1156);
        assert_eq!(pcm.interleaved.len(), 2312);
    }

    #[test]
    fn rejects_wrong_format_fields() {
        assert!(parse_wav(&wave(1, 2, 48_000, 16)).is_err());
        assert!(parse_wav(&wave(1, 1, 44_100, 16)).is_err());
        assert!(parse_wav(&wave(1, 2, 44_100, 8)).is_err());
        assert!(parse_wav(&wave(3, 2, 44_100, 16)).is_err());
    }

    #[test]
    fn skips_unknown_chunks() {
        let mut bytes = wave(1, 2, 44_100, 16);
        bytes.truncate(bytes.len() - 8);
        bytes.extend_from_slice(b"LIST");
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(b"abc\0");
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&1i16.to_le_bytes());
        bytes.extend_from_slice(&(-2i16).to_le_bytes());
        let riff_size = u32::try_from(bytes.len() - 8).expect("test wave fits in RIFF");
        bytes[4..8].copy_from_slice(&riff_size.to_le_bytes());

        let pcm = parse_wav(&bytes).expect("parse extra chunk");
        assert_eq!(pcm.interleaved, [1, -2]);
    }

    #[test]
    fn rejects_missing_headers_and_chunks() {
        assert!(parse_wav(b"not a wave").is_err());

        let mut missing_format = b"RIFF\0\0\0\0WAVEdata".to_vec();
        missing_format.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_wav(&missing_format).is_err());

        let mut missing_data = wave(1, 2, 44_100, 16);
        missing_data.truncate(missing_data.len() - 8);
        assert!(parse_wav(&missing_data).is_err());
    }

    #[test]
    fn ignores_data_chunk_after_declared_riff_end() {
        let mut bytes = b"RIFF".to_vec();
        // RIFF size covers "WAVE" and the fmt chunk, but not the trailing data
        // chunk that is physically present in the byte buffer.
        bytes.extend_from_slice(&28u32.to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&44_100u32.to_le_bytes());
        bytes.extend_from_slice(&176_400u32.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);

        assert!(matches!(
            parse_wav(&bytes),
            Err(Error::Protocol(message)) if message == "wav: missing data chunk"
        ));
    }

    #[test]
    fn rejects_data_chunk_larger_than_limit() {
        let mut bytes = wave(1, 2, 44_100, 16);
        bytes.truncate(bytes.len() - 4);
        bytes.extend_from_slice(&((MAX_DATA_LEN as u32) + 4).to_le_bytes());

        // The declared-length limit is checked from the chunk header, before
        // bounds-checking or allocating storage for the absent payload.
        assert!(matches!(
            parse_wav(&bytes),
            Err(Error::Protocol(message))
                if message
                    == format!(
                        "wav: data chunk length {} exceeds maximum {MAX_DATA_LEN}",
                        MAX_DATA_LEN + 4
                    )
        ));
    }

    #[test]
    fn rejects_truncated_and_incomplete_data() {
        let mut oversized = b"RIFF\0\0\0\0WAVELIST".to_vec();
        oversized.extend_from_slice(&10u32.to_le_bytes());
        oversized.extend_from_slice(b"short");
        assert!(parse_wav(&oversized).is_err());

        let mut incomplete = wave(1, 2, 44_100, 16);
        incomplete.truncate(incomplete.len() - 4);
        incomplete.extend_from_slice(&2u32.to_le_bytes());
        incomplete.extend_from_slice(&0i16.to_le_bytes());
        assert!(parse_wav(&incomplete).is_err());
    }
}
