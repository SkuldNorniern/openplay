//! Minimal RIFF/WAVE parsing: integer and float PCM in any layout.
//!
//! The samples are returned as raw bytes with their [`PcmFormat`], and go
//! through the same [`super::AudioInput`] conversion as live audio.

use super::format::{PcmFormat, SampleFormat};
use crate::error::{Error, Result};

const FORMAT_PCM: u16 = 1;
const FORMAT_FLOAT: u16 = 3;
const FORMAT_EXTENSIBLE: u16 = 0xfffe;
/// Offset of the sub-format GUID, whose first two bytes are the real
/// format tag, in a WAVE_FORMAT_EXTENSIBLE `fmt ` chunk.
const SUBFORMAT_OFFSET: usize = 24;

/// Upper bound on a WAV file's `data` chunk, about 1.7 hours of CD audio.
/// Rejects a corrupt or absurd declared length before allocating storage
/// proportional to it, the same defense-in-depth this crate already applies
/// to other parsed-input-driven allocations (see e.g. `info::MAX_INFO_RESPONSE`).
const MAX_DATA_LEN: usize = 1 << 30;

/// Audio from a WAV file, still in the file's own format.
pub struct WavAudio {
    pub format: PcmFormat,
    /// Interleaved little-endian samples, whole frames only.
    pub data: Vec<u8>,
}

impl WavAudio {
    pub fn frame_count(&self) -> usize {
        self.data.len() / self.format.bytes_per_frame()
    }
}

/// Parse a WAV file's bytes.
///
/// Accepts 16, 24 and 32-bit integer PCM and 32-bit float, including the
/// WAVE_FORMAT_EXTENSIBLE header, at any channel count and sample rate that
/// [`PcmFormat::validate`] allows.
pub fn parse_wav(bytes: &[u8]) -> Result<WavAudio> {
    if bytes.get(0..4) != Some(b"RIFF") || bytes.get(8..12) != Some(b"WAVE") {
        return Err(Error::Protocol("wav: missing RIFF/WAVE header".into()));
    }
    let riff_size = read_u32(bytes, 4, "RIFF size")?;
    // The declared size excludes the 8-byte "RIFF"+size header itself, so the
    // container's chunks end at offset 8 + riff_size. A parser that instead
    // scanned to the end of the buffer would happily decode trailing bytes
    // appended after a (possibly truncated or polyglot) WAV container.
    // Streaming writers that cannot seek back leave the size 0 or all ones,
    // meaning "until the end".
    let riff_end = if riff_size == 0 || riff_size == u32::MAX {
        bytes.len()
    } else {
        8usize
            .checked_add(riff_size as usize)
            .ok_or_else(|| Error::Protocol("wav: RIFF size overflow".into()))?
            .min(bytes.len())
    };

    let mut cursor = 12usize;
    let mut format = None;
    let mut data: Option<&[u8]> = None;
    let mut data_truncated = false;

    while cursor < riff_end {
        let header_end = cursor
            .checked_add(8)
            .ok_or_else(|| Error::Protocol("wav: chunk header offset overflow".into()))?;
        let Some(header) = bytes.get(cursor..header_end) else {
            // Trailing bytes after complete audio are not worth failing on.
            if format.is_some() && data.is_some() {
                break;
            }
            return Err(Error::Protocol("wav: truncated chunk header".into()));
        };
        let chunk_id = &header[0..4];
        let chunk_size = read_u32(header, 4, "chunk size")? as usize;
        let data_start = header_end;
        let data_end = data_start
            .checked_add(chunk_size)
            .ok_or_else(|| Error::Protocol("wav: chunk size overflow".into()))?;

        let chunk = match bytes.get(data_start..data_end) {
            Some(chunk) => chunk,
            // A recording cut short, or streamed with a placeholder size,
            // still holds usable audio up to where the file ends.
            None if chunk_id == b"data" && data.is_none() => {
                data_truncated = true;
                &bytes[data_start.min(bytes.len())..]
            }
            None if format.is_some() && data.is_some() => break,
            None => {
                return Err(Error::Protocol(
                    "wav: chunk extends past end of file".into(),
                ));
            }
        };
        if chunk_id == b"data" && chunk.len() > MAX_DATA_LEN {
            return Err(Error::Protocol(format!(
                "wav: data chunk length {} exceeds maximum {MAX_DATA_LEN}",
                chunk.len()
            )));
        }

        match chunk_id {
            b"fmt " if format.is_none() => format = Some(parse_format(chunk)?),
            b"data" if data.is_none() => data = Some(chunk),
            _ => {}
        }
        if data_truncated {
            break;
        }

        // Odd-sized chunks are padded to even length; writers that leave the
        // pad off the final chunk lose nothing.
        cursor = data_end
            .checked_add(chunk_size % 2)
            .ok_or_else(|| Error::Protocol("wav: chunk padding offset overflow".into()))?;
    }

    let format = format.ok_or_else(|| Error::Protocol("wav: missing fmt chunk".into()))?;
    let format = pcm_format(format)?;
    let mut data = data.ok_or_else(|| Error::Protocol("wav: missing data chunk".into()))?;
    let partial = data.len() % format.bytes_per_frame();
    if partial != 0 {
        if !data_truncated {
            return Err(Error::Protocol(
                "wav: data length is not a whole number of frames".into(),
            ));
        }
        data = &data[..data.len() - partial];
    }

    Ok(WavAudio {
        format,
        data: data.to_vec(),
    })
}

#[derive(Clone, Copy)]
struct WaveFormat {
    audio_format: u16,
    channels: u16,
    sample_rate: u32,
    bits_per_sample: u16,
    block_align: u16,
    /// Real format tag of an extensible header.
    subformat: Option<u16>,
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
        block_align: read_u16(chunk, 12, "block align")?,
        bits_per_sample: read_u16(chunk, 14, "bits per sample")?,
        subformat: read_u16(chunk, SUBFORMAT_OFFSET, "sub-format").ok(),
    })
}

fn pcm_format(format: WaveFormat) -> Result<PcmFormat> {
    let tag = match (format.audio_format, format.subformat) {
        (FORMAT_EXTENSIBLE, Some(subformat)) => subformat,
        (FORMAT_EXTENSIBLE, None) => {
            return Err(Error::Protocol(
                "wav: extensible fmt chunk without sub-format".into(),
            ));
        }
        (tag, _) => tag,
    };
    let sample = match (tag, format.bits_per_sample) {
        (FORMAT_PCM, 16) => SampleFormat::I16,
        (FORMAT_PCM, 24) => SampleFormat::I24,
        (FORMAT_PCM, 32) => SampleFormat::I32,
        (FORMAT_FLOAT, 32) => SampleFormat::F32,
        (tag, bits) => {
            return Err(Error::Protocol(format!(
                "wav: unsupported encoding: format {tag} at {bits} bits"
            )));
        }
    };
    let pcm = PcmFormat {
        sample_rate: format.sample_rate,
        channels: format.channels,
        sample,
    };
    pcm.validate()?;
    if usize::from(format.block_align) != pcm.bytes_per_frame() {
        // Decoding at the wrong stride would turn the audio into noise.
        return Err(Error::Protocol(format!(
            "wav: block align {} does not match {} channels of {} bytes",
            format.block_align,
            pcm.channels,
            pcm.sample.bytes()
        )));
    }
    Ok(pcm)
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
        let audio = parse_wav(TONE).expect("parse fixture");
        assert_eq!(audio.format, PcmFormat::AIRPLAY);
        assert_eq!(audio.frame_count(), 1156);
    }

    #[test]
    fn accepts_common_layouts() {
        for (tag, channels, rate, bits, sample) in [
            (1, 2, 48_000, 16, SampleFormat::I16),
            (1, 1, 44_100, 24, SampleFormat::I24),
            (1, 6, 96_000, 32, SampleFormat::I32),
            (3, 2, 48_000, 32, SampleFormat::F32),
        ] {
            let audio = parse_wav(&wave(tag, channels, rate, bits)).expect("parse layout");
            assert_eq!(
                audio.format,
                PcmFormat {
                    sample_rate: rate,
                    channels,
                    sample
                }
            );
        }
    }

    #[test]
    fn reads_extensible_sub_format() {
        let mut bytes = b"RIFF".to_vec();
        bytes.extend_from_slice(&60u32.to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&40u32.to_le_bytes());
        bytes.extend_from_slice(&0xfffe_u16.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&48_000u32.to_le_bytes());
        bytes.extend_from_slice(&384_000u32.to_le_bytes());
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&22u16.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        // KSDATAFORMAT_SUBTYPE_IEEE_FLOAT starts with format tag 3.
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&[0; 14]);
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let audio = parse_wav(&bytes).expect("parse extensible");
        assert_eq!(audio.format.sample, SampleFormat::F32);
    }

    #[test]
    fn rejects_unsupported_encodings() {
        assert!(parse_wav(&wave(1, 2, 44_100, 8)).is_err());
        assert!(parse_wav(&wave(3, 2, 44_100, 16)).is_err());
        assert!(parse_wav(&wave(2, 2, 44_100, 16)).is_err());
        assert!(parse_wav(&wave(1, 0, 44_100, 16)).is_err());
        assert!(parse_wav(&wave(1, 2, 1_000, 16)).is_err());
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

        let audio = parse_wav(&bytes).expect("parse extra chunk");
        assert_eq!(audio.data, [1, 0, 0xfe, 0xff]);
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
    fn huge_declared_data_size_reads_only_present_bytes() {
        // The size alone allocates nothing: only bytes in the file are used.
        let mut bytes = wave(1, 2, 44_100, 16);
        bytes.truncate(bytes.len() - 4);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&[1, 0, 2, 0, 3, 0, 4, 0, 9]);

        let audio = parse_wav(&bytes).expect("streamed wav");
        assert_eq!(audio.data, [1, 0, 2, 0, 3, 0, 4, 0]);
    }

    #[test]
    fn streamed_riff_size_reads_to_end() {
        let mut bytes = wave(1, 2, 44_100, 16);
        bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
        bytes.truncate(bytes.len() - 4);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[5, 0, 6, 0]);

        assert_eq!(parse_wav(&bytes).expect("parse").data, [5, 0, 6, 0]);
    }

    #[test]
    fn final_odd_chunk_without_pad_byte_is_accepted() {
        // Mono 24-bit, one frame: a 3-byte data chunk, pad byte missing.
        let mut bytes = wave(1, 1, 44_100, 24);
        bytes.truncate(bytes.len() - 4);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        let riff_size = u32::try_from(bytes.len() - 8).expect("fits");
        bytes[4..8].copy_from_slice(&riff_size.to_le_bytes());

        assert_eq!(parse_wav(&bytes).expect("parse").data, [1, 2, 3]);
    }

    #[test]
    fn rejects_block_align_that_disagrees_with_layout() {
        let mut bytes = wave(1, 2, 44_100, 16);
        // fmt chunk starts at 20; block align sits 12 bytes in.
        bytes[32..34].copy_from_slice(&6u16.to_le_bytes());
        assert!(parse_wav(&bytes).is_err());
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
