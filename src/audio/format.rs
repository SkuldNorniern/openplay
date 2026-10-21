//! Input PCM formats and their decoding to stereo float frames.
//!
//! Live sources hand over whatever their audio engine produces, typically
//! 48 kHz float on Windows, so everything is first decoded to stereo `f32`
//! and only then resampled and quantized to the 44.1 kHz/16-bit stereo that
//! AirPlay realtime audio carries.

use crate::error::{Error, Result};

/// One stereo frame, each channel nominally in `-1.0..=1.0`.
pub type StereoFrame = [f32; 2];

/// Scale between 16-bit integers and float, chosen so `i16 -> f32 -> i16`
/// round-trips exactly.
const I16_SCALE: f32 = 32_768.0;
const I24_SCALE: f32 = 8_388_608.0;
const I32_SCALE: f32 = 2_147_483_648.0;

/// Highest channel count accepted; WAVE_FORMAT_EXTENSIBLE goes no further.
const MAX_CHANNELS: u16 = 32;
const MIN_SAMPLE_RATE: u32 = 8_000;
const MAX_SAMPLE_RATE: u32 = 384_000;

/// Little-endian sample encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFormat {
    I16,
    /// Packed 3-byte signed integers.
    I24,
    I32,
    F32,
}

impl SampleFormat {
    pub fn bytes(self) -> usize {
        match self {
            Self::I16 => 2,
            Self::I24 => 3,
            Self::I32 | Self::F32 => 4,
        }
    }

    fn decode(self, bytes: &[u8]) -> f32 {
        match self {
            Self::I16 => f32::from(i16::from_le_bytes([bytes[0], bytes[1]])) / I16_SCALE,
            // Place the 24 bits in the top of an i32 so the sign extends.
            Self::I24 => {
                (i32::from_le_bytes([0, bytes[0], bytes[1], bytes[2]]) >> 8) as f32 / I24_SCALE
            }
            Self::I32 => {
                i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f32 / I32_SCALE
            }
            Self::F32 => f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }
}

/// Layout of interleaved PCM handed to [`super::AudioInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcmFormat {
    pub sample_rate: u32,
    pub channels: u16,
    pub sample: SampleFormat,
}

impl PcmFormat {
    /// What AirPlay realtime audio carries.
    pub const AIRPLAY: Self = Self {
        sample_rate: 44_100,
        channels: 2,
        sample: SampleFormat::I16,
    };

    pub fn bytes_per_frame(self) -> usize {
        usize::from(self.channels) * self.sample.bytes()
    }

    /// Reject layouts no real source produces, before any audio flows.
    pub fn validate(self) -> Result<()> {
        if self.channels == 0 || self.channels > MAX_CHANNELS {
            return Err(Error::Protocol(format!(
                "pcm: unsupported channel count {}",
                self.channels
            )));
        }
        if !(MIN_SAMPLE_RATE..=MAX_SAMPLE_RATE).contains(&self.sample_rate) {
            return Err(Error::Protocol(format!(
                "pcm: unsupported sample rate {}",
                self.sample_rate
            )));
        }
        Ok(())
    }
}

/// Decode whole interleaved frames to stereo and append them to `out`.
///
/// Mono is copied to both sides. With more than two channels the first two
/// are kept, which are front left and right in both WAV and Windows order.
/// A trailing partial frame is ignored; callers carry it to the next call.
pub fn decode_stereo(format: PcmFormat, bytes: &[u8], out: &mut Vec<StereoFrame>) {
    let sample_bytes = format.sample.bytes();
    let frame_bytes = format.bytes_per_frame();
    for frame in bytes.chunks_exact(frame_bytes) {
        let left = format.sample.decode(&frame[..sample_bytes]);
        let right = if format.channels == 1 {
            left
        } else {
            format.sample.decode(&frame[sample_bytes..2 * sample_bytes])
        };
        out.push([left, right]);
    }
}

/// Quantize to 16-bit, clipping anything outside full scale, and append
/// interleaved samples to `out`.
pub fn quantize_i16(frames: &[StereoFrame], out: &mut Vec<i16>) {
    for frame in frames {
        for channel in frame {
            let scaled = (channel * I16_SCALE).round();
            // `as` saturates float to integer conversion, and NaN becomes 0.
            out.push(scaled.clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format(channels: u16, sample: SampleFormat) -> PcmFormat {
        PcmFormat {
            sample_rate: 48_000,
            channels,
            sample,
        }
    }

    #[test]
    fn i16_round_trips_exactly() {
        let samples: Vec<i16> = vec![i16::MIN, -1, 0, 1, i16::MAX, 12_345];
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let mut frames = Vec::new();
        decode_stereo(format(2, SampleFormat::I16), &bytes, &mut frames);
        let mut back = Vec::new();
        quantize_i16(&frames, &mut back);

        assert_eq!(back, samples);
    }

    #[test]
    fn i24_sign_extends() {
        let bytes = [0xff, 0xff, 0x7f, 0x00, 0x00, 0x80];
        let mut frames = Vec::new();
        decode_stereo(format(2, SampleFormat::I24), &bytes, &mut frames);

        assert!((frames[0][0] - (8_388_607.0 / I24_SCALE)).abs() < 1e-9);
        assert_eq!(frames[0][1], -1.0);
    }

    #[test]
    fn f32_and_i32_decode_full_scale() {
        let mut bytes = 0.5_f32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(-1.0_f32).to_le_bytes());
        let mut frames = Vec::new();
        decode_stereo(format(2, SampleFormat::F32), &bytes, &mut frames);
        assert_eq!(frames, [[0.5, -1.0]]);

        let mut bytes = i32::MIN.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        frames.clear();
        decode_stereo(format(2, SampleFormat::I32), &bytes, &mut frames);
        assert_eq!(frames, [[-1.0, 0.0]]);
    }

    #[test]
    fn mono_duplicates_and_surround_keeps_front_pair() {
        let mut frames = Vec::new();
        decode_stereo(
            format(1, SampleFormat::I16),
            &16_384_i16.to_le_bytes(),
            &mut frames,
        );
        assert_eq!(frames, [[0.5, 0.5]]);

        let six: Vec<u8> = [1_i16, 2, 3, 1, 1, 1]
            .iter()
            .flat_map(|s| (s * 8_192).to_le_bytes())
            .collect();
        frames.clear();
        decode_stereo(format(6, SampleFormat::I16), &six, &mut frames);
        assert_eq!(frames, [[0.25, 0.5]]);
    }

    #[test]
    fn partial_trailing_frame_is_left_alone() {
        let mut frames = Vec::new();
        decode_stereo(format(2, SampleFormat::I16), &[0, 0, 0, 0, 9], &mut frames);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn quantize_clips_overs_and_nan() {
        let mut out = Vec::new();
        quantize_i16(&[[2.0, -2.0], [f32::NAN, 0.0]], &mut out);
        assert_eq!(out, [i16::MAX, i16::MIN, 0, 0]);
    }

    #[test]
    fn validate_rejects_impossible_layouts() {
        assert!(PcmFormat::AIRPLAY.validate().is_ok());
        assert!(format(0, SampleFormat::I16).validate().is_err());
        assert!(format(33, SampleFormat::I16).validate().is_err());
        let mut slow = PcmFormat::AIRPLAY;
        slow.sample_rate = 100;
        assert!(slow.validate().is_err());
    }
}
