//! Format conversion from a live source into the sender's ring.

use super::format::{PcmFormat, StereoFrame, decode_stereo, quantize_i16};
use super::resample::Resampler;
use super::source::{AudioSource, WriteOutcome};
use crate::error::Result;

/// Writer side of a stream: takes PCM in the source's own format, in any
/// chunk size, and feeds 44.1 kHz/16-bit stereo into an [`AudioSource`].
///
/// One `AudioInput` per producer, since it carries resampler state and any
/// partial frame between calls. Its buffers are reused, so after the first
/// few calls a write allocates nothing, which suits a realtime callback.
pub struct AudioInput {
    format: PcmFormat,
    source: AudioSource,
    resampler: Option<Resampler>,
    /// Bytes of an incomplete frame left over from the previous write.
    partial: Vec<u8>,
    decoded: Vec<StereoFrame>,
    resampled: Vec<StereoFrame>,
    samples: Vec<i16>,
}

impl AudioInput {
    pub fn new(format: PcmFormat, source: AudioSource) -> Result<Self> {
        format.validate()?;
        let output_rate = PcmFormat::AIRPLAY.sample_rate;
        Ok(Self {
            format,
            source,
            resampler: (format.sample_rate != output_rate)
                .then(|| Resampler::new(format.sample_rate, output_rate)),
            partial: Vec::with_capacity(format.bytes_per_frame()),
            decoded: Vec::new(),
            resampled: Vec::new(),
            samples: Vec::new(),
        })
    }

    pub fn format(&self) -> PcmFormat {
        self.format
    }

    /// Convert and queue interleaved little-endian PCM.
    pub fn write(&mut self, bytes: &[u8]) -> WriteOutcome {
        let frame_bytes = self.format.bytes_per_frame();
        self.decoded.clear();

        // Finish a frame split across the previous call first.
        let mut rest = bytes;
        if !self.partial.is_empty() {
            let needed = (frame_bytes - self.partial.len()).min(rest.len());
            self.partial.extend_from_slice(&rest[..needed]);
            rest = &rest[needed..];
            if self.partial.len() < frame_bytes {
                return WriteOutcome::Ok;
            }
            decode_stereo(self.format, &self.partial, &mut self.decoded);
            self.partial.clear();
        }
        let whole = rest.len() - rest.len() % frame_bytes;
        decode_stereo(self.format, &rest[..whole], &mut self.decoded);
        self.partial.extend_from_slice(&rest[whole..]);

        let frames = match &mut self.resampler {
            Some(resampler) => {
                self.resampled.clear();
                resampler.process(&self.decoded, &mut self.resampled);
                &self.resampled
            }
            None => &self.decoded,
        };
        self.samples.clear();
        quantize_i16(frames, &mut self.samples);
        self.source.write(&self.samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::SampleFormat;

    fn f32_bytes(frames: &[[f32; 2]]) -> Vec<u8> {
        frames
            .iter()
            .flatten()
            .flat_map(|sample| sample.to_le_bytes())
            .collect()
    }

    #[test]
    fn airplay_format_passes_samples_through() {
        let source = AudioSource::new(16);
        let mut input = AudioInput::new(PcmFormat::AIRPLAY, source.clone()).expect("input");
        let samples = [100_i16, -100, 7, -7];
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();

        input.write(&bytes);
        assert_eq!(source.read(2), samples);
    }

    #[test]
    fn frames_split_across_writes_are_rejoined() {
        let source = AudioSource::new(16);
        let mut input = AudioInput::new(PcmFormat::AIRPLAY, source.clone()).expect("input");
        let bytes: Vec<u8> = [1_i16, 2, 3, 4]
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect();

        input.write(&bytes[..3]);
        input.write(&bytes[3..5]);
        input.write(&bytes[5..]);
        assert_eq!(source.read(2), [1, 2, 3, 4]);
    }

    #[test]
    fn windows_float_48k_becomes_airplay_rate() {
        let source = AudioSource::new(100_000);
        let format = PcmFormat {
            sample_rate: 48_000,
            channels: 2,
            sample: SampleFormat::F32,
        };
        let mut input = AudioInput::new(format, source.clone()).expect("input");

        // One second in 10 ms engine periods.
        for _ in 0..100 {
            input.write(&f32_bytes(&[[0.25, -0.25]; 480]));
        }
        let buffered = source.buffered_frames();
        assert!((44_095..=44_100).contains(&buffered), "{buffered}");

        let samples = source.read(buffered);
        assert!(samples[200..].chunks(2).all(|f| f == [8_192, -8_192]));
    }

    #[test]
    fn rejects_invalid_format() {
        let format = PcmFormat {
            sample_rate: 48_000,
            channels: 0,
            sample: SampleFormat::F32,
        };
        assert!(AudioInput::new(format, AudioSource::new(1)).is_err());
    }
}
