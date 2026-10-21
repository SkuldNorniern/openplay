//! Format conversion from a live source into the sender's ring.

use super::format::{PcmFormat, StereoFrame, decode_stereo, quantize_i16};
use super::resample::Resampler;
use super::source::{AudioSource, WriteOutcome};
use crate::error::Result;

/// Largest drift correction, in parts per million. 1000 ppm is a pitch
/// change of about 1.7 cents, below what listeners notice, and well above
/// the 10 to 100 ppm two crystal clocks usually differ by.
const MAX_ADJUSTMENT_PPM: f64 = 1_000.0;
/// Correction per unit of relative fill error: 10% over target asks for the
/// full 1000 ppm, and a 100 ppm drift settles 1% off target. The loop's time
/// constant is about 25 s at a quarter-second target, slow enough that the
/// 352-frame steps of the sender's reads cause no audible wobble.
const ADJUSTMENT_GAIN_PPM: f64 = 10_000.0;
/// Time the smoothed fill level averages over, in output frames: about a
/// second, hiding the 352-frame steps of the sender's reads whatever size
/// the writes come in.
const FILL_SMOOTHING_FRAMES: f64 = 44_100.0;

/// Keeps the ring near a target fill by nudging the resampler, so a source
/// clock that runs slightly fast or slow against the sender never drains
/// or floods the ring.
struct DriftControl {
    target_frames: f64,
    smoothed_frames: f64,
    /// Source epoch the smoothing belongs to.
    epoch: u64,
}

impl DriftControl {
    /// Fold in the fill seen after writing `written` frames, and return the
    /// correction for the next write.
    ///
    /// The target applies to the ring's low point, just before a write:
    /// between writes the sender drains a whole write's worth, so holding
    /// any higher point at target would let the ring run dry each cycle.
    /// A new session restarts the average at target rather than at the
    /// backlog that built up while nothing was draining.
    fn update(&mut self, buffered_after: usize, written: usize, epoch: u64) -> i32 {
        if epoch != self.epoch {
            self.epoch = epoch;
            self.smoothed_frames = self.target_frames;
        }
        let low_point = buffered_after.saturating_sub(written) as f64;
        let weight = 1.0 - (-(written as f64) / FILL_SMOOTHING_FRAMES).exp();
        self.smoothed_frames += weight * (low_point - self.smoothed_frames);
        let error = (self.smoothed_frames - self.target_frames) / self.target_frames;
        (error * ADJUSTMENT_GAIN_PPM).clamp(-MAX_ADJUSTMENT_PPM, MAX_ADJUSTMENT_PPM) as i32
    }
}

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
    drift: Option<DriftControl>,
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
            drift: None,
            partial: Vec::with_capacity(format.bytes_per_frame()),
            decoded: Vec::new(),
            resampled: Vec::new(),
            samples: Vec::new(),
        })
    }

    /// Follow a live source's clock: keep about `target_frames` buffered by
    /// adjusting the conversion rate slightly. Not for files, which are fed
    /// at the sender's pace anyway.
    pub fn with_drift_correction(mut self, target_frames: usize) -> Self {
        let output_rate = PcmFormat::AIRPLAY.sample_rate;
        self.resampler
            .get_or_insert_with(|| Resampler::new(self.format.sample_rate, output_rate));
        self.drift = Some(DriftControl {
            target_frames: target_frames.max(1) as f64,
            smoothed_frames: target_frames as f64,
            epoch: self.source.epoch(),
        });
        self
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
        let written = frames.len();
        self.samples.clear();
        quantize_i16(frames, &mut self.samples);
        let outcome = self.source.write(&self.samples);

        if let (Some(drift), Some(resampler)) = (&mut self.drift, &mut self.resampler) {
            let ppm = drift.update(self.source.buffered_frames(), written, self.source.epoch());
            resampler.set_adjustment_ppm(ppm);
        }
        outcome
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

    /// Two minutes of a source clock running about 208 ppm fast: 48010
    /// frames a second in 10 ms periods, while the sender takes 441 frames a
    /// period.
    fn run_fast_source(input: &mut AudioInput, source: &AudioSource) {
        let silence = vec![0_u8; 482 * 8];
        for period in 0..12_000_usize {
            let frames = if period % 10 == 0 { 481 } else { 480 };
            input.write(&silence[..frames * 8]);
            source.read(441);
        }
    }

    fn float_48k() -> PcmFormat {
        PcmFormat {
            sample_rate: 48_000,
            channels: 2,
            sample: SampleFormat::F32,
        }
    }

    #[test]
    fn drift_correction_holds_fill_near_target() {
        let source = AudioSource::new(22_050);
        source.write(&vec![0; 11_025 * 2]);
        let mut input = AudioInput::new(float_48k(), source.clone())
            .expect("input")
            .with_drift_correction(11_025);

        run_fast_source(&mut input, &source);

        let fill = source.buffered_frames();
        assert!((11_025..=11_800).contains(&fill), "fill {fill}");
        assert_eq!(source.stats().overrun_frames, 0);
        assert_eq!(source.stats().underrun_frames, 0);
    }

    #[test]
    fn without_correction_fast_source_keeps_growing() {
        let source = AudioSource::new(22_050);
        source.write(&vec![0; 11_025 * 2]);
        let mut input = AudioInput::new(float_48k(), source.clone()).expect("input");

        run_fast_source(&mut input, &source);

        // About 1100 frames gained in two minutes, and still climbing.
        let fill = source.buffered_frames();
        assert!(fill > 12_000, "fill {fill}");
    }

    #[test]
    fn large_writes_never_run_the_ring_dry() {
        // A source handing over 100 ms at a time, read in ten 10 ms slices.
        let source = AudioSource::new(22_050);
        let mut input = AudioInput::new(float_48k(), source.clone())
            .expect("input")
            .with_drift_correction(2_205);
        let silence = vec![0_u8; 4_800 * 8];
        // A session starts at target, as `Sender` trims to it on connect.
        source.write(&vec![0; 2_205 * 2]);
        source.restart_at(2_205);

        let mut low_points = Vec::new();
        for _ in 0..1_800 {
            low_points.push(source.buffered_frames());
            input.write(&silence);
            for _ in 0..10 {
                source.read(441);
            }
        }
        let settled = &low_points[low_points.len() - 100..];
        let lowest = settled.iter().min().copied().unwrap_or_default();
        let highest = settled.iter().max().copied().unwrap_or_default();
        assert!(
            (1_800..=2_700).contains(&lowest) && highest <= 2_700,
            "low points {lowest}..{highest}"
        );
        assert_eq!(source.stats().underrun_frames, 0);
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
