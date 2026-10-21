//! Streaming sample-rate conversion to 44.1 kHz.
//!
//! Live sources deliver audio in arbitrary chunks, so the resampler keeps
//! the few input frames that interpolation still needs between calls and its
//! fractional read position, which makes chunked output identical to
//! resampling the whole stream at once.
//!
//! Interpolation is 4-point Catmull-Rom: far cleaner than linear for music,
//! and small enough to run in a realtime callback. A windowed-sinc filter can
//! replace it behind the same interface if aliasing ever becomes audible.

use super::format::StereoFrame;

/// Frames of history kept before the read position.
const LOOKBEHIND: usize = 1;
/// Frames needed after the read position's integer part.
const LOOKAHEAD: usize = 2;
/// Fixed-point bits in the read position's fraction.
const FRACTION_BITS: u32 = 32;
const FRACTION_MASK: u64 = (1 << FRACTION_BITS) - 1;
const PPM: i64 = 1_000_000;

pub struct Resampler {
    /// Input frames per output frame at the nominal rates, in 32.32 fixed
    /// point.
    nominal_step: u64,
    /// `nominal_step` with the current drift adjustment applied.
    step: u64,
    /// Integer part of the read position, an index into `history`.
    index: usize,
    /// Fractional part of the read position, in 1/2^32 input frames.
    /// Integer bookkeeping keeps the position exact, so chunk boundaries
    /// cannot shift it by rounding.
    phase: u64,
    history: Vec<StereoFrame>,
}

impl Resampler {
    pub fn new(input_rate: u32, output_rate: u32) -> Self {
        let (input_rate, output_rate) = (u64::from(input_rate), u64::from(output_rate));
        let nominal_step = ((input_rate << FRACTION_BITS) + output_rate / 2) / output_rate;
        Self {
            nominal_step,
            step: nominal_step,
            // One silent frame before the first real one lets interpolation
            // start at the first input frame instead of skipping it.
            index: LOOKBEHIND,
            phase: 0,
            history: vec![[0.0; 2]; LOOKBEHIND],
        }
    }

    /// Consume input `ppm` parts per million faster than nominal (slower
    /// when negative), producing correspondingly fewer output frames. Used
    /// to follow a source clock that drifts against the sender's.
    pub fn set_adjustment_ppm(&mut self, ppm: i32) {
        let scaled =
            i128::from(self.nominal_step) * i128::from(PPM + i64::from(ppm)) / i128::from(PPM);
        self.step = u64::try_from(scaled.max(1)).unwrap_or(self.nominal_step);
    }

    /// Resample `input` and append the result to `out`.
    pub fn process(&mut self, input: &[StereoFrame], out: &mut Vec<StereoFrame>) {
        self.history.extend_from_slice(input);

        while self.index + LOOKAHEAD < self.history.len() {
            let fraction = (self.phase as f64 / (1_u64 << FRACTION_BITS) as f64) as f32;
            let [p0, p1, p2, p3] = [
                self.history[self.index - 1],
                self.history[self.index],
                self.history[self.index + 1],
                self.history[self.index + 2],
            ];
            out.push([
                catmull_rom(p0[0], p1[0], p2[0], p3[0], fraction),
                catmull_rom(p0[1], p1[1], p2[1], p3[1], fraction),
            ]);
            self.phase += self.step;
            self.index += (self.phase >> FRACTION_BITS) as usize;
            self.phase &= FRACTION_MASK;
        }

        // Drop frames no future output can reach, keeping the lookbehind.
        let consumed = self
            .index
            .saturating_sub(LOOKBEHIND)
            .min(self.history.len());
        self.history.drain(..consumed);
        self.index -= consumed;
    }
}

fn catmull_rom(p0: f32, p1: f32, p2: f32, p3: f32, t: f32) -> f32 {
    p1 + 0.5
        * t
        * (p2 - p0 + t * (2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3 + t * (3.0 * (p1 - p2) + p3 - p0)))
}

#[cfg(test)]
mod tests {
    use std::f32::consts::TAU;

    use super::*;

    fn sine(rate: u32, frequency: f32, frames: usize) -> Vec<StereoFrame> {
        (0..frames)
            .map(|index| {
                let value = (TAU * frequency * index as f32 / rate as f32).sin() * 0.5;
                [value, -value]
            })
            .collect()
    }

    fn resample_all(input: &[StereoFrame], chunk: usize) -> Vec<StereoFrame> {
        let mut resampler = Resampler::new(48_000, 44_100);
        let mut out = Vec::new();
        for piece in input.chunks(chunk) {
            resampler.process(piece, &mut out);
        }
        out
    }

    #[test]
    fn output_length_follows_rate_ratio() {
        let out = resample_all(&sine(48_000, 440.0, 48_000), 480);
        // One second in, one second out, less the lookahead still pending.
        assert!((44_095..=44_100).contains(&out.len()), "{}", out.len());
    }

    #[test]
    fn chunking_does_not_change_output() {
        let input = sine(48_000, 1_000.0, 9_600);
        assert_eq!(resample_all(&input, 9_600), resample_all(&input, 37));
    }

    #[test]
    fn tone_keeps_frequency_and_level() {
        let out = resample_all(&sine(48_000, 1_000.0, 48_000), 480);
        let expected = sine(44_100, 1_000.0, out.len());
        let worst = out
            .iter()
            .zip(&expected)
            .skip(4)
            .map(|(got, want)| (got[0] - want[0]).abs())
            .fold(0.0_f32, f32::max);
        assert!(worst < 2e-3, "max error {worst}");
    }

    #[test]
    fn adjustment_changes_output_count_by_ppm() {
        let input = vec![[0.0; 2]; 441_000];
        let count = |ppm| {
            let mut resampler = Resampler::new(44_100, 44_100);
            resampler.set_adjustment_ppm(ppm);
            let mut out = Vec::new();
            resampler.process(&input, &mut out);
            out.len() as i64
        };
        let nominal = count(0);

        // 1000 ppm faster consumption leaves about 441 fewer of 441000.
        assert!((count(1_000) - (nominal - 441)).abs() <= 1);
        assert!((count(-1_000) - (nominal + 441)).abs() <= 1);
    }

    #[test]
    fn equal_rates_pass_frames_through() {
        let mut resampler = Resampler::new(44_100, 44_100);
        let input = sine(44_100, 440.0, 100);
        let mut out = Vec::new();
        resampler.process(&input, &mut out);
        assert_eq!(out, input[..out.len()]);
    }
}
