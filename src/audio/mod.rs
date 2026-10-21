//! Audio input for AirPlay realtime streams.
//!
//! Live and file sources hand PCM in their own format to [`AudioInput`],
//! which converts it to 44,100 Hz signed 16-bit stereo in an [`AudioSource`]
//! ring. The sender drains the ring one 352-frame ALAC packet at a time.

pub mod alac;
pub mod alac24;
pub mod format;
pub mod input;
pub mod resample;
pub mod source;
pub mod wav;

pub use alac::{AlacEncoder, AlacPacket, encode_all};
pub use format::{PcmFormat, SampleFormat, StereoFrame};
pub use input::AudioInput;
pub use resample::Resampler;
pub use source::{AudioSource, SourceStats, WriteOutcome};
pub use wav::{WavAudio, parse_wav};
