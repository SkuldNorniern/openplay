//! Fixed-format PCM-to-ALAC encoding for AirPlay realtime audio.
//!
//! Audio is always 44,100 Hz, signed 16-bit, and stereo.

pub mod alac;
pub mod source;
pub mod wav;

pub use alac::{AlacEncoder, AlacPacket, encode_all};
pub use source::{AudioSource, Frame, WriteOutcome};
pub use wav::{PcmSamples, parse_wav};
