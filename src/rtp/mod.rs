//! RTP packet construction and transport for realtime AirPlay audio.

pub mod packet;
pub mod sender;
pub mod sync;
pub mod timing;

pub use packet::RtpPacketBuilder;
pub use sender::RtpSender;
pub use sync::SyncSender;
pub use timing::{
    NtpTimestamp, TimingRequest, TimingResponder, build_timing_response, parse_timing_request,
};
