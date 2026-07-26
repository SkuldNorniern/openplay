//! RTP packet construction and transport for realtime AirPlay audio.

pub mod packet;
pub mod sender;

pub use packet::RtpPacketBuilder;
pub use sender::RtpSender;
