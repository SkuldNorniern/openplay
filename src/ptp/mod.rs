//! PTP (IEEE 1588) clock following for AirPlay buffered audio.
//!
//! Buffered streams schedule playback on the receiver's PTP timeline, so the
//! sender follows the receiver's clock to know what "now" is over there.

pub mod follower;
pub mod message;
pub mod node;

pub use follower::{Action, Follower, FollowerClock, Sample};
pub use message::{Body, Message, PortIdentity, Timestamp};
pub use node::{EVENT_PORT, GENERAL_PORT, LocalClock, PtpNode, PtpTime};
