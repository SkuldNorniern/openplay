//! PTP (IEEE 1588) clock following for AirPlay buffered audio.
//!
//! Buffered streams schedule playback on the receiver's PTP timeline, so the
//! sender follows the receiver's clock to know what "now" is over there.

pub mod follower;
pub mod message;

pub use follower::{Action, Follower, FollowerClock, Sample};
pub use message::{Body, Message, PortIdentity, Timestamp};
