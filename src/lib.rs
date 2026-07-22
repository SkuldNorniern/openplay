//! openplay — an AirPlay 2 audio sender.
//!
//! Streams audio from a PC to AirPlay 2 receivers (HomePod, Apple TV) using the
//! encrypted RAOP realtime path: mDNS discovery, HomeKit transient pairing,
//! ChaCha20-Poly1305 RTSP control, and ALAC over RTP.
//!
//! The crate is library-first; the bundled binary is a thin harness for driving
//! and testing the protocol core.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod error;

pub use error::{Error, Result};
