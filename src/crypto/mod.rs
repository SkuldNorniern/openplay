//! Encryption for the RTSP control channel established by transient pairing.
//!
//! Independent send and receive state protects control messages while preserving
//! the protocol's strict directional nonce ordering.

pub mod cipher;
pub mod nonce;
