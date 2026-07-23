//! HomeKit pair-setup for AirPlay.
//!
//! Transient pairing (`X-Apple-HKP: 4`) runs SRP-6a over TLV8 to derive a shared
//! secret, from which the ChaCha20-Poly1305 control keys are expanded. No
//! long-term keys are persisted.

pub mod tlv;

pub use tlv::{Tlv, TlvType};
