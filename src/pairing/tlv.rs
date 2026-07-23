//! HAP TLV8 encoding used by pair-setup.
//!
//! Each item is `type (1 byte) | length (1 byte) | value`. Values longer than
//! 255 bytes are split into consecutive fragments sharing the same type; on
//! decode, adjacent fragments of the same type are concatenated. HAP never
//! places two distinct items of the same type next to each other, so coalescing
//! adjacent equal types is unambiguous.

use crate::error::{Error, Result};

/// Maximum bytes carried by a single TLV fragment.
const MAX_FRAGMENT: usize = 255;

/// HAP TLV item types (the subset pair-setup uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvType {
    Method = 0x00,
    Identifier = 0x01,
    Salt = 0x02,
    PublicKey = 0x03,
    Proof = 0x04,
    EncryptedData = 0x05,
    State = 0x06,
    Error = 0x07,
    Signature = 0x0a,
    Flags = 0x13,
}

/// An ordered TLV8 collection.
#[derive(Debug, Default, Clone)]
pub struct Tlv {
    entries: Vec<(u8, Vec<u8>)>,
}

impl Tlv {
    pub fn new() -> Self {
        Tlv {
            entries: Vec::new(),
        }
    }

    /// Append an item (builder style).
    pub fn put(mut self, ty: TlvType, value: &[u8]) -> Self {
        self.entries.push((ty as u8, value.to_vec()));
        self
    }

    /// Append a single-byte item (State, Method, ...).
    pub fn put_u8(self, ty: TlvType, value: u8) -> Self {
        self.put(ty, &[value])
    }

    /// First value stored for `ty`.
    pub fn get(&self, ty: TlvType) -> Option<&[u8]> {
        let want = ty as u8;
        self.entries
            .iter()
            .find(|(t, _)| *t == want)
            .map(|(_, v)| v.as_slice())
    }

    /// A single-byte item as `u8` (e.g. `State`).
    pub fn get_u8(&self, ty: TlvType) -> Option<u8> {
        match self.get(ty) {
            Some([b]) => Some(*b),
            _ => None,
        }
    }

    /// The device error code, if the peer reported one.
    pub fn error_code(&self) -> Option<u8> {
        self.get_u8(TlvType::Error)
    }

    /// Serialize to the wire format, fragmenting long values.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (ty, value) in &self.entries {
            if value.is_empty() {
                out.push(*ty);
                out.push(0);
                continue;
            }
            for chunk in value.chunks(MAX_FRAGMENT) {
                out.push(*ty);
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    /// Parse the wire format, concatenating adjacent same-type fragments.
    pub fn decode(bytes: &[u8]) -> Result<Tlv> {
        let mut entries: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let ty = bytes[i];
            let len = *bytes
                .get(i + 1)
                .ok_or_else(|| Error::Pairing("tlv: truncated length".into()))?
                as usize;
            let start = i + 2;
            let end = start + len;
            let value = bytes
                .get(start..end)
                .ok_or_else(|| Error::Pairing("tlv: truncated value".into()))?;
            match entries.last_mut() {
                Some((last_ty, buf)) if *last_ty == ty => buf.extend_from_slice(value),
                _ => entries.push((ty, value.to_vec())),
            }
            i = end;
        }
        Ok(Tlv { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real pair-setup M1 (transient) captured from HomePod mini "Bedroom".
    const M1: &[u8] = &[
        0x00, 0x01, 0x00, // Method = 0
        0x06, 0x01, 0x01, // State = 1
        0x13, 0x04, 0x10, 0x00, 0x00, 0x00, // Flags = 0x10 (transient)
    ];

    #[test]
    fn encodes_transient_m1_exactly() {
        let tlv = Tlv::new()
            .put_u8(TlvType::Method, 0)
            .put_u8(TlvType::State, 1)
            .put(TlvType::Flags, &[0x10, 0, 0, 0]);
        assert_eq!(tlv.encode(), M1);
    }

    #[test]
    fn decodes_m1_fields() {
        let tlv = Tlv::decode(M1).expect("decode");
        assert_eq!(tlv.get_u8(TlvType::Method), Some(0));
        assert_eq!(tlv.get_u8(TlvType::State), Some(1));
        assert_eq!(tlv.get(TlvType::Flags), Some(&[0x10, 0, 0, 0][..]));
    }

    #[test]
    fn fragments_and_rejoins_long_values() {
        let big = vec![0xabu8; 384];
        let wire = Tlv::new().put(TlvType::PublicKey, &big).encode();
        // 384 bytes -> fragments of 255 + 129, each with a 2-byte header.
        assert_eq!(wire.len(), 2 + 255 + 2 + 129);
        assert_eq!(wire[1], 255);
        assert_eq!(wire[2 + 255 + 1], 129);
        let back = Tlv::decode(&wire).expect("decode");
        assert_eq!(back.get(TlvType::PublicKey), Some(big.as_slice()));
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(Tlv::decode(&[0x06, 0x04, 0x01]).is_err());
        assert!(Tlv::decode(&[0x06]).is_err());
    }
}
