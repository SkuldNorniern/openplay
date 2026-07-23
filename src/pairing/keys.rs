//! Control-channel key derivation for transient pair-setup.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::{Error, Result};

const CONTROL_SALT: &[u8] = b"Control-Salt";
const WRITE_INFO: &[u8] = b"Control-Write-Encryption-Key";
const READ_INFO: &[u8] = b"Control-Read-Encryption-Key";

/// Keys used for the encrypted control channel after pair-setup.
pub struct ControlKeys {
    /// Key used to encrypt control-channel data sent to the receiver.
    pub write: [u8; 32],
    /// Key used to decrypt control-channel data received from the receiver.
    pub read: [u8; 32],
}

impl fmt::Debug for ControlKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlKeys(..)")
    }
}

/// Derive the directional control-channel keys from the SRP session key.
///
/// HKDF accepts input key material of any length, so unexpected input lengths
/// are handled without panicking.
pub fn derive_control_keys(session_key: &[u8]) -> Result<ControlKeys> {
    let hkdf = Hkdf::<Sha512>::new(Some(CONTROL_SALT), session_key);
    let mut write = [0_u8; 32];
    let mut read = [0_u8; 32];

    hkdf.expand(WRITE_INFO, &mut write)
        .map_err(|error| Error::Crypto(format!("hkdf write-key expansion failed: {error}")))?;
    hkdf.expand(READ_INFO, &mut read)
        .map_err(|error| Error::Crypto(format!("hkdf read-key expansion failed: {error}")))?;

    Ok(ControlKeys { write, read })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let session_key = [0x42_u8; 64];
        let first = derive_control_keys(&session_key).expect("first derivation");
        let second = derive_control_keys(&session_key).expect("second derivation");

        assert_eq!(first.write, second.write);
        assert_eq!(first.read, second.read);
    }

    #[test]
    fn write_and_read_keys_differ() {
        let keys = derive_control_keys(&[0x42_u8; 64]).expect("derive keys");

        assert_ne!(keys.write, keys.read);
    }

    #[test]
    fn different_session_keys_produce_different_keys() {
        let first = derive_control_keys(&[0x11_u8; 64]).expect("derive first keys");
        let second = derive_control_keys(&[0x22_u8; 64]).expect("derive second keys");

        assert_ne!(first.write, second.write);
        assert_ne!(first.read, second.read);
    }

    #[test]
    fn arbitrary_length_input_is_supported() {
        let first = derive_control_keys(b"short").expect("derive from short input");
        let second = derive_control_keys(b"short").expect("repeat short input");

        assert_eq!(first.write, second.write);
        assert_eq!(first.read, second.read);
    }

    #[test]
    fn debug_output_redacts_key_material() {
        let keys = ControlKeys {
            write: [0xa1; 32],
            read: [0xb2; 32],
        };
        let debug = format!("{keys:?}");

        assert_eq!(debug, "ControlKeys(..)");
        assert!(!debug.contains("a1a1a1a1"));
        assert!(!debug.contains("[161, 161"));
        assert!(!debug.contains("b2b2b2b2"));
        assert!(!debug.contains("[178, 178"));
    }
}
