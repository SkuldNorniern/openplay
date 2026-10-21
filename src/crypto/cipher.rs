//! Directional AEAD state for RTSP control-channel messages.

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use super::nonce::NonceCounter;
use crate::error::{Error, Result};

/// Encrypts outgoing control-channel messages with a strictly ordered nonce sequence.
///
/// Exactly one `SealingKey` may exist per control-channel key for the lifetime
/// of a session: each instance starts its nonce counter at zero, so deriving a
/// second `SealingKey` from the same key bytes reuses `(key, nonce)` pairs and
/// breaks both confidentiality and authentication for every message either
/// instance sends. A key must never outlive or be shared beyond the one
/// `SealingKey` constructed from it.
pub struct SealingKey {
    cipher: ChaCha20Poly1305,
    nonces: NonceCounter,
}

impl SealingKey {
    /// Create outgoing cipher state from a 32-byte control-channel key.
    ///
    /// See the type-level doc: this key must not be reused to construct
    /// another `SealingKey`.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            nonces: NonceCounter::new(),
        }
    }

    /// Encrypt one message with the next nonce in sequence.
    ///
    /// An `Err` here must be treated as fatal to the whole control channel:
    /// the nonce drawn for the failed attempt is not recoverable, so retrying
    /// or continuing on this instance would desynchronize it from the peer.
    /// The caller must tear down the channel and re-pair.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from(self.nonces.next()?);
        self.cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("aead: encryption failed".to_owned()))
    }
}

impl fmt::Debug for SealingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealingKey(..)")
    }
}

/// Decrypts incoming control-channel messages with a strictly ordered nonce sequence.
///
/// As with [`SealingKey`], exactly one `OpeningKey` may exist per
/// control-channel key for the lifetime of a session.
pub struct OpeningKey {
    cipher: ChaCha20Poly1305,
    nonces: NonceCounter,
}

impl OpeningKey {
    /// Create incoming cipher state from a 32-byte control-channel key.
    ///
    /// See [`SealingKey::new`]: this key must not be reused to construct
    /// another `OpeningKey`.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            nonces: NonceCounter::new(),
        }
    }

    /// Decrypt one message with the next nonce in sequence.
    ///
    /// An `Err` here — whether from a genuinely tampered message or one
    /// dropped/reordered in transit — must be treated as fatal to the whole
    /// control channel: the nonce advances regardless of outcome, so any
    /// message processed after a failure is checked against the wrong nonce.
    /// The caller must tear down the channel and re-pair, not retry.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from(self.nonces.next()?);
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("aead: authentication failed".to_owned()))
    }
}

impl fmt::Debug for OpeningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpeningKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Record length prefix, as the control channel authenticates it.
    const AAD: &[u8] = &[0x0d, 0x00];

    #[test]
    fn round_trips_different_plaintexts_and_keys() {
        for (key, plaintext) in [
            ([0x11; 32], b"first control message".as_slice()),
            ([0xa5; 32], b"\0binary\0control\0message".as_slice()),
        ] {
            let mut sealing = SealingKey::new(key);
            let mut opening = OpeningKey::new(key);
            let ciphertext = sealing.seal(AAD, plaintext).expect("seal");

            assert_eq!(opening.open(AAD, &ciphertext).expect("open"), plaintext);
        }
    }

    #[test]
    fn sequential_messages_round_trip_in_order() {
        let key = [0x42; 32];
        let messages = [
            b"message one".as_slice(),
            b"message two".as_slice(),
            b"message three".as_slice(),
        ];
        let mut sealing = SealingKey::new(key);
        let mut opening = OpeningKey::new(key);
        let ciphertexts: Vec<_> = messages
            .iter()
            .map(|message| sealing.seal(AAD, message).expect("seal"))
            .collect();

        for (ciphertext, message) in ciphertexts.iter().zip(messages) {
            assert_eq!(opening.open(AAD, ciphertext).expect("open"), message);
        }
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = [0x33; 32];
        let mut sealing = SealingKey::new(key);
        let mut ciphertext = sealing.seal(AAD, b"authenticated").expect("seal");
        ciphertext[0] ^= 0x80;
        let mut opening = OpeningKey::new(key);

        assert!(opening.open(AAD, &ciphertext).is_err());
    }

    #[test]
    fn different_length_prefix_fails_authentication() {
        let key = [0x66; 32];
        let mut sealing = SealingKey::new(key);
        let ciphertext = sealing.seal(AAD, b"length bound").expect("seal");
        let mut opening = OpeningKey::new(key);

        assert!(opening.open(&[0x0e, 0x00], &ciphertext).is_err());
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let mut sealing = SealingKey::new([0x44; 32]);
        let ciphertext = sealing.seal(AAD, b"secret").expect("seal");
        let mut opening = OpeningKey::new([0x45; 32]);

        assert!(opening.open(AAD, &ciphertext).is_err());
    }

    #[test]
    fn out_of_order_message_fails_authentication() {
        let key = [0x55; 32];
        let mut sealing = SealingKey::new(key);
        let _first = sealing.seal(AAD, b"first").expect("seal first");
        let second = sealing.seal(AAD, b"second").expect("seal second");
        let mut opening = OpeningKey::new(key);

        assert!(opening.open(AAD, &second).is_err());
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", SealingKey::new([0xa1; 32])),
            "SealingKey(..)"
        );
        assert_eq!(
            format!("{:?}", OpeningKey::new([0xb2; 32])),
            "OpeningKey(..)"
        );
    }
}
