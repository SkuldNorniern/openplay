//! Monotonic nonces for one direction of the encrypted control channel.

use crate::error::{Error, Result};

/// A single-owner sequence of ChaCha20-Poly1305 nonces.
///
/// Send and receive directions must each own a separate counter.
pub struct NonceCounter {
    counter: u64,
}

impl NonceCounter {
    /// Start a fresh nonce sequence at zero.
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Produce the next 12-byte nonce and advance the counter.
    ///
    /// The wire representation is four zero bytes followed by the counter in
    /// little-endian byte order. Exhaustion fails instead of reusing nonce zero.
    #[allow(clippy::should_implement_trait)] // The protocol API returns Result, not Iterator's Option.
    pub fn next(&mut self) -> Result<[u8; 12]> {
        let next_counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("control-channel nonce counter exhausted".to_owned()))?;

        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = next_counter;

        Ok(nonce)
    }
}

impl Default for NonceCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn first_nonce_is_all_zeroes() {
        let mut counter = NonceCounter::new();

        assert_eq!(counter.next().expect("first nonce"), [0_u8; 12]);
    }

    #[test]
    fn second_nonce_uses_little_endian_counter() {
        let mut counter = NonceCounter::new();
        let _first = counter.next().expect("first nonce");

        assert_eq!(
            counter.next().expect("second nonce"),
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn sequential_nonces_are_unique() {
        let mut counter = NonceCounter::new();
        let mut nonces = HashSet::new();

        for _ in 0..512 {
            let nonce = counter.next().expect("nonce");
            assert!(nonces.insert(nonce));
        }
    }

    #[test]
    fn exhaustion_returns_an_error() {
        let mut counter = NonceCounter { counter: u64::MAX };

        assert!(counter.next().is_err());
    }
}
