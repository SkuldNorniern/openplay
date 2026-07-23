//! SRP-6a client state for transient HomeKit pair-setup.
//!
//! Pair-setup transports the public values and proofs over TLV8, but SRP itself
//! is independent of that framing. This module owns the ephemeral client state
//! across M2 through M4 and exposes only the values needed by the pairing flow.

use rand::fill;
use sha2::Sha512;
use srp::{AuthError, Client, ClientVerifier, bigint::BoxedUint, groups::G3072};

use crate::error::{Error, Result};

/// SRP identity used by transient pair-setup.
pub const USERNAME: &[u8] = b"Pair-Setup";

/// Fixed setup code used by PIN-less transient pairing.
pub const TRANSIENT_PASSWORD: &[u8] = b"3939";

/// The G3072 modulus is exactly 384 bytes; a well-formed `B` never exceeds that.
/// `BoxedUint::from_be_slice_vartime` sizes its allocation from the input length
/// with no cap of its own, so an oversized value from a malformed or hostile
/// receiver would otherwise force unbounded allocation and bignum work before
/// any validation runs.
const MAX_SERVER_PUBLIC_LEN: usize = 384;

/// RFC5054 salts are typically 16 bytes; this is generous headroom, not a
/// protocol limit. It exists only to keep a malformed `salt` from growing
/// unboundedly on the way into the identity hash.
const MAX_SALT_LEN: usize = 256;

/// Stateful SRP-6a client for one pair-setup exchange.
pub struct SrpClient {
    client: Client<G3072, Sha512>,
    secret: [u8; 32],
    verifier: Option<ClientVerifier<Sha512>>,
}

impl SrpClient {
    /// Begin an exchange with a fresh 256-bit private ephemeral value.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            secret: fresh_secret(),
            verifier: None,
        }
    }

    /// Consume M2 and produce the public value and proof carried by M3.
    ///
    /// A fresh ephemeral exponent is drawn on every call: SRP's security
    /// argument assumes each exchange uses an independent private value, so a
    /// retried challenge on the same client must not reuse the one from `new`
    /// or an earlier attempt.
    pub fn process_challenge(
        &mut self,
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        server_public: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // A failed replacement challenge must not leave an earlier exchange
        // available for M4 verification.
        self.verifier = None;

        if server_public.is_empty() || server_public.len() > MAX_SERVER_PUBLIC_LEN {
            return Err(Error::Pairing(format!(
                "srp: server public value has invalid length {}",
                server_public.len()
            )));
        }
        if salt.is_empty() || salt.len() > MAX_SALT_LEN {
            return Err(Error::Pairing(format!(
                "srp: salt has invalid length {}",
                salt.len()
            )));
        }

        self.secret = fresh_secret();
        let private = BoxedUint::from_be_slice_vartime(&self.secret);
        let client_public: Vec<u8> = self
            .client
            .compute_g_x(&private)
            .to_be_bytes_trimmed_vartime()
            .into();
        let verifier = self
            .client
            .process_reply(&self.secret, username, password, salt, server_public)
            .map_err(pairing_error)?;
        let client_proof = verifier.proof().to_vec();
        self.verifier = Some(verifier);

        Ok((client_public, client_proof))
    }

    /// Authenticate M4 and return the SRP session key used as HKDF input.
    pub fn verify_server(&self, server_proof: &[u8]) -> Result<Vec<u8>> {
        let verifier = self
            .verifier
            .as_ref()
            .ok_or_else(|| Error::Pairing("srp: no challenge has been processed".into()))?;

        verifier
            .verify_server(server_proof)
            .map(Vec::from)
            .map_err(pairing_error)
    }
}

impl Default for SrpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn pairing_error(error: AuthError) -> Error {
    Error::Pairing(format!("srp: {error}"))
}

fn fresh_secret() -> [u8; 32] {
    let mut secret = [0_u8; 32];
    fill(&mut secret);
    secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use srp::Server;

    const SALT: &[u8] = b"transient-salt!";
    const SERVER_SECRET: &[u8] = b"receiver ephemeral secret value";

    fn receiver_challenge() -> (Server<G3072, Sha512>, Vec<u8>, Vec<u8>) {
        let registration = Client::<G3072, Sha512>::new();
        let password_verifier = registration.compute_verifier(USERNAME, TRANSIENT_PASSWORD, SALT);
        let server = Server::<G3072, Sha512>::new();
        let server_public = server.compute_public_ephemeral(SERVER_SECRET, &password_verifier);

        (server, password_verifier, server_public)
    }

    #[test]
    fn completes_round_trip_and_agrees_on_session_key() {
        let (server, password_verifier, server_public) = receiver_challenge();
        let mut client = SrpClient::new();
        let (client_public, client_proof) = client
            .process_challenge(USERNAME, TRANSIENT_PASSWORD, SALT, &server_public)
            .expect("client processes M2");
        let server_verifier = server
            .process_reply(
                USERNAME,
                SALT,
                SERVER_SECRET,
                &password_verifier,
                &client_public,
            )
            .expect("server processes M3 public value");
        let server_key = server_verifier
            .verify_client(&client_proof)
            .expect("server verifies M3 proof")
            .to_vec();
        let client_key = client
            .verify_server(server_verifier.proof())
            .expect("client verifies M4 proof");

        assert_eq!(client_key, server_key);
    }

    #[test]
    fn rejects_corrupted_server_proof() {
        let (_, _, server_public) = receiver_challenge();
        let mut client = SrpClient::new();
        client
            .process_challenge(USERNAME, TRANSIENT_PASSWORD, SALT, &server_public)
            .expect("client processes M2");

        assert!(client.verify_server(&[0_u8; 64]).is_err());
    }

    #[test]
    fn rejects_zero_server_public_value() {
        let mut client = SrpClient::new();

        let error = client
            .process_challenge(USERNAME, TRANSIENT_PASSWORD, SALT, &[0_u8; 384])
            .expect_err("zero B must be rejected");
        assert!(matches!(error, Error::Pairing(_)));
    }

    #[test]
    fn rejects_oversized_server_public_before_touching_bignum_code() {
        let mut client = SrpClient::new();
        let huge = vec![1_u8; MAX_SERVER_PUBLIC_LEN + 1];

        let error = client
            .process_challenge(USERNAME, TRANSIENT_PASSWORD, SALT, &huge)
            .expect_err("oversized B must be rejected");
        assert!(matches!(error, Error::Pairing(_)));
    }

    #[test]
    fn rejects_empty_and_oversized_salt() {
        let mut client = SrpClient::new();
        let (_, _, server_public) = receiver_challenge();

        assert!(
            client
                .process_challenge(USERNAME, TRANSIENT_PASSWORD, b"", &server_public)
                .is_err()
        );
        let huge_salt = vec![1_u8; MAX_SALT_LEN + 1];
        assert!(
            client
                .process_challenge(USERNAME, TRANSIENT_PASSWORD, &huge_salt, &server_public)
                .is_err()
        );
    }

    #[test]
    fn draws_a_fresh_ephemeral_on_every_challenge() {
        let (_, _, server_public) = receiver_challenge();
        let mut client = SrpClient::new();
        let first_secret = client.secret;

        client
            .process_challenge(USERNAME, TRANSIENT_PASSWORD, SALT, &server_public)
            .expect("first challenge succeeds");
        let second_secret = client.secret;

        // A retried challenge on the same client must not reuse the ephemeral
        // exponent from construction or from the previous attempt.
        assert_ne!(first_secret, second_secret);

        client
            .process_challenge(USERNAME, TRANSIENT_PASSWORD, SALT, &server_public)
            .expect("second challenge succeeds");
        let third_secret = client.secret;
        assert_ne!(second_secret, third_secret);
    }
}
