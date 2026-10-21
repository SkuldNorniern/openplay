//! HomeKit pair-setup for AirPlay.
//!
//! Transient pairing (`X-Apple-HKP: 4`) runs SRP-6a over TLV8 to derive a shared
//! secret, from which the ChaCha20-Poly1305 control keys are expanded. No
//! long-term keys are persisted.

pub mod keys;
pub mod srp;
pub mod tlv;

pub use tlv::{Tlv, TlvType};

use std::fmt;

use crate::error::{Error, Result};
use srp::{SrpClient, TRANSIENT_PASSWORD, USERNAME};

/// Initial pair-setup state.
pub struct Init;

/// Pair-setup state waiting for the receiver's M2 challenge.
pub struct AwaitM2 {
    srp: SrpClient,
}

/// Pair-setup state waiting for the receiver's M4 proof.
pub struct AwaitM4 {
    srp: SrpClient,
}

/// Everything a finished pair-setup yields.
pub struct Paired {
    /// Keys for the encrypted RTSP control channel.
    pub control_keys: keys::ControlKeys,
    /// Raw SRP session key; the audio stream secret is taken from it.
    pub session_key: Vec<u8>,
}

impl fmt::Debug for Paired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Paired(..)")
    }
}

/// Sans-IO transient pair-setup driver.
///
/// Response-processing methods consume the driver. Any protocol or
/// authentication error therefore fails closed: the exchange cannot be resumed
/// and the caller must create a fresh driver to retry.
pub struct PairSetup<S> {
    state: S,
}

impl PairSetup<Init> {
    /// Create a new transient pair-setup exchange.
    pub fn new() -> Self {
        Self { state: Init }
    }

    /// Build M1 and transition to waiting for M2.
    pub fn start(self) -> (Tlv, PairSetup<AwaitM2>) {
        let m1 = Tlv::new()
            .put_u8(TlvType::Method, 0)
            .put_u8(TlvType::State, 1)
            .put(TlvType::Flags, &[0x10, 0, 0, 0]);

        (
            m1,
            PairSetup {
                state: AwaitM2 {
                    srp: SrpClient::new(),
                },
            },
        )
    }
}

impl Default for PairSetup<Init> {
    fn default() -> Self {
        Self::new()
    }
}

impl PairSetup<AwaitM2> {
    /// Consume M2, build M3, and transition to waiting for M4.
    pub fn process_m2(mut self, m2: &Tlv) -> Result<(Tlv, PairSetup<AwaitM4>)> {
        validate_response(m2, 2, "M2")?;
        let salt = required_field(m2, TlvType::Salt, "M2 Salt")?;
        let server_public = required_field(m2, TlvType::PublicKey, "M2 PublicKey")?;
        let (client_public, client_proof) =
            self.state
                .srp
                .process_challenge(USERNAME, TRANSIENT_PASSWORD, salt, server_public)?;
        let m3 = Tlv::new()
            .put_u8(TlvType::State, 3)
            .put(TlvType::PublicKey, &client_public)
            .put(TlvType::Proof, &client_proof);

        Ok((
            m3,
            PairSetup {
                state: AwaitM4 {
                    srp: self.state.srp,
                },
            },
        ))
    }
}

impl PairSetup<AwaitM4> {
    /// Consume and authenticate M4, then derive the control-channel keys.
    pub fn process_m4(self, m4: &Tlv) -> Result<Paired> {
        validate_response(m4, 4, "M4")?;
        let server_proof = required_field(m4, TlvType::Proof, "M4 Proof")?;
        let session_key = self.state.srp.verify_server(server_proof)?;
        let control_keys = keys::derive_control_keys(&session_key)?;

        Ok(Paired {
            control_keys,
            session_key,
        })
    }
}

fn validate_response(tlv: &Tlv, expected_state: u8, message: &str) -> Result<()> {
    // `error_code()` returns `None` both when Error is genuinely absent and when
    // it is present but not exactly one byte (e.g. coalesced from adjacent
    // fragments). Those are different situations: an Error field the receiver
    // did send must never be silently treated as "no error occurred", so the
    // raw field is inspected here instead of relying on that collapsed result.
    match tlv.get(TlvType::Error) {
        None => {}
        Some([code]) => {
            return Err(Error::Pairing(format!(
                "{message}: receiver returned error code {code}"
            )));
        }
        Some(value) => {
            return Err(Error::Pairing(format!(
                "{message}: malformed Error field ({} bytes)",
                value.len()
            )));
        }
    }

    match tlv.get(TlvType::State) {
        Some([actual]) if *actual == expected_state => Ok(()),
        Some([actual]) => Err(Error::Pairing(format!(
            "{message}: expected State {expected_state}, received {actual}"
        ))),
        Some(value) => Err(Error::Pairing(format!(
            "{message}: State must contain one byte, received {} bytes",
            value.len()
        ))),
        None => Err(Error::Pairing(format!("{message}: missing State"))),
    }
}

fn required_field<'a>(tlv: &'a Tlv, field: TlvType, name: &str) -> Result<&'a [u8]> {
    tlv.get(field)
        .ok_or_else(|| Error::Pairing(format!("{name}: missing required field")))
}

#[cfg(test)]
mod tests {
    use sha2::Sha512;
    use srp::{Client, Server, groups::G3072};

    use super::{AwaitM2, AwaitM4, PairSetup, TRANSIENT_PASSWORD, Tlv, TlvType, USERNAME};

    const SALT: &[u8] = b"transient-salt!";
    const SERVER_SECRET: &[u8] = b"receiver ephemeral secret value";

    fn receiver_challenge() -> (Server<G3072, Sha512>, Vec<u8>, Vec<u8>) {
        let registration = Client::<G3072, Sha512>::new();
        let password_verifier = registration.compute_verifier(USERNAME, TRANSIENT_PASSWORD, SALT);
        // g_no_pad: the HomeKit proof form a real receiver checks.
        let server = Server::<G3072, Sha512>::new_with_options(true);
        let server_public = server.compute_public_ephemeral(SERVER_SECRET, &password_verifier);

        (server, password_verifier, server_public)
    }

    fn awaiting_m2() -> PairSetup<AwaitM2> {
        let (_, driver) = PairSetup::new().start();
        driver
    }

    fn awaiting_m4() -> PairSetup<AwaitM4> {
        let (_, _, server_public) = receiver_challenge();
        let m2 = Tlv::new()
            .put_u8(TlvType::State, 2)
            .put(TlvType::Salt, SALT)
            .put(TlvType::PublicKey, &server_public);
        let (_, driver) = awaiting_m2().process_m2(&m2).expect("process M2");
        driver
    }

    #[test]
    fn completes_pair_setup_and_derives_control_keys() {
        let (server, password_verifier, server_public) = receiver_challenge();
        let (m1, driver) = PairSetup::new().start();
        assert_eq!(m1.get_u8(TlvType::State), Some(1));

        let m2 = Tlv::new()
            .put_u8(TlvType::State, 2)
            .put(TlvType::Salt, SALT)
            .put(TlvType::PublicKey, &server_public);
        let (m3, driver) = driver.process_m2(&m2).expect("process M2");
        assert_eq!(m3.get_u8(TlvType::State), Some(3));

        let client_public = m3
            .get(TlvType::PublicKey)
            .expect("M3 contains client public value");
        let client_proof = m3.get(TlvType::Proof).expect("M3 contains client proof");
        let server_verifier = server
            .process_reply(
                USERNAME,
                SALT,
                SERVER_SECRET,
                &password_verifier,
                client_public,
            )
            .expect("server processes M3 public value");
        let server_key = server_verifier
            .verify_client(client_proof)
            .expect("server verifies M3 proof")
            .to_vec();
        let m4 = Tlv::new()
            .put_u8(TlvType::State, 4)
            .put(TlvType::Proof, server_verifier.proof());

        let paired = driver.process_m4(&m4).expect("process M4");
        assert_ne!(paired.control_keys.write, paired.control_keys.read);
        assert_eq!(paired.session_key, server_key);
    }

    #[test]
    fn rejects_m2_receiver_error() {
        let m2 = Tlv::new()
            .put_u8(TlvType::Error, 2)
            .put_u8(TlvType::State, 99);

        let error = match awaiting_m2().process_m2(&m2) {
            Err(error) => error,
            Ok(_) => panic!("receiver error must fail"),
        };
        assert!(error.to_string().contains("error code 2"));
    }

    #[test]
    fn rejects_m2_with_malformed_error_field() {
        // An empty Error field must not be treated as "no error" -- the
        // receiver explicitly sent one, so a response that would otherwise
        // look valid (State=2 plus Salt/PublicKey) must still be rejected.
        let (_, _, server_public) = receiver_challenge();
        let m2 = Tlv::new()
            .put(TlvType::Error, &[])
            .put_u8(TlvType::State, 2)
            .put(TlvType::Salt, SALT)
            .put(TlvType::PublicKey, &server_public);

        let error = match awaiting_m2().process_m2(&m2) {
            Err(error) => error,
            Ok(_) => panic!("malformed Error field must not be silently accepted"),
        };
        assert!(error.to_string().contains("malformed Error"));
    }

    #[test]
    fn rejects_m2_wrong_state() {
        let m2 = Tlv::new().put_u8(TlvType::State, 3);

        assert!(awaiting_m2().process_m2(&m2).is_err());
    }

    #[test]
    fn rejects_m2_missing_salt_or_public_key() {
        let missing_salt = Tlv::new()
            .put_u8(TlvType::State, 2)
            .put(TlvType::PublicKey, &[1]);
        assert!(awaiting_m2().process_m2(&missing_salt).is_err());

        let missing_public = Tlv::new()
            .put_u8(TlvType::State, 2)
            .put(TlvType::Salt, SALT);
        assert!(awaiting_m2().process_m2(&missing_public).is_err());
    }

    #[test]
    fn rejects_m4_wrong_state() {
        let m4 = Tlv::new().put_u8(TlvType::State, 3);

        assert!(awaiting_m4().process_m4(&m4).is_err());
    }
}
