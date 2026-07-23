//! Crate-wide error type.
//!
//! Hand-rolled to keep the dependency surface small — no `thiserror`/`anyhow`.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::result::Result as StdResult;

/// Convenience alias used throughout the crate.
pub type Result<T> = StdResult<T, Error>;

/// Every fallible operation in openplay reports through this enum.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure (sockets, files).
    Io(io::Error),
    /// mDNS discovery failed or returned nothing usable.
    Discovery(String),
    /// RTSP request/response could not be built or parsed.
    Rtsp(String),
    /// Pairing handshake failed.
    Pairing(String),
    /// Cryptographic operation failed.
    Crypto(String),
    /// A protocol invariant was violated by the peer or by us.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Discovery(m) => write!(f, "discovery: {m}"),
            Error::Rtsp(m) => write!(f, "rtsp: {m}"),
            Error::Pairing(m) => write!(f, "pairing: {m}"),
            Error::Crypto(m) => write!(f, "crypto: {m}"),
            Error::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
