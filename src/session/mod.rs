//! Session runtime pieces that keep pairing and the control transport on one
//! connection, and will eventually drive SETUP, RECORD, and media streaming.

pub mod transport;

pub use transport::ControlTransport;
