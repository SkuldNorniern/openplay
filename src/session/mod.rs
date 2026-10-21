//! Session runtime: pairing and the control transport on one connection,
//! SETUP and RECORD, and the streaming session that ties them together.

pub mod buffered;
pub mod client;
pub mod event_channel;
pub mod setup;
pub mod stream;
pub mod transport;

pub use client::{Identity, RtspClient, USER_AGENT};
pub use event_channel::EventChannel;
pub use setup::{
    AudioStreamSecret, LocalStreamPorts, SessionId, SessionSetupResponse, StreamSetupResponse,
    parse_session_setup_response, parse_stream_setup_response, record_request,
    session_setup_request, stream_setup_request, volume_db, volume_request,
};
pub use stream::{Streaming, start};
pub use transport::ControlTransport;
