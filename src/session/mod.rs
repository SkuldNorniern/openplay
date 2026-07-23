//! Session runtime pieces that keep pairing and the control transport on one
//! connection, and will eventually drive SETUP, RECORD, and media streaming.

pub mod event_channel;
pub mod setup;
pub mod transport;

pub use event_channel::EventChannel;
pub use setup::{
    AudioStreamSecret, LocalStreamPorts, SessionId, SessionSetupResponse, StreamSetupResponse,
    parse_session_setup_response, parse_stream_setup_response, record_request,
    session_setup_request, stream_setup_request,
};
pub use transport::ControlTransport;
