//! RTSP request/response client for one control connection.

use std::io::Cursor;
use std::time::Duration;

use log::{Level, debug, log_enabled};
use plist::Value;
use rand::random;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::pairing::keys::ControlKeys;
use crate::rtsp::{Request, Response};

use super::ControlTransport;

/// User-Agent of the working sender in the HomePod capture. Receivers gate
/// some behavior on the sender's AirPlay version, so this stays fixed.
pub const USER_AGENT: &str = "AirPlay/745.83";
const CLIENT_NAME: &str = "openplay";
/// A receiver that never answers is treated as failed rather than waited on.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Sender identity sent on every request. Keeping it across reconnects,
/// and across runs once stored, lets the receiver see one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    device_id: [u8; 6],
    active_remote: u32,
}

impl Identity {
    pub fn generate() -> Self {
        Self::from_device_id(random())
    }

    /// Rebuild a stored identity from its device ID.
    pub fn from_device_id(device_id: [u8; 6]) -> Self {
        // Active-Remote only has to be stable per device, so derive it.
        let active_remote =
            u32::from_be_bytes([device_id[2], device_id[3], device_id[4], device_id[5]]);
        Self {
            device_id,
            active_remote,
        }
    }

    /// The 6-byte ID to store for [`Self::from_device_id`].
    pub fn device_id(&self) -> [u8; 6] {
        self.device_id
    }

    fn device_id_hex(&self) -> String {
        self.device_id
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn device_id_colons(&self) -> String {
        self.device_id
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Sends RTSP requests with an increasing CSeq and the sender identity
/// headers, and waits for each response in turn.
pub struct RtspClient<S> {
    transport: ControlTransport<S>,
    identity: Identity,
    cseq: u32,
}

impl<S> RtspClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(stream: S, identity: Identity) -> Self {
        Self {
            transport: ControlTransport::new(stream),
            identity,
            cseq: 0,
        }
    }

    /// Switch the connection to the encrypted record layer after pairing.
    pub fn upgrade(&mut self, keys: ControlKeys) -> Result<()> {
        self.transport.upgrade(keys)
    }

    /// Send `request` and return its response, failing on a non-2xx status.
    pub async fn request(&mut self, request: Request) -> Result<Response> {
        self.cseq += 1;
        let request = self.with_common_headers(request);
        let method = request.method.clone();
        let uri = request.uri.clone();
        debug!("rtsp >> {method} {uri} cseq={}", self.cseq);
        self.transport.send(&request).await?;

        let response = timeout(RESPONSE_TIMEOUT, self.transport.receive())
            .await
            .map_err(|_| Error::Rtsp(format!("{method} {uri}: no response")))??;
        debug!(
            "rtsp << {} {} ({} byte body)",
            response.status,
            response.reason,
            response.body.len()
        );
        if log_enabled!(Level::Debug) {
            log_response_details(&response);
        }
        if !response.is_success() {
            return Err(Error::Rtsp(format!(
                "{method} {uri}: status {} {}",
                response.status, response.reason
            )));
        }
        Ok(response)
    }

    fn with_common_headers(&self, request: Request) -> Request {
        let device_id = self.identity.device_id_hex();
        request
            .header("CSeq", self.cseq.to_string())
            .header("Active-Remote", self.identity.active_remote.to_string())
            .header("Client-Instance", device_id.clone())
            .header("DACP-ID", device_id)
            .header("User-Agent", USER_AGENT)
            .header("X-Apple-Client-Name", CLIENT_NAME)
            .header("X-Apple-Device-ID", self.identity.device_id_colons())
    }
}

/// Headers and plist bodies, for learning what a receiver reports, such as
/// its playout latency.
fn log_response_details(response: &Response) {
    for (name, value) in response.headers.iter() {
        if !matches!(name, "CSeq" | "Content-Length" | "Date") {
            debug!("rtsp <<   {name}: {value}");
        }
    }
    let is_plist = response
        .headers
        .get("Content-Type")
        .is_some_and(|kind| kind.contains("plist"));
    if is_plist && let Ok(body) = Value::from_reader(Cursor::new(&response.body)) {
        debug!("rtsp <<   {body:?}");
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio::spawn;

    use super::*;

    const IDENTITY: Identity = Identity {
        device_id: [0x66, 0x5f, 0xdf, 0x25, 0x18, 0x11],
        active_remote: 1_234_567_890,
    };

    async fn read_request(receiver: &mut DuplexStream) -> String {
        let mut buffer = vec![0_u8; 4096];
        let length = receiver.read(&mut buffer).await.expect("read request");
        String::from_utf8(buffer[..length].to_vec()).expect("utf-8 request")
    }

    #[tokio::test]
    async fn requests_carry_identity_and_increasing_cseq() {
        let (sender, mut receiver) = duplex(4096);
        let mut client = RtspClient::new(sender, IDENTITY);
        let fake_receiver = spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..2 {
                requests.push(read_request(&mut receiver).await);
                receiver
                    .write_all(b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .expect("write response");
            }
            requests
        });

        client
            .request(Request::new("GET", "/info"))
            .await
            .expect("first request");
        client
            .request(Request::new("POST", "/feedback"))
            .await
            .expect("second request");
        let requests = fake_receiver.await.expect("fake receiver");

        assert!(requests[0].starts_with("GET /info RTSP/1.0\r\nCSeq: 1\r\n"));
        assert!(requests[1].starts_with("POST /feedback RTSP/1.0\r\nCSeq: 2\r\n"));
        for header in [
            "Active-Remote: 1234567890\r\n",
            "Client-Instance: 665FDF251811\r\n",
            "DACP-ID: 665FDF251811\r\n",
            "User-Agent: AirPlay/745.83\r\n",
            "X-Apple-Device-ID: 66:5F:DF:25:18:11\r\n",
        ] {
            assert!(requests[0].contains(header), "missing {header:?}");
        }
    }

    #[test]
    fn identity_round_trips_through_device_id() {
        let identity = Identity::generate();
        assert_eq!(Identity::from_device_id(identity.device_id()), identity);
    }

    #[tokio::test]
    async fn error_status_fails_with_method_and_status() {
        let (sender, mut receiver) = duplex(4096);
        let mut client = RtspClient::new(sender, IDENTITY);
        spawn(async move {
            let _request = read_request(&mut receiver).await;
            receiver
                .write_all(b"RTSP/1.0 470 Connection Authorization Required\r\n\r\n")
                .await
                .expect("write response");
        });

        let error = client
            .request(Request::new("SETUP", "/1"))
            .await
            .expect_err("non-2xx must fail");
        assert_eq!(
            error.to_string(),
            "rtsp: SETUP /1: status 470 Connection Authorization Required"
        );
    }
}
