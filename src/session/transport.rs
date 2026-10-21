//! RTSP control-channel transport and its post-pairing record layer.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::cipher::{OpeningKey, SealingKey};
use crate::error::{Error, Result};
use crate::pairing::keys::ControlKeys;
use crate::rtsp::{self, Request, Response};

const AUTH_TAG_LEN: usize = 16;
const READ_CHUNK_LEN: usize = 2048;
/// HomeKit encrypted frames carry at most this much plaintext each, so a
/// longer message is split across consecutive frames in both directions.
const MAX_RECORD_PLAINTEXT: usize = 1024;

/// Upper bound on a buffered plaintext response. `rtsp::parse_response` has no
/// size cap of its own, so without this a peer that never sends a terminating
/// blank line, or that advertises a huge `Content-Length`, would grow
/// `read_buf` without limit. Matches the cap `info::fetch` already uses for
/// the same reason; real control messages are at most a few KiB.
const MAX_PLAINTEXT_RESPONSE: usize = 64 * 1024;

/// Carries RTSP over the connection that survives transient pairing.
///
/// Pair-setup begins with ordinary RTSP messages. Once it yields directional
/// control keys, [`ControlTransport::upgrade`] keeps the same stream but wraps
/// every later message in the authenticated record framing required by the
/// receiver.
pub struct ControlTransport<S> {
    stream: S,
    read_buf: Vec<u8>,
    sealing: Option<SealingKey>,
    opening: Option<OpeningKey>,
}

impl<S> ControlTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Start a plaintext control channel on an already-connected stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: Vec::new(),
            sealing: None,
            opening: None,
        }
    }

    /// Install the one directional key pair owned by this connection.
    ///
    /// Re-upgrading is rejected because fresh cipher instances would restart
    /// their nonce sequences and either desynchronize the channel or reuse a
    /// nonce with existing key material.
    pub fn upgrade(&mut self, keys: ControlKeys) -> Result<()> {
        if self.sealing.is_some() || self.opening.is_some() {
            return Err(Error::Protocol(
                "control transport is already encrypted".to_owned(),
            ));
        }
        if !self.read_buf.is_empty() {
            return Err(Error::Protocol(
                "cannot upgrade with unread plaintext data".to_owned(),
            ));
        }

        let ControlKeys { write, read } = keys;
        self.sealing = Some(SealingKey::new(write));
        self.opening = Some(OpeningKey::new(read));
        Ok(())
    }

    /// Send one complete RTSP request in the channel's current wire mode.
    ///
    /// Once encrypted, the request goes out as one or more frames of at most
    /// [`MAX_RECORD_PLAINTEXT`] bytes, each with its own length prefix.
    pub async fn send(&mut self, request: &Request) -> Result<()> {
        let plaintext = request.encode();
        if let Some(sealing) = self.sealing.as_mut() {
            for chunk in plaintext.chunks(MAX_RECORD_PLAINTEXT) {
                let length = u16::try_from(chunk.len())
                    .map_err(|_| Error::Protocol("encrypted record too long".to_owned()))?
                    .to_le_bytes();
                // The length prefix is authenticated as AAD, as HomeKit framing requires.
                let ciphertext = sealing.seal(&length, chunk)?;
                self.stream.write_all(&length).await?;
                self.stream.write_all(&ciphertext).await?;
            }
        } else {
            self.stream.write_all(&plaintext).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive one complete RTSP response in the channel's current wire mode.
    pub async fn receive(&mut self) -> Result<Response> {
        if self.opening.is_some() {
            self.receive_encrypted().await
        } else {
            self.receive_plaintext().await
        }
    }

    async fn receive_plaintext(&mut self) -> Result<Response> {
        let mut chunk = [0_u8; READ_CHUNK_LEN];
        loop {
            if let Some((response, consumed)) = rtsp::parse_response(&self.read_buf)? {
                self.read_buf.drain(..consumed);
                return Ok(response);
            }

            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(Error::Protocol(
                    "control connection closed while reading RTSP response".to_owned(),
                ));
            }
            self.read_buf.extend_from_slice(&chunk[..read]);
            if self.read_buf.len() > MAX_PLAINTEXT_RESPONSE {
                return Err(Error::Protocol(
                    "plaintext RTSP response exceeded the maximum buffered size".to_owned(),
                ));
            }
        }
    }

    /// Decrypt frames until they add up to one RTSP response. A response
    /// longer than one frame, such as `/info`, spans several.
    async fn receive_encrypted(&mut self) -> Result<Response> {
        loop {
            if let Some((response, consumed)) = rtsp::parse_response(&self.read_buf)? {
                self.read_buf.drain(..consumed);
                return Ok(response);
            }

            let mut length = [0_u8; 2];
            read_fully(&mut self.stream, &mut length, "encrypted record length").await?;
            let plaintext_len = usize::from(u16::from_le_bytes(length));
            let mut ciphertext = vec![0_u8; plaintext_len + AUTH_TAG_LEN];
            read_fully(&mut self.stream, &mut ciphertext, "encrypted record body").await?;

            let opening = self.opening.as_mut().ok_or_else(|| {
                Error::Protocol("encrypted transport has no opening key".to_owned())
            })?;
            let plaintext = opening.open(&length, &ciphertext)?;
            self.read_buf.extend_from_slice(&plaintext);
            if self.read_buf.len() > MAX_PLAINTEXT_RESPONSE {
                return Err(Error::Protocol(
                    "encrypted RTSP response exceeded the maximum buffered size".to_owned(),
                ));
            }
        }
    }
}

async fn read_fully<S>(stream: &mut S, buffer: &mut [u8], part: &str) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut offset = 0;
    while offset < buffer.len() {
        let read = stream.read(&mut buffer[offset..]).await?;
        if read == 0 {
            return Err(Error::Protocol(format!(
                "control connection closed while reading {part}"
            )));
        }
        offset += read;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::slice;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio::spawn;

    use super::*;

    const RESPONSE: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n";
    const WRITE_KEY: [u8; 32] = [0x31; 32];
    const READ_KEY: [u8; 32] = [0x72; 32];

    fn request() -> Request {
        Request::new("GET", "/info").header("CSeq", "1")
    }

    fn keys() -> ControlKeys {
        ControlKeys {
            write: WRITE_KEY,
            read: READ_KEY,
        }
    }

    async fn read_record(peer: &mut DuplexStream) -> Vec<u8> {
        let mut length = [0_u8; 2];
        peer.read_exact(&mut length)
            .await
            .expect("read record length");
        let plaintext_len = usize::from(u16::from_le_bytes(length));
        let mut ciphertext = vec![0_u8; plaintext_len + AUTH_TAG_LEN];
        peer.read_exact(&mut ciphertext)
            .await
            .expect("read record body");
        ciphertext
    }

    #[tokio::test]
    async fn plaintext_round_trip_has_no_outer_framing() {
        let (client, mut peer) = duplex(4096);
        let mut transport = ControlTransport::new(client);
        let request = request();
        let expected = request.encode();

        transport.send(&request).await.expect("send request");
        let mut received = vec![0_u8; expected.len()];
        peer.read_exact(&mut received).await.expect("read request");
        assert_eq!(received, expected);

        peer.write_all(RESPONSE).await.expect("write response");
        peer.flush().await.expect("flush response");
        let response = transport.receive().await.expect("receive response");
        assert_eq!(response.status, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(response.headers.get("CSeq"), Some("1"));
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn encrypted_round_trip_uses_crossed_directional_keys() {
        let (client, mut peer) = duplex(4096);
        let mut transport = ControlTransport::new(client);
        transport.upgrade(keys()).expect("upgrade");

        let mut peer_sealing = SealingKey::new(READ_KEY);
        let ciphertext = peer_sealing
            .seal(&(RESPONSE.len() as u16).to_le_bytes(), RESPONSE)
            .expect("seal response");
        peer.write_all(&(RESPONSE.len() as u16).to_le_bytes())
            .await
            .expect("write response length");
        peer.write_all(&ciphertext)
            .await
            .expect("write encrypted response");
        peer.flush().await.expect("flush encrypted response");

        let response = transport.receive().await.expect("receive response");
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get("CSeq"), Some("1"));

        let request = request();
        let expected = request.encode();
        transport.send(&request).await.expect("send request");
        let ciphertext = read_record(&mut peer).await;
        let mut peer_opening = OpeningKey::new(WRITE_KEY);
        let plaintext = peer_opening
            .open(&(expected.len() as u16).to_le_bytes(), &ciphertext)
            .expect("open request");
        assert_eq!(plaintext, expected);
    }

    #[tokio::test]
    async fn long_request_is_split_into_1024_byte_frames() {
        let (client, mut peer) = duplex(8192);
        let mut transport = ControlTransport::new(client);
        transport.upgrade(keys()).expect("upgrade");
        let request = Request::new("SETUP", "/1").body(vec![0x5a; 1500]);
        let expected = request.encode();

        transport.send(&request).await.expect("send request");
        let mut peer_opening = OpeningKey::new(WRITE_KEY);
        let mut received = Vec::new();
        let mut frame_lengths = Vec::new();
        while received.len() < expected.len() {
            let ciphertext = read_record(&mut peer).await;
            let length = ciphertext.len() - AUTH_TAG_LEN;
            frame_lengths.push(length);
            let length = u16::try_from(length).expect("frame length").to_le_bytes();
            received.extend(peer_opening.open(&length, &ciphertext).expect("open frame"));
        }

        assert_eq!(received, expected);
        assert_eq!(frame_lengths, [1024, expected.len() - 1024]);
    }

    #[tokio::test]
    async fn response_spanning_frames_is_reassembled() {
        let (client, mut peer) = duplex(8192);
        let mut transport = ControlTransport::new(client);
        transport.upgrade(keys()).expect("upgrade");
        let mut response = b"RTSP/1.0 200 OK\r\nContent-Length: 1500\r\n\r\n".to_vec();
        response.extend([0x5a; 1500]);

        let mut peer_sealing = SealingKey::new(READ_KEY);
        for chunk in response.chunks(1024) {
            let length = u16::try_from(chunk.len())
                .expect("frame length")
                .to_le_bytes();
            let ciphertext = peer_sealing.seal(&length, chunk).expect("seal frame");
            peer.write_all(&length).await.expect("write length");
            peer.write_all(&ciphertext).await.expect("write frame");
        }

        let response = transport.receive().await.expect("receive response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, vec![0x5a; 1500]);
    }

    #[tokio::test]
    async fn second_upgrade_is_rejected() {
        let (client, _peer) = duplex(4096);
        let mut transport = ControlTransport::new(client);

        transport.upgrade(keys()).expect("first upgrade");
        let error = transport.upgrade(keys()).expect_err("second upgrade");

        assert!(matches!(error, Error::Protocol(_)));
        assert!(error.to_string().contains("already encrypted"));
    }

    #[tokio::test]
    async fn plaintext_receive_handles_byte_by_byte_delivery() {
        let (client, mut peer) = duplex(4096);
        let mut transport = ControlTransport::new(client);

        for byte in RESPONSE {
            peer.write_all(slice::from_ref(byte))
                .await
                .expect("write response byte");
            peer.flush().await.expect("flush response byte");
        }

        let response = transport.receive().await.expect("receive response");
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn encrypted_receive_handles_separate_prefix_and_body_chunks() {
        let (client, mut peer) = duplex(4096);
        let mut transport = ControlTransport::new(client);
        transport.upgrade(keys()).expect("upgrade");
        let mut peer_sealing = SealingKey::new(READ_KEY);
        let ciphertext = peer_sealing
            .seal(&(RESPONSE.len() as u16).to_le_bytes(), RESPONSE)
            .expect("seal response");
        let length = (RESPONSE.len() as u16).to_le_bytes();

        peer.write_all(&length[..1])
            .await
            .expect("write prefix byte");
        peer.flush().await.expect("flush prefix byte");
        peer.write_all(&length[1..])
            .await
            .expect("write rest of prefix");
        peer.flush().await.expect("flush rest of prefix");
        for chunk in ciphertext.chunks(3) {
            peer.write_all(chunk).await.expect("write body chunk");
            peer.flush().await.expect("flush body chunk");
        }

        let response = transport.receive().await.expect("receive response");
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn closed_connection_mid_record_returns_error() {
        let (client, mut peer) = duplex(4096);
        let mut transport = ControlTransport::new(client);
        transport.upgrade(keys()).expect("upgrade");

        peer.write_all(&[RESPONSE.len() as u8])
            .await
            .expect("write partial prefix");
        peer.flush().await.expect("flush partial prefix");
        drop(peer);

        let error = transport.receive().await.expect_err("early EOF");
        assert!(matches!(error, Error::Protocol(_)));
        assert!(error.to_string().contains("record length"));
    }

    #[tokio::test]
    async fn plaintext_response_with_no_terminator_is_bounded() {
        // A peer that never sends a blank line (or a Content-Length far larger
        // than any real response) must not be able to grow read_buf without
        // limit -- this is the regression test for that cap.
        let (client, mut peer) = duplex(4096);
        let mut transport = ControlTransport::new(client);

        let writer = spawn(async move {
            let chunk = [b'a'; 4096];
            loop {
                if peer.write_all(&chunk).await.is_err() {
                    return;
                }
            }
        });

        let error = transport
            .receive()
            .await
            .expect_err("unterminated response must be rejected");
        assert!(matches!(error, Error::Protocol(_)));
        assert!(error.to_string().contains("maximum buffered size"));

        writer.abort();
    }
}
