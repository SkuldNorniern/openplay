//! RTSP control-channel transport and its post-pairing record layer.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::cipher::{OpeningKey, SealingKey};
use crate::error::{Error, Result};
use crate::pairing::keys::ControlKeys;
use crate::rtsp::{self, Request, Response};

const AUTH_TAG_LEN: usize = 16;
const READ_CHUNK_LEN: usize = 2048;

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
    /// Once encrypted, a request is capped at 65535 bytes: the record framing
    /// uses a 2-byte length prefix and this protocol has no multi-record
    /// fragmentation for a single message. Pairing and SETUP/RECORD control
    /// messages are all comfortably under this; a future request built around
    /// a large embedded blob (e.g. artwork) would need its own framing, not
    /// just a bigger integer here.
    pub async fn send(&mut self, request: &Request) -> Result<()> {
        let plaintext = request.encode();
        if let Some(sealing) = self.sealing.as_mut() {
            let plaintext_len = u16::try_from(plaintext.len()).map_err(|_| {
                Error::Protocol("encrypted RTSP request exceeds record length".to_owned())
            })?;
            let ciphertext = sealing.seal(&plaintext)?;
            self.stream.write_all(&plaintext_len.to_le_bytes()).await?;
            self.stream.write_all(&ciphertext).await?;
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

    async fn receive_encrypted(&mut self) -> Result<Response> {
        let mut length = [0_u8; 2];
        read_fully(&mut self.stream, &mut length, "encrypted record length").await?;
        let plaintext_len = usize::from(u16::from_le_bytes(length));
        let ciphertext_len = plaintext_len.checked_add(AUTH_TAG_LEN).ok_or_else(|| {
            Error::Protocol("encrypted control record length overflow".to_owned())
        })?;
        let mut ciphertext = vec![0_u8; ciphertext_len];
        read_fully(&mut self.stream, &mut ciphertext, "encrypted record body").await?;

        let opening = self
            .opening
            .as_mut()
            .ok_or_else(|| Error::Protocol("encrypted transport has no opening key".to_owned()))?;
        let plaintext = opening.open(&ciphertext)?;
        match rtsp::parse_response(&plaintext)? {
            Some((response, consumed)) if consumed == plaintext.len() => Ok(response),
            Some(_) => Err(Error::Protocol(
                "encrypted record contains more than one RTSP message".to_owned(),
            )),
            None => Err(Error::Protocol(
                "encrypted record contains an incomplete RTSP response".to_owned(),
            )),
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
        let ciphertext = peer_sealing.seal(RESPONSE).expect("seal response");
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
        let plaintext = peer_opening.open(&ciphertext).expect("open request");
        assert_eq!(plaintext, expected);
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
        let ciphertext = peer_sealing.seal(RESPONSE).expect("seal response");
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
