//! Connection establishment for the receiver-initiated AirPlay event channel.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream};

use crate::error::{Error, Result};

/// A connected event channel: the separate TCP connection the receiver uses
/// for unsolicited requests (remote-control events, keepalive) once streaming
/// has been set up.
///
/// This connection is established after SETUP and before RECORD so the
/// receiver has a path back to the sender when playback begins.
pub struct EventChannel {
    stream: TcpStream,
}

impl EventChannel {
    /// Open the event channel advertised by the receiver during SETUP.
    ///
    /// Binding the source address is important on multi-homed senders: it
    /// keeps the event connection on the same local interface as the rest of
    /// the AirPlay session.
    pub async fn connect(addr: IpAddr, port: u16, bind: Option<Ipv4Addr>) -> Result<Self> {
        let target = SocketAddr::new(addr, port);
        let socket = match target {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        if let Some(ip) = bind {
            if !target.is_ipv4() {
                return Err(Error::Protocol("cannot bind IPv4 to an IPv6 target".into()));
            }
            socket.bind(SocketAddr::from((ip, 0)))?;
        }

        let stream = socket.connect(target).await?;
        Ok(Self { stream })
    }

    /// Return the local endpoint selected for this connection.
    ///
    /// Session setup can use this to confirm that an explicitly requested
    /// interface was honored without exposing the event stream itself.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.stream.local_addr()?)
    }

    /// Read and discard what the receiver sends until it closes the
    /// connection. Unread data would fill the TCP window and stall the
    /// receiver's event writes. Closing ends the session, so it is an error.
    pub async fn drain(mut self) -> Result<()> {
        let mut buffer = [0_u8; 4096];
        loop {
            if self.stream.read(&mut buffer).await? == 0 {
                return Err(Error::Protocol(
                    "receiver closed the event channel".to_owned(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::spawn;

    use super::*;

    #[tokio::test]
    async fn connects_to_receiver_event_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("listener address").port();

        let channel = EventChannel::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
            .await
            .expect("connect event channel");
        let (_peer, peer_addr) = listener.accept().await.expect("accept event channel");

        assert_eq!(
            channel.stream.peer_addr().expect("event peer address"),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        );
        assert_eq!(
            peer_addr,
            channel.local_addr().expect("event local address")
        );
    }

    #[tokio::test]
    async fn drain_discards_data_until_receiver_closes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("listener address").port();
        let receiver = spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            stream
                .write_all(b"POST /command RTSP/1.0\r\n\r\n")
                .await
                .expect("write");
        });
        let channel = EventChannel::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
            .await
            .expect("connect");
        receiver.await.expect("receiver");

        let error = channel.drain().await.expect_err("close ends drain");
        assert!(error.to_string().contains("closed the event channel"));
    }

    #[tokio::test]
    async fn connection_refusal_returns_error() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("listener address").port();
        drop(listener);

        let error = match EventChannel::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port, None).await {
            Ok(_) => panic!("connection to closed port unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(matches!(error, Error::Io(_)));
    }

    #[tokio::test]
    async fn binds_requested_local_interface() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("listener address").port();

        let channel = EventChannel::connect(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Some(Ipv4Addr::LOCALHOST),
        )
        .await
        .expect("connect bound event channel");
        let (_peer, _) = listener.accept().await.expect("accept event channel");

        assert_eq!(
            channel.local_addr().expect("event local address").ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }
}
