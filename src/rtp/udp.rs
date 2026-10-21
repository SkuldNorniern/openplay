//! UDP socket binding shared by the audio, control, and timing channels.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// Bind a UDP socket on an ephemeral port in the receiver's address family.
///
/// Sockets are bound before SETUP because our ports go into the SETUP
/// requests, while the receiver's ports only come back in the responses.
/// When `bind` is supplied the socket uses that local IPv4 interface,
/// matching [`crate::info::fetch`]. An IPv4 bind cannot reach an IPv6 receiver.
pub async fn bind_udp(receiver_ip: IpAddr, bind: Option<Ipv4Addr>) -> Result<(UdpSocket, u16)> {
    let local_addr = match receiver_ip {
        IpAddr::V4(_) => SocketAddr::from((bind.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)),
        IpAddr::V6(_) => {
            if bind.is_some() {
                return Err(Error::Protocol("cannot bind IPv4 to an IPv6 target".into()));
            }
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        }
    };

    let socket = UdpSocket::bind(local_addr).await?;
    let local_port = socket.local_addr()?.port();
    Ok((socket, local_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_requested_interface_on_ephemeral_port() {
        let (socket, port) = bind_udp(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(Ipv4Addr::LOCALHOST))
            .await
            .expect("bind");

        assert_ne!(port, 0);
        assert_eq!(
            socket.local_addr().expect("address"),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        );
    }

    #[tokio::test]
    async fn rejects_ipv4_bind_for_ipv6_receiver() {
        assert!(
            bind_udp(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(Ipv4Addr::LOCALHOST))
                .await
                .is_err()
        );
    }
}
