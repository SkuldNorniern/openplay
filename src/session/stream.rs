//! Drives one realtime audio session from TCP connect to TEARDOWN.
//!
//! Order matches the working HomePod capture: `/info`, transient pairing,
//! encrypted session SETUP, event channel, stream SETUP, RECORD, then audio
//! with sync packets and a `/feedback` keepalive every two seconds.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::result::Result as StdResult;
use std::time::Duration;

use log::info;
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::{MissedTickBehavior, interval};
use tokio::{select, spawn};

use crate::audio::AudioSource;
use crate::error::{Error, Result};
use crate::info::DeviceInfo;
use crate::pairing::{PairSetup, Paired, Tlv};
use crate::rtp::{RtpSender, SyncSender, TimingResponder, bind_udp};
use crate::rtsp::Request;

use super::client::{Identity, RtspClient};
use super::{
    AudioStreamSecret, EventChannel, LocalStreamPorts, SessionId, parse_session_setup_response,
    parse_stream_setup_response, record_request, session_setup_request, stream_setup_request,
};

const FEEDBACK_INTERVAL: Duration = Duration::from_secs(2);

/// A running session. Audio flows until [`Self::run_until`] returns, then
/// [`Self::teardown`] ends it on the receiver.
pub struct Streaming {
    client: RtspClient<TcpStream>,
    session: SessionId,
    device: DeviceInfo,
    /// Held open for the session's lifetime; the receiver tears down the
    /// session when it closes.
    _event_channel: EventChannel,
    timing_task: JoinHandle<Result<()>>,
    audio_task: JoinHandle<Result<()>>,
}

/// Connect to the receiver at `addr`, set up a session, and start sending
/// audio pulled from `source`.
pub async fn start(
    addr: SocketAddr,
    bind: Option<Ipv4Addr>,
    source: AudioSource,
) -> Result<Streaming> {
    let receiver_ip = addr.ip();
    let mut client = RtspClient::new(connect_tcp(addr, bind).await?, Identity::generate());

    let info = client.request(Request::new("GET", "/info")).await?;
    let device = DeviceInfo::from_plist(&info.body)?;
    if !device.supports_transient_pairing() {
        return Err(Error::Pairing(format!(
            "{} does not support transient pairing",
            device.name
        )));
    }

    info!(
        "{} ({}, {})",
        device.name, device.model, device.source_version
    );

    let paired = pair(&mut client).await?;
    info!("paired");
    let secret = AudioStreamSecret::derive(&paired.session_key);
    client.upgrade(paired.control_keys)?;
    // First encrypted request in the capture; it confirms the keys work
    // before anything stateful is sent.
    client.request(Request::new("GET", "/info")).await?;

    // The receiver asks for timing as soon as session SETUP completes, so the
    // responder runs before that request goes out.
    let (timing, timing_port) = TimingResponder::bind(receiver_ip, bind).await?;
    let timing_task = spawn(async move { timing.run().await });

    let session = SessionId::generate();
    let response = client
        .request(session_setup_request(&session, &secret, timing_port)?)
        .await?;
    let session_ports = parse_session_setup_response(&response.body)?;
    info!(
        "session setup done, event port {}",
        session_ports.event_port
    );
    let event_channel = EventChannel::connect(receiver_ip, session_ports.event_port, bind).await?;

    let (audio_socket, audio_port) = bind_udp(receiver_ip, bind).await?;
    let (control_socket, control_port) = bind_udp(receiver_ip, bind).await?;
    let ports = LocalStreamPorts {
        audio: audio_port,
        control: control_port,
        timing: timing_port,
    };
    let response = client
        .request(stream_setup_request(&session, &ports, &secret)?)
        .await?;
    let stream_ports = parse_stream_setup_response(&response.body)?;
    info!(
        "stream setup done, data port {}, control port {}",
        stream_ports.data_port, stream_ports.control_port
    );

    let sync = SyncSender::new(
        control_socket,
        SocketAddr::new(receiver_ip, stream_ports.control_port),
    );
    let mut sender = RtpSender::new(
        audio_socket,
        SocketAddr::new(receiver_ip, stream_ports.data_port),
        source,
        secret.audio_key(),
    )
    .with_sync(sync);

    client.request(record_request(&session)).await?;
    let audio_task = spawn(async move { sender.run().await });

    Ok(Streaming {
        client,
        session,
        device,
        _event_channel: event_channel,
        timing_task,
        audio_task,
    })
}

impl Streaming {
    /// Receiver description from `/info`.
    pub fn device(&self) -> &DeviceInfo {
        &self.device
    }

    /// Keep the session alive until `stop` completes.
    ///
    /// Fails early when the audio or timing task stops or a keepalive is
    /// rejected, since the receiver drops the stream in either case.
    pub async fn run_until<F: Future<Output = ()>>(&mut self, stop: F) -> Result<()> {
        let mut feedback = interval(FEEDBACK_INTERVAL);
        feedback.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick is immediate; RECORD has just been answered.
        feedback.tick().await;
        let mut stop = pin!(stop);

        loop {
            select! {
                () = &mut stop => return Ok(()),
                _ = feedback.tick() => {
                    self.client.request(Request::new("POST", "/feedback")).await?;
                }
                result = &mut self.audio_task => return task_ended("audio", result),
                result = &mut self.timing_task => return task_ended("timing", result),
            }
        }
    }

    /// Stop the background tasks and send TEARDOWN.
    pub async fn teardown(mut self) -> Result<()> {
        self.audio_task.abort();
        self.timing_task.abort();
        self.client
            .request(Request::new("TEARDOWN", &self.session.path()))
            .await?;
        Ok(())
    }
}

/// A background task never ends on its own, so any exit is an error.
fn task_ended(name: &str, result: StdResult<Result<()>, JoinError>) -> Result<()> {
    match result {
        Ok(Err(error)) => Err(error),
        Ok(Ok(())) => Err(Error::Protocol(format!("{name} task stopped"))),
        Err(error) => Err(Error::Protocol(format!("{name} task failed: {error}"))),
    }
}

async fn pair(client: &mut RtspClient<TcpStream>) -> Result<Paired> {
    let (m1, driver) = PairSetup::new().start();
    let m2 = client.request(pair_setup_request(&m1)).await?;
    let (m3, driver) = driver.process_m2(&Tlv::decode(&m2.body)?)?;
    let m4 = client.request(pair_setup_request(&m3)).await?;
    driver.process_m4(&Tlv::decode(&m4.body)?)
}

fn pair_setup_request(tlv: &Tlv) -> Request {
    Request::new("POST", "/pair-setup")
        .header("Content-Type", "application/octet-stream")
        .header("X-Apple-HKP", "4")
        .body(tlv.encode())
}

async fn connect_tcp(addr: SocketAddr, bind: Option<Ipv4Addr>) -> Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(ip) = bind {
        if !addr.is_ipv4() {
            return Err(Error::Protocol("cannot bind IPv4 to an IPv6 target".into()));
        }
        socket.bind(SocketAddr::from((ip, 0)))?;
    }
    Ok(socket.connect(addr).await?)
}
