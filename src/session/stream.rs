//! Drives one audio session from TCP connect to TEARDOWN.
//!
//! Realtime order matches the working HomePod capture: `/info`, transient
//! pairing, encrypted session SETUP, event channel, stream SETUP, RECORD,
//! then audio with sync packets and a `/feedback` keepalive every two
//! seconds. Buffered sessions replace NTP timing with a PTP follower, send
//! audio ahead over TCP, and start playback with SETRATEANCHORTIME.

use std::future::Future;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, info, warn};
use rand::random;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::select;
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, Interval, MissedTickBehavior, interval, sleep, timeout};

use crate::audio::AudioSource;
use crate::error::{Error, Result};
use crate::info::DeviceInfo;
use crate::pairing::{PairSetup, Paired, Tlv};
use crate::ptp::{EVENT_PORT, Follower, GENERAL_PORT, PortIdentity, PtpNode, PtpTime, Timestamp};
use crate::rtp::{
    BufferedSender, HISTORY_PACKETS, PacketHistory, ResendResponder, RtpSender, SyncSender,
    TimingResponder, bind_udp,
};
use crate::rtsp::{Request, Response};

use super::buffered::{
    Anchor, PtpPeer, buffered_stream_setup_request, ptp_session_setup_request, set_peers_request,
    set_rate_anchor_time_request,
};
use super::client::{Identity, RtspClient};
use super::{
    AudioStreamSecret, DEFAULT_LATENCY_FRAMES, EventChannel, LocalStreamPorts, SessionId,
    parse_session_setup_response, parse_stream_setup_response, record_request,
    session_setup_request, stream_setup_request, volume_db, volume_request,
};

const FEEDBACK_INTERVAL: Duration = Duration::from_secs(2);
/// How long a buffered session waits for its PTP follower to lock on.
const PTP_SYNC_TIMEOUT: Duration = Duration::from_secs(5);
const PTP_SYNC_POLL: Duration = Duration::from_millis(20);
/// Playback starts this long after SETRATEANCHORTIME, so the first packets
/// are already buffered on the receiver.
const ANCHOR_DELAY: Duration = Duration::from_secs(1);
/// Audio kept in flight ahead of the playback position.
const BUFFERED_LEAD: Duration = Duration::from_secs(2);

/// How to reach and present to the receiver.
#[derive(Debug, Clone, Copy)]
pub struct StreamOptions {
    /// Local IPv4 interface to use, when the machine has several.
    pub bind: Option<Ipv4Addr>,
    pub identity: Identity,
    /// Playout latency to ask a realtime receiver for, in 44.1 kHz frames.
    /// `None` keeps what the working HomePod capture used.
    pub latency_frames: Option<u32>,
}

impl StreamOptions {
    pub fn new(identity: Identity) -> Self {
        Self {
            bind: None,
            identity,
            latency_frames: None,
        }
    }
}

/// Background work: each task is named so a failure can say which one died.
type Tasks = JoinSet<(&'static str, Result<()>)>;

fn spawn_task<F>(tasks: &mut Tasks, name: &'static str, task: F)
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    tasks.spawn(async move { (name, task.await) });
}

/// A running session. Audio flows until [`Self::run_until`] returns, then
/// [`Self::teardown`] ends it on the receiver.
pub struct Streaming {
    client: RtspClient<TcpStream>,
    session: SessionId,
    device: DeviceInfo,
    /// Playout latency the receiver reported in its RECORD reply.
    receiver_latency_frames: Option<u32>,
    tasks: Tasks,
    /// Kept across [`Self::run_until`] calls, so frequent returns (each
    /// UI command) cannot starve the keepalive.
    feedback: Interval,
}

/// A paired, encrypted control connection.
struct Connected {
    client: RtspClient<TcpStream>,
    device: DeviceInfo,
    secret: AudioStreamSecret,
    /// Our address on the receiver's network, as the receiver sees it.
    local_ip: IpAddr,
}

async fn connect(
    addr: SocketAddr,
    bind: Option<Ipv4Addr>,
    identity: Identity,
) -> Result<Connected> {
    let stream = connect_tcp(addr, bind).await?;
    let local_ip = stream.local_addr()?.ip();
    let mut client = RtspClient::new(stream, identity);

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

    Ok(Connected {
        client,
        device,
        secret,
        local_ip,
    })
}

/// Connect to the receiver at `addr`, set up a realtime session, and start
/// sending audio pulled from `source`.
pub async fn start(
    addr: SocketAddr,
    options: StreamOptions,
    source: AudioSource,
) -> Result<Streaming> {
    let bind = options.bind;
    let Connected {
        mut client,
        device,
        secret,
        ..
    } = connect(addr, bind, options.identity).await?;
    let mut tasks = Tasks::new();

    // The receiver asks for timing as soon as session SETUP completes, so the
    // responder runs before that request goes out.
    let (timing, timing_port) = TimingResponder::bind(addr.ip(), bind).await?;
    spawn_task(&mut tasks, "timing", async move { timing.run().await });

    let session = SessionId::generate();
    let started = async {
        let response = client
            .request(session_setup_request(&session, &secret, timing_port)?)
            .await?;
        let event_port = parse_session_setup_response(&response.body)?.event_port;
        info!("session setup done, event port {event_port}");
        start_realtime(
            &mut client,
            &session,
            &secret,
            (event_port, timing_port),
            addr,
            options,
            source,
            &mut tasks,
        )
        .await
    }
    .await;
    finish(client, session, device, tasks, started).await
}

/// Everything after realtime session SETUP: event channel, stream SETUP,
/// RECORD and the audio tasks.
#[allow(clippy::too_many_arguments)]
async fn start_realtime(
    client: &mut RtspClient<TcpStream>,
    session: &SessionId,
    secret: &AudioStreamSecret,
    (event_port, timing_port): (u16, u16),
    addr: SocketAddr,
    options: StreamOptions,
    source: AudioSource,
    tasks: &mut Tasks,
) -> Result<Option<u32>> {
    let receiver_ip = addr.ip();
    let bind = options.bind;
    let latency_frames = options.latency_frames.unwrap_or(DEFAULT_LATENCY_FRAMES);
    let event_channel = EventChannel::connect(receiver_ip, event_port, bind).await?;
    spawn_task(tasks, "event channel", event_channel.drain());

    let (audio_socket, audio_port) = bind_udp(receiver_ip, bind).await?;
    let (control_socket, control_port) = bind_udp(receiver_ip, bind).await?;
    let ports = LocalStreamPorts {
        audio: audio_port,
        control: control_port,
        timing: timing_port,
    };
    let response = client
        .request(stream_setup_request(
            session,
            &ports,
            secret,
            latency_frames,
        )?)
        .await?;
    let stream_ports = parse_stream_setup_response(&response.body)?;
    let receiver_control_port = stream_ports.require_control_port()?;
    info!(
        "stream setup done, data port {}, control port {receiver_control_port}",
        stream_ports.data_port
    );

    let control_socket = Arc::new(control_socket);
    let history = PacketHistory::new(HISTORY_PACKETS);
    let mut sync = SyncSender::new(
        Arc::clone(&control_socket),
        SocketAddr::new(receiver_ip, receiver_control_port),
    );
    // Only an explicit request changes the sync packets from the capture's.
    if let Some(latency) = options.latency_frames {
        sync = sync.with_latency(latency);
    }
    let resender = ResendResponder::new(control_socket, receiver_ip, history.clone());
    let mut sender = RtpSender::new(
        audio_socket,
        SocketAddr::new(receiver_ip, stream_ports.data_port),
        source,
        secret.audio_key(),
    )
    .with_sync(sync)
    .with_history(history);

    let record = client.request(record_request(session)).await?;
    spawn_task(tasks, "audio", async move { sender.run().await });
    spawn_task(tasks, "resend", async move { resender.run().await });
    Ok(audio_latency(&record))
}

/// The receiver's playout latency from a RECORD reply's `Audio-Latency`.
fn audio_latency(record: &Response) -> Option<u32> {
    let latency = record.headers.get("Audio-Latency")?.trim().parse().ok();
    if let Some(frames) = latency {
        info!("receiver latency {frames} frames");
    }
    latency
}

/// Connect to the receiver at `addr`, set up a buffered PTP-timed session,
/// and start sending audio pulled from `source`.
pub async fn start_buffered(
    addr: SocketAddr,
    options: StreamOptions,
    source: AudioSource,
) -> Result<Streaming> {
    let bind = options.bind;
    let Connected {
        mut client,
        device,
        secret,
        local_ip,
    } = connect(addr, bind, options.identity).await?;
    let mut tasks = Tasks::new();
    let receiver_ip = addr.ip();

    let (event, general) = bind_ptp_sockets(receiver_ip, bind).await?;
    let clock_port = event.local_addr()?.port();
    let clock_id: u64 = random();
    let node = PtpNode::new(
        Follower::new(
            PortIdentity {
                clock_identity: clock_id,
                port_number: 1,
            },
            0,
        ),
        event,
        general,
        receiver_ip,
        EVENT_PORT,
    );
    let time = node.time();
    spawn_task(&mut tasks, "ptp", node.run());

    let session = SessionId::generate();
    let started = async {
        let peer = PtpPeer {
            addresses: vec![local_ip],
            clock_id,
            clock_port,
        };
        let response = client
            .request(ptp_session_setup_request(
                &session,
                &secret,
                &peer,
                &random_uuid(),
            )?)
            .await?;
        let event_port = parse_session_setup_response(&response.body)?.event_port;
        info!("session setup done, event port {event_port}");
        start_buffered_stream(
            &mut client,
            &session,
            &secret,
            BufferedPorts {
                event: event_port,
                clock: clock_port,
            },
            (local_ip, addr),
            bind,
            source,
            time,
            &mut tasks,
        )
        .await
    }
    .await;
    finish(client, session, device, tasks, started).await
}

struct BufferedPorts {
    /// The receiver's event port.
    event: u16,
    /// Our PTP port, where Delay_Resp comes back.
    clock: u16,
}

#[allow(clippy::too_many_arguments)]
async fn start_buffered_stream(
    client: &mut RtspClient<TcpStream>,
    session: &SessionId,
    secret: &AudioStreamSecret,
    ports: BufferedPorts,
    (local_ip, addr): (IpAddr, SocketAddr),
    bind: Option<Ipv4Addr>,
    source: AudioSource,
    time: PtpTime,
    tasks: &mut Tasks,
) -> Result<Option<u32>> {
    let receiver_ip = addr.ip();
    let event_channel = EventChannel::connect(receiver_ip, ports.event, bind).await?;
    spawn_task(tasks, "event channel", event_channel.drain());

    let (control_socket, control_port) = bind_udp(receiver_ip, bind).await?;
    spawn_task(tasks, "control", drain_control(control_socket));
    let local_ports = LocalStreamPorts {
        audio: 0,
        control: control_port,
        timing: ports.clock,
    };
    let response = client
        .request(buffered_stream_setup_request(
            session,
            &local_ports,
            secret,
        )?)
        .await?;
    let stream_ports = parse_stream_setup_response(&response.body)?;
    info!(
        "buffered stream setup done, data port {}",
        stream_ports.data_port
    );

    client
        .request(set_peers_request(session, &[local_ip, receiver_ip])?)
        .await?;
    let data = connect_tcp(SocketAddr::new(receiver_ip, stream_ports.data_port), bind).await?;
    let mut sender = BufferedSender::new(data, source, secret.audio_key());
    let record = client.request(record_request(session)).await?;

    let (network_now, timeline_id) = wait_for_ptp(&time).await?;
    let anchor = Anchor {
        rtp_time: sender.next_rtp_time(),
        network_time: Timestamp::from_nanos(network_now.to_nanos() + ANCHOR_DELAY.as_nanos()),
        timeline_id,
    };
    let start = Instant::now() + ANCHOR_DELAY;
    client
        .request(set_rate_anchor_time_request(session, 1.0, Some(&anchor))?)
        .await?;
    info!("playback anchored on timeline {timeline_id:016X}");
    spawn_task(tasks, "audio", async move {
        sender.run(start, BUFFERED_LEAD).await
    });
    Ok(audio_latency(&record))
}

/// Bind the PTP sockets on the standard ports when allowed, otherwise on
/// ephemeral ones. Delay_Resp still finds an ephemeral port through
/// `ClockPorts`, but a receiver that sends Sync only to port 319 will not.
async fn bind_ptp_sockets(
    receiver_ip: IpAddr,
    bind: Option<Ipv4Addr>,
) -> Result<(UdpSocket, UdpSocket)> {
    let local = match receiver_ip {
        IpAddr::V4(_) => IpAddr::V4(bind.unwrap_or(Ipv4Addr::UNSPECIFIED)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let standard = async {
        let event = UdpSocket::bind((local, EVENT_PORT)).await?;
        let general = UdpSocket::bind((local, GENERAL_PORT)).await?;
        Ok::<_, IoError>((event, general))
    };
    match standard.await {
        Ok(sockets) => Ok(sockets),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::PermissionDenied | ErrorKind::AddrInUse
            ) =>
        {
            warn!(
                "ptp ports {EVENT_PORT}/{GENERAL_PORT} unavailable ({error}), using ephemeral ports"
            );
            let (event, _) = bind_udp(receiver_ip, bind).await?;
            let (general, _) = bind_udp(receiver_ip, bind).await?;
            Ok((event, general))
        }
        Err(error) => Err(error.into()),
    }
}

async fn wait_for_ptp(time: &PtpTime) -> Result<(Timestamp, u64)> {
    timeout(PTP_SYNC_TIMEOUT, async {
        loop {
            if let (Some(now), Some(timeline)) = (time.now(), time.timeline_id()) {
                return (now, timeline);
            }
            sleep(PTP_SYNC_POLL).await;
        }
    })
    .await
    .map_err(|_| Error::Protocol("ptp: no sync from receiver".to_owned()))
}

/// Keep the buffered control socket open and log what arrives on it.
async fn drain_control(socket: UdpSocket) -> Result<()> {
    let mut buffer = [0_u8; 2048];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        debug!("control: {length} bytes from {peer}");
    }
}

/// Random UUID in the uppercase form AirPlay uses for group IDs.
fn random_uuid() -> String {
    let bytes: [u8; 16] = random();
    let hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Turn a setup result into a session, or end the half-built session.
async fn finish(
    mut client: RtspClient<TcpStream>,
    session: SessionId,
    device: DeviceInfo,
    mut tasks: Tasks,
    started: Result<Option<u32>>,
) -> Result<Streaming> {
    let receiver_latency_frames = match started {
        Ok(latency) => latency,
        Err(error) => {
            // Leaving a half-built session behind makes the receiver ignore the
            // next attempt for a while, so end it before reporting.
            tasks.abort_all();
            if let Err(teardown_error) = client.request(teardown_request(&session)).await {
                warn!("teardown after failed setup: {teardown_error}");
            }
            return Err(error);
        }
    };
    let mut feedback = interval(FEEDBACK_INTERVAL);
    feedback.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first tick is immediate; RECORD has just been answered.
    feedback.tick().await;
    Ok(Streaming {
        client,
        session,
        device,
        receiver_latency_frames,
        tasks,
        feedback,
    })
}

impl Streaming {
    /// Receiver description from `/info`.
    pub fn device(&self) -> &DeviceInfo {
        &self.device
    }

    /// Playout latency the receiver reported, in 44.1 kHz frames, when it
    /// sent one.
    pub fn receiver_latency_frames(&self) -> Option<u32> {
        self.receiver_latency_frames
    }

    /// Set playback volume, 0 (mute) to 100.
    pub async fn set_volume(&mut self, percent: u8) -> Result<()> {
        self.client
            .request(volume_request(&self.session, volume_db(percent)))
            .await?;
        Ok(())
    }

    /// Keep the session alive until `stop` completes.
    ///
    /// Fails early when a background task stops or a keepalive is rejected,
    /// since the stream is broken in either case.
    pub async fn run_until<F: Future<Output = ()>>(&mut self, stop: F) -> Result<()> {
        let mut stop = pin!(stop);

        loop {
            select! {
                () = &mut stop => return Ok(()),
                _ = self.feedback.tick() => {
                    self.client.request(Request::new("POST", "/feedback")).await?;
                }
                Some(joined) = self.tasks.join_next() => return task_ended(joined),
            }
        }
    }

    /// Stop the background tasks and send TEARDOWN.
    pub async fn teardown(mut self) -> Result<()> {
        self.tasks.abort_all();
        self.client.request(teardown_request(&self.session)).await?;
        Ok(())
    }
}

/// A background task never ends on its own, so any exit is an error.
fn task_ended(joined: StdResult<(&'static str, Result<()>), JoinError>) -> Result<()> {
    match joined {
        Ok((_, Err(error))) => Err(error),
        Ok((name, Ok(()))) => Err(Error::Protocol(format!("{name} task stopped"))),
        Err(error) => Err(Error::Protocol(format!("background task failed: {error}"))),
    }
}

fn teardown_request(session: &SessionId) -> Request {
    Request::new("TEARDOWN", &session.path())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_has_group_id_shape() {
        let uuid = random_uuid();
        let lengths: Vec<_> = uuid.split('-').map(str::len).collect();
        assert_eq!(lengths, [8, 4, 4, 4, 12]);
        assert!(uuid.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        assert_eq!(uuid, uuid.to_uppercase());
    }
}
