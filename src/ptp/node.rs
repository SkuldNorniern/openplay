//! Socket loop that runs a [`Follower`] against a live PTP leader.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use log::debug;
use tokio::net::UdpSocket;
use tokio::select;

use super::follower::{Action, Follower};
use super::message::{Message, Timestamp};
use crate::error::Result;
use crate::rtp::is_transient;

/// Standard PTP event port, where Sync and Delay_Req travel.
pub const EVENT_PORT: u16 = 319;
/// Standard PTP general port, for Follow_Up, Delay_Resp and Announce.
pub const GENERAL_PORT: u16 = 320;
/// Room for any datagram a LAN peer sends, so Windows never fails a
/// receive as oversized.
const RECEIVE_BUFFER_LEN: usize = 2_048;

/// Monotonic local time in nanoseconds since the node started. Wall-clock
/// steps would corrupt the offset, so all local stamps come from here.
#[derive(Debug, Clone, Copy)]
pub struct LocalClock {
    origin: Instant,
}

impl LocalClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    pub fn now(self) -> i128 {
        self.origin.elapsed().as_nanos() as i128
    }
}

impl Default for LocalClock {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Published {
    offset: Option<i128>,
    leader: Option<u64>,
}

/// Read side of a running node: the leader's time now, for scheduling
/// playback. Cheap to clone.
#[derive(Clone)]
pub struct PtpTime {
    local: LocalClock,
    published: Arc<Mutex<Published>>,
}

impl PtpTime {
    /// The leader's current time, once enough exchanges have completed.
    pub fn now(&self) -> Option<Timestamp> {
        let published = *self.lock();
        let leader = self.local.now() - published.offset?;
        u128::try_from(leader).ok().map(Timestamp::from_nanos)
    }

    /// Leader clock identity, the timeline ID SETRATEANCHORTIME names.
    pub fn timeline_id(&self) -> Option<u64> {
        self.lock().leader
    }

    fn publish(&self, follower: &Follower) {
        *self.lock() = Published {
            offset: follower.clock().offset_nanos(),
            leader: follower.leader(),
        };
    }

    fn lock(&self) -> MutexGuard<'_, Published> {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for PtpTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PtpTime({:?})", *self.lock())
    }
}

/// Follows the PTP leader at `leader_ip`.
pub struct PtpNode {
    follower: Follower,
    event: UdpSocket,
    general: UdpSocket,
    leader_event: SocketAddr,
    time: PtpTime,
}

impl PtpNode {
    /// `event` and `general` are already bound; their ports are where the
    /// leader's messages arrive. Delay_Req goes out of `event` to the
    /// leader's `leader_event_port`, normally [`EVENT_PORT`].
    pub fn new(
        follower: Follower,
        event: UdpSocket,
        general: UdpSocket,
        leader_ip: IpAddr,
        leader_event_port: u16,
    ) -> Self {
        Self {
            follower,
            event,
            general,
            leader_event: SocketAddr::new(leader_ip, leader_event_port),
            time: PtpTime {
                local: LocalClock::new(),
                published: Arc::default(),
            },
        }
    }

    pub fn time(&self) -> PtpTime {
        self.time.clone()
    }

    /// Process messages until a socket fails.
    pub async fn run(mut self) -> Result<()> {
        let mut event_buffer = [0_u8; RECEIVE_BUFFER_LEN];
        let mut general_buffer = [0_u8; RECEIVE_BUFFER_LEN];
        loop {
            let (received, from_event) = select! {
                received = self.event.recv_from(&mut event_buffer) => (received, true),
                received = self.general.recv_from(&mut general_buffer) => (received, false),
            };
            let (length, peer) = match received {
                Ok(received) => received,
                Err(error) if is_transient(&error) => {
                    debug!("ptp: receive failed, continuing: {error}");
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            // Stamp before parsing so decode time is not counted as path delay.
            let received = self.time.local.now();
            if peer.ip() != self.leader_event.ip() {
                continue;
            }
            let bytes = if from_event {
                &event_buffer[..length]
            } else {
                &general_buffer[..length]
            };
            let message = match Message::decode(bytes) {
                Ok(message) => message,
                Err(error) => {
                    debug!("ptp: ignored datagram from {peer}: {error}");
                    continue;
                }
            };

            if let Action::SendDelayReq { sequence_id, bytes } =
                self.follower.on_message(&message, received)
            {
                match self.event.send_to(&bytes, self.leader_event).await {
                    Ok(_) => self
                        .follower
                        .delay_req_sent(sequence_id, self.time.local.now()),
                    // The exchange is lost; the next Sync starts another.
                    Err(error) if is_transient(&error) => {
                        debug!("ptp: delay request failed: {error}");
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            self.time.publish(&self.follower);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::spawn;
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::ptp::message::{
        Body, PortIdentity, encode_delay_resp, encode_follow_up, encode_sync,
    };

    const LEADER: PortIdentity = PortIdentity {
        clock_identity: 0x96_9b_5f_ff_fe_c7_5f_9d,
        port_number: 1,
    };
    const ME: PortIdentity = PortIdentity {
        clock_identity: 0x0102_0304_0506_0708,
        port_number: 1,
    };
    /// The fake leader's clock runs this far ahead of the test's clock.
    const LEADER_AHEAD: Duration = Duration::from_secs(5_000);

    async fn bind() -> UdpSocket {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind")
    }

    /// A leader on localhost: sends Sync and Follow_Up, answers Delay_Req.
    async fn fake_leader(event: UdpSocket, general: UdpSocket, follower: [SocketAddr; 2]) {
        let origin = Instant::now();
        let leader_now = || Timestamp::from_nanos((origin.elapsed() + LEADER_AHEAD).as_nanos());
        let mut buffer = [0_u8; 512];
        for sequence in 0_u16.. {
            let sent = leader_now();
            event
                .send_to(
                    &encode_sync(LEADER, 0, sequence, Timestamp::default()),
                    follower[0],
                )
                .await
                .expect("send sync");
            general
                .send_to(&encode_follow_up(LEADER, 0, sequence, sent), follower[1])
                .await
                .expect("send follow up");
            if let Ok(Ok((length, _))) =
                timeout(Duration::from_millis(50), event.recv_from(&mut buffer)).await
            {
                let received = leader_now();
                let request = Message::decode(&buffer[..length]).expect("delay req");
                assert!(matches!(request.body, Body::DelayReq { .. }));
                general
                    .send_to(
                        &encode_delay_resp(
                            LEADER,
                            0,
                            request.header.sequence_id,
                            received,
                            request.header.source,
                        ),
                        follower[1],
                    )
                    .await
                    .expect("send delay resp");
            }
            sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn follows_leader_clock_over_udp() {
        let (leader_event, leader_general) = (bind().await, bind().await);
        let (event, general) = (bind().await, bind().await);
        let follower_ports = [
            event.local_addr().expect("event addr"),
            general.local_addr().expect("general addr"),
        ];
        let leader_event_port = leader_event.local_addr().expect("leader addr").port();

        let node = PtpNode::new(
            Follower::new(ME, 0),
            event,
            general,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            leader_event_port,
        );
        let time = node.time();
        let reference = Instant::now();
        let node_task = spawn(node.run());
        let leader_task = spawn(fake_leader(leader_event, leader_general, follower_ports));

        let synced = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(now) = time.now() {
                    return now;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("node synchronizes");
        node_task.abort();
        leader_task.abort();

        // The leader started its clock at about `reference + LEADER_AHEAD`.
        let expected = (reference.elapsed() + LEADER_AHEAD).as_nanos() as i128;
        let error = (synced.to_nanos() as i128 - expected).abs();
        assert!(error < 20_000_000, "off by {error} ns");
        assert_eq!(time.timeline_id(), Some(LEADER.clock_identity));
    }
}
