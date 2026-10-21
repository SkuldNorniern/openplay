//! One receiver as a speaker: the entry point for drivers and UIs.
//!
//! [`Sender::start`] returns an [`AudioInput`] to write PCM into and runs
//! the session in the background. When the receiver drops the stream the
//! sender reconnects with backoff while audio keeps arriving, so a system
//! audio device built on it survives Wi-Fi hiccups without the OS noticing.

use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::time::Duration;

use log::warn;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tokio::{select, spawn};

use crate::audio::{AudioInput, AudioSource, PcmFormat, SourceStats};
use crate::error::{Error, Result};
use crate::session::{self, DEFAULT_LATENCY_FRAMES, Identity, StreamOptions, Streaming};

/// 200 ms of 44.1 kHz audio: the most the ring buffers before dropping the
/// oldest, which bounds added latency when the receiver stalls.
pub const DEFAULT_CAPACITY_FRAMES: usize = 8_820;
/// 50 ms: the fill drift correction holds with live input. Packets leave
/// every 8 ms and audio engines deliver every 10 ms or so, so this leaves
/// room for scheduling jitter without adding noticeable delay.
pub const DEFAULT_TARGET_FRAMES: usize = 2_205;
const SAMPLE_RATE: f64 = 44_100.0;
const FIRST_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);
const COMMAND_QUEUE: usize = 8;
/// A session this long-lived resets the retry count and backoff.
const STABLE_SESSION: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    /// Low latency, NTP timed: the right choice for a system speaker.
    Realtime,
    /// PTP timed and buffered ahead, for receivers or groups that need it.
    Buffered,
}

#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Local IPv4 interface to use, when the machine has several.
    pub bind: Option<Ipv4Addr>,
    pub mode: StreamMode,
    /// Volume to set after each connect, 0 to 100; unset keeps the
    /// receiver's.
    pub volume: Option<u8>,
    /// Follow the input's clock: for live sources, not for files.
    pub drift_correction: bool,
    pub capacity_frames: usize,
    pub target_frames: usize,
    /// Reconnect attempts after a failure before giving up; `None` retries
    /// forever, which suits a speaker that should come back on its own.
    pub max_retries: Option<u32>,
    /// Who we are to the receiver; a fresh random identity when unset.
    /// Store [`Identity::device_id`] to stay the same device across runs.
    pub identity: Option<Identity>,
    /// Playout latency to ask a realtime receiver for. Unset keeps what the
    /// working HomePod capture used; lower values may not be honoured.
    pub receiver_latency: Option<Duration>,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            bind: None,
            mode: StreamMode::Realtime,
            volume: None,
            drift_correction: true,
            capacity_frames: DEFAULT_CAPACITY_FRAMES,
            target_frames: DEFAULT_TARGET_FRAMES,
            max_retries: None,
            identity: None,
            receiver_latency: None,
        }
    }
}

/// What the sender is doing, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Connecting,
    /// Streaming to the named receiver, with the estimated time from input
    /// to sound, for a driver to report so players keep video in sync.
    Streaming {
        receiver: String,
        latency: Duration,
    },
    /// Waiting to retry after `error`.
    Reconnecting {
        attempt: u32,
        error: String,
    },
    Stopped,
    /// Gave up after the configured retries.
    Failed {
        error: String,
    },
}

enum Command {
    SetVolume(u8, oneshot::Sender<Result<()>>),
    Stop,
}

/// Handle to a background session with one receiver.
pub struct Sender {
    status: watch::Receiver<Status>,
    commands: mpsc::Sender<Command>,
    source: AudioSource,
    task: JoinHandle<()>,
}

impl Sender {
    /// Start streaming to the receiver at `addr`. Write PCM in `format`
    /// into the returned [`AudioInput`]; until a session is up, it simply
    /// fills the ring.
    pub fn start(
        addr: SocketAddr,
        format: PcmFormat,
        config: SenderConfig,
    ) -> Result<(Self, AudioInput)> {
        let source = AudioSource::new(config.capacity_frames);
        let mut input = AudioInput::new(format, source.clone())?;
        if config.drift_correction {
            input = input.with_drift_correction(config.target_frames);
        }

        let (status_sender, status) = watch::channel(Status::Connecting);
        let (commands, command_receiver) = mpsc::channel(COMMAND_QUEUE);
        let task = spawn(run(
            addr,
            config,
            source.clone(),
            status_sender,
            command_receiver,
        ));
        Ok((
            Self {
                status,
                commands,
                source,
                task,
            },
            input,
        ))
    }

    /// Current status, with change notification.
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }

    pub fn stats(&self) -> SourceStats {
        self.source.stats()
    }

    /// Frames waiting to be sent.
    pub fn buffered_frames(&self) -> usize {
        self.source.buffered_frames()
    }

    /// Set the volume now, and again after any reconnect.
    pub async fn set_volume(&self, percent: u8) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::SetVolume(percent, reply))
            .await
            .map_err(|_| stopped())?;
        response.await.map_err(|_| stopped())?
    }

    /// End the session with TEARDOWN and wait for the background task.
    pub async fn stop(self) {
        // A send error means the task already ended on its own.
        let _ = self.commands.send(Command::Stop).await;
        let _ = self.task.await;
    }
}

impl fmt::Debug for Sender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sender({:?})", *self.status.borrow())
    }
}

fn stopped() -> Error {
    Error::Protocol("sender has stopped".to_owned())
}

/// Why one session ended.
enum Ended {
    Stopped,
    Failed(Error),
}

async fn run(
    addr: SocketAddr,
    mut config: SenderConfig,
    source: AudioSource,
    status: watch::Sender<Status>,
    mut commands: mpsc::Receiver<Command>,
) {
    // One identity for every reconnect, so the receiver sees one device.
    let options = StreamOptions {
        bind: config.bind,
        identity: config.identity.unwrap_or_else(Identity::generate),
        latency_frames: config.receiver_latency.map(duration_frames),
    };
    let mut attempt = 0_u32;
    loop {
        status.send_replace(Status::Connecting);
        let mode = config.mode;
        let start = async {
            match mode {
                StreamMode::Realtime => session::start(addr, options, source.clone()).await,
                StreamMode::Buffered => {
                    session::start_buffered(addr, options, source.clone()).await
                }
            }
        };
        let Some(started) = until_stopped(start, &mut config, &mut commands).await else {
            status.send_replace(Status::Stopped);
            return;
        };
        let ended = match started {
            Ok(streaming) => {
                let began = Instant::now();
                let ended = stream(streaming, &mut config, &status, &mut commands).await;
                // Only a session that held up counts as recovered; one that
                // dies right after setup keeps backing off.
                if began.elapsed() >= STABLE_SESSION {
                    attempt = 0;
                }
                ended
            }
            Err(error) => Ended::Failed(error),
        };

        let error = match ended {
            Ended::Stopped => {
                status.send_replace(Status::Stopped);
                return;
            }
            Ended::Failed(error) => error,
        };
        attempt += 1;
        if config.max_retries.is_some_and(|max| attempt > max) {
            status.send_replace(Status::Failed {
                error: error.to_string(),
            });
            return;
        }
        warn!("{error}, reconnecting (attempt {attempt})");
        status.send_replace(Status::Reconnecting {
            attempt,
            error: error.to_string(),
        });
        if until_stopped(sleep(retry_delay(attempt)), &mut config, &mut commands)
            .await
            .is_none()
        {
            status.send_replace(Status::Stopped);
            return;
        }
    }
}

/// Drive `work` while no session is up, answering commands meanwhile:
/// a volume is kept for the next session, a stop abandons `work`.
async fn until_stopped<T>(
    work: impl Future<Output = T>,
    config: &mut SenderConfig,
    commands: &mut mpsc::Receiver<Command>,
) -> Option<T> {
    let mut work = pin!(work);
    loop {
        select! {
            done = &mut work => return Some(done),
            command = commands.recv() => match command {
                Some(Command::SetVolume(percent, reply)) => {
                    config.volume = Some(percent);
                    let _ = reply.send(Ok(()));
                }
                Some(Command::Stop) | None => return None,
            },
        }
    }
}

/// Run one connected session until it fails or is stopped.
async fn stream(
    mut streaming: Streaming,
    config: &mut SenderConfig,
    status: &watch::Sender<Status>,
    commands: &mut mpsc::Receiver<Command>,
) -> Ended {
    if let Some(volume) = config.volume
        && let Err(error) = streaming.set_volume(volume).await
    {
        if !streaming.is_control_healthy() {
            return Ended::Failed(error);
        }
        // A receiver may refuse a volume; that is no reason to drop audio
        // or to retry it on every reconnect.
        warn!("volume {volume} rejected: {error}");
        config.volume = None;
    }
    let receiver_frames = streaming
        .receiver_latency_frames()
        .or(config.receiver_latency.map(duration_frames))
        .unwrap_or(DEFAULT_LATENCY_FRAMES);
    status.send_replace(Status::Streaming {
        receiver: streaming.device().name.clone(),
        latency: frames_duration(config.target_frames as u64 + u64::from(receiver_frames)),
    });

    loop {
        // `run_until` returns when the next command arrives, so it can be
        // handled between keepalives without racing them.
        let mut next = None;
        let outcome = streaming
            .run_until(async {
                next = commands.recv().await;
            })
            .await;
        if let Err(error) = outcome {
            return end_failed(streaming, error).await;
        }
        match next {
            Some(Command::SetVolume(percent, reply)) => {
                let result = streaming.set_volume(percent).await;
                if result.is_ok() {
                    config.volume = Some(percent);
                }
                let failed = result.as_ref().err().map(ToString::to_string);
                let _ = reply.send(result);
                if let Some(error) = failed
                    && !streaming.is_control_healthy()
                {
                    return end_failed(streaming, Error::Session(error)).await;
                }
            }
            // A dropped handle means nobody can stop us later; stop now.
            Some(Command::Stop) | None => {
                if let Err(error) = streaming.teardown().await {
                    warn!("teardown: {error}");
                }
                return Ended::Stopped;
            }
        }
    }
}

/// End a failed session, telling the receiver when the control connection
/// still works, so the reconnect is not ignored as a duplicate.
async fn end_failed(streaming: Streaming, error: Error) -> Ended {
    if streaming.is_control_healthy()
        && let Err(teardown_error) = streaming.teardown().await
    {
        warn!("teardown after failure: {teardown_error}");
    }
    Ended::Failed(error)
}

fn duration_frames(duration: Duration) -> u32 {
    (duration.as_secs_f64() * SAMPLE_RATE).round() as u32
}

fn frames_duration(frames: u64) -> Duration {
    Duration::from_secs_f64(frames as f64 / SAMPLE_RATE)
}

/// Doubling backoff from half a second, capped at ten.
fn retry_delay(attempt: u32) -> Duration {
    FIRST_RETRY_DELAY
        .saturating_mul(1 << attempt.saturating_sub(1).min(5))
        .min(MAX_RETRY_DELAY)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use tokio::time::timeout;

    use super::*;

    #[test]
    fn frame_and_duration_conversions_agree() {
        assert_eq!(duration_frames(Duration::from_millis(100)), 4_410);
        assert_eq!(frames_duration(2_205), Duration::from_millis(50));
    }

    #[test]
    fn retry_delay_doubles_then_caps() {
        let delays: Vec<_> = (1..=7).map(retry_delay).collect();
        assert_eq!(
            delays,
            [500, 1_000, 2_000, 4_000, 8_000, 10_000, 10_000].map(Duration::from_millis)
        );
    }

    /// A localhost port with nothing listening.
    fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        listener.local_addr().expect("addr")
    }

    #[tokio::test]
    async fn unreachable_receiver_fails_after_retries() {
        let config = SenderConfig {
            max_retries: Some(1),
            ..SenderConfig::default()
        };
        let (sender, _input) =
            Sender::start(closed_port(), PcmFormat::AIRPLAY, config).expect("start");
        let mut status = sender.status();

        let mut seen = Vec::new();
        let final_status = timeout(Duration::from_secs(5), async {
            loop {
                let current = status.borrow_and_update().clone();
                seen.push(current.clone());
                if matches!(current, Status::Failed { .. }) {
                    return current;
                }
                status.changed().await.expect("status open");
            }
        })
        .await
        .expect("fails in time");

        assert!(matches!(final_status, Status::Failed { .. }));
        assert!(
            seen.iter()
                .any(|status| matches!(status, Status::Reconnecting { attempt: 1, .. }))
        );
    }

    #[tokio::test]
    async fn stop_during_backoff_ends_cleanly() {
        let (sender, _input) =
            Sender::start(closed_port(), PcmFormat::AIRPLAY, SenderConfig::default())
                .expect("start");
        let mut status = sender.status();
        timeout(
            Duration::from_secs(5),
            status.wait_for(|status| matches!(status, Status::Reconnecting { .. })),
        )
        .await
        .expect("reconnecting in time")
        .expect("status open");

        // Kept for the next session while disconnected.
        assert!(sender.set_volume(50).await.is_ok());
        timeout(Duration::from_secs(1), sender.stop())
            .await
            .expect("stops promptly");
        assert_eq!(*status.borrow(), Status::Stopped);
    }

    #[tokio::test]
    async fn input_fills_ring_while_disconnected() {
        let (sender, mut input) =
            Sender::start(closed_port(), PcmFormat::AIRPLAY, SenderConfig::default())
                .expect("start");
        input.write(&[0_u8; 400]);
        // Drift correction keeps the resampler on, which holds back the
        // couple of frames its interpolation still needs.
        assert!((98..=100).contains(&sender.buffered_frames()));
        sender.stop().await;
    }
}
