//! One receiver as a speaker: the entry point for drivers and UIs.
//!
//! [`Sender::start`] returns an [`AudioInput`] to write PCM into and runs
//! the session in the background. When the receiver drops the stream the
//! sender reconnects with backoff while audio keeps arriving, so a system
//! audio device built on it survives Wi-Fi hiccups without the OS noticing.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::time::Duration;

use log::warn;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio::{select, spawn};

use crate::audio::{AudioInput, AudioSource, PcmFormat, SourceStats};
use crate::error::{Error, Result};
use crate::session::{self, Streaming};

/// Half a second of 44.1 kHz audio: the most the ring buffers.
pub const DEFAULT_CAPACITY_FRAMES: usize = 22_050;
/// A quarter second: the fill drift correction aims for with live input.
pub const DEFAULT_TARGET_FRAMES: usize = 11_025;
const FIRST_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);
const COMMAND_QUEUE: usize = 8;

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
        }
    }
}

/// What the sender is doing, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Connecting,
    /// Streaming to the named receiver.
    Streaming {
        receiver: String,
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
    let mut attempt = 0_u32;
    loop {
        status.send_replace(Status::Connecting);
        let started = match config.mode {
            StreamMode::Realtime => session::start(addr, config.bind, source.clone()).await,
            StreamMode::Buffered => {
                session::start_buffered(addr, config.bind, source.clone()).await
            }
        };
        let ended = match started {
            Ok(streaming) => {
                attempt = 0;
                stream(streaming, &mut config, &status, &mut commands).await
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
        if wait_or_stop(retry_delay(attempt), &mut commands).await {
            status.send_replace(Status::Stopped);
            return;
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
        return Ended::Failed(error);
    }
    status.send_replace(Status::Streaming {
        receiver: streaming.device().name.clone(),
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
            return Ended::Failed(error);
        }
        match next {
            Some(Command::SetVolume(percent, reply)) => {
                config.volume = Some(percent);
                let result = streaming.set_volume(percent).await;
                let failed = result.as_ref().err().map(ToString::to_string);
                let _ = reply.send(result);
                if let Some(error) = failed {
                    return Ended::Failed(Error::Rtsp(error));
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

/// Sleep before a retry; returns true if a stop arrived meanwhile.
async fn wait_or_stop(delay: Duration, commands: &mut mpsc::Receiver<Command>) -> bool {
    let mut deadline = pin!(sleep(delay));
    loop {
        select! {
            () = &mut deadline => return false,
            command = commands.recv() => match command {
                Some(Command::SetVolume(_, reply)) => {
                    let _ = reply.send(Err(Error::Protocol("not connected".to_owned())));
                }
                Some(Command::Stop) | None => return true,
            },
        }
    }
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

        assert!(sender.set_volume(50).await.is_err());
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
