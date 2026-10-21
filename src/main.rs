#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use log::info;
use openplay::audio::{AudioInput, PcmFormat, WavAudio, parse_wav};
use openplay::capture::{self, CAPTURE_FORMAT, Loopback};
use openplay::cli::{self, CliError, Command};
use openplay::device::{self, Device, DeviceKind, Features};
use openplay::info;
use openplay::logging;
use openplay::sender::{DEFAULT_CAPACITY_FRAMES, Sender, SenderConfig, Status, StreamMode};
use openplay::session::USER_AGENT;
use openplay::{Error, Result};
use tokio::signal::ctrl_c;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio::{select, spawn};

const BROWSE_WAIT: Duration = Duration::from_secs(3);
const AIRPLAY_PORT: u16 = 7000;
/// The file is fed until 100 ms is queued, well below the sender's ring
/// capacity so nothing is dropped.
const FEED_TARGET_FRAMES: usize = 4_410;
const _: () = assert!(FEED_TARGET_FRAMES < DEFAULT_CAPACITY_FRAMES);
/// Chunk the file like an audio engine period.
const FEED_PERIOD: Duration = Duration::from_millis(10);
const FEED_POLL: Duration = Duration::from_millis(4);
/// Receiver buffers about two seconds; wait that long after the last packet
/// before TEARDOWN so the end of the file is still heard.
const PLAYOUT_TAIL: Duration = Duration::from_secs(2);
/// Extra wait past a reported latency before TEARDOWN.
const PLAYOUT_MARGIN: Duration = Duration::from_millis(500);
/// Chunks of stdin buffered between the reader thread and the sender.
const STDIN_QUEUE: usize = 16;
/// A receiver now and then rejects stream SETUP when its clock exchange
/// has not started yet; one fresh session usually works.
const PLAY_RETRIES: u32 = 1;
/// How often loopback mode checks that capture is still running.
const CAPTURE_CHECK: Duration = Duration::from_millis(500);

#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args().skip(1);
    let cli = match cli::parse(args) {
        Ok(cli) => cli,
        Err(CliError::Help) => {
            println!("{}", cli::usage());
            return ExitCode::SUCCESS;
        }
        Err(CliError::Usage) => {
            eprintln!("{}", cli::usage());
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = logging::init(cli.verbose) {
        eprintln!("error: logger: {error}");
        return ExitCode::FAILURE;
    }

    let settings = Settings {
        bind: cli.bind,
        volume: cli.volume,
        buffered: cli.buffered,
        latency: cli.latency,
    };
    let result = match cli.command {
        Command::Discover => run_discover(cli.bind).await,
        Command::Info { target } => run_info(&target, cli.bind).await,
        Command::Devices => run_devices(),
        Command::Loopback { target, device } => {
            run_loopback(&target, device.as_deref(), &settings).await
        }
        Command::Play { target, file } => {
            let feed = if file == Path::new("-") {
                Ok(Feed::Stdin(cli.pcm))
            } else {
                fs::read(&file)
                    .map_err(Error::from)
                    .and_then(|bytes| parse_wav(&bytes))
                    .map(Feed::File)
            };
            match feed {
                Ok(feed) => run_play(&target, feed, &settings).await,
                Err(error) => Err(error),
            }
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_discover(bind: Option<Ipv4Addr>) -> Result<()> {
    let devices = device::scan(bind, BROWSE_WAIT).await?;
    if devices.is_empty() {
        println!("no receivers found");
        return Ok(());
    }
    for device in devices {
        println!("{}", describe(&device));
    }
    Ok(())
}

fn describe(device: &Device) -> String {
    let model = device.model.as_deref().unwrap_or("?");
    let version = device.airplay_version.as_deref().unwrap_or("?");
    let pairing = if device.can_stream_without_pin() {
        "no pin"
    } else {
        "needs pin"
    };
    format!(
        "{:<20} {:<21} {} ({model}) airplay {version}, {pairing} [{}]",
        device.name,
        device.addr.to_string(),
        device.kind,
        device.features.names().join(", ")
    )
}

async fn run_info(target: &str, bind: Option<Ipv4Addr>) -> Result<()> {
    let addr = resolve(target, bind).await?;
    let info = info::fetch(addr, bind, USER_AGENT).await?;
    let features = Features::from_bits(info.features);

    println!("name      {}", info.name);
    println!("address   {addr}");
    println!(
        "model     {} ({})",
        info.model,
        DeviceKind::from_model(&info.model)
    );
    println!("airplay   {}", info.source_version);
    println!("device id {}", info.device_id);
    println!(
        "features  {:#018x} [{}]",
        info.features,
        features.names().join(", ")
    );
    println!("status    {:#x}", info.status_flags);
    Ok(())
}

/// Where the audio comes from.
enum Feed {
    File(WavAudio),
    /// Live PCM on stdin, from a capture tool such as `parec`.
    Stdin(PcmFormat),
}

async fn run_play(target: &str, feed: Feed, settings: &Settings) -> Result<()> {
    let addr = resolve(target, settings.bind).await?;
    let (format, live, name) = match &feed {
        Feed::File(audio) => (audio.format, false, "file"),
        Feed::Stdin(format) => (*format, true, "stdin"),
    };
    let config = sender_config(settings, live);
    let (sender, input) = Sender::start(addr, format, config)?;
    let logger = spawn(log_status(sender.status(), name));

    let outcome = select! {
        _ = ctrl_c() => Ok(()),
        fed = feed_input(input, &sender, feed) => fed,
        failed = wait_for_failure(&sender) => failed,
    };
    let stats = sender.stats();
    info!(
        "underrun {} frames, overrun {} frames",
        stats.underrun_frames, stats.overrun_frames
    );
    sender.stop().await;
    logger.abort();
    outcome
}

async fn feed_input(input: AudioInput, sender: &Sender, feed: Feed) -> Result<()> {
    match feed {
        Feed::File(audio) => {
            feed_file(input, sender, &audio).await;
            Ok(())
        }
        Feed::Stdin(format) => feed_stdin(input, sender, format).await,
    }
}

/// Pass stdin through as it arrives; the capture tool sets the pace.
async fn feed_stdin(mut input: AudioInput, sender: &Sender, format: PcmFormat) -> Result<()> {
    let period_frames = (u128::from(format.sample_rate) * FEED_PERIOD.as_millis() / 1000) as usize;
    let mut chunks = read_stdin(period_frames * format.bytes_per_frame());
    while let Some(chunk) = chunks.recv().await {
        input.write(&chunk?);
    }
    drain(sender, false).await;
    Ok(())
}

/// Read stdin on a plain thread, in chunks of up to `chunk_len` bytes; the
/// channel closes at end of input.
///
/// Tokio's stdin blocks runtime shutdown until a pending read returns, so
/// ctrl-c would hang on a quiet pipe. A detached thread ends with the
/// process instead.
fn read_stdin(chunk_len: usize) -> mpsc::Receiver<Result<Vec<u8>>> {
    let (chunks, receiver) = mpsc::channel(STDIN_QUEUE);
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buffer = vec![0_u8; chunk_len];
        loop {
            let chunk = match stdin.read(&mut buffer) {
                Ok(0) => return,
                Ok(read) => Ok(buffer[..read].to_vec()),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => Err(error.into()),
            };
            let failed = chunk.is_err();
            if chunks.blocking_send(chunk).is_err() || failed {
                return;
            }
        }
    });
    receiver
}

/// Wait for queued audio to go out and play.
///
/// Nothing drains the queue without a session. A file waits out reconnects,
/// which end in `Failed` since its retries are capped; live input that ends
/// while disconnected is dropped, as retries there never give up.
async fn drain(sender: &Sender, wait_for_session: bool) {
    let waiting = || match *sender.status().borrow() {
        Status::Streaming { .. } => true,
        Status::Connecting | Status::Reconnecting { .. } => wait_for_session,
        Status::Stopped | Status::Failed { .. } => false,
    };
    while sender.buffered_frames() > 0 && waiting() {
        sleep(FEED_POLL).await;
    }
    // The receiver plays the last packet its own latency after it arrives.
    let latency = match *sender.status().borrow() {
        Status::Streaming { latency, .. } => Some(latency),
        _ => None,
    };
    if let Some(latency) = latency {
        sleep(PLAYOUT_TAIL.max(latency + PLAYOUT_MARGIN)).await;
    }
}

/// Settings for a CLI run. Live input follows its source's clock and
/// outlasts receiver hiccups; a file is fed at the sender's pace and fails
/// fast instead.
fn sender_config(cli: &Settings, live: bool) -> SenderConfig {
    let Settings {
        bind,
        volume,
        buffered,
        latency,
    } = *cli;
    SenderConfig {
        bind,
        mode: if buffered {
            StreamMode::Buffered
        } else {
            StreamMode::Realtime
        },
        volume,
        drift_correction: live,
        max_retries: if live { None } else { Some(PLAY_RETRIES) },
        receiver_latency: latency,
        ..SenderConfig::default()
    }
}

/// Stream settings shared by every play mode.
#[derive(Clone, Copy)]
struct Settings {
    bind: Option<Ipv4Addr>,
    volume: Option<u8>,
    buffered: bool,
    latency: Option<Duration>,
}

/// Resolve once the sender gives up, with its last error.
async fn wait_for_failure(sender: &Sender) -> Result<()> {
    let mut status = sender.status();
    let failed = status
        .wait_for(|status| matches!(status, Status::Failed { .. }))
        .await
        .map(|status| status.clone());
    match failed {
        Ok(Status::Failed { error }) => Err(Error::Session(error)),
        _ => Ok(()),
    }
}

fn run_devices() -> Result<()> {
    for (index, name) in capture::render_devices()?.iter().enumerate() {
        let default = if index == 0 { " (default)" } else { "" };
        println!("{name}{default}");
    }
    Ok(())
}

/// Stream what the PC plays until ctrl-c.
async fn run_loopback(target: &str, device: Option<&str>, settings: &Settings) -> Result<()> {
    // Fails fast where capture is unsupported, before any connection.
    capture::render_devices()?;
    let addr = resolve(target, settings.bind).await?;
    let config = sender_config(settings, true);
    let (sender, input) = Sender::start(addr, CAPTURE_FORMAT, config)?;
    let capture = match Loopback::start(device, input) {
        Ok(capture) => capture,
        Err(error) => {
            sender.stop().await;
            return Err(error);
        }
    };
    info!("capturing {}", capture.device());
    let logger = spawn(log_status(sender.status(), "system audio"));

    let outcome = select! {
        _ = ctrl_c() => Ok(()),
        failed = wait_for_failure(&sender) => failed,
        () = wait_while(|| capture.is_running()) => {
            Err(Error::Audio("capture stopped".to_owned()))
        }
    };
    // The thread's own error explains a stopped capture better.
    let outcome = match (outcome, capture.stop()) {
        (Err(Error::Audio(_)), Err(capture_error)) => Err(capture_error),
        (outcome, _) => outcome,
    };
    sender.stop().await;
    logger.abort();
    outcome
}

async fn wait_while(condition: impl Fn() -> bool) {
    while condition() {
        sleep(CAPTURE_CHECK).await;
    }
}

/// Print status changes as they happen.
async fn log_status(mut status: watch::Receiver<Status>, name: &'static str) {
    loop {
        match status.borrow_and_update().clone() {
            Status::Streaming { receiver, latency } => {
                println!(
                    "streaming {name} to {receiver} (about {} ms behind), ctrl-c to stop",
                    latency.as_millis()
                );
            }
            // The sender logs reconnects itself.
            Status::Connecting
            | Status::Reconnecting { .. }
            | Status::Stopped
            | Status::Failed { .. } => {}
        }
        if status.changed().await.is_err() {
            return;
        }
    }
}

/// Accept an IP address directly, otherwise find the receiver by name.
async fn resolve(target: &str, bind: Option<Ipv4Addr>) -> Result<SocketAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, AIRPLAY_PORT));
    }

    device::scan(bind, BROWSE_WAIT)
        .await?
        .into_iter()
        .find(|device| device.name.eq_ignore_ascii_case(target))
        .map(|device| device.addr)
        .ok_or_else(|| Error::Discovery(format!("no receiver named {target}")))
}

/// Feed the file through the same conversion a live driver uses, in engine
/// sized chunks, no faster than the sender drains them.
async fn feed_file(mut input: AudioInput, sender: &Sender, audio: &WavAudio) {
    let period_frames =
        (u128::from(audio.format.sample_rate) * FEED_PERIOD.as_millis() / 1000) as usize;
    for chunk in audio
        .data
        .chunks(period_frames * audio.format.bytes_per_frame())
    {
        while sender.buffered_frames() >= FEED_TARGET_FRAMES {
            sleep(FEED_POLL).await;
        }
        input.write(chunk);
    }
    drain(sender, true).await;
}
