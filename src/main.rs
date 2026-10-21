#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use log::info;
use openplay::audio::{AudioInput, WavAudio, parse_wav};
use openplay::cli::{self, CliError, Command};
use openplay::device::{self, Device, DeviceKind, Features};
use openplay::info;
use openplay::logging;
use openplay::sender::{Sender, SenderConfig, Status, StreamMode};
use openplay::session::USER_AGENT;
use openplay::{Error, Result};
use tokio::signal::ctrl_c;
use tokio::sync::watch;
use tokio::time::sleep;
use tokio::{select, spawn};

const BROWSE_WAIT: Duration = Duration::from_secs(3);
const AIRPLAY_PORT: u16 = 7000;
/// The file is fed until about a quarter second is queued, well below the
/// sender's half-second capacity so nothing is dropped.
const FEED_TARGET_FRAMES: usize = 11_025;
/// Chunk the file like an audio engine period.
const FEED_PERIOD: Duration = Duration::from_millis(10);
const FEED_POLL: Duration = Duration::from_millis(4);
/// Receiver buffers about two seconds; wait that long after the last packet
/// before TEARDOWN so the end of the file is still heard.
const PLAYOUT_TAIL: Duration = Duration::from_secs(2);
/// A receiver now and then rejects stream SETUP when its clock exchange
/// has not started yet; one fresh session usually works.
const PLAY_RETRIES: u32 = 1;

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

    let result = match cli.command {
        Command::Discover => run_discover(cli.bind).await,
        Command::Info { target } => run_info(&target, cli.bind).await,
        Command::Play { target, file } => {
            run_play(&target, &file, cli.bind, cli.volume, cli.buffered).await
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

async fn run_play(
    target: &str,
    file: &Path,
    bind: Option<Ipv4Addr>,
    volume: Option<u8>,
    buffered: bool,
) -> Result<()> {
    let audio = parse_wav(&fs::read(file)?)?;
    let addr = resolve(target, bind).await?;
    let config = SenderConfig {
        bind,
        mode: if buffered {
            StreamMode::Buffered
        } else {
            StreamMode::Realtime
        },
        volume,
        // The file is fed at the sender's pace, so there is no clock to follow.
        drift_correction: false,
        max_retries: Some(PLAY_RETRIES),
        ..SenderConfig::default()
    };
    let (sender, input) = Sender::start(addr, audio.format, config)?;
    let logger = spawn(log_status(sender.status(), file.display().to_string()));

    let mut status = sender.status();
    let outcome = select! {
        _ = ctrl_c() => Ok(()),
        () = feed(input, &sender, &audio) => Ok(()),
        failed = status.wait_for(|status| matches!(status, Status::Failed { .. })) => {
            match failed.map(|status| status.clone()) {
                Ok(Status::Failed { error }) => Err(Error::Protocol(error)),
                _ => Ok(()),
            }
        }
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

/// Print status changes as they happen.
async fn log_status(mut status: watch::Receiver<Status>, file: String) {
    loop {
        match status.borrow_and_update().clone() {
            Status::Streaming { receiver } => {
                println!("streaming {file} to {receiver}, ctrl-c to stop");
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
async fn feed(mut input: AudioInput, sender: &Sender, audio: &WavAudio) {
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
    while sender.buffered_frames() > 0 {
        sleep(FEED_POLL).await;
    }
    sleep(PLAYOUT_TAIL).await;
}
