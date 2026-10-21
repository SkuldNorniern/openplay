#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use log::{info, warn};
use openplay::audio::{AudioInput, AudioSource, WavAudio, parse_wav};
use openplay::cli::{self, CliError, Command};
use openplay::device::{self, Device, DeviceKind, Features};
use openplay::info;
use openplay::session::USER_AGENT;
use openplay::{Error, Result};
use openplay::{logging, session};
use tokio::select;
use tokio::signal::ctrl_c;
use tokio::time::sleep;

const BROWSE_WAIT: Duration = Duration::from_secs(3);
const AIRPLAY_PORT: u16 = 7000;
/// Half a second of 44.1 kHz audio: the most the source buffers.
const SOURCE_CAPACITY_FRAMES: usize = 22_050;
/// The file is fed until about a quarter second is queued, well below
/// capacity so nothing is dropped.
const FEED_TARGET_FRAMES: usize = 11_025;
/// Chunk the file like an audio engine period.
const FEED_PERIOD: Duration = Duration::from_millis(10);
const FEED_POLL: Duration = Duration::from_millis(4);
/// Receiver buffers about two seconds; wait that long after the last packet
/// before TEARDOWN so the end of the file is still heard.
const PLAYOUT_TAIL: Duration = Duration::from_secs(2);
const START_RETRY_DELAY: Duration = Duration::from_secs(2);

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
    let source = AudioSource::new(SOURCE_CAPACITY_FRAMES);
    let input = AudioInput::new(audio.format, source.clone())?;

    let start = || async {
        if buffered {
            session::start_buffered(addr, bind, source.clone()).await
        } else {
            session::start(addr, bind, source.clone()).await
        }
    };
    let mut streaming = match start().await {
        Ok(streaming) => streaming,
        Err(error) => {
            // A receiver now and then rejects stream SETUP when its clock
            // exchange has not started yet; a fresh session usually works.
            warn!("{error}, retrying");
            sleep(START_RETRY_DELAY).await;
            start().await?
        }
    };
    if let Some(volume) = volume {
        streaming.set_volume(volume).await?;
    }
    println!(
        "streaming {} to {} ({addr}), ctrl-c to stop",
        file.display(),
        streaming.device().name
    );
    let stop = async {
        select! {
            _ = ctrl_c() => {}
            () = feed(input, &source, &audio) => {}
        }
    };
    let outcome = streaming.run_until(stop).await;
    let stats = source.stats();
    info!(
        "underrun {} frames, overrun {} frames",
        stats.underrun_frames, stats.overrun_frames
    );
    let teardown = streaming.teardown().await;
    outcome.and(teardown)
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
async fn feed(mut input: AudioInput, source: &AudioSource, audio: &WavAudio) {
    let period_frames =
        (u128::from(audio.format.sample_rate) * FEED_PERIOD.as_millis() / 1000) as usize;
    for chunk in audio
        .data
        .chunks(period_frames * audio.format.bytes_per_frame())
    {
        while source.buffered_frames() >= FEED_TARGET_FRAMES {
            sleep(FEED_POLL).await;
        }
        input.write(chunk);
    }
    while source.buffered_frames() > 0 {
        sleep(FEED_POLL).await;
    }
    sleep(PLAYOUT_TAIL).await;
}
