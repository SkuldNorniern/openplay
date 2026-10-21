#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use openplay::audio::{AudioSource, Frame, PcmSamples, parse_wav};
use openplay::cli::{self, CliError, Command};
use openplay::discovery::{self, SERVICE_AIRPLAY, SERVICE_RAOP};
use openplay::{Error, Result};
use openplay::{logging, session};
use tokio::select;
use tokio::signal::ctrl_c;
use tokio::time::sleep;

const BROWSE_WAIT: Duration = Duration::from_secs(3);
const AIRPLAY_PORT: u16 = 7000;
const FRAMES_PER_PACKET: usize = 352;
/// About a quarter second of queued audio between the file and the sender.
const QUEUED_PACKETS: usize = 32;
const FEED_POLL: Duration = Duration::from_millis(4);
/// Receiver buffers about two seconds; wait that long after the last packet
/// before TEARDOWN so the end of the file is still heard.
const PLAYOUT_TAIL: Duration = Duration::from_secs(2);

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
        Command::Play { target, file } => run_play(&target, &file, cli.bind).await,
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
    let found = discovery::browse(&[SERVICE_AIRPLAY, SERVICE_RAOP], bind, BROWSE_WAIT).await?;
    if found.is_empty() {
        println!("no receivers found");
        return Ok(());
    }
    for r in found {
        let model = r.txt.get("model").map(String::as_str).unwrap_or("?");
        let addr = r
            .addrs
            .first()
            .map(|a| a.to_string())
            .unwrap_or_else(|| r.host.clone());
        println!("{:<24} {}:{}  [{}]", r.instance, addr, r.port, model);
    }
    Ok(())
}

async fn run_play(target: &str, file: &Path, bind: Option<Ipv4Addr>) -> Result<()> {
    let samples = parse_wav(&fs::read(file)?)?;
    let addr = resolve(target, bind).await?;
    let source = AudioSource::new(QUEUED_PACKETS);

    let mut streaming = session::start(addr, bind, source.clone()).await?;
    println!(
        "streaming {} to {} ({addr}), ctrl-c to stop",
        file.display(),
        streaming.device().name
    );
    let stop = async {
        select! {
            _ = ctrl_c() => {}
            () = feed(&source, samples) => {}
        }
    };
    let outcome = streaming.run_until(stop).await;
    let teardown = streaming.teardown().await;
    outcome.and(teardown)
}

/// Accept an IP address directly, otherwise find the receiver by name.
async fn resolve(target: &str, bind: Option<Ipv4Addr>) -> Result<SocketAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, AIRPLAY_PORT));
    }

    let found = discovery::browse(&[SERVICE_AIRPLAY], bind, BROWSE_WAIT).await?;
    let record = found
        .into_iter()
        .find(|record| record.instance.eq_ignore_ascii_case(target))
        .ok_or_else(|| Error::Discovery(format!("no receiver named {target}")))?;
    let ip = record
        .addrs
        .iter()
        .find(|addr| addr.is_ipv4())
        .or(record.addrs.first())
        .copied()
        .ok_or_else(|| Error::Discovery(format!("{target} has no address")))?;
    Ok(SocketAddr::new(ip, record.port))
}

/// Queue the file in packet-sized chunks no faster than the sender drains
/// them, since a full source drops its oldest audio.
async fn feed(source: &AudioSource, samples: PcmSamples) {
    for chunk in samples.interleaved.chunks(FRAMES_PER_PACKET * 2) {
        while source.len() >= QUEUED_PACKETS {
            sleep(FEED_POLL).await;
        }
        source.write(Frame::Pcm(chunk.to_vec()));
    }
    while !source.is_empty() {
        sleep(FEED_POLL).await;
    }
    sleep(PLAYOUT_TAIL).await;
}
