//! Hand-rolled command-line argument parsing. Intentionally tiny — no `clap`.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use crate::audio::{PcmFormat, SampleFormat};

/// What the binary was asked to do.
pub enum Command {
    /// List AirPlay receivers on the network.
    Discover,
    /// Show one receiver's details from its `/info`.
    Info { target: String },
    /// Stream a WAV file, or raw PCM from stdin when `file` is `-`, to a
    /// receiver (name or IP).
    Play { target: String, file: PathBuf },
    /// Stream what this PC plays (Windows loopback capture).
    Loopback {
        target: String,
        /// Render device name to capture; the default output when unset.
        device: Option<String>,
    },
    /// List output devices that loopback can capture.
    Devices,
}

/// Parsed command line.
pub struct Cli {
    pub command: Command,
    /// Local IPv4 to bind (the LAN interface), pinning the egress path.
    pub bind: Option<Ipv4Addr>,
    /// Playback volume 0 to 100; the receiver's current volume when unset.
    pub volume: Option<u8>,
    /// Use a buffered, PTP-timed stream instead of realtime.
    pub buffered: bool,
    /// Layout of raw PCM read from stdin.
    pub pcm: PcmFormat,
    /// Playout latency to ask the receiver for (experimental).
    pub latency: Option<Duration>,
    pub verbose: bool,
}

/// Why parsing did not yield a runnable command.
#[derive(Debug)]
pub enum CliError {
    /// `--help` was requested — not an error; print usage to stdout.
    Help,
    /// Bad arguments — print usage to stderr and exit non-zero.
    Usage,
}

/// Usage text shown on `--help` or a parse error.
pub fn usage() -> &'static str {
    "openplay — AirPlay 2 audio sender\n\
     \n\
     usage:\n\
     \x20 openplay --discover [--iface <ip>]\n\
     \x20 openplay --info <target> [--iface <ip>]\n\
     \x20 openplay --devices\n\
     \x20 openplay <target> <file.wav> [--iface <ip>] [--volume <0-100>] [--buffered]\n\
     \x20 openplay <target> - [--rate <hz>] [--channels <n>] [--sample <s16|s24|s32|f32>]\n\
     \x20 openplay <target> --loopback [--device <name>]\n\
     \n\
     options:\n\
     \x20 -i, --iface <ip>  bind to this local IPv4 (LAN interface)\n\
     \x20 --volume <0-100>  playback volume, 0 mutes\n\
     \x20 --buffered        buffered stream timed by PTP (experimental)\n\
     \x20 --latency-ms <n>  playout latency to ask the receiver for (experimental)\n\
     \x20 --rate <hz>       stdin sample rate (default 44100)\n\
     \x20 --channels <n>    stdin channel count (default 2)\n\
     \x20 --sample <type>   stdin sample type: s16, s24, s32 or f32 (default s16)\n\
     \x20 --loopback        stream what this PC plays (Windows)\n\
     \x20 --device <name>   output device to capture, by part of its name\n\
     \x20 -v, --verbose     more log detail\n\
     \x20 -h, --help        show this help\n\
     \n\
     <target> is a receiver name (e.g. Speaker) or an IP address.\n\
     A file of - reads interleaved little-endian PCM from stdin."
}

/// Parse process arguments (excluding argv[0]).
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Cli, CliError> {
    let mut bind = None;
    let mut volume = None;
    let mut buffered = false;
    let mut pcm = PcmFormat::AIRPLAY;
    let mut latency = None;
    let mut verbose = false;
    let mut selected = Selected::default();
    let mut positionals: Vec<String> = Vec::new();
    let mut opts_done = false;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        if opts_done {
            positionals.push(arg);
            continue;
        }
        match arg.as_str() {
            "--" => opts_done = true,
            "-h" | "--help" => return Err(CliError::Help),
            "-v" | "--verbose" => verbose = true,
            "--discover" => selected.discover = true,
            "--devices" => selected.devices = true,
            "--loopback" => selected.loopback = true,
            "--device" => selected.device = Some(it.next().ok_or(CliError::Usage)?),
            "--buffered" => buffered = true,
            "--rate" => pcm.sample_rate = parse_value(it.next())?,
            "--latency-ms" => {
                latency = Some(Duration::from_millis(parse_value(it.next())?));
            }
            "--channels" => pcm.channels = parse_value(it.next())?,
            "--sample" => {
                pcm.sample = match it.next().as_deref() {
                    Some("s16") => SampleFormat::I16,
                    Some("s24") => SampleFormat::I24,
                    Some("s32") => SampleFormat::I32,
                    Some("f32") => SampleFormat::F32,
                    _ => return Err(CliError::Usage),
                }
            }
            "--info" => selected.info = Some(it.next().ok_or(CliError::Usage)?),
            "-i" | "--iface" => {
                let val = it.next().ok_or(CliError::Usage)?;
                let ip = val.parse::<Ipv4Addr>().map_err(|_| CliError::Usage)?;
                bind = Some(ip);
            }
            "--volume" => {
                let val = it.next().ok_or(CliError::Usage)?;
                let level = val.parse::<u8>().map_err(|_| CliError::Usage)?;
                if level > 100 {
                    return Err(CliError::Usage);
                }
                volume = Some(level);
            }
            // A lone dash is the stdin file argument, not an option.
            "-" => positionals.push(arg),
            other if other.starts_with('-') => return Err(CliError::Usage),
            _ => positionals.push(arg),
        }
    }

    pcm.validate().map_err(|_| CliError::Usage)?;
    let command = build_command(selected, positionals)?;
    Ok(Cli {
        command,
        bind,
        volume,
        buffered,
        pcm,
        latency,
        verbose,
    })
}

fn parse_value<T: FromStr>(value: Option<String>) -> Result<T, CliError> {
    value
        .ok_or(CliError::Usage)?
        .parse()
        .map_err(|_| CliError::Usage)
}

/// Options that pick the command.
#[derive(Default)]
struct Selected {
    discover: bool,
    info: Option<String>,
    devices: bool,
    loopback: bool,
    device: Option<String>,
}

fn build_command(selected: Selected, positionals: Vec<String>) -> Result<Command, CliError> {
    let modes = [
        selected.discover,
        selected.info.is_some(),
        selected.devices,
        selected.loopback,
    ];
    if modes.iter().filter(|mode| **mode).count() > 1
        || (selected.device.is_some() && !selected.loopback)
    {
        return Err(CliError::Usage);
    }

    match (selected, positionals.as_slice()) {
        (Selected { discover: true, .. }, []) => Ok(Command::Discover),
        (Selected { devices: true, .. }, []) => Ok(Command::Devices),
        (
            Selected {
                info: Some(target), ..
            },
            [],
        ) => Ok(Command::Info { target }),
        (
            Selected {
                loopback: true,
                device,
                ..
            },
            [target],
        ) => Ok(Command::Loopback {
            target: target.clone(),
            device,
        }),
        (
            Selected {
                discover: false,
                info: None,
                devices: false,
                loopback: false,
                ..
            },
            [target, file],
        ) => Ok(Command::Play {
            target: target.clone(),
            file: PathBuf::from(file),
        }),
        _ => Err(CliError::Usage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Cli {
        parse(args.iter().map(|s| s.to_string())).unwrap_or_else(|_| panic!("parse failed"))
    }

    #[test]
    fn parses_discover_with_iface() {
        let cli = parse_ok(&["--discover", "--iface", "192.0.2.10"]);
        assert!(matches!(cli.command, Command::Discover));
        assert_eq!(cli.bind, Some(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn parses_play_positionals() {
        let cli = parse_ok(&["Speaker", "song.wav", "-v"]);
        assert!(cli.verbose);
        match cli.command {
            Command::Play { target, file } => {
                assert_eq!(target, "Speaker");
                assert_eq!(file, PathBuf::from("song.wav"));
            }
            _ => panic!("expected play"),
        }
    }

    #[test]
    fn parses_info_target() {
        let cli = parse_ok(&["--info", "Speaker", "-i", "192.0.2.10"]);
        match cli.command {
            Command::Info { target } => assert_eq!(target, "Speaker"),
            _ => panic!("expected info"),
        }
        assert!(matches!(
            parse(["--info"].map(String::from)),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            parse(["--info", "Speaker", "--discover"].map(String::from)),
            Err(CliError::Usage)
        ));
    }

    #[test]
    fn parses_stdin_pcm_format() {
        let cli = parse_ok(&[
            "Speaker",
            "-",
            "--rate",
            "48000",
            "--channels",
            "6",
            "--sample",
            "f32",
        ]);
        assert_eq!(
            cli.pcm,
            PcmFormat {
                sample_rate: 48_000,
                channels: 6,
                sample: SampleFormat::F32
            }
        );
        assert_eq!(parse_ok(&["Speaker", "-"]).pcm, PcmFormat::AIRPLAY);
        for bad in [
            &["Speaker", "-", "--sample", "u8"][..],
            &["Speaker", "-", "--rate", "fast"],
            &["Speaker", "-", "--channels", "0"],
            &["Speaker", "-", "--rate"],
        ] {
            assert!(matches!(
                parse(bad.iter().map(|s| s.to_string())),
                Err(CliError::Usage)
            ));
        }
    }

    #[test]
    fn parses_loopback_and_devices() {
        match parse_ok(&["Speaker", "--loopback", "--device", "CABLE"]).command {
            Command::Loopback { target, device } => {
                assert_eq!(target, "Speaker");
                assert_eq!(device.as_deref(), Some("CABLE"));
            }
            _ => panic!("expected loopback"),
        }
        assert!(matches!(
            parse_ok(&["Speaker", "--loopback"]).command,
            Command::Loopback { device: None, .. }
        ));
        assert!(matches!(parse_ok(&["--devices"]).command, Command::Devices));
        for bad in [
            &["Speaker", "song.wav", "--loopback"][..],
            &["Speaker", "song.wav", "--device", "x"],
            &["--devices", "--discover"],
            &["--loopback"],
        ] {
            assert!(matches!(
                parse(bad.iter().map(|s| s.to_string())),
                Err(CliError::Usage)
            ));
        }
    }

    #[test]
    fn parses_latency_in_milliseconds() {
        assert_eq!(
            parse_ok(&["Speaker", "-", "--latency-ms", "100"]).latency,
            Some(Duration::from_millis(100))
        );
        assert_eq!(parse_ok(&["Speaker", "-"]).latency, None);
        assert!(matches!(
            parse(["Speaker", "-", "--latency-ms", "-5"].map(String::from)),
            Err(CliError::Usage)
        ));
    }

    #[test]
    fn parses_buffered_flag() {
        assert!(parse_ok(&["Speaker", "song.wav", "--buffered"]).buffered);
        assert!(!parse_ok(&["Speaker", "song.wav"]).buffered);
    }

    #[test]
    fn parses_volume_in_range_only() {
        assert_eq!(
            parse_ok(&["Speaker", "song.wav", "--volume", "35"]).volume,
            Some(35)
        );
        assert_eq!(parse_ok(&["Speaker", "song.wav"]).volume, None);
        for bad in ["101", "-1", "loud"] {
            assert!(matches!(
                parse(["Speaker", "song.wav", "--volume", bad].map(String::from)),
                Err(CliError::Usage)
            ));
        }
    }

    #[test]
    fn rejects_bad_iface_and_stray_args() {
        assert!(matches!(
            parse(["--iface", "nope"].map(String::from)),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            parse(["--discover", "extra"].map(String::from)),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            parse(["only-one-positional"].map(String::from)),
            Err(CliError::Usage)
        ));
    }

    #[test]
    fn help_is_distinct_from_usage_error() {
        assert!(matches!(
            parse(["--help"].map(String::from)),
            Err(CliError::Help)
        ));
    }

    #[test]
    fn double_dash_allows_dash_prefixed_positionals() {
        let cli = parse_ok(&["--", "-Speaker", "song.wav"]);
        match cli.command {
            Command::Play { target, .. } => assert_eq!(target, "-Speaker"),
            _ => panic!("expected play"),
        }
    }
}
