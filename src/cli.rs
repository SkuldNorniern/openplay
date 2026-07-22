//! Hand-rolled argument parsing for the dev binary.
//!
//! Intentionally tiny — no `clap`. The crate is library-first; this exists only
//! to drive the protocol core while building it out.

use std::net::Ipv4Addr;
use std::path::PathBuf;

/// What the binary was asked to do.
pub enum Command {
    /// List AirPlay receivers on the network.
    Discover,
    /// Stream a WAV file to a receiver (name or IP).
    Play { target: String, file: PathBuf },
}

/// Parsed command line.
pub struct Cli {
    pub command: Command,
    /// Local IPv4 to bind (the LAN interface), pinning the egress path.
    pub bind: Option<Ipv4Addr>,
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
     \x20 openplay <target> <file.wav> [--iface <ip>]\n\
     \n\
     options:\n\
     \x20 -i, --iface <ip>  bind to this local IPv4 (LAN interface)\n\
     \x20 -v, --verbose     more log detail\n\
     \x20 -h, --help        show this help\n\
     \n\
     <target> is a receiver name (e.g. Bedroom) or an IP address."
}

/// Parse process arguments (excluding argv[0]).
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Cli, CliError> {
    let mut bind = None;
    let mut verbose = false;
    let mut discover = false;
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
            "--discover" => discover = true,
            "-i" | "--iface" => {
                let val = it.next().ok_or(CliError::Usage)?;
                let ip = val.parse::<Ipv4Addr>().map_err(|_| CliError::Usage)?;
                bind = Some(ip);
            }
            other if other.starts_with('-') => return Err(CliError::Usage),
            _ => positionals.push(arg),
        }
    }

    let command = build_command(discover, positionals)?;
    Ok(Cli {
        command,
        bind,
        verbose,
    })
}

fn build_command(discover: bool, positionals: Vec<String>) -> Result<Command, CliError> {
    if discover {
        if !positionals.is_empty() {
            return Err(CliError::Usage);
        }
        return Ok(Command::Discover);
    }
    match positionals.as_slice() {
        [target, file] => Ok(Command::Play {
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
        let cli = parse_ok(&["--discover", "--iface", "192.168.50.5"]);
        assert!(matches!(cli.command, Command::Discover));
        assert_eq!(cli.bind, Some(Ipv4Addr::new(192, 168, 50, 5)));
    }

    #[test]
    fn parses_play_positionals() {
        let cli = parse_ok(&["Bedroom", "song.wav", "-v"]);
        assert!(cli.verbose);
        match cli.command {
            Command::Play { target, file } => {
                assert_eq!(target, "Bedroom");
                assert_eq!(file, PathBuf::from("song.wav"));
            }
            Command::Discover => panic!("expected play"),
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
        let cli = parse_ok(&["--", "-Bedroom", "song.wav"]);
        match cli.command {
            Command::Play { target, .. } => assert_eq!(target, "-Bedroom"),
            Command::Discover => panic!("expected play"),
        }
    }
}
