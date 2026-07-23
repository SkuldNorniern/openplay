#![forbid(unsafe_code)]

use std::env;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use openplay::Result;
use openplay::cli::{self, CliError, Command};
use openplay::discovery::{self, SERVICE_AIRPLAY, SERVICE_RAOP};

const BROWSE_WAIT: Duration = Duration::from_secs(3);

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

    let result = match cli.command {
        Command::Discover => run_discover(cli.bind).await,
        Command::Play { .. } => {
            eprintln!("streaming is not implemented yet");
            return ExitCode::FAILURE;
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
