#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("openplay {}", env!("CARGO_PKG_VERSION"));
    eprintln!("usage: openplay --discover");
    eprintln!("       openplay <target> <file.wav>");
    ExitCode::SUCCESS
}
