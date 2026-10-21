//! Minimal stderr backend for the `log` facade, so no logger crate is needed.

use log::{
    Level, LevelFilter, Log, Metadata, Record, SetLoggerError, max_level, set_logger, set_max_level,
};

struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        };
        eprintln!("{level}: {}", record.args());
    }

    fn flush(&self) {}
}

/// Install the logger. `verbose` turns on debug output.
pub fn init(verbose: bool) -> Result<(), SetLoggerError> {
    set_logger(&LOGGER)?;
    set_max_level(if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
    Ok(())
}
