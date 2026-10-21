//! System audio capture: what the PC plays, as live input for a [`Sender`].
//!
//! On Windows this is WASAPI loopback on a render device: the default
//! speakers, or a virtual cable a user routes apps to. It is the stopgap
//! until openplay has its own virtual audio device. Other platforms pipe
//! audio in on stdin instead (PipeWire or PulseAudio `parec` from a null
//! sink).
//!
//! [`Sender`]: crate::sender::Sender

use crate::audio::{PcmFormat, SampleFormat};

/// The format capture asks Windows for. Its shared-mode converter does the
/// resampling, so no rate conversion runs in openplay.
pub const CAPTURE_FORMAT: PcmFormat = PcmFormat {
    sample_rate: 44_100,
    channels: 2,
    sample: SampleFormat::F32,
};

#[cfg(windows)]
pub use self::windows::{Loopback, render_devices};

#[cfg(not(windows))]
pub use self::unsupported::{Loopback, render_devices};

#[cfg(windows)]
mod windows {
    use std::fmt::Display;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use log::{info, warn};
    use wasapi::{
        AudioClient, Device, DeviceEnumerator, Direction, SampleType, StreamMode, WaveFormat,
        initialize_mta,
    };

    use super::CAPTURE_FORMAT;
    use crate::audio::AudioInput;
    use crate::error::{Error, Result};

    /// How often the capture thread drains WASAPI's buffer. Loopback gives
    /// no events while nothing plays, so it polls.
    const POLL_INTERVAL: Duration = Duration::from_millis(3);
    /// Shared-mode buffer: 100 ms, in 100 ns units. Loose enough that a
    /// late wake-up never loses audio.
    const BUFFER_DURATION_HNS: i64 = 1_000_000;
    /// Polls between checks for a new default output: about a second.
    const DEFAULT_CHECK_POLLS: u32 = 333;

    fn audio_error(error: impl Display) -> Error {
        Error::Audio(error.to_string())
    }

    /// Names of the active render devices, default first.
    pub fn render_devices() -> Result<Vec<String>> {
        let _ = initialize_mta();
        let enumerator = DeviceEnumerator::new().map_err(audio_error)?;
        let default = enumerator
            .get_default_device(&Direction::Render)
            .and_then(|device| device.get_friendlyname())
            .ok();
        let collection = enumerator
            .get_device_collection(&Direction::Render)
            .map_err(audio_error)?;
        let mut names = Vec::new();
        for device in &collection {
            let name = device
                .and_then(|device| device.get_friendlyname())
                .map_err(audio_error)?;
            names.push(name);
        }
        if let Some(default) = default
            && let Some(position) = names.iter().position(|name| *name == default)
        {
            names[..=position].rotate_right(1);
        }
        Ok(names)
    }

    fn find_device(enumerator: &DeviceEnumerator, name: Option<&str>) -> Result<Device> {
        let Some(wanted) = name else {
            return enumerator
                .get_default_device(&Direction::Render)
                .map_err(audio_error);
        };
        let wanted = wanted.to_lowercase();
        let collection = enumerator
            .get_device_collection(&Direction::Render)
            .map_err(audio_error)?;
        for device in &collection {
            let device = device.map_err(audio_error)?;
            let name = device.get_friendlyname().map_err(audio_error)?;
            if name.to_lowercase().contains(&wanted) {
                return Ok(device);
            }
        }
        Err(Error::Audio(format!(
            "no render device matching {wanted:?}"
        )))
    }

    /// Loopback capture running on its own thread, feeding an [`AudioInput`]
    /// created for [`CAPTURE_FORMAT`].
    pub struct Loopback {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<Result<()>>>,
        device: String,
    }

    impl Loopback {
        /// Capture the render device whose name contains `device`, or the
        /// default output when `None`.
        pub fn start(device: Option<&str>, mut input: AudioInput) -> Result<Self> {
            if input.format() != CAPTURE_FORMAT {
                return Err(Error::Audio(
                    "loopback input must be created for CAPTURE_FORMAT".to_owned(),
                ));
            }
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let wanted = device.map(str::to_owned);
            let (ready_sender, ready) = mpsc::channel();

            // COM objects stay on the thread that made them.
            let thread = thread::Builder::new()
                .name("openplay-loopback".to_owned())
                .spawn(move || {
                    let opened = open(wanted.as_deref());
                    let (mut client, mut device_id, name) = match opened {
                        Ok(opened) => opened,
                        Err(error) => {
                            let message = error.to_string();
                            let _ = ready_sender.send(Err(error));
                            return Err(Error::Audio(message));
                        }
                    };
                    let _ = ready_sender.send(Ok(name));
                    // With no device named, follow the Windows default output
                    // when the user switches it, as speakers would.
                    let follow_default = wanted.is_none();
                    loop {
                        match capture_loop(
                            &client,
                            &device_id,
                            follow_default,
                            &mut input,
                            &thread_stop,
                        )? {
                            Ended::Stopped => return Ok(()),
                            Ended::DefaultChanged => {
                                (client, device_id, _) = open(None)?;
                            }
                        }
                    }
                })
                .map_err(Error::from)?;

            let device = ready
                .recv()
                .map_err(|_| Error::Audio("capture thread ended during setup".to_owned()))??;
            Ok(Self {
                stop,
                thread: Some(thread),
                device,
            })
        }

        /// Name of the device being captured.
        pub fn device(&self) -> &str {
            &self.device
        }

        /// Whether the capture thread is still running.
        pub fn is_running(&self) -> bool {
            self.thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
        }

        /// Stop capturing and report how the thread ended.
        pub fn stop(mut self) -> Result<()> {
            self.stop.store(true, Ordering::Relaxed);
            match self.thread.take().map(JoinHandle::join) {
                Some(Ok(result)) => result,
                Some(Err(_)) => Err(Error::Audio("capture thread panicked".to_owned())),
                None => Ok(()),
            }
        }
    }

    impl Drop for Loopback {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    /// Open loopback on a device; returns its client, endpoint ID and name.
    fn open(device: Option<&str>) -> Result<(AudioClient, String, String)> {
        let _ = initialize_mta();
        let enumerator = DeviceEnumerator::new().map_err(audio_error)?;
        let device = find_device(&enumerator, device)?;
        let name = device.get_friendlyname().map_err(audio_error)?;
        let id = device.get_id().map_err(audio_error)?;
        let mut client = device.get_iaudioclient().map_err(audio_error)?;
        let format = WaveFormat::new(
            32,
            32,
            &SampleType::Float,
            CAPTURE_FORMAT.sample_rate as usize,
            usize::from(CAPTURE_FORMAT.channels),
            None,
        );
        // Capture direction on a render device is WASAPI loopback.
        client
            .initialize_client(
                &format,
                &Direction::Capture,
                &StreamMode::PollingShared {
                    autoconvert: true,
                    buffer_duration_hns: BUFFER_DURATION_HNS,
                },
            )
            .map_err(audio_error)?;
        info!("loopback capturing {name}");
        Ok((client, id, name))
    }

    enum Ended {
        Stopped,
        DefaultChanged,
    }

    /// Whether the default output is no longer the device with `id`.
    fn default_changed(id: &str) -> bool {
        DeviceEnumerator::new()
            .and_then(|enumerator| enumerator.get_default_device(&Direction::Render))
            .and_then(|device| device.get_id())
            .is_ok_and(|current| current != id)
    }

    fn capture_loop(
        client: &AudioClient,
        device_id: &str,
        follow_default: bool,
        input: &mut AudioInput,
        stop: &AtomicBool,
    ) -> Result<Ended> {
        let capture = client.get_audiocaptureclient().map_err(audio_error)?;
        let frame_bytes = CAPTURE_FORMAT.bytes_per_frame();
        let mut buffer = Vec::new();
        // WASAPI flags the first packet after a start as a discontinuity.
        let mut first_packet = true;
        let mut polls = 0_u32;
        client.start_stream().map_err(audio_error)?;

        while !stop.load(Ordering::Relaxed) {
            polls = polls.wrapping_add(1);
            if follow_default
                && polls.is_multiple_of(DEFAULT_CHECK_POLLS)
                && default_changed(device_id)
            {
                client.stop_stream().map_err(audio_error)?;
                return Ok(Ended::DefaultChanged);
            }
            while let Some(frames) = capture.get_next_packet_size().map_err(audio_error)? {
                if frames == 0 {
                    break;
                }
                buffer.resize(frames as usize * frame_bytes, 0);
                let (read, info) = capture.read_from_device(&mut buffer).map_err(audio_error)?;
                let bytes = &mut buffer[..read as usize * frame_bytes];
                if info.flags.silent {
                    // The engine marks silent packets; their bytes are not
                    // guaranteed to be zero.
                    bytes.fill(0);
                }
                if info.flags.data_discontinuity && !first_packet {
                    warn!("loopback: capture glitch, audio skipped");
                }
                first_packet = false;
                input.write(bytes);
            }
            thread::sleep(POLL_INTERVAL);
        }
        client.stop_stream().map_err(audio_error)?;
        Ok(Ended::Stopped)
    }
}

#[cfg(not(windows))]
mod unsupported {
    use crate::audio::AudioInput;
    use crate::error::{Error, Result};

    fn unsupported() -> Error {
        Error::Audio("loopback capture is only available on Windows; pipe audio to stdin".into())
    }

    pub fn render_devices() -> Result<Vec<String>> {
        Err(unsupported())
    }

    /// Placeholder with the Windows API, so callers need no `cfg`.
    #[derive(Debug)]
    pub struct Loopback;

    impl Loopback {
        pub fn start(_device: Option<&str>, _input: AudioInput) -> Result<Self> {
            Err(unsupported())
        }

        pub fn device(&self) -> &str {
            ""
        }

        pub fn is_running(&self) -> bool {
            false
        }

        pub fn stop(self) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_format_is_valid() {
        assert!(CAPTURE_FORMAT.validate().is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn other_platforms_explain_the_stdin_route() {
        let error = render_devices().expect_err("unsupported");
        assert!(error.to_string().contains("stdin"));
    }
}
