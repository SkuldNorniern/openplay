//! Thread-safe buffering between live PCM producers and the paced sender.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const CHANNELS: usize = 2;

/// Bounded ring of 44.1 kHz stereo `i16` samples between a live producer
/// (any thread, including a realtime OS audio callback) and the sender,
/// which takes exactly one packet's worth every 8 ms.
///
/// Producers and the sender run on different clocks, so the ring absorbs
/// jitter and slow drift: when the sender finds too little it plays silence
/// for the gap, and when the producer runs ahead past `capacity` the oldest
/// audio is dropped so latency stays bounded.
///
/// Cheaply cloneable; all clones share one ring.
#[derive(Clone)]
pub struct AudioSource {
    ring: Arc<Mutex<VecDeque<i16>>>,
    capacity_frames: usize,
    stats: Arc<Counters>,
}

/// Whether a write fit, or pushed out older audio to make room.
#[derive(Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    Ok,
    Overrun,
}

#[derive(Default)]
struct Counters {
    underrun_frames: AtomicU64,
    overrun_frames: AtomicU64,
    /// Bumped by [`AudioSource::restart_at`], so writers can tell a new
    /// session began.
    epoch: AtomicU64,
}

/// Running totals for diagnostics and UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceStats {
    /// Frames of silence the sender had to play because the ring ran dry.
    pub underrun_frames: u64,
    /// Frames of audio dropped because the ring was full.
    pub overrun_frames: u64,
}

impl AudioSource {
    /// Create a ring holding at most `capacity_frames` stereo frames.
    pub fn new(capacity_frames: usize) -> Self {
        Self {
            ring: Arc::new(Mutex::new(VecDeque::with_capacity(
                capacity_frames * CHANNELS,
            ))),
            capacity_frames,
            stats: Arc::default(),
        }
    }

    /// Append interleaved stereo samples. A trailing odd sample is dropped,
    /// since it cannot form a frame.
    pub fn write(&self, samples: &[i16]) -> WriteOutcome {
        let samples = &samples[..samples.len() - samples.len() % CHANNELS];
        let capacity = self.capacity_frames * CHANNELS;
        let mut ring = self.lock();

        // Only the newest `capacity` samples of an oversized write can stay.
        let incoming = &samples[samples.len().saturating_sub(capacity)..];
        let overflow = (ring.len() + incoming.len()).saturating_sub(capacity);
        let dropped = overflow + (samples.len() - incoming.len());
        ring.drain(..overflow);
        ring.extend(incoming);
        drop(ring);

        if dropped == 0 {
            return WriteOutcome::Ok;
        }
        self.stats
            .overrun_frames
            .fetch_add((dropped / CHANNELS) as u64, Ordering::Relaxed);
        WriteOutcome::Overrun
    }

    /// Take exactly `frames` stereo frames, padding with silence when the
    /// ring holds fewer.
    pub fn read(&self, frames: usize) -> Vec<i16> {
        let wanted = frames * CHANNELS;
        let mut out = Vec::with_capacity(wanted);
        let mut ring = self.lock();
        let available = ring.len().min(wanted);
        out.extend(ring.drain(..available));
        drop(ring);

        let missing = wanted - available;
        if missing > 0 {
            out.resize(wanted, 0);
            self.stats
                .underrun_frames
                .fetch_add((missing / CHANNELS) as u64, Ordering::Relaxed);
        }
        out
    }

    /// Frames currently buffered.
    pub fn buffered_frames(&self) -> usize {
        self.lock().len() / CHANNELS
    }

    /// Start a new session at `frames` of buffering: audio queued while no
    /// session was draining it is dropped, oldest first, instead of adding
    /// its whole backlog to the new session's latency.
    pub fn restart_at(&self, frames: usize) {
        let mut ring = self.lock();
        let excess = ring.len().saturating_sub(frames * CHANNELS);
        ring.drain(..excess);
        drop(ring);
        self.stats.epoch.fetch_add(1, Ordering::Relaxed);
    }

    /// Changes each time [`Self::restart_at`] runs.
    pub fn epoch(&self) -> u64 {
        self.stats.epoch.load(Ordering::Relaxed)
    }

    pub fn capacity_frames(&self) -> usize {
        self.capacity_frames
    }

    pub fn stats(&self) -> SourceStats {
        SourceStats {
            underrun_frames: self.stats.underrun_frames.load(Ordering::Relaxed),
            overrun_frames: self.stats.overrun_frames.load(Ordering::Relaxed),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<i16>> {
        // Only whole drain/extend calls run under the lock, so a panic
        // elsewhere cannot leave a half-written frame behind. Recovering the
        // guard keeps one panicking handle from wedging a live stream.
        self.ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn read_returns_written_samples_in_order() {
        let source = AudioSource::new(4);
        assert_eq!(source.write(&[1, -1, 2, -2]), WriteOutcome::Ok);

        assert_eq!(source.read(2), [1, -1, 2, -2]);
        assert_eq!(source.stats(), SourceStats::default());
    }

    #[test]
    fn short_ring_pads_with_silence_and_counts_it() {
        let source = AudioSource::new(4);
        source.write(&[5, 6]);

        assert_eq!(source.read(3), [5, 6, 0, 0, 0, 0]);
        assert_eq!(source.stats().underrun_frames, 2);
    }

    #[test]
    fn reads_are_exact_regardless_of_write_sizes() {
        let source = AudioSource::new(1_000);
        for chunk in [480_usize, 7, 1, 352] {
            source.write(&vec![1; chunk * 2]);
        }

        assert_eq!(source.read(352).len(), 704);
        assert_eq!(source.buffered_frames(), 840 - 352);
    }

    #[test]
    fn full_ring_drops_oldest_frames() {
        let source = AudioSource::new(2);
        source.write(&[1, 1, 2, 2]);

        assert_eq!(source.write(&[3, 3]), WriteOutcome::Overrun);
        assert_eq!(source.read(2), [2, 2, 3, 3]);
        assert_eq!(source.stats().overrun_frames, 1);
    }

    #[test]
    fn oversized_write_keeps_its_newest_frames() {
        let source = AudioSource::new(2);
        source.write(&[9, 9]);

        assert_eq!(source.write(&[1, 1, 2, 2, 3, 3]), WriteOutcome::Overrun);
        assert_eq!(source.read(2), [2, 2, 3, 3]);
        assert_eq!(source.stats().overrun_frames, 2);
    }

    #[test]
    fn restart_keeps_only_the_newest_target_frames() {
        let source = AudioSource::new(8);
        source.write(&[1, 1, 2, 2, 3, 3, 4, 4]);
        let epoch = source.epoch();

        source.restart_at(1);
        assert_eq!(source.read(1), [4, 4]);
        assert_ne!(source.epoch(), epoch);
        assert_eq!(source.stats(), SourceStats::default());
    }

    #[test]
    fn odd_trailing_sample_is_dropped() {
        let source = AudioSource::new(4);
        source.write(&[1, 2, 3]);
        assert_eq!(source.buffered_frames(), 1);
    }

    #[test]
    fn zero_capacity_drops_everything() {
        let source = AudioSource::new(0);
        assert_eq!(source.write(&[1, 2]), WriteOutcome::Overrun);
        assert_eq!(source.read(1), [0, 0]);
    }

    #[test]
    fn concurrent_writer_and_reader_keep_frames_whole() {
        let source = AudioSource::new(256);
        let writer_source = source.clone();
        let writer = thread::spawn(move || {
            for value in 0..2_000_i16 {
                writer_source.write(&[value, value]);
            }
        });
        let mut seen = Vec::new();
        while !writer.is_finished() || source.buffered_frames() > 0 {
            seen.extend(source.read(16));
            thread::yield_now();
        }
        writer.join().expect("writer completes");

        assert!(seen.chunks(2).all(|frame| frame[0] == frame[1]));
    }
}
