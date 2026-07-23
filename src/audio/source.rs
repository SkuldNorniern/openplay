//! Thread-safe buffering between live PCM producers and paced consumers.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

/// One unit of media data queued between a live source and the pacing task
/// that drains it. Deliberately minimal today (interleaved PCM only); more
/// variants (already-encoded audio, eventually video) are added as other
/// media stream types need to flow through the same queue.
#[non_exhaustive]
pub enum Frame {
    /// Interleaved 16-bit stereo PCM samples: `[L0, R0, L1, R1, ...]`.
    Pcm(Vec<i16>),
}

/// Bounded, thread-safe queue between a live audio source (pushed from any
/// thread, including a real-time OS audio callback) and the async task that
/// paces frames out to the ALAC encoder.
///
/// Cheaply cloneable: clone one handle for the writer side (the audio
/// callback) and another for the reader side (the pacing task); both refer
/// to the same underlying queue.
#[derive(Clone)]
pub struct AudioSource {
    queue: Arc<Mutex<VecDeque<Frame>>>,
    capacity: usize,
}

/// Whether a write succeeded cleanly or had to evict the oldest buffered
/// frame to make room.
#[derive(Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    Ok,
    Overrun,
}

impl AudioSource {
    /// Create a source with room for at most `capacity` queued frames.
    /// Callers choose `capacity` based on their driver's typical push size
    /// and desired buffering depth -- this module has no opinion on that.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Push one frame. Safe to call from any thread. If the queue is already
    /// at capacity, the oldest queued frame is dropped to make room.
    ///
    /// A zero-capacity source cannot retain a frame, so every write reports
    /// an overrun and drops the incoming frame. This preserves the hard bound
    /// rather than silently turning a zero-sized queue into a one-frame queue.
    pub fn write(&self, frame: Frame) -> WriteOutcome {
        let mut queue = self.lock_queue();
        if self.capacity == 0 {
            return WriteOutcome::Overrun;
        }

        let outcome = if queue.len() == self.capacity {
            queue.pop_front();
            WriteOutcome::Overrun
        } else {
            WriteOutcome::Ok
        };
        queue.push_back(frame);
        outcome
    }

    /// Pop the next queued frame, if any, without blocking.
    pub fn try_next(&self) -> Option<Frame> {
        self.lock_queue().pop_front()
    }

    /// Pop the next queued PCM frame, or synthesize `frame_count` frames
    /// (`frame_count * 2` interleaved samples, this crate's fixed stereo
    /// format) of silence if the queue is empty. Convenience built on
    /// [`Self::try_next`] for a pacing task that always wants a fixed-size
    /// chunk every cycle regardless of whether real audio is ready.
    ///
    /// A queued frame is returned unchanged even when its length differs from
    /// `frame_count`: live drivers need not push chunks aligned to the pacing
    /// task's packet size, and this buffering layer must not re-chunk them.
    pub fn next_or_silence(&self, frame_count: usize) -> Frame {
        self.try_next()
            .unwrap_or_else(|| Frame::Pcm(vec![0; frame_count * 2]))
    }

    /// Number of frames currently queued (for diagnostics/tests, not part of
    /// the steady-state control flow).
    pub fn len(&self) -> usize {
        self.lock_queue().len()
    }

    /// Whether no frames are currently queued.
    pub fn is_empty(&self) -> bool {
        self.lock_queue().is_empty()
    }

    fn lock_queue(&self) -> MutexGuard<'_, VecDeque<Frame>> {
        // A panic while holding the short queue lock may leave an operation
        // incomplete, but VecDeque remains memory-safe. Recovering the guard
        // prevents one producer or consumer panic from permanently wedging
        // every other handle to a live stream.
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use super::*;

    fn pcm_samples(frame: Frame) -> Vec<i16> {
        match frame {
            Frame::Pcm(samples) => samples,
        }
    }

    #[test]
    fn write_and_read_round_trip() {
        let source = AudioSource::new(2);

        assert_eq!(
            source.write(Frame::Pcm(vec![1, -2, 3, -4])),
            WriteOutcome::Ok
        );
        assert_eq!(
            pcm_samples(source.try_next().expect("queued frame")),
            [1, -2, 3, -4]
        );
        assert!(source.try_next().is_none());
    }

    #[test]
    fn overrun_evicts_the_oldest_frame() {
        let source = AudioSource::new(2);

        assert_eq!(source.write(Frame::Pcm(vec![1])), WriteOutcome::Ok);
        assert_eq!(source.write(Frame::Pcm(vec![2])), WriteOutcome::Ok);
        assert_eq!(source.write(Frame::Pcm(vec![3])), WriteOutcome::Overrun);

        assert_eq!(pcm_samples(source.try_next().expect("second frame")), [2]);
        assert_eq!(pcm_samples(source.try_next().expect("third frame")), [3]);
        assert!(source.try_next().is_none());
    }

    #[test]
    fn underrun_returns_exactly_the_requested_silence() {
        let source = AudioSource::new(1);

        let samples = pcm_samples(source.next_or_silence(352));
        assert_eq!(samples.len(), 704);
        assert!(samples.iter().all(|sample| *sample == 0));
    }

    #[test]
    fn next_or_silence_prefers_an_unaligned_real_frame() {
        let source = AudioSource::new(1);
        assert_eq!(
            source.write(Frame::Pcm(vec![7, 8, 9, 10, 11, 12])),
            WriteOutcome::Ok
        );

        assert_eq!(
            pcm_samples(source.next_or_silence(352)),
            [7, 8, 9, 10, 11, 12]
        );
    }

    #[test]
    fn concurrent_writers_and_reader_complete() {
        let source = AudioSource::new(4_096);
        let writers_done = Arc::new(AtomicBool::new(false));
        let reader_source = source.clone();
        let reader_done = Arc::clone(&writers_done);
        let reader = thread::spawn(move || {
            while !reader_done.load(Ordering::Acquire) || !reader_source.is_empty() {
                let _frame = reader_source.try_next();
                thread::yield_now();
            }
        });

        let writers: Vec<_> = (0..4)
            .map(|writer| {
                let writer_source = source.clone();
                thread::spawn(move || {
                    for sample in 0..1_000 {
                        let _outcome = writer_source.write(Frame::Pcm(vec![writer, sample]));
                    }
                })
            })
            .collect();

        for writer in writers {
            writer.join().expect("writer completes");
        }
        writers_done.store(true, Ordering::Release);
        reader.join().expect("reader completes");
    }

    #[test]
    fn length_and_empty_state_follow_queue_contents() {
        let source = AudioSource::new(2);
        assert!(source.is_empty());
        assert_eq!(source.len(), 0);

        assert_eq!(source.write(Frame::Pcm(vec![1, 2])), WriteOutcome::Ok);
        assert!(!source.is_empty());
        assert_eq!(source.len(), 1);

        let _frame = source.try_next().expect("queued frame");
        assert!(source.is_empty());
        assert_eq!(source.len(), 0);
    }
}
