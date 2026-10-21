//! Sans-IO PTP follower: turns a leader's messages into a clock offset.
//!
//! One exchange gives four times, two on each clock:
//!
//! ```text
//! leader            follower
//!   t1 ── Sync ──────► t2
//!   t1' ─ Follow_Up ─►        (precise t1 for two-step leaders)
//!   t4 ◄─ Delay_Req ── t3
//!      ── Delay_Resp ─►       (carries t4)
//! ```
//!
//! offset = ((t2 − t1) − (t4 − t3)) / 2 is how far the local clock is ahead
//! of the leader's, assuming the path is symmetric; delay is the one-way
//! path time. Wi-Fi queues make single samples noisy, so the clock trusts
//! the recent sample with the smallest delay, the one least delayed by
//! queueing.

use std::collections::VecDeque;

use super::message::{Body, FLAG_TWO_STEP, Message, PortIdentity, Timestamp, encode_delay_req};

/// Samples considered when picking the least-delayed one.
const WINDOW: usize = 16;
/// Samples needed before the offset is trusted.
const MIN_SAMPLES: usize = 4;
/// Correction field unit: nanoseconds scaled by 2^16.
const CORRECTION_SHIFT: u32 = 16;

/// One completed exchange, in nanoseconds: `t1` and `t4` on the leader's
/// clock, `t2` and `t3` on the local one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub t1: i128,
    pub t2: i128,
    pub t3: i128,
    pub t4: i128,
}

impl Sample {
    /// Local clock minus leader clock.
    pub fn offset(self) -> i128 {
        ((self.t2 - self.t1) - (self.t4 - self.t3)) / 2
    }

    pub fn delay(self) -> i128 {
        ((self.t2 - self.t1) + (self.t4 - self.t3)) / 2
    }
}

/// Offset estimate from recent samples.
#[derive(Debug, Default)]
pub struct FollowerClock {
    samples: VecDeque<Sample>,
}

impl FollowerClock {
    pub fn add(&mut self, sample: Sample) {
        // A negative delay means a clock stepped mid-exchange; the sample
        // says nothing reliable about the offset.
        if sample.delay() < 0 {
            return;
        }
        if self.samples.len() == WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn is_synchronized(&self) -> bool {
        self.samples.len() >= MIN_SAMPLES
    }

    /// Local minus leader time, from the least-delayed recent sample.
    pub fn offset_nanos(&self) -> Option<i128> {
        if !self.is_synchronized() {
            return None;
        }
        self.samples
            .iter()
            .min_by_key(|sample| sample.delay())
            .map(|sample| sample.offset())
    }

    /// Leader time corresponding to a local time.
    pub fn leader_time(&self, local_nanos: i128) -> Option<Timestamp> {
        let leader = local_nanos - self.offset_nanos()?;
        u128::try_from(leader).ok().map(Timestamp::from_nanos)
    }
}

/// What the caller should do after feeding a message in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Send this Delay_Req to the leader's event port, then report the
    /// local send time with [`Follower::delay_req_sent`].
    SendDelayReq {
        sequence_id: u16,
        bytes: Vec<u8>,
    },
}

struct PendingSync {
    sequence_id: u16,
    received: i128,
    origin: Option<i128>,
    /// A two-step Sync's own correction, which applies on top of its
    /// Follow_Up's.
    correction: i128,
}

struct PendingDelayReq {
    sequence_id: u16,
    t1: i128,
    t2: i128,
    sent: Option<i128>,
}

/// Follows one leader: the first clock whose Sync or Announce arrives.
pub struct Follower {
    identity: PortIdentity,
    domain: u8,
    leader: Option<PortIdentity>,
    sync: Option<PendingSync>,
    delay_req: Option<PendingDelayReq>,
    next_sequence: u16,
    clock: FollowerClock,
}

impl Follower {
    pub fn new(identity: PortIdentity, domain: u8) -> Self {
        Self {
            identity,
            domain,
            leader: None,
            sync: None,
            delay_req: None,
            next_sequence: 0,
            clock: FollowerClock::default(),
        }
    }

    pub fn clock(&self) -> &FollowerClock {
        &self.clock
    }

    /// The leader's clock identity, which AirPlay calls the timeline ID.
    pub fn leader(&self) -> Option<u64> {
        self.leader.map(|leader| leader.clock_identity)
    }

    /// Handle a message received at local time `received` (nanoseconds).
    pub fn on_message(&mut self, message: &Message, received: i128) -> Action {
        if message.header.domain != self.domain || message.header.source == self.identity {
            return Action::None;
        }
        let source = message.header.source;
        if matches!(message.body, Body::Sync { .. } | Body::Announce(_)) && self.leader.is_none() {
            self.leader = Some(source);
        }
        if self.leader != Some(source) {
            return Action::None;
        }
        let correction = i128::from(message.header.correction >> CORRECTION_SHIFT);

        match message.body {
            Body::Sync { origin } => {
                let two_step = message.header.flags & FLAG_TWO_STEP != 0;
                self.sync = Some(PendingSync {
                    sequence_id: message.header.sequence_id,
                    received,
                    origin: (!two_step).then(|| nanos(origin) + correction),
                    correction,
                });
                if two_step {
                    Action::None
                } else {
                    self.start_delay_req()
                }
            }
            Body::FollowUp { precise_origin } => match &mut self.sync {
                Some(sync) if sync.sequence_id == message.header.sequence_id => {
                    sync.origin = Some(nanos(precise_origin) + sync.correction + correction);
                    self.start_delay_req()
                }
                _ => Action::None,
            },
            Body::DelayResp {
                receive,
                requesting,
            } => {
                let Some(pending) = &self.delay_req else {
                    return Action::None;
                };
                if requesting != self.identity || message.header.sequence_id != pending.sequence_id
                {
                    return Action::None;
                }
                if let Some(t3) = pending.sent {
                    self.clock.add(Sample {
                        t1: pending.t1,
                        t2: pending.t2,
                        t3,
                        t4: nanos(receive) - correction,
                    });
                    self.delay_req = None;
                }
                Action::None
            }
            Body::DelayReq { .. } | Body::Announce(_) | Body::Other { .. } => Action::None,
        }
    }

    /// Record when the Delay_Req for `sequence_id` actually left.
    pub fn delay_req_sent(&mut self, sequence_id: u16, sent: i128) {
        if let Some(pending) = &mut self.delay_req
            && pending.sequence_id == sequence_id
        {
            pending.sent = Some(sent);
        }
    }

    fn start_delay_req(&mut self) -> Action {
        let Some(PendingSync {
            received,
            origin: Some(origin),
            ..
        }) = self.sync.take()
        else {
            return Action::None;
        };
        let sequence_id = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.delay_req = Some(PendingDelayReq {
            sequence_id,
            t1: origin,
            t2: received,
            sent: None,
        });
        Action::SendDelayReq {
            sequence_id,
            bytes: encode_delay_req(self.identity, self.domain, sequence_id),
        }
    }
}

fn nanos(timestamp: Timestamp) -> i128 {
    timestamp.to_nanos() as i128
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ptp::message::{encode_delay_resp, encode_follow_up, encode_sync};

    const LEADER: PortIdentity = PortIdentity {
        clock_identity: 0xaaaa,
        port_number: 1,
    };
    const ME: PortIdentity = PortIdentity {
        clock_identity: 0xbbbb,
        port_number: 1,
    };
    const SECOND: i128 = 1_000_000_000;

    fn stamp(nanos: i128) -> Timestamp {
        Timestamp::from_nanos(nanos as u128)
    }

    fn decode(bytes: &[u8]) -> Message {
        Message::decode(bytes).expect("decode")
    }

    /// Run one two-step exchange with the local clock `offset` ns ahead and a
    /// one-way `delay`.
    fn exchange(
        follower: &mut Follower,
        sequence: u16,
        leader_now: i128,
        offset: i128,
        delay: i128,
    ) {
        let t1 = leader_now;
        let t2 = t1 + delay + offset;
        assert_eq!(
            follower.on_message(&decode(&encode_sync(LEADER, 0, sequence, stamp(0))), t2),
            Action::None
        );
        let Action::SendDelayReq { sequence_id, .. } = follower.on_message(
            &decode(&encode_follow_up(LEADER, 0, sequence, stamp(t1))),
            t2 + 1_000,
        ) else {
            panic!("follow up should ask for a delay request");
        };
        let t3 = t2 + 2_000_000;
        follower.delay_req_sent(sequence_id, t3);
        let t4 = t3 - offset + delay;
        follower.on_message(
            &decode(&encode_delay_resp(LEADER, 0, sequence_id, stamp(t4), ME)),
            t4 + offset + delay,
        );
    }

    #[test]
    fn sample_math_recovers_offset_and_delay() {
        let sample = Sample {
            t1: 100,
            t2: 100 + 30 + 5_000,
            t3: 6_000,
            t4: 6_000 - 5_000 + 30,
        };
        assert_eq!(sample.offset(), 5_000);
        assert_eq!(sample.delay(), 30);
    }

    #[test]
    fn exchanges_converge_on_offset() {
        let mut follower = Follower::new(ME, 0);
        for sequence in 0..3 {
            exchange(&mut follower, sequence, 10 * SECOND, 7_000_000, 400_000);
        }
        assert!(follower.clock().offset_nanos().is_none());

        exchange(&mut follower, 3, 11 * SECOND, 7_000_000, 400_000);
        assert_eq!(follower.clock().offset_nanos(), Some(7_000_000));
        assert_eq!(follower.leader(), Some(LEADER.clock_identity));
        assert_eq!(
            follower.clock().leader_time(20 * SECOND + 7_000_000),
            Some(stamp(20 * SECOND))
        );
    }

    #[test]
    fn least_delayed_sample_wins() {
        let mut follower = Follower::new(ME, 0);
        // Queueing delays are asymmetric in reality; model the noisy ones as
        // a wrong offset with a large delay.
        for (sequence, (offset, delay)) in [
            (9_000_000, 30_000_000),
            (7_000_000, 300_000),
            (2_000_000, 25_000_000),
            (11_000_000, 40_000_000),
        ]
        .into_iter()
        .enumerate()
        {
            exchange(&mut follower, sequence as u16, 10 * SECOND, offset, delay);
        }
        assert_eq!(follower.clock().offset_nanos(), Some(7_000_000));
    }

    #[test]
    fn ignores_other_clocks_and_stale_replies() {
        let mut follower = Follower::new(ME, 0);
        exchange(&mut follower, 0, SECOND, 0, 1_000);
        let stranger = PortIdentity {
            clock_identity: 0xcccc,
            port_number: 1,
        };
        assert_eq!(
            follower.on_message(&decode(&encode_sync(stranger, 0, 1, stamp(0))), 5),
            Action::None
        );
        assert_eq!(
            follower.on_message(&decode(&encode_delay_resp(LEADER, 0, 99, stamp(1), ME)), 5),
            Action::None
        );
        assert_eq!(follower.leader(), Some(LEADER.clock_identity));
    }

    #[test]
    fn two_step_sync_correction_is_applied() {
        // A switch adds 500 us of residence time and records it in the
        // Sync's correction field; the path is otherwise symmetric with
        // 100 us each way and no clock offset.
        let residence: i128 = 500_000;
        let delay: i128 = 100_000;
        let mut follower = Follower::new(ME, 0);
        for sequence in 0..MIN_SAMPLES as u16 {
            let t1 = i128::from(sequence) * SECOND + SECOND;
            let mut sync = encode_sync(LEADER, 0, sequence, stamp(0));
            sync[8..16].copy_from_slice(&((residence as i64) << 16).to_be_bytes());
            let t2 = t1 + delay + residence;
            follower.on_message(&decode(&sync), t2);
            let Action::SendDelayReq { sequence_id, .. } = follower.on_message(
                &decode(&encode_follow_up(LEADER, 0, sequence, stamp(t1))),
                t2,
            ) else {
                panic!("follow up should ask for a delay request");
            };
            let t3 = t2 + 1_000_000;
            follower.delay_req_sent(sequence_id, t3);
            follower.on_message(
                &decode(&encode_delay_resp(
                    LEADER,
                    0,
                    sequence_id,
                    stamp(t3 + delay),
                    ME,
                )),
                t3 + 2 * delay,
            );
        }
        assert_eq!(follower.clock().offset_nanos(), Some(0));
    }

    #[test]
    fn negative_delay_samples_are_dropped() {
        let mut clock = FollowerClock::default();
        for _ in 0..MIN_SAMPLES {
            clock.add(Sample {
                t1: 1_000,
                t2: 0,
                t3: 0,
                t4: 0,
            });
        }
        assert!(!clock.is_synchronized());
    }
}
