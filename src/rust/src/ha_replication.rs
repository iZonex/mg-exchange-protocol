//! HA state replication + failover primitives.
//!
//! Complements `ha.rs` (Raft-style leader election). `ha.rs` answers
//! "who is the leader"; this module answers "what exactly is
//! replicated between them, and how do we keep the standby in sync".
//!
//! # What's here
//!
//! * [`FencingToken`] — monotonic id bumped on every takeover; receivers
//!   reject messages with a stale token.
//! * [`StateDelta`] + [`StateStreamer`] — primary-side serializer of
//!   business-critical state changes (journal, orders, kill-switch,
//!   audit chain, entitlements).
//! * [`StateApplier`] — standby-side consumer with split-brain
//!   protection and monotonic-seq enforcement.
//! * [`FailoverDecision`] — watchdog that tells the standby whether to
//!   take over based on primary heartbeats.
//!
//! Out of scope (intentionally): log transport (use `replication.rs`
//! or external pubsub), actual writes to `IdempotencyStore` /
//! `KillSwitchState` on the standby (caller holds those handles and
//! applies the deltas into them).

use std::time::{Duration, Instant};

// ─── Fencing ────────────────────────────────────────────────

/// Monotonic token incremented on every takeover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FencingToken(pub u64);

impl FencingToken {
    /// Starting value for a fresh cluster. The first primary takes this
    /// token; every subsequent takeover bumps it.
    pub const INITIAL: Self = Self(1);

    /// Return the next token after a takeover. Wraps at `u64::MAX`
    /// (impractically distant — 2⁶⁴ takeovers).
    pub fn bump(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Returns `true` if `received` token is at-or-beyond `self` — i.e.
    /// this message is NOT from a stale primary. Use:
    /// `current.is_current(rd.token)`.
    pub fn is_current(self, received: FencingToken) -> bool {
        received >= self
    }
}

// ─── State delta ────────────────────────────────────────────

/// The kinds of state change the primary replicates to the standby.
/// Each variant has just enough payload for the standby to reconstruct
/// the corresponding in-memory structure without reaching back to the
/// primary.
#[derive(Debug, Clone)]
pub enum StateDelta {
    /// Append `bytes` to session `session_id`'s outbound journal at
    /// `seq`. Mirrors `Session::journal_outbound`.
    JournalAppend { session_id: u64, seq: u64, bytes: Vec<u8> },
    /// An order was accepted by the primary's matching engine; standby
    /// caches the `(session, client_order_id) → server_order_id +
    /// response bytes` mapping so idempotency survives failover.
    OrderAccepted { session_id: u64, client_order_id: u64, server_order_id: u64, response: Vec<u8> },
    /// Primary detected session loss. Standby runs the same COD flow.
    SessionLost { session_id: u64, reason_code: u8 },
    /// Kill-switch transitioned. `scope_tag` is a packed
    /// (scope_kind, scope_id) pair; see `kill_switch::KillSwitchScope`.
    HaltChanged { scope_tag: u64, engaged: bool, reason_code: u8 },
    /// Entitlement grant installed or revoked on the primary.
    EntitlementChanged { grant_id: u64, installed: bool },
    /// Audit record appended — replicated verbatim so the chain's
    /// `prev_digest` continuity survives failover.
    AuditAppended { audit_seq: u64, payload: Vec<u8> },
}

/// Envelope attached by the streamer. Carries the fencing token and a
/// monotonic delta sequence within the token epoch.
#[derive(Debug, Clone)]
pub struct ReplicatedDelta {
    pub token: FencingToken,
    pub delta_seq: u64,
    pub delta: StateDelta,
}

// ─── Streamer (primary) ─────────────────────────────────────

/// Primary-side serializer. Wraps every `StateDelta` with the current
/// fencing token and a fresh monotonic delta seq, ready to ship to the
/// standby via whatever transport the operator picked.
pub struct StateStreamer {
    token: FencingToken,
    next_delta_seq: u64,
}

impl StateStreamer {
    /// Start a streamer at the given fencing token. A fresh primary
    /// uses `FencingToken::INITIAL`; a primary that just took over uses
    /// `previous_token.bump()`.
    pub fn new(token: FencingToken) -> Self {
        Self { token, next_delta_seq: 1 }
    }

    /// Wrap `delta` with the current token and the next delta seq.
    pub fn emit(&mut self, delta: StateDelta) -> ReplicatedDelta {
        let seq = self.next_delta_seq;
        self.next_delta_seq += 1;
        ReplicatedDelta { token: self.token, delta_seq: seq, delta }
    }

    pub fn token(&self) -> FencingToken {
        self.token
    }

    pub fn next_delta_seq(&self) -> u64 {
        self.next_delta_seq
    }
}

// ─── Applier (standby) ──────────────────────────────────────

/// Standby-side consumer. Verifies fencing + monotonicity and
/// dispatches deltas to a caller-supplied sink (which typically
/// applies them into the standby's shadow copies of the relevant
/// components).
pub struct StateApplier {
    token: FencingToken,
    last_delta_seq: u64,
    applied_count: u64,
    rejected_stale: u64,
}

/// The outcome of applying one `ReplicatedDelta`. Callers inspect this
/// to decide whether to metric (applied), alert ops (non-monotonic —
/// transport bug), or fire split-brain alarms (stale token).
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    RejectedStaleToken { got: FencingToken, current: FencingToken },
    NonMonotonic { got: u64, expected_min: u64 },
}

impl StateApplier {
    /// Start an applier at the given fencing token. Standby reads the
    /// token from stable storage at boot; on first startup, use
    /// `FencingToken::INITIAL`.
    pub fn new(starting_token: FencingToken) -> Self {
        Self {
            token: starting_token,
            last_delta_seq: 0,
            applied_count: 0,
            rejected_stale: 0,
        }
    }

    /// Consume one replicated delta. `sink` is called with the inner
    /// `StateDelta` if and only if the outcome is `Applied`.
    pub fn apply<F>(&mut self, rd: ReplicatedDelta, mut sink: F) -> ApplyOutcome
    where
        F: FnMut(&StateDelta),
    {
        if rd.token < self.token {
            self.rejected_stale += 1;
            return ApplyOutcome::RejectedStaleToken {
                got: rd.token,
                current: self.token,
            };
        }
        if rd.token > self.token {
            self.token = rd.token;
            self.last_delta_seq = 0;
        }
        if rd.delta_seq <= self.last_delta_seq {
            return ApplyOutcome::NonMonotonic {
                got: rd.delta_seq,
                expected_min: self.last_delta_seq + 1,
            };
        }
        self.last_delta_seq = rd.delta_seq;
        self.applied_count += 1;
        sink(&rd.delta);
        ApplyOutcome::Applied
    }

    pub fn token(&self) -> FencingToken {
        self.token
    }

    pub fn applied_count(&self) -> u64 {
        self.applied_count
    }

    pub fn rejected_stale(&self) -> u64 {
        self.rejected_stale
    }
}

// ─── Failover decision ──────────────────────────────────────

/// Watchdog that decides when the standby should take over.
///
/// Tune `miss_threshold` carefully: too low causes spurious takeovers
/// on brief network blips; too high extends outages. 3× the
/// heartbeat interval is a standard compromise.
pub struct FailoverDecision {
    primary_heartbeat_interval: Duration,
    miss_threshold: u32,
    last_heartbeat: Option<Instant>,
    consecutive_misses: u32,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

/// Outcome of a `FailoverDecision::tick`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverVerdict {
    /// Last heartbeat was within tolerance; nothing to do.
    PrimaryHealthy,
    /// We've missed at least one heartbeat. Typically page ops but
    /// don't take over yet.
    Suspect { consecutive_misses: u32 },
    /// Standby should take over now.
    TakeOver { reason: TakeoverReason },
}

/// Why a `TakeOver` verdict fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverReason {
    HeartbeatTimeout,
    ExternalSignal,
}

impl FailoverDecision {
    /// Build a watchdog. `primary_heartbeat_interval` is how often the
    /// primary is expected to beat; `miss_threshold` is how many
    /// intervals can be missed before takeover.
    pub fn new(primary_heartbeat_interval: Duration, miss_threshold: u32) -> Self {
        Self {
            primary_heartbeat_interval,
            miss_threshold,
            last_heartbeat: None,
            consecutive_misses: 0,
            now: Box::new(Instant::now),
        }
    }

    /// Replace the clock source — intended for deterministic tests.
    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> Instant + Send + Sync + 'static,
    {
        self.now = Box::new(clock);
        self
    }

    /// Record a heartbeat observed from the primary. Clears the miss
    /// counter.
    pub fn on_heartbeat(&mut self) {
        self.last_heartbeat = Some((self.now)());
        self.consecutive_misses = 0;
    }

    /// Evaluate the current state. Called on a periodic tick
    /// (typically every heartbeat interval).
    pub fn tick(&mut self) -> FailoverVerdict {
        let now = (self.now)();
        let last = match self.last_heartbeat {
            Some(t) => t,
            None => return FailoverVerdict::PrimaryHealthy,
        };
        let since = now.saturating_duration_since(last);
        let slots_missed = (since.as_millis()
            / self.primary_heartbeat_interval.as_millis().max(1)) as u32;
        self.consecutive_misses = slots_missed;

        if slots_missed >= self.miss_threshold {
            FailoverVerdict::TakeOver {
                reason: TakeoverReason::HeartbeatTimeout,
            }
        } else if slots_missed > 0 {
            FailoverVerdict::Suspect { consecutive_misses: slots_missed }
        } else {
            FailoverVerdict::PrimaryHealthy
        }
    }

    /// Externally forced takeover — operator intervention or a
    /// cluster-manager signal (etcd lease loss, Consul flag, etc.).
    pub fn force_takeover(&mut self) -> FailoverVerdict {
        FailoverVerdict::TakeOver {
            reason: TakeoverReason::ExternalSignal,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn mock_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync + 'static) {
        let anchor = Arc::new(Mutex::new(Instant::now()));
        let c = anchor.clone();
        (anchor, move || *c.lock().unwrap())
    }

    #[test]
    fn fencing_token_ordering() {
        let t = FencingToken::INITIAL;
        let next = t.bump();
        assert!(next > t);
        assert!(next.is_current(next));
        assert!(!next.is_current(t));
    }

    #[test]
    fn streamer_assigns_monotonic_seq() {
        let mut s = StateStreamer::new(FencingToken::INITIAL);
        let d1 = s.emit(StateDelta::SessionLost { session_id: 1, reason_code: 1 });
        let d2 = s.emit(StateDelta::SessionLost { session_id: 2, reason_code: 1 });
        assert_eq!(d1.delta_seq, 1);
        assert_eq!(d2.delta_seq, 2);
        assert_eq!(d1.token, FencingToken::INITIAL);
    }

    #[test]
    fn applier_processes_in_order() {
        let mut a = StateApplier::new(FencingToken::INITIAL);
        let mut s = StateStreamer::new(FencingToken::INITIAL);
        let mut count = 0;
        for _ in 0..5 {
            let d = s.emit(StateDelta::SessionLost { session_id: 1, reason_code: 0 });
            let o = a.apply(d, |_| count += 1);
            assert_eq!(o, ApplyOutcome::Applied);
        }
        assert_eq!(count, 5);
        assert_eq!(a.applied_count(), 5);
    }

    #[test]
    fn stale_token_rejected() {
        let mut a = StateApplier::new(FencingToken(5));
        let rd = ReplicatedDelta {
            token: FencingToken(3),
            delta_seq: 1,
            delta: StateDelta::SessionLost { session_id: 1, reason_code: 0 },
        };
        let o = a.apply(rd, |_| {});
        match o {
            ApplyOutcome::RejectedStaleToken { got: FencingToken(3), current: FencingToken(5) } => {}
            other => panic!("expected reject, got {:?}", other),
        }
        assert_eq!(a.rejected_stale(), 1);
    }

    #[test]
    fn new_token_resets_delta_seq() {
        let mut a = StateApplier::new(FencingToken(1));
        a.apply(
            ReplicatedDelta {
                token: FencingToken(1),
                delta_seq: 5,
                delta: StateDelta::SessionLost { session_id: 1, reason_code: 0 },
            },
            |_| {},
        );
        let o = a.apply(
            ReplicatedDelta {
                token: FencingToken(2),
                delta_seq: 1,
                delta: StateDelta::SessionLost { session_id: 1, reason_code: 0 },
            },
            |_| {},
        );
        assert_eq!(o, ApplyOutcome::Applied);
        assert_eq!(a.token(), FencingToken(2));
    }

    #[test]
    fn non_monotonic_seq_within_epoch_rejected() {
        let mut a = StateApplier::new(FencingToken::INITIAL);
        a.apply(
            ReplicatedDelta {
                token: FencingToken::INITIAL,
                delta_seq: 5,
                delta: StateDelta::SessionLost { session_id: 1, reason_code: 0 },
            },
            |_| {},
        );
        let o = a.apply(
            ReplicatedDelta {
                token: FencingToken::INITIAL,
                delta_seq: 5,
                delta: StateDelta::SessionLost { session_id: 1, reason_code: 0 },
            },
            |_| {},
        );
        assert!(matches!(o, ApplyOutcome::NonMonotonic { .. }));
    }

    #[test]
    fn failover_stays_healthy_under_heartbeats() {
        let (clock, now_fn) = mock_clock();
        let mut d = FailoverDecision::new(Duration::from_millis(100), 3).with_clock(now_fn);
        d.on_heartbeat();
        *clock.lock().unwrap() += Duration::from_millis(50);
        assert_eq!(d.tick(), FailoverVerdict::PrimaryHealthy);
    }

    #[test]
    fn failover_triggers_after_missed_threshold() {
        let (clock, now_fn) = mock_clock();
        let mut d = FailoverDecision::new(Duration::from_millis(100), 3).with_clock(now_fn);
        d.on_heartbeat();
        *clock.lock().unwrap() += Duration::from_millis(150);
        match d.tick() {
            FailoverVerdict::Suspect { .. } => {}
            other => panic!("got {:?}", other),
        }
        *clock.lock().unwrap() += Duration::from_millis(200);
        match d.tick() {
            FailoverVerdict::TakeOver { reason: TakeoverReason::HeartbeatTimeout } => {}
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn failover_recovers_on_heartbeat() {
        let (clock, now_fn) = mock_clock();
        let mut d = FailoverDecision::new(Duration::from_millis(100), 3).with_clock(now_fn);
        d.on_heartbeat();
        *clock.lock().unwrap() += Duration::from_millis(180);
        assert!(matches!(d.tick(), FailoverVerdict::Suspect { .. }));
        d.on_heartbeat();
        *clock.lock().unwrap() += Duration::from_millis(30);
        assert_eq!(d.tick(), FailoverVerdict::PrimaryHealthy);
    }

    #[test]
    fn force_takeover_returns_external_reason() {
        let mut d = FailoverDecision::new(Duration::from_millis(100), 3);
        let v = d.force_takeover();
        assert_eq!(
            v,
            FailoverVerdict::TakeOver { reason: TakeoverReason::ExternalSignal }
        );
    }
}
