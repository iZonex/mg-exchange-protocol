//! Layer-7 rate limiting.
//!
//! # Why this exists
//!
//! The pre-existing "rate limit" in `server.rs` was a counter that reset once
//! per second. When it hit zero the server silently stopped reading the
//! socket — no feedback to the client, no reject message, just a stall that
//! clients interpreted as network jitter. It also had no per-account view:
//! one client with three sessions got three times the quota of a client with
//! one, which is the opposite of what fair-use requires.
//!
//! This module replaces it with a proper token-bucket limiter:
//!
//! * **Bucket primitive** — refills at a fixed `tokens/sec`, caps at
//!   `capacity` to bound burst.
//! * **Hierarchy** — every request is checked against BOTH a session-level
//!   bucket and an account-level bucket (many sessions → one account). The
//!   tighter bucket wins.
//! * **Two dimensions** — message rate (msg/s) and byte rate (B/s); either
//!   can trigger a reject. Real exchanges care about both: a trader spamming
//!   cheap cancels is as dangerous as one dumping 10MB mass-quotes.
//! * **Honest outcomes** — `Admitted`, `Rejected`, or `Throttle{delay}`.
//!   Server emits a `BusinessReject` on `Rejected`; reactor can optionally
//!   sleep on `Throttle` to apply backpressure instead of dropping.
//! * **Metrics** — per-bucket tokens_consumed, rejections, current level.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Single-dimension token bucket.
///
/// Tokens accrue continuously at `refill_per_sec`; each admission costs the
/// caller-specified weight. Fractional accounting prevents drift when cost
/// doesn't evenly divide the refill rate.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub capacity: f64,
    pub refill_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    pub fn with_clock(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_refill: now,
        }
    }

    /// Refill based on elapsed time, then try to subtract `cost`. Returns
    /// `true` on success, `false` if not enough tokens.
    pub fn try_consume(&mut self, cost: f64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Time until `cost` tokens are available, given the current fill and
    /// refill rate. `Duration::ZERO` if already sufficient. Useful for
    /// Throttle decisions.
    pub fn time_until(&self, cost: f64, now: Instant) -> Duration {
        let mut projected = self.tokens;
        // Apply any pending refill for accuracy.
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        projected = (projected + elapsed * self.refill_per_sec).min(self.capacity);
        if projected >= cost {
            return Duration::ZERO;
        }
        let deficit = cost - projected;
        if self.refill_per_sec <= 0.0 {
            return Duration::from_secs(u64::MAX / 2); // effectively forever
        }
        Duration::from_secs_f64(deficit / self.refill_per_sec)
    }

    /// Current token level (after applying pending refill).
    pub fn level(&self, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        (self.tokens + elapsed * self.refill_per_sec).min(self.capacity)
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
    }
}

// ─── Config ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct BucketConfig {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

impl BucketConfig {
    pub const UNLIMITED: Self = Self { capacity: f64::INFINITY, refill_per_sec: f64::INFINITY };

    pub fn messages(burst: u32, rate: u32) -> Self {
        Self { capacity: burst as f64, refill_per_sec: rate as f64 }
    }

    pub fn bytes(burst: u64, rate: u64) -> Self {
        Self { capacity: burst as f64, refill_per_sec: rate as f64 }
    }

    pub fn is_unlimited(&self) -> bool {
        self.capacity.is_infinite() || self.refill_per_sec.is_infinite()
    }
}

/// Per-tenant configuration. Accounts and sessions each get independent
/// message and byte buckets; the tightest bucket determines admission.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub per_session_msgs: BucketConfig,
    pub per_session_bytes: BucketConfig,
    pub per_account_msgs: BucketConfig,
    pub per_account_bytes: BucketConfig,
    /// When `true`, admit-failure returns `Throttle { delay }` (reactor may
    /// sleep and retry). When `false`, returns `Rejected` and the server
    /// emits a BusinessReject — no silent drops either way.
    pub throttle_mode: bool,
}

impl RateLimitConfig {
    pub const UNLIMITED: Self = Self {
        per_session_msgs: BucketConfig::UNLIMITED,
        per_session_bytes: BucketConfig::UNLIMITED,
        per_account_msgs: BucketConfig::UNLIMITED,
        per_account_bytes: BucketConfig::UNLIMITED,
        throttle_mode: false,
    };

    /// A reasonable default for a colocation-grade trading API.
    pub fn strict_colocation() -> Self {
        Self {
            per_session_msgs: BucketConfig::messages(5_000, 2_500),
            per_session_bytes: BucketConfig::bytes(10 * 1024 * 1024, 5 * 1024 * 1024),
            per_account_msgs: BucketConfig::messages(20_000, 10_000),
            per_account_bytes: BucketConfig::bytes(50 * 1024 * 1024, 25 * 1024 * 1024),
            throttle_mode: false,
        }
    }
}

/// Why a request was rejected. Carried into the BusinessReject text so the
/// client can distinguish among limits and back off appropriately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDimension {
    SessionMsgs,
    SessionBytes,
    AccountMsgs,
    AccountBytes,
}

impl RateLimitDimension {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::SessionMsgs => "rate_limited:session_msgs",
            Self::SessionBytes => "rate_limited:session_bytes",
            Self::AccountMsgs => "rate_limited:account_msgs",
            Self::AccountBytes => "rate_limited:account_bytes",
        }
    }
}

/// Admission outcome. Callers must act on all three — silent drops are
/// exactly what this module exists to prevent.
#[derive(Debug, Clone)]
pub enum RateLimitOutcome {
    Admitted,
    /// Reject the request. Server should emit BusinessReject with
    /// `business_reason = dimension.as_code()`.
    Rejected { dimension: RateLimitDimension },
    /// Reactor may sleep for `delay` then retry admission. Sleeping is
    /// optional — callers on a strict-latency path may downgrade this to
    /// a Reject.
    Throttle { dimension: RateLimitDimension, delay: Duration },
}

// ─── Limiter ─────────────────────────────────────────────────

struct SessionBuckets {
    account_id: u64,
    msgs: TokenBucket,
    bytes: TokenBucket,
}

struct AccountBuckets {
    msgs: TokenBucket,
    bytes: TokenBucket,
}

#[derive(Debug, Clone, Default)]
pub struct RateLimitMetrics {
    pub admitted: u64,
    pub rejected_session_msgs: u64,
    pub rejected_session_bytes: u64,
    pub rejected_account_msgs: u64,
    pub rejected_account_bytes: u64,
}

impl RateLimitMetrics {
    pub fn total_rejected(&self) -> u64 {
        self.rejected_session_msgs
            + self.rejected_session_bytes
            + self.rejected_account_msgs
            + self.rejected_account_bytes
    }
}

pub struct RateLimiter {
    config: RateLimitConfig,
    sessions: HashMap<u64, SessionBuckets>,
    accounts: HashMap<u64, AccountBuckets>,
    metrics: RateLimitMetrics,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            accounts: HashMap::new(),
            metrics: RateLimitMetrics::default(),
            now: Box::new(Instant::now),
        }
    }

    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> Instant + Send + Sync + 'static,
    {
        self.now = Box::new(clock);
        self
    }

    pub fn register_session(&mut self, session_id: u64, account_id: u64) {
        let now = (self.now)();
        self.sessions.entry(session_id).or_insert_with(|| SessionBuckets {
            account_id,
            msgs: TokenBucket::with_clock(
                self.config.per_session_msgs.capacity,
                self.config.per_session_msgs.refill_per_sec,
                now,
            ),
            bytes: TokenBucket::with_clock(
                self.config.per_session_bytes.capacity,
                self.config.per_session_bytes.refill_per_sec,
                now,
            ),
        });
        self.accounts.entry(account_id).or_insert_with(|| AccountBuckets {
            msgs: TokenBucket::with_clock(
                self.config.per_account_msgs.capacity,
                self.config.per_account_msgs.refill_per_sec,
                now,
            ),
            bytes: TokenBucket::with_clock(
                self.config.per_account_bytes.capacity,
                self.config.per_account_bytes.refill_per_sec,
                now,
            ),
        });
    }

    pub fn drop_session(&mut self, session_id: u64) {
        self.sessions.remove(&session_id);
        // Account buckets persist: a reconnecting session should not get a
        // fresh quota. Callers must explicitly `drop_account` when the
        // account goes away entirely.
    }

    pub fn drop_account(&mut self, account_id: u64) {
        self.accounts.remove(&account_id);
    }

    /// Admit a request of `msg_cost` messages (typically 1) and `byte_cost`
    /// bytes. Consults both session and account buckets; all must pass.
    ///
    /// On rejection, no tokens are consumed — the request never enters the
    /// system.
    pub fn try_admit(
        &mut self,
        session_id: u64,
        msg_cost: f64,
        byte_cost: f64,
    ) -> RateLimitOutcome {
        let now = (self.now)();

        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            // Unknown session: admit. Upstream should reject unknown sessions
            // for session-layer reasons, not rate-limit reasons.
            None => {
                self.metrics.admitted += 1;
                return RateLimitOutcome::Admitted;
            }
        };
        let account_id = session.account_id;

        // Check all four buckets (without mutating) before committing, so a
        // failure doesn't partially consume quota.
        let check = |bucket: &TokenBucket, cost: f64| -> (bool, Duration) {
            let ok = bucket.level(now) >= cost;
            let wait = bucket.time_until(cost, now);
            (ok, wait)
        };

        let (sm_ok, sm_wait) = check(&session.msgs, msg_cost);
        let (sb_ok, sb_wait) = check(&session.bytes, byte_cost);
        let (am_ok, am_wait, ab_ok, ab_wait) = match self.accounts.get(&account_id) {
            Some(a) => {
                let (am_ok, am_wait) = check(&a.msgs, msg_cost);
                let (ab_ok, ab_wait) = check(&a.bytes, byte_cost);
                (am_ok, am_wait, ab_ok, ab_wait)
            }
            None => (true, Duration::ZERO, true, Duration::ZERO),
        };

        if sm_ok && sb_ok && am_ok && ab_ok {
            // Commit. Infallible now.
            let _ = session.msgs.try_consume(msg_cost, now);
            let _ = session.bytes.try_consume(byte_cost, now);
            if let Some(a) = self.accounts.get_mut(&account_id) {
                let _ = a.msgs.try_consume(msg_cost, now);
                let _ = a.bytes.try_consume(byte_cost, now);
            }
            self.metrics.admitted += 1;
            return RateLimitOutcome::Admitted;
        }

        // Pick the dimension that failed first (stable priority).
        let (dimension, delay) = if !sm_ok {
            (RateLimitDimension::SessionMsgs, sm_wait)
        } else if !sb_ok {
            (RateLimitDimension::SessionBytes, sb_wait)
        } else if !am_ok {
            (RateLimitDimension::AccountMsgs, am_wait)
        } else {
            (RateLimitDimension::AccountBytes, ab_wait)
        };

        match dimension {
            RateLimitDimension::SessionMsgs => self.metrics.rejected_session_msgs += 1,
            RateLimitDimension::SessionBytes => self.metrics.rejected_session_bytes += 1,
            RateLimitDimension::AccountMsgs => self.metrics.rejected_account_msgs += 1,
            RateLimitDimension::AccountBytes => self.metrics.rejected_account_bytes += 1,
        }

        if self.config.throttle_mode {
            RateLimitOutcome::Throttle { dimension, delay }
        } else {
            RateLimitOutcome::Rejected { dimension }
        }
    }

    pub fn metrics(&self) -> &RateLimitMetrics {
        &self.metrics
    }

    pub fn tracked_sessions(&self) -> usize {
        self.sessions.len()
    }

    pub fn tracked_accounts(&self) -> usize {
        self.accounts.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn mock_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync + 'static) {
        let anchor = Arc::new(Mutex::new(Instant::now()));
        let anchor_clone = anchor.clone();
        (anchor, move || *anchor_clone.lock().unwrap())
    }

    #[test]
    fn bucket_refills_over_time() {
        let start = Instant::now();
        let mut b = TokenBucket::with_clock(10.0, 5.0, start);
        // Consume everything.
        assert!(b.try_consume(10.0, start));
        assert!(!b.try_consume(1.0, start));

        // After 1 second at 5 tok/s we get 5 more.
        let later = start + Duration::from_secs(1);
        assert!(b.try_consume(5.0, later));
        assert!(!b.try_consume(0.01, later));
    }

    #[test]
    fn bucket_caps_at_capacity() {
        let start = Instant::now();
        let mut b = TokenBucket::with_clock(10.0, 100.0, start);
        // Long idle — refill would be 1000 tokens but capped at 10.
        let later = start + Duration::from_secs(10);
        assert_eq!(b.level(later), 10.0);
        assert!(b.try_consume(10.0, later));
        assert!(!b.try_consume(1.0, later));
    }

    #[test]
    fn time_until_is_accurate() {
        let start = Instant::now();
        let mut b = TokenBucket::with_clock(10.0, 10.0, start);
        b.try_consume(10.0, start);
        // Need 5 more tokens at 10 tok/s = 500 ms.
        let wait = b.time_until(5.0, start);
        assert!(wait >= Duration::from_millis(490) && wait <= Duration::from_millis(510));
    }

    #[test]
    fn reject_on_session_msg_burst() {
        let (_clock, now_fn) = mock_clock();
        let config = RateLimitConfig {
            per_session_msgs: BucketConfig::messages(3, 1),
            ..RateLimitConfig::UNLIMITED
        };
        let mut rl = RateLimiter::new(config).with_clock(now_fn);
        rl.register_session(1, 100);

        // 3 admits pass (burst), 4th rejects.
        for _ in 0..3 {
            assert!(matches!(rl.try_admit(1, 1.0, 64.0), RateLimitOutcome::Admitted));
        }
        match rl.try_admit(1, 1.0, 64.0) {
            RateLimitOutcome::Rejected { dimension: RateLimitDimension::SessionMsgs } => {}
            other => panic!("expected session msg rejection, got {:?}", other),
        }
        assert_eq!(rl.metrics().rejected_session_msgs, 1);
    }

    #[test]
    fn reject_on_bytes_even_if_msg_ok() {
        let (_clock, now_fn) = mock_clock();
        let config = RateLimitConfig {
            per_session_msgs: BucketConfig::messages(1_000_000, 1_000_000),
            per_session_bytes: BucketConfig::bytes(1000, 100),
            ..RateLimitConfig::UNLIMITED
        };
        let mut rl = RateLimiter::new(config).with_clock(now_fn);
        rl.register_session(1, 100);

        // One big message eats all bytes; msg quota is fine.
        assert!(matches!(rl.try_admit(1, 1.0, 1000.0), RateLimitOutcome::Admitted));
        // Next even tiny one fails on bytes.
        match rl.try_admit(1, 1.0, 1.0) {
            RateLimitOutcome::Rejected { dimension: RateLimitDimension::SessionBytes } => {}
            other => panic!("expected byte-rejection, got {:?}", other),
        }
    }

    #[test]
    fn account_bucket_shared_across_sessions() {
        let (clock, now_fn) = mock_clock();
        let config = RateLimitConfig {
            per_session_msgs: BucketConfig::messages(100, 100),
            per_account_msgs: BucketConfig::messages(5, 1),
            ..RateLimitConfig::UNLIMITED
        };
        let mut rl = RateLimiter::new(config).with_clock(now_fn);
        // Two sessions for account 100.
        rl.register_session(1, 100);
        rl.register_session(2, 100);

        // Session 1 consumes 3, session 2 consumes 2 → account bucket hits 0.
        for _ in 0..3 {
            assert!(matches!(rl.try_admit(1, 1.0, 16.0), RateLimitOutcome::Admitted));
        }
        for _ in 0..2 {
            assert!(matches!(rl.try_admit(2, 1.0, 16.0), RateLimitOutcome::Admitted));
        }
        // Either session's next request now rejects on account quota.
        match rl.try_admit(1, 1.0, 16.0) {
            RateLimitOutcome::Rejected { dimension: RateLimitDimension::AccountMsgs } => {}
            other => panic!("expected account rejection, got {:?}", other),
        }

        // After 2 seconds the account bucket refills 2 tokens.
        *clock.lock().unwrap() += Duration::from_secs(2);
        assert!(matches!(rl.try_admit(2, 1.0, 16.0), RateLimitOutcome::Admitted));
        assert!(matches!(rl.try_admit(2, 1.0, 16.0), RateLimitOutcome::Admitted));
    }

    #[test]
    fn throttle_mode_returns_delay_instead_of_reject() {
        let (_clock, now_fn) = mock_clock();
        let config = RateLimitConfig {
            per_session_msgs: BucketConfig::messages(1, 10),
            throttle_mode: true,
            ..RateLimitConfig::UNLIMITED
        };
        let mut rl = RateLimiter::new(config).with_clock(now_fn);
        rl.register_session(1, 100);

        // Consume the burst.
        assert!(matches!(rl.try_admit(1, 1.0, 16.0), RateLimitOutcome::Admitted));

        // Next admit returns Throttle with ~100 ms delay.
        match rl.try_admit(1, 1.0, 16.0) {
            RateLimitOutcome::Throttle {
                dimension: RateLimitDimension::SessionMsgs,
                delay,
            } => {
                assert!(delay >= Duration::from_millis(95));
                assert!(delay <= Duration::from_millis(105));
            }
            other => panic!("expected Throttle, got {:?}", other),
        }
    }

    #[test]
    fn rejection_does_not_consume_tokens() {
        let (_clock, now_fn) = mock_clock();
        let config = RateLimitConfig {
            per_session_msgs: BucketConfig::messages(1, 0),
            ..RateLimitConfig::UNLIMITED
        };
        let mut rl = RateLimiter::new(config).with_clock(now_fn);
        rl.register_session(1, 100);

        assert!(matches!(rl.try_admit(1, 1.0, 16.0), RateLimitOutcome::Admitted));
        // Burst exhausted. A stream of rejections must not dig a hole.
        for _ in 0..100 {
            assert!(matches!(
                rl.try_admit(1, 1.0, 16.0),
                RateLimitOutcome::Rejected { .. }
            ));
        }
        // The token count is still 0 (not -100), so the moment the bucket
        // recovers it admits promptly. Verified indirectly by the metric.
        assert_eq!(rl.metrics().rejected_session_msgs, 100);
        assert_eq!(rl.metrics().admitted, 1);
    }

    #[test]
    fn unknown_session_is_admitted() {
        let mut rl = RateLimiter::new(RateLimitConfig::UNLIMITED);
        assert!(matches!(rl.try_admit(42, 1.0, 16.0), RateLimitOutcome::Admitted));
    }

    #[test]
    fn drop_session_keeps_account_bucket() {
        let (_clock, now_fn) = mock_clock();
        let config = RateLimitConfig {
            per_account_msgs: BucketConfig::messages(2, 0),
            ..RateLimitConfig::UNLIMITED
        };
        let mut rl = RateLimiter::new(config).with_clock(now_fn);
        rl.register_session(1, 100);
        rl.try_admit(1, 1.0, 16.0); // account quota: 1
        rl.try_admit(1, 1.0, 16.0); // account quota: 0

        // Session disconnects — account bucket must persist so a reconnect
        // doesn't reset the quota.
        rl.drop_session(1);
        rl.register_session(2, 100);
        match rl.try_admit(2, 1.0, 16.0) {
            RateLimitOutcome::Rejected { dimension: RateLimitDimension::AccountMsgs } => {}
            other => panic!("account quota must survive session teardown, got {:?}", other),
        }
    }

    #[test]
    fn dimension_codes_are_stable() {
        assert_eq!(
            RateLimitDimension::SessionMsgs.as_code(),
            "rate_limited:session_msgs"
        );
        assert_eq!(
            RateLimitDimension::AccountBytes.as_code(),
            "rate_limited:account_bytes"
        );
    }
}
