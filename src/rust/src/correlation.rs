//! Request/response correlation.
//!
//! # Why this exists
//!
//! Every MGEP message already carries `correlation_id` in its header, but
//! before this module the session layer never looked at it. The consequence
//! was a well-known family of bugs in live trading systems:
//!
//! * Client sends `OrderStatusRequest` for order A and B back-to-back; the
//!   server streams two `ExecutionReport`s. Which one is the ack for A?
//!   Without correlation matching, the client has to heuristically match
//!   on `order_id` — and that breaks for RFQ flows where the mapping is
//!   not 1:1.
//! * Client sends a cancel, times out internally, retries. Server
//!   eventually responds to the first cancel. Client attributes it to the
//!   retry and double-confirms the wrong order state.
//!
//! The fix is the same pattern FIX `ClOrdID` / iLink `requestID` use: an
//! unsigned 64-bit correlation ID, allocated monotonically by the client,
//! echoed by the server on the **first** response. Subsequent related
//! messages (e.g. partial fills streamed after an initial ack) reference
//! the same correlation_id.
//!
//! # Scope
//!
//! This module owns:
//!
//! * [`CorrelationIdGenerator`] — allocates IDs, skips 0 (reserved "no
//!   correlation").
//! * [`CorrelationTable`] — bounded map of outstanding requests with
//!   time-based expiry. Pure data structure; transport lives elsewhere.
//! * [`TimedOutRequest`] — what the reactor does when a deadline passes
//!   without a response.
//!
//! Wiring this into the server / client dispatch path is a follow-up task;
//! this module gives the primitive.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ─── ID generator ────────────────────────────────────────────

/// Monotonic allocator for correlation IDs. Thread-safe; the underlying
/// counter is `AtomicU64` so a fleet of producer threads can share one
/// allocator without contention.
///
/// `0` is reserved to mean "no correlation" — messages that do not expect
/// a response (heartbeats, one-way market data) use `0` and will not
/// collide with tracked requests.
pub struct CorrelationIdGenerator {
    next: AtomicU64,
}

impl CorrelationIdGenerator {
    pub fn new() -> Self {
        Self { next: AtomicU64::new(1) }
    }

    /// Start from a specific value. Useful when resuming across restarts to
    /// avoid reusing IDs that might still be echoed by the peer.
    pub fn starting_at(initial: u64) -> Self {
        let start = if initial == 0 { 1 } else { initial };
        Self { next: AtomicU64::new(start) }
    }

    /// Allocate the next ID. Always non-zero; wraps cleanly past 2^64.
    pub fn next(&self) -> u64 {
        loop {
            let candidate = self.next.fetch_add(1, Ordering::Relaxed);
            if candidate != 0 {
                return candidate;
            }
        }
    }
}

impl Default for CorrelationIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Pending request metadata ────────────────────────────────

/// Metadata about an outstanding request. The caller may attach any payload
/// they need to reconstruct the request on resolve/timeout — e.g. a
/// `ClOrdID` to route back to the originating user-space future.
#[derive(Debug, Clone)]
pub struct PendingRequest<T> {
    pub correlation_id: u64,
    pub payload: T,
    pub deadline: Instant,
    pub submitted_at: Instant,
}

/// A request that tripped its deadline without receiving a response.
/// Returned by [`CorrelationTable::poll_timeouts`].
#[derive(Debug)]
pub struct TimedOutRequest<T> {
    pub correlation_id: u64,
    pub payload: T,
    pub age: Duration,
}

// ─── Errors & outcomes ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationError {
    /// `correlation_id == 0` is reserved.
    InvalidZeroId,
    /// Correlation ID already in the table. The caller is attempting to
    /// reuse an ID; this is almost always a programming bug.
    DuplicateId { correlation_id: u64 },
    /// Outstanding-request capacity exceeded. Caller must wait for
    /// in-flight responses to drain or abort older ones.
    CapacityExceeded { capacity: usize },
}

impl std::fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidZeroId => write!(f, "correlation_id 0 is reserved"),
            Self::DuplicateId { correlation_id } => {
                write!(f, "correlation_id {} already outstanding", correlation_id)
            }
            Self::CapacityExceeded { capacity } => {
                write!(f, "correlation table at capacity ({})", capacity)
            }
        }
    }
}

impl std::error::Error for CorrelationError {}

// ─── Correlation table ───────────────────────────────────────

/// Bounded, time-indexed map of outstanding correlation IDs.
///
/// Insertion order is preserved in a FIFO side-queue so the expiry sweep is
/// amortized O(1) per call rather than O(n). Capacity acts as a hard cap —
/// a runaway client that never resolves requests can't OOM the process.
///
/// NOT thread-safe; callers that need cross-thread tracking should wrap in
/// `Mutex` or shard by session.
pub struct CorrelationTable<T> {
    entries: HashMap<u64, PendingRequest<T>>,
    /// FIFO of correlation IDs in submission order. Used for expiry sweep.
    /// Stale entries (already removed from `entries`) are skipped.
    fifo: VecDeque<u64>,
    capacity: usize,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl<T> CorrelationTable<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(1024)),
            fifo: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
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

    /// Register an outgoing request. The `deadline` is wall-clock; callers
    /// typically compute it as `now + request_timeout`.
    pub fn register(
        &mut self,
        correlation_id: u64,
        payload: T,
        timeout: Duration,
    ) -> Result<(), CorrelationError> {
        if correlation_id == 0 {
            return Err(CorrelationError::InvalidZeroId);
        }
        if self.entries.len() >= self.capacity {
            return Err(CorrelationError::CapacityExceeded { capacity: self.capacity });
        }
        if self.entries.contains_key(&correlation_id) {
            return Err(CorrelationError::DuplicateId { correlation_id });
        }
        let now = (self.now)();
        self.entries.insert(
            correlation_id,
            PendingRequest {
                correlation_id,
                payload,
                deadline: now + timeout,
                submitted_at: now,
            },
        );
        self.fifo.push_back(correlation_id);
        Ok(())
    }

    /// Look up a response correlation ID and remove the entry. Returns the
    /// pending request if it was outstanding, `None` if unknown (which is
    /// either an unsolicited response — suspicious — or a late response to
    /// something that already timed out).
    pub fn resolve(&mut self, correlation_id: u64) -> Option<PendingRequest<T>> {
        if correlation_id == 0 {
            return None;
        }
        self.entries.remove(&correlation_id)
    }

    /// Drop a pending entry without a response. Returns the removed entry,
    /// if any. Used when the caller decides to abort the request locally
    /// (e.g. the user canceled the future).
    pub fn cancel(&mut self, correlation_id: u64) -> Option<PendingRequest<T>> {
        self.entries.remove(&correlation_id)
    }

    /// Sweep expired entries and return them.
    ///
    /// The sweep inspects the FIFO front-to-back, stopping at the first
    /// entry whose deadline is still in the future. Because the FIFO is
    /// insertion-ordered and `timeout` is usually uniform, this is
    /// amortized O(1) per call in steady state.
    pub fn poll_timeouts(&mut self) -> Vec<TimedOutRequest<T>> {
        let now = (self.now)();
        let mut out = Vec::new();
        while let Some(&front) = self.fifo.front() {
            let entry = match self.entries.get(&front) {
                Some(e) => e,
                None => {
                    // Stale FIFO entry (already resolved or canceled).
                    self.fifo.pop_front();
                    continue;
                }
            };
            if entry.deadline > now {
                break;
            }
            self.fifo.pop_front();
            if let Some(pending) = self.entries.remove(&front) {
                out.push(TimedOutRequest {
                    correlation_id: pending.correlation_id,
                    payload: pending.payload,
                    age: now.saturating_duration_since(pending.submitted_at),
                });
            }
        }
        out
    }

    pub fn outstanding(&self) -> usize {
        self.entries.len()
    }

    pub fn is_outstanding(&self, correlation_id: u64) -> bool {
        self.entries.contains_key(&correlation_id)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn mock_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync + 'static) {
        let anchor = Arc::new(Mutex::new(Instant::now()));
        let clone = anchor.clone();
        (anchor, move || *clone.lock().unwrap())
    }

    #[test]
    fn generator_skips_zero_and_is_monotonic() {
        let g = CorrelationIdGenerator::new();
        let a = g.next();
        let b = g.next();
        let c = g.next();
        assert_ne!(a, 0);
        assert_eq!(b, a + 1);
        assert_eq!(c, b + 1);
    }

    #[test]
    fn generator_starting_at_rejects_zero() {
        let g = CorrelationIdGenerator::starting_at(0);
        assert_eq!(g.next(), 1);
    }

    #[test]
    fn register_and_resolve_roundtrip() {
        let mut table: CorrelationTable<&str> = CorrelationTable::new(16);
        table.register(42, "new-order-A", Duration::from_secs(5)).unwrap();
        assert_eq!(table.outstanding(), 1);
        assert!(table.is_outstanding(42));

        let pending = table.resolve(42).unwrap();
        assert_eq!(pending.payload, "new-order-A");
        assert_eq!(table.outstanding(), 0);

        // Second resolve returns None (already matched).
        assert!(table.resolve(42).is_none());
    }

    #[test]
    fn zero_id_rejected() {
        let mut table: CorrelationTable<&str> = CorrelationTable::new(16);
        let err = table.register(0, "x", Duration::from_secs(1)).unwrap_err();
        assert_eq!(err, CorrelationError::InvalidZeroId);
        assert!(table.resolve(0).is_none());
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut table: CorrelationTable<&str> = CorrelationTable::new(16);
        table.register(7, "first", Duration::from_secs(1)).unwrap();
        let err = table.register(7, "second", Duration::from_secs(1)).unwrap_err();
        assert_eq!(err, CorrelationError::DuplicateId { correlation_id: 7 });
        // First entry still there.
        assert_eq!(table.resolve(7).unwrap().payload, "first");
    }

    #[test]
    fn capacity_exceeded() {
        let mut table: CorrelationTable<u32> = CorrelationTable::new(2);
        table.register(1, 100, Duration::from_secs(1)).unwrap();
        table.register(2, 200, Duration::from_secs(1)).unwrap();
        let err = table.register(3, 300, Duration::from_secs(1)).unwrap_err();
        assert_eq!(err, CorrelationError::CapacityExceeded { capacity: 2 });

        // Resolving frees capacity.
        table.resolve(1).unwrap();
        table.register(3, 300, Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn timeouts_fire_after_deadline() {
        let (clock, now_fn) = mock_clock();
        let mut table: CorrelationTable<&str> = CorrelationTable::new(16).with_clock(now_fn);

        table.register(1, "A", Duration::from_secs(5)).unwrap();
        table.register(2, "B", Duration::from_secs(10)).unwrap();
        assert!(table.poll_timeouts().is_empty());

        // 7 seconds: only A expired.
        *clock.lock().unwrap() += Duration::from_secs(7);
        let expired = table.poll_timeouts();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].correlation_id, 1);
        assert_eq!(expired[0].payload, "A");
        assert!(expired[0].age >= Duration::from_secs(5));

        // 12 seconds: B also expires now.
        *clock.lock().unwrap() += Duration::from_secs(5);
        let expired = table.poll_timeouts();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].correlation_id, 2);
        assert_eq!(table.outstanding(), 0);
    }

    #[test]
    fn timeouts_skip_already_resolved_entries() {
        let (clock, now_fn) = mock_clock();
        let mut table: CorrelationTable<&str> = CorrelationTable::new(16).with_clock(now_fn);

        table.register(1, "A", Duration::from_secs(5)).unwrap();
        table.register(2, "B", Duration::from_secs(5)).unwrap();

        // Resolve A before it expires.
        table.resolve(1).unwrap();

        // Advance past the deadline.
        *clock.lock().unwrap() += Duration::from_secs(10);
        let expired = table.poll_timeouts();
        // Only B should be reported — A was already resolved.
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].correlation_id, 2);
    }

    #[test]
    fn cancel_removes_entry_without_timeout() {
        let mut table: CorrelationTable<&str> = CorrelationTable::new(16);
        table.register(42, "to-cancel", Duration::from_secs(30)).unwrap();
        let canceled = table.cancel(42).unwrap();
        assert_eq!(canceled.payload, "to-cancel");
        assert!(!table.is_outstanding(42));
        assert!(table.resolve(42).is_none());
    }

    #[test]
    fn late_response_to_timed_out_request_is_ignored() {
        // Classic source of trading bugs: a slow server responds after the
        // client already timed out and retried. The table must treat the
        // late response as unknown (caller logs it as unsolicited).
        let (clock, now_fn) = mock_clock();
        let mut table: CorrelationTable<&str> = CorrelationTable::new(16).with_clock(now_fn);

        table.register(1, "original", Duration::from_secs(2)).unwrap();
        *clock.lock().unwrap() += Duration::from_secs(5);
        let expired = table.poll_timeouts();
        assert_eq!(expired.len(), 1);

        // Server finally replies. resolve() returns None — the caller must
        // treat it as unsolicited (probably log + ignore).
        assert!(table.resolve(1).is_none());
    }

    #[test]
    fn reentrant_requests_are_independent() {
        // Multiple outstanding requests overlap and each resolves
        // independently based on correlation_id — the core invariant.
        let mut table: CorrelationTable<u64> = CorrelationTable::new(8);
        for i in 1..=5u64 {
            table.register(i, i * 100, Duration::from_secs(10)).unwrap();
        }
        assert_eq!(table.outstanding(), 5);

        // Resolve out of order.
        assert_eq!(table.resolve(3).unwrap().payload, 300);
        assert_eq!(table.resolve(1).unwrap().payload, 100);
        assert_eq!(table.resolve(5).unwrap().payload, 500);
        assert_eq!(table.outstanding(), 2);
    }
}
