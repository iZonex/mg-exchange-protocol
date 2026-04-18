//! Server-side idempotency store for order entry.
//!
//! # Why this exists
//!
//! HFT clients retry aggressively on timeout. Without deduplication, a client
//! that sends `NewOrderSingle` and times out before receiving the ack will
//! retry — and the exchange will accept both submissions, filling the client's
//! book twice. This is the single most common production bug in crypto
//! exchanges that weren't built with idempotent submission in mind.
//!
//! Real exchanges solve this with a client-provided unique ID (FIX `ClOrdID`,
//! ITCH `ClOrdID`, OUCH `ClOrdID`, iLink `clientID`). The exchange remembers
//! the response to every `(session, client_order_id)` pair seen within a
//! sliding time window, and returns the cached response rather than creating
//! a second order.
//!
//! # Model
//!
//! * Key: `(session_id, client_order_id)`. Sessions are isolated — two
//!   different clients may legitimately use the same ClOrdID.
//! * Value: a server-chosen `server_order_id` plus the bytes of the original
//!   `ExecutionReport` (so retries get byte-exact replays, not just
//!   "yeah that one").
//! * Eviction: time-based sliding window. An entry is dropped once it's been
//!   idle for `window`. The window should be at least 2× the worst-case
//!   client retry interval (typically 30 s – 5 min).
//! * Capacity: bounded; oldest entries evicted under memory pressure. The
//!   bound prevents a malicious client from growing the table without limit.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Outcome of submitting a new order through the idempotency store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// First time we've seen this (session, client_order_id). Caller should
    /// process the order normally and then call `record` with the response.
    Fresh,
    /// Duplicate submission. Caller must return `cached_response` bytes
    /// rather than creating a new order.
    Duplicate { server_order_id: u64, cached_response: Vec<u8> },
    /// `client_order_id = 0` is reserved as a sentinel. Reject with a
    /// Reject/BusinessReject.
    InvalidKey,
}

/// Key used by the store. Kept explicit to avoid accidental cross-session
/// key collisions.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    session_id: u64,
    client_order_id: u64,
}

struct Entry {
    server_order_id: u64,
    response: Vec<u8>,
    recorded_at: Instant,
}

/// Bounded, time-windowed dedup store.
///
/// NOT thread-safe on its own; wrap in `Mutex` or partition by session.
pub struct IdempotencyStore {
    entries: HashMap<Key, Entry>,
    /// FIFO of keys in insertion order for capacity-based eviction.
    lru: VecDeque<Key>,
    /// Max entries. `evict_expired` + capacity-based eviction keep memory
    /// bounded.
    capacity: usize,
    /// How long an entry is valid after recording.
    window: Duration,
    /// Injectable clock for testing.
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl IdempotencyStore {
    /// Create a store with the given capacity and dedup window.
    ///
    /// `capacity = 1_000_000` and `window = 5 min` are reasonable defaults
    /// for a busy exchange session (10K orders/sec × 5 min = 3M, so 1M caps
    /// memory at roughly 200 MB assuming ~200 B per cached response; adjust
    /// upward for higher throughput or longer dedup windows).
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(4096)),
            lru: VecDeque::with_capacity(capacity.min(4096)),
            capacity,
            window,
            now: Box::new(Instant::now),
        }
    }

    /// Install a custom clock. Intended for tests; the default is
    /// `Instant::now`.
    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> Instant + Send + Sync + 'static,
    {
        self.now = Box::new(clock);
        self
    }

    /// Check whether `(session_id, client_order_id)` is a fresh submission or
    /// a duplicate of something already recorded. This is a **read-only**
    /// query — the caller must follow up with `record` once the order has
    /// been processed so future retries see the cached response.
    pub fn submit(&mut self, session_id: u64, client_order_id: u64) -> SubmitOutcome {
        if client_order_id == 0 {
            return SubmitOutcome::InvalidKey;
        }

        let key = Key { session_id, client_order_id };
        self.evict_expired();

        if let Some(entry) = self.entries.get(&key) {
            return SubmitOutcome::Duplicate {
                server_order_id: entry.server_order_id,
                cached_response: entry.response.clone(),
            };
        }
        SubmitOutcome::Fresh
    }

    /// Record the response to a fresh submission. After this call, further
    /// `submit` calls with the same key (within the window) return
    /// `Duplicate`.
    ///
    /// `response_bytes` is the encoded wire message (typically the
    /// `ExecutionReport` ack) that the server sent back to the client. It is
    /// replayed verbatim on retry.
    pub fn record(
        &mut self,
        session_id: u64,
        client_order_id: u64,
        server_order_id: u64,
        response_bytes: Vec<u8>,
    ) {
        if client_order_id == 0 {
            return;
        }
        let key = Key { session_id, client_order_id };
        let entry = Entry {
            server_order_id,
            response: response_bytes,
            recorded_at: (self.now)(),
        };

        // Insert; if the key was already there we overwrite but don't move
        // its LRU position (overwriting should be rare — only happens if the
        // caller records twice for the same key, which is a bug).
        if self.entries.insert(key, entry).is_none() {
            self.lru.push_back(key);
        }

        // Capacity-based eviction.
        while self.lru.len() > self.capacity {
            if let Some(oldest) = self.lru.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Evict entries older than `window`. Amortized O(1) per call because
    /// entries are stored in insertion order.
    pub fn evict_expired(&mut self) {
        let cutoff = match (self.now)().checked_sub(self.window) {
            Some(t) => t,
            None => return,
        };
        while let Some(&key) = self.lru.front() {
            let stale = self
                .entries
                .get(&key)
                .map(|e| e.recorded_at < cutoff)
                .unwrap_or(true);
            if stale {
                self.lru.pop_front();
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Purge all entries associated with a session. Called when the session
    /// tears down — prevents memory leak when sessions end legitimately
    /// while entries are still within the dedup window.
    pub fn purge_session(&mut self, session_id: u64) {
        self.entries.retain(|k, _| k.session_id != session_id);
        self.lru.retain(|k| k.session_id != session_id);
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock clock that advances manually. Use with `with_clock`.
    fn mock_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync + 'static) {
        let anchor = Arc::new(Mutex::new(Instant::now()));
        let anchor_clone = anchor.clone();
        let now_fn = move || *anchor_clone.lock().unwrap();
        (anchor, now_fn)
    }

    #[test]
    fn fresh_then_duplicate() {
        let mut store = IdempotencyStore::new(1024, Duration::from_secs(60));

        // First submission — fresh.
        let outcome = store.submit(1, 42);
        assert!(matches!(outcome, SubmitOutcome::Fresh));

        // Record response.
        let response = vec![0xAB; 88];
        store.record(1, 42, 9999, response.clone());
        assert_eq!(store.len(), 1);

        // Retry — must return cached response byte-exact.
        let outcome = store.submit(1, 42);
        match outcome {
            SubmitOutcome::Duplicate { server_order_id, cached_response } => {
                assert_eq!(server_order_id, 9999);
                assert_eq!(cached_response, response);
            }
            other => panic!("expected Duplicate, got {:?}", other),
        }
    }

    #[test]
    fn different_sessions_dont_collide() {
        let mut store = IdempotencyStore::new(1024, Duration::from_secs(60));

        store.record(1, 42, 100, vec![0xAA]);
        store.record(2, 42, 200, vec![0xBB]);

        match store.submit(1, 42) {
            SubmitOutcome::Duplicate { server_order_id, cached_response } => {
                assert_eq!(server_order_id, 100);
                assert_eq!(cached_response, vec![0xAA]);
            }
            _ => panic!("session 1 should match"),
        }
        match store.submit(2, 42) {
            SubmitOutcome::Duplicate { server_order_id, cached_response } => {
                assert_eq!(server_order_id, 200);
                assert_eq!(cached_response, vec![0xBB]);
            }
            _ => panic!("session 2 should match"),
        }
    }

    #[test]
    fn client_order_id_zero_rejected() {
        let mut store = IdempotencyStore::new(1024, Duration::from_secs(60));
        assert!(matches!(store.submit(1, 0), SubmitOutcome::InvalidKey));

        // Record with zero should be a no-op (not a panic).
        store.record(1, 0, 999, vec![0xFF]);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn expiry_after_window() {
        let (clock, now_fn) = mock_clock();
        let mut store =
            IdempotencyStore::new(1024, Duration::from_secs(60)).with_clock(now_fn);

        store.record(1, 42, 100, vec![0xAA]);
        assert!(matches!(store.submit(1, 42), SubmitOutcome::Duplicate { .. }));

        // Advance past the window.
        *clock.lock().unwrap() += Duration::from_secs(120);
        assert!(matches!(store.submit(1, 42), SubmitOutcome::Fresh));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn capacity_eviction_fifo() {
        let mut store = IdempotencyStore::new(3, Duration::from_secs(3600));
        store.record(1, 1, 10, vec![1]);
        store.record(1, 2, 20, vec![2]);
        store.record(1, 3, 30, vec![3]);
        assert_eq!(store.len(), 3);

        // 4th entry evicts the oldest (ClOrdID=1).
        store.record(1, 4, 40, vec![4]);
        assert_eq!(store.len(), 3);
        assert!(matches!(store.submit(1, 1), SubmitOutcome::Fresh));
        assert!(matches!(store.submit(1, 2), SubmitOutcome::Duplicate { .. }));
        assert!(matches!(store.submit(1, 4), SubmitOutcome::Duplicate { .. }));
    }

    #[test]
    fn purge_session_removes_all() {
        let mut store = IdempotencyStore::new(1024, Duration::from_secs(60));
        store.record(1, 1, 10, vec![1]);
        store.record(1, 2, 20, vec![2]);
        store.record(2, 1, 30, vec![3]);

        store.purge_session(1);
        assert_eq!(store.len(), 1);
        assert!(matches!(store.submit(1, 1), SubmitOutcome::Fresh));
        assert!(matches!(store.submit(2, 1), SubmitOutcome::Duplicate { .. }));
    }

    #[test]
    fn overwrite_record_is_noop_on_lru() {
        let mut store = IdempotencyStore::new(2, Duration::from_secs(3600));
        store.record(1, 1, 10, vec![1]);
        store.record(1, 2, 20, vec![2]);
        // Re-record ClOrdID=1: should NOT move it to back of LRU.
        store.record(1, 1, 99, vec![9]);

        // Adding a third entry still evicts the (still-oldest) ClOrdID=1.
        store.record(1, 3, 30, vec![3]);
        assert!(matches!(store.submit(1, 1), SubmitOutcome::Fresh));
        assert!(matches!(store.submit(1, 2), SubmitOutcome::Duplicate { .. }));
        assert!(matches!(store.submit(1, 3), SubmitOutcome::Duplicate { .. }));
    }
}
