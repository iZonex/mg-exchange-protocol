//! Cancel-on-disconnect enforcement.
//!
//! # Why this exists
//!
//! `SessionFlags::CANCEL_ON_DISCONNECT` is negotiated during the handshake,
//! but prior to this module nothing actually *did* anything when the flag was
//! set. If the transport dropped — TCP reset, peer timeout, client crashed —
//! open orders belonging to the dead session remained resting in the book.
//! For a real exchange this is catastrophic: clients rely on COD to manage
//! risk when they cannot reach the exchange.
//!
//! # Design
//!
//! The manager sits between the session layer and the matching engine:
//!
//!   * On order accept, the caller invokes `register` to track the
//!     `(session_id, order_id)` pair.
//!   * On order terminal state (fill / cancel / reject), the caller invokes
//!     `unregister`.
//!   * On transport loss, the caller invokes `on_session_lost`. The manager
//!     schedules a cancellation **only if** the session had negotiated
//!     `CANCEL_ON_DISCONNECT`. The cancellation is deferred for the
//!     configured `grace_period` to allow clean reconnects.
//!   * If the session re-establishes within the grace period,
//!     `on_session_reconnected` aborts the pending cancellation.
//!   * `poll_due_cancels` is called periodically (e.g. each reactor tick)
//!     and returns a list of orders to cancel in the matching engine, with
//!     a reason code for the ExecutionReport.
//!
//! The matching-engine integration is the caller's responsibility: the
//! manager is a **pure index**. It has no dependency on `OrderBook` so it
//! can be used with any engine.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Why a session was lost. Surfaced to audit logs and reflected in the
/// downstream `ExecutionReport` emitted for each auto-cancellation so clients
/// can distinguish an operational cancellation from a risk-driven one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// TCP FIN/RST, abrupt socket close.
    TransportClose,
    /// Keepalive/heartbeat watchdog tripped.
    PeerTimeout,
    /// Explicit `Terminate` message from peer.
    ExplicitTerminate,
    /// Server-side forced disconnect (e.g. admin kill, rate-limit).
    ServerInitiated,
    /// Catch-all — prefer a specific variant where possible for audit quality.
    Unknown,
}

impl DisconnectReason {
    /// Short identifier suitable for audit-log / cancel-reason text field.
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::TransportClose => "session_lost:transport_close",
            Self::PeerTimeout => "session_lost:peer_timeout",
            Self::ExplicitTerminate => "session_lost:explicit_terminate",
            Self::ServerInitiated => "session_lost:server_initiated",
            Self::Unknown => "session_lost:unknown",
        }
    }
}

/// An order the caller must cancel in the matching engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCancel {
    pub session_id: u64,
    pub order_id: u64,
    pub reason: DisconnectReason,
}

/// Per-session state tracked by the manager.
struct SessionState {
    /// Set of open order IDs belonging to this session.
    orders: HashSet<u64>,
    /// `Some(deadline)` if we've scheduled cancellation. The pending cancel
    /// is committed when `now() >= deadline`; aborted if the session
    /// re-establishes first.
    pending_cancel_at: Option<(Instant, DisconnectReason)>,
    /// Whether this session negotiated CANCEL_ON_DISCONNECT. Captured at
    /// `register` time so the manager doesn't have to dip into the Session
    /// state on every call.
    cod_enabled: bool,
}

impl SessionState {
    fn new(cod_enabled: bool) -> Self {
        Self {
            orders: HashSet::new(),
            pending_cancel_at: None,
            cod_enabled,
        }
    }
}

/// Coordinates cancel-on-disconnect for all sessions on the server.
///
/// **Thread safety:** not `Sync`. Callers integrating into an async server
/// should wrap in `Mutex` or partition the manager by session.
pub struct CancelOnDisconnectManager {
    sessions: HashMap<u64, SessionState>,
    /// Grace period between a session being lost and its orders actually
    /// being canceled. Allows clean reconnects.
    grace_period: Duration,
    /// Injectable clock for deterministic tests.
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl CancelOnDisconnectManager {
    /// Default grace: 5 seconds. Reasonable for exchange clients across WAN
    /// links; production deployments should tune per-tenant.
    pub fn new(grace_period: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            grace_period,
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

    /// Record a session's COD flag once at handshake time. Call this even if
    /// `cod_enabled` is `false` — it ensures the manager has the session
    /// registered so later bookkeeping calls are no-ops rather than silently
    /// dropped on a non-existent session.
    pub fn register_session(&mut self, session_id: u64, cod_enabled: bool) {
        self.sessions
            .entry(session_id)
            .and_modify(|s| s.cod_enabled = cod_enabled)
            .or_insert_with(|| SessionState::new(cod_enabled));
    }

    /// Register an order as open for the given session. Idempotent.
    pub fn register(&mut self, session_id: u64, order_id: u64) {
        let state = self
            .sessions
            .entry(session_id)
            .or_insert_with(|| SessionState::new(false));
        state.orders.insert(order_id);
    }

    /// Mark an order as no longer open (filled, canceled, rejected).
    pub fn unregister(&mut self, session_id: u64, order_id: u64) {
        if let Some(state) = self.sessions.get_mut(&session_id) {
            state.orders.remove(&order_id);
        }
    }

    /// Schedule cancellation of all this session's orders after the grace
    /// period. No-op if the session did not negotiate COD.
    ///
    /// Returns `true` if a cancellation was scheduled. A session that is
    /// already in the grace window keeps its existing deadline — repeated
    /// calls don't extend it.
    pub fn on_session_lost(
        &mut self,
        session_id: u64,
        reason: DisconnectReason,
    ) -> bool {
        let state = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return false,
        };
        if !state.cod_enabled {
            return false;
        }
        if state.pending_cancel_at.is_none() {
            let deadline = (self.now)() + self.grace_period;
            state.pending_cancel_at = Some((deadline, reason));
        }
        true
    }

    /// Session re-established — abort any pending cancellation. Returns
    /// `true` if an abort actually occurred.
    pub fn on_session_reconnected(&mut self, session_id: u64) -> bool {
        let state = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return false,
        };
        state.pending_cancel_at.take().is_some()
    }

    /// Sweep for sessions whose grace period has elapsed and return the list
    /// of orders the matching engine should cancel. The manager updates its
    /// own state: the orders are unregistered and the session's pending flag
    /// is cleared.
    ///
    /// Callers should invoke this on a timer (e.g. each reactor tick, or on
    /// the keepalive interval). The expected volume is small — one call per
    /// disconnected-COD session per grace window.
    pub fn poll_due_cancels(&mut self) -> Vec<PendingCancel> {
        let now = (self.now)();
        let mut out = Vec::new();

        let due_sessions: Vec<(u64, DisconnectReason)> = self
            .sessions
            .iter()
            .filter_map(|(&sid, s)| match s.pending_cancel_at {
                Some((deadline, reason)) if deadline <= now => Some((sid, reason)),
                _ => None,
            })
            .collect();

        for (session_id, reason) in due_sessions {
            if let Some(state) = self.sessions.get_mut(&session_id) {
                for order_id in state.orders.drain() {
                    out.push(PendingCancel { session_id, order_id, reason });
                }
                state.pending_cancel_at = None;
            }
        }

        out
    }

    /// Remove a session entirely from tracking. Call after a clean termination
    /// where there is no reason to retain state — e.g. on `Terminate` received
    /// and all orders already resolved.
    pub fn drop_session(&mut self, session_id: u64) {
        self.sessions.remove(&session_id);
    }

    /// Number of sessions currently tracked.
    pub fn tracked_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Open orders count for a session (useful for metrics / audit).
    pub fn open_orders(&self, session_id: u64) -> usize {
        self.sessions
            .get(&session_id)
            .map(|s| s.orders.len())
            .unwrap_or(0)
    }

    /// True if a session is currently in the grace window after a disconnect.
    pub fn is_pending(&self, session_id: u64) -> bool {
        self.sessions
            .get(&session_id)
            .map(|s| s.pending_cancel_at.is_some())
            .unwrap_or(false)
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
    fn disconnect_triggers_cancel_after_grace() {
        let (clock, now_fn) = mock_clock();
        let mut mgr =
            CancelOnDisconnectManager::new(Duration::from_secs(5)).with_clock(now_fn);

        mgr.register_session(1, true);
        mgr.register(1, 100);
        mgr.register(1, 101);
        mgr.register(1, 102);

        assert!(mgr.on_session_lost(1, DisconnectReason::TransportClose));
        assert!(mgr.is_pending(1));

        // Before grace elapses: nothing to cancel.
        assert!(mgr.poll_due_cancels().is_empty());

        // Advance past grace.
        *clock.lock().unwrap() += Duration::from_secs(6);

        let pending = mgr.poll_due_cancels();
        assert_eq!(pending.len(), 3);
        let ids: HashSet<u64> = pending.iter().map(|p| p.order_id).collect();
        assert_eq!(ids, HashSet::from([100, 101, 102]));
        assert!(pending.iter().all(|p| p.session_id == 1));
        assert!(pending
            .iter()
            .all(|p| p.reason == DisconnectReason::TransportClose));

        // Second poll is idempotent: nothing remaining.
        assert!(mgr.poll_due_cancels().is_empty());
        assert_eq!(mgr.open_orders(1), 0);
        assert!(!mgr.is_pending(1));
    }

    #[test]
    fn reconnect_within_grace_aborts_cancel() {
        let (clock, now_fn) = mock_clock();
        let mut mgr =
            CancelOnDisconnectManager::new(Duration::from_secs(5)).with_clock(now_fn);

        mgr.register_session(1, true);
        mgr.register(1, 100);

        mgr.on_session_lost(1, DisconnectReason::PeerTimeout);
        assert!(mgr.is_pending(1));

        // Advance partway, then reconnect.
        *clock.lock().unwrap() += Duration::from_secs(3);
        assert!(mgr.on_session_reconnected(1));
        assert!(!mgr.is_pending(1));

        // Advance past the original deadline: no cancel.
        *clock.lock().unwrap() += Duration::from_secs(10);
        assert!(mgr.poll_due_cancels().is_empty());
        assert_eq!(mgr.open_orders(1), 1);
    }

    #[test]
    fn cod_disabled_session_keeps_orders() {
        let mut mgr = CancelOnDisconnectManager::new(Duration::from_secs(1));
        mgr.register_session(1, false);
        mgr.register(1, 100);

        assert!(!mgr.on_session_lost(1, DisconnectReason::TransportClose));
        assert!(!mgr.is_pending(1));

        std::thread::sleep(Duration::from_millis(10));
        assert!(mgr.poll_due_cancels().is_empty());
        assert_eq!(mgr.open_orders(1), 1);
    }

    #[test]
    fn unregister_removes_from_tracking() {
        let mut mgr = CancelOnDisconnectManager::new(Duration::from_secs(1));
        mgr.register_session(1, true);
        mgr.register(1, 100);
        mgr.register(1, 101);
        assert_eq!(mgr.open_orders(1), 2);

        mgr.unregister(1, 100);
        assert_eq!(mgr.open_orders(1), 1);

        // Unregister of an unknown order is a no-op.
        mgr.unregister(1, 999);
        assert_eq!(mgr.open_orders(1), 1);
    }

    #[test]
    fn sessions_are_isolated() {
        let (clock, now_fn) = mock_clock();
        let mut mgr =
            CancelOnDisconnectManager::new(Duration::from_secs(5)).with_clock(now_fn);
        mgr.register_session(1, true);
        mgr.register_session(2, true);
        mgr.register(1, 100);
        mgr.register(2, 200);

        mgr.on_session_lost(1, DisconnectReason::TransportClose);
        *clock.lock().unwrap() += Duration::from_secs(10);

        let pending = mgr.poll_due_cancels();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].session_id, 1);
        assert_eq!(pending[0].order_id, 100);

        // Session 2 is intact.
        assert_eq!(mgr.open_orders(2), 1);
    }

    #[test]
    fn on_session_lost_is_idempotent() {
        let (clock, now_fn) = mock_clock();
        let mut mgr =
            CancelOnDisconnectManager::new(Duration::from_secs(5)).with_clock(now_fn);
        mgr.register_session(1, true);
        mgr.register(1, 100);

        assert!(mgr.on_session_lost(1, DisconnectReason::TransportClose));
        // Advance halfway through the grace window.
        *clock.lock().unwrap() += Duration::from_secs(3);

        // Re-entering on_session_lost must not extend the deadline —
        // otherwise a flapping connection would never commit the cancel.
        assert!(mgr.on_session_lost(1, DisconnectReason::PeerTimeout));

        // Advance past the ORIGINAL deadline (5s total, we're at 3s + 3s = 6s).
        *clock.lock().unwrap() += Duration::from_secs(3);
        let pending = mgr.poll_due_cancels();
        assert_eq!(pending.len(), 1);
        // Reason is still the first one captured.
        assert_eq!(pending[0].reason, DisconnectReason::TransportClose);
    }

    #[test]
    fn drop_session_removes_all_state() {
        let mut mgr = CancelOnDisconnectManager::new(Duration::from_secs(5));
        mgr.register_session(1, true);
        mgr.register(1, 100);
        mgr.on_session_lost(1, DisconnectReason::TransportClose);
        assert_eq!(mgr.tracked_sessions(), 1);

        mgr.drop_session(1);
        assert_eq!(mgr.tracked_sessions(), 0);
        assert!(!mgr.is_pending(1));
        assert_eq!(mgr.open_orders(1), 0);
    }

    #[test]
    fn zero_grace_cancels_immediately() {
        let mut mgr = CancelOnDisconnectManager::new(Duration::from_millis(0));
        mgr.register_session(1, true);
        mgr.register(1, 100);

        mgr.on_session_lost(1, DisconnectReason::TransportClose);
        // Small sleep to guarantee the deadline is in the past even on
        // fast machines where Instant::now resolution matters.
        std::thread::sleep(Duration::from_millis(1));
        let pending = mgr.poll_due_cancels();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn disconnect_reason_audit_codes_are_stable() {
        assert_eq!(
            DisconnectReason::TransportClose.as_code(),
            "session_lost:transport_close"
        );
        assert_eq!(
            DisconnectReason::PeerTimeout.as_code(),
            "session_lost:peer_timeout"
        );
        assert_eq!(
            DisconnectReason::ExplicitTerminate.as_code(),
            "session_lost:explicit_terminate"
        );
    }

    #[test]
    fn unknown_session_is_noop() {
        let mut mgr = CancelOnDisconnectManager::new(Duration::from_secs(5));
        // No register_session called.
        assert!(!mgr.on_session_lost(42, DisconnectReason::TransportClose));
        assert!(!mgr.on_session_reconnected(42));
        assert_eq!(mgr.open_orders(42), 0);
        assert!(mgr.poll_due_cancels().is_empty());
    }

    // ─── End-to-end: Session + Manager + OrderBook ───────────
    //
    // Simulates: client negotiates COD, submits two orders; network
    // partition → session lost; grace elapses; manager issues cancellations;
    // order book reflects the cancel. Exactly the scenario the task #3
    // description calls out.

    #[test]
    fn e2e_negotiated_cod_actually_cancels_resting_orders() {
        use crate::messages::NewOrderSingleCore;
        use crate::orderbook::OrderBook;
        use crate::session::{Session, SessionFlags};
        use crate::types::{Decimal, OrderType, Side, TimeInForce};

        let session_id = 0xABCD_EF01;

        // Client side — request COD in Negotiate.
        let mut client = Session::new(session_id);
        client.request_flags(SessionFlags::CANCEL_ON_DISCONNECT);

        // Drive a minimal handshake so the server Session captures the flag.
        let mut buf = [0u8; 256];
        let n = client.build_negotiate(&mut buf, [0; 32]).unwrap();

        let hdr_size = crate::header::FullHeader::SIZE;
        let neg = crate::session::NegotiateCore::from_bytes(&buf[hdr_size..n]);

        let mut server = Session::new(session_id);
        server.handle_negotiate(neg).unwrap();
        // Server accepts the flag unchanged.
        let mut srv_buf = [0u8; 256];
        let m = server.build_negotiate_response(&mut srv_buf, true, 0, [0; 32]).unwrap();
        let resp = crate::session::NegotiateResponseCore::from_bytes(&srv_buf[hdr_size..m]);
        client.handle_negotiate_response(resp).unwrap();

        assert!(server.cancel_on_disconnect(), "server must record COD");
        assert!(client.cancel_on_disconnect(), "client must record COD");

        // ── Submit two resting orders ─────────────────────────
        let mut book = OrderBook::new(1);
        let order1 = NewOrderSingleCore {
            order_id: 1001,
            client_order_id: 77,
            instrument_id: 1,
            side: Side::Buy as u8,
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(99.0),
            quantity: Decimal::from_f64(10.0),
            stop_price: Decimal::NULL,
        };
        let order2 = NewOrderSingleCore {
            order_id: 1002,
            client_order_id: 78,
            instrument_id: 1,
            side: Side::Sell as u8,
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(101.0),
            quantity: Decimal::from_f64(5.0),
            stop_price: Decimal::NULL,
        };
        let _ = book.submit(&order1);
        let _ = book.submit(&order2);
        assert_eq!(book.order_count(), 2);

        // ── Register with the manager ─────────────────────────
        let (clock, now_fn) = mock_clock();
        let mut mgr =
            CancelOnDisconnectManager::new(Duration::from_secs(5)).with_clock(now_fn);
        mgr.register_session(session_id, server.cancel_on_disconnect());
        mgr.register(session_id, order1.order_id);
        mgr.register(session_id, order2.order_id);

        // ── Simulate network partition: server detects peer timeout ──
        mgr.on_session_lost(session_id, DisconnectReason::PeerTimeout);
        // Inside grace window: book untouched.
        assert_eq!(book.order_count(), 2);

        // ── Grace elapses; manager emits cancellations ───────
        *clock.lock().unwrap() += Duration::from_secs(6);
        let pending = mgr.poll_due_cancels();
        assert_eq!(pending.len(), 2);
        for p in &pending {
            assert_eq!(p.reason, DisconnectReason::PeerTimeout);
            // Matching engine applies the cancel.
            assert!(book.cancel(p.order_id));
        }
        assert_eq!(book.order_count(), 0);
    }
}
