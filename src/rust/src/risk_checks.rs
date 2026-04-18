//! Pre-trade risk checks.
//!
//! # Why this exists
//!
//! The matching engine is the last line of defense, not the first. Before
//! an order reaches the book, a regulated venue MUST apply pre-trade risk
//! controls — **SEC Rule 15c3-5** (US), **MiFID II RTS 6 Art. 17** (EU),
//! **CFTC Reg AT**. Participants and clearing brokers rely on these to
//! bound their liability; without them, a misconfigured algo or a fat
//! finger dumps millions in bad trades in seconds.
//!
//! Required checks:
//!
//! * **Max notional per order** — any single submission cannot exceed
//!   `price × quantity ≤ limit`.
//! * **Max quantity per order** — independent of price, some instruments
//!   need a hard share-count cap.
//! * **Fat-finger price collar** — order price must lie within `±N%` of
//!   a reference (last trade, mid, or exchange-published reference).
//! * **Position limits** — running net position per (account, instrument)
//!   bounded on both sides.
//! * **Message throttle per account** — separate from L7 rate limit:
//!   counts *accepted* orders, not messages, so a client can't hide
//!   behind rejected submissions.
//! * **Self-trade prevention** — if a submission would cross with the
//!   account's own resting liquidity, the newer side is canceled (or the
//!   older — policy choice).
//! * **Price outside halted book** — if the instrument is halted, no
//!   submission; that is `kill_switch.rs`'s job.
//!
//! Missing any of these on a real venue means regulator denies
//! authorization. This module implements the checks as pure logic so the
//! dispatch layer can consult them on every submission.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::messages::NewOrderSingleCore;
use crate::types::{Decimal, Side};

// ─── Per-instrument reference price ──────────────────────────

/// The venue-published price a collar is measured against. Updated by the
/// matching engine on every trade; a client can also poll it via
/// `MarketStatistics`.
#[derive(Debug, Clone, Copy)]
pub struct ReferencePrice {
    pub price: Decimal,
    /// If `true`, the reference is too stale to be authoritative (no
    /// trades in the last N seconds). Collar checks still apply but the
    /// venue may emit a degraded ClockQuality-style signal.
    pub stale: bool,
}

// ─── Policy ──────────────────────────────────────────────────

/// Risk limits applied to every submission. A single zero / None on any
/// field disables that specific check; if everything is default, only
/// the session-level kill-switch and rate limit run.
#[derive(Debug, Clone, Copy)]
pub struct RiskPolicy {
    /// Max notional value (`price × quantity`) per order. `None` = no cap.
    pub max_notional_per_order: Option<Decimal>,
    /// Max raw share/contract count per order.
    pub max_quantity_per_order: Option<Decimal>,
    /// Max absolute net position per (account, instrument), either side.
    pub max_position: Option<Decimal>,
    /// Collar: order price must be within `collar_bps` basis points of
    /// the reference. 1000 bps = 10%.
    pub collar_bps: Option<u32>,
    /// Rolling-window throttle on ACCEPTED orders per account. Separate
    /// from `rate_limit.rs` which throttles all messages.
    pub max_accepted_orders_per_window: Option<u32>,
    pub accepted_order_window: Duration,
    /// Self-trade prevention: if a submission would match its own
    /// resting order, reject the aggressor (`RejectAggressor`), reject
    /// the resting (`CancelResting`), or disable.
    pub self_trade_prevention: SelfTradePreventionMode,
}

impl Default for RiskPolicy {
    fn default() -> Self {
        Self {
            max_notional_per_order: None,
            max_quantity_per_order: None,
            max_position: None,
            collar_bps: None,
            max_accepted_orders_per_window: None,
            accepted_order_window: Duration::from_secs(1),
            self_trade_prevention: SelfTradePreventionMode::Disabled,
        }
    }
}

impl RiskPolicy {
    /// A reasonable starting policy for a small equity market.
    pub fn conservative_equity() -> Self {
        Self {
            max_notional_per_order: Some(Decimal::from_f64(1_000_000.0)),
            max_quantity_per_order: Some(Decimal::from_f64(100_000.0)),
            max_position: Some(Decimal::from_f64(5_000_000.0)),
            collar_bps: Some(1000), // ±10%
            max_accepted_orders_per_window: Some(100),
            accepted_order_window: Duration::from_secs(1),
            self_trade_prevention: SelfTradePreventionMode::RejectAggressor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTradePreventionMode {
    Disabled,
    RejectAggressor,
    CancelResting,
}

// ─── Outcomes ────────────────────────────────────────────────

/// Why a pre-trade check failed. Stable codes for wire reporting (pair
/// with `BusinessReject.business_reason = 4 /* risk_rejected */` and
/// put the code string in the flex `text` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskReject {
    NotionalExceeded { limit: Decimal, actual: Decimal },
    QuantityExceeded { limit: Decimal, actual: Decimal },
    PositionWouldExceed { limit: Decimal, projected: Decimal },
    PriceOutsideCollar { ref_price: Decimal, collar_bps: u32, order_price: Decimal },
    /// Reference price unavailable (no trades yet, stale, etc.); the
    /// venue refuses new orders until a reference is re-established.
    NoReferencePrice,
    SubmissionThrottle { limit: u32, window: Duration },
    SelfTradeAttempt { resting_order_id: u64 },
}

impl RiskReject {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::NotionalExceeded { .. } => "risk:notional_exceeded",
            Self::QuantityExceeded { .. } => "risk:quantity_exceeded",
            Self::PositionWouldExceed { .. } => "risk:position_exceeded",
            Self::PriceOutsideCollar { .. } => "risk:price_collar",
            Self::NoReferencePrice => "risk:no_reference_price",
            Self::SubmissionThrottle { .. } => "risk:submission_throttle",
            Self::SelfTradeAttempt { .. } => "risk:self_trade",
        }
    }
}

// ─── Checker ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct SubmissionWindow {
    count: u32,
    window_start: Instant,
}

/// Tracks running per-account state and applies the policy on each
/// order. Pure state; no I/O; thread-unsafe (wrap in `Mutex` or shard).
pub struct PreTradeRiskChecker {
    policy: RiskPolicy,
    /// Running net position: positive = long, negative = short.
    positions: HashMap<(u64, u32), Decimal>,
    /// Per-account accepted-order count in the current rolling window.
    throttles: HashMap<u64, SubmissionWindow>,
    /// Per-instrument reference price.
    references: HashMap<u32, ReferencePrice>,
    /// Resting orders by (account, instrument, side) — used for STP.
    /// Values: (order_id, price).
    resting: HashMap<(u64, u32, Side), Vec<(u64, Decimal)>>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl PreTradeRiskChecker {
    pub fn new(policy: RiskPolicy) -> Self {
        Self {
            policy,
            positions: HashMap::new(),
            throttles: HashMap::new(),
            references: HashMap::new(),
            resting: HashMap::new(),
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

    pub fn set_policy(&mut self, policy: RiskPolicy) {
        self.policy = policy;
    }

    /// Update the reference price for an instrument. Called by the
    /// matching engine on every trade.
    pub fn set_reference(&mut self, instrument_id: u32, price: Decimal) {
        self.references.insert(
            instrument_id,
            ReferencePrice { price, stale: false },
        );
    }

    /// Mark the current reference stale (no recent trades). Collar
    /// checks still apply but will reject with `NoReferencePrice` if
    /// `collar_bps` is set and no reference is available.
    pub fn mark_reference_stale(&mut self, instrument_id: u32) {
        if let Some(r) = self.references.get_mut(&instrument_id) {
            r.stale = true;
        }
    }

    /// Run all pre-trade checks against the order. `account_id` is the
    /// authenticated participant; we keep it separate from `session_id`
    /// because one account may have multiple sessions.
    ///
    /// On success, the caller should commit the order by invoking
    /// [`on_accepted`](Self::on_accepted) and (on fill) [`on_fill`].
    pub fn check(&mut self, account_id: u64, order: &NewOrderSingleCore) -> Result<(), RiskReject> {
        // 1. Raw size caps.
        if let Some(limit) = self.policy.max_quantity_per_order
            && order.quantity > limit {
                return Err(RiskReject::QuantityExceeded {
                    limit,
                    actual: order.quantity,
                });
            }
        if let Some(limit) = self.policy.max_notional_per_order {
            // price × quantity. For market orders (price is NULL), the
            // caller must set an implied reference; we skip here if
            // price is not concrete.
            if !order.price.is_null() {
                let notional = Decimal(
                    (order.price.0 as i128 * order.quantity.0 as i128
                        / Decimal::SCALE as i128) as i64,
                );
                if notional > limit {
                    return Err(RiskReject::NotionalExceeded {
                        limit,
                        actual: notional,
                    });
                }
            }
        }

        // 2. Price collar.
        if let Some(collar_bps) = self.policy.collar_bps
            && !order.price.is_null() {
                let reference = self.references.get(&order.instrument_id).copied();
                let reference = match reference {
                    Some(r) if !r.stale => r,
                    _ => return Err(RiskReject::NoReferencePrice),
                };
                let ref_p = reference.price.0;
                let order_p = order.price.0;
                // |order - ref| / ref > collar_bps/10000
                let diff_bps = ((order_p - ref_p).unsigned_abs() as u128 * 10_000u128
                    / ref_p.unsigned_abs() as u128) as u32;
                if diff_bps > collar_bps {
                    return Err(RiskReject::PriceOutsideCollar {
                        ref_price: reference.price,
                        collar_bps,
                        order_price: order.price,
                    });
                }
            }

        // 3. Position limit (projected post-fill).
        if let Some(limit) = self.policy.max_position {
            let side = Side::from_u8(order.side).unwrap_or(Side::Buy);
            let sign = if side == Side::Buy { 1i64 } else { -1i64 };
            let current = self
                .positions
                .get(&(account_id, order.instrument_id))
                .copied()
                .unwrap_or(Decimal::ZERO);
            let projected = Decimal(current.0 + sign * order.quantity.0);
            if projected.0.unsigned_abs() > limit.0.unsigned_abs() {
                return Err(RiskReject::PositionWouldExceed {
                    limit,
                    projected,
                });
            }
        }

        // 4. Submission throttle (accepted orders / window).
        if let Some(limit) = self.policy.max_accepted_orders_per_window {
            let now = (self.now)();
            let entry = self.throttles.entry(account_id).or_insert(SubmissionWindow {
                count: 0,
                window_start: now,
            });
            if now.saturating_duration_since(entry.window_start)
                >= self.policy.accepted_order_window
            {
                entry.count = 0;
                entry.window_start = now;
            }
            if entry.count >= limit {
                return Err(RiskReject::SubmissionThrottle {
                    limit,
                    window: self.policy.accepted_order_window,
                });
            }
        }

        // 5. Self-trade prevention (STP). Only one direction: a buy at
        // price P would cross our own asks at <= P, and vice versa.
        if self.policy.self_trade_prevention != SelfTradePreventionMode::Disabled
            && !order.price.is_null()
        {
            let side = Side::from_u8(order.side).unwrap_or(Side::Buy);
            let opposite = match side {
                Side::Buy => Side::Sell,
                Side::Sell => Side::Buy,
            };
            if let Some(list) = self.resting.get(&(account_id, order.instrument_id, opposite)) {
                for &(rest_id, rest_price) in list {
                    let would_cross = match side {
                        Side::Buy => order.price.0 >= rest_price.0,
                        Side::Sell => order.price.0 <= rest_price.0,
                    };
                    if would_cross {
                        return Err(RiskReject::SelfTradeAttempt {
                            resting_order_id: rest_id,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Commit an accepted order's effects on the state. Caller invokes
    /// this AFTER `check()` succeeds and the order has been queued to
    /// the matching engine.
    pub fn on_accepted(&mut self, account_id: u64, order: &NewOrderSingleCore) {
        // Bump the throttle counter.
        if self.policy.max_accepted_orders_per_window.is_some() {
            let now = (self.now)();
            let entry = self
                .throttles
                .entry(account_id)
                .or_insert(SubmissionWindow { count: 0, window_start: now });
            if now.saturating_duration_since(entry.window_start)
                >= self.policy.accepted_order_window
            {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
        }

        // Track as resting for STP. Market orders don't rest.
        if !order.price.is_null() {
            let side = Side::from_u8(order.side).unwrap_or(Side::Buy);
            self.resting
                .entry((account_id, order.instrument_id, side))
                .or_default()
                .push((order.order_id, order.price));
        }
    }

    /// Update the running position on every fill. `side` is the
    /// account's side of the fill (Buy = account took the ask, Sell =
    /// account gave the ask).
    pub fn on_fill(&mut self, account_id: u64, instrument_id: u32, side: Side, quantity: Decimal) {
        let sign = if side == Side::Buy { 1i64 } else { -1i64 };
        let cur = self
            .positions
            .entry((account_id, instrument_id))
            .or_insert(Decimal::ZERO);
        *cur = Decimal(cur.0 + sign * quantity.0);
    }

    /// Untrack an order that left the book (filled / canceled).
    pub fn on_order_removed(&mut self, account_id: u64, instrument_id: u32, side: Side, order_id: u64) {
        if let Some(list) = self.resting.get_mut(&(account_id, instrument_id, side)) {
            list.retain(|entry: &(u64, Decimal)| entry.0 != order_id);
        }
    }

    pub fn position(&self, account_id: u64, instrument_id: u32) -> Decimal {
        self.positions
            .get(&(account_id, instrument_id))
            .copied()
            .unwrap_or(Decimal::ZERO)
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OrderType, TimeInForce};

    fn mk_order(order_id: u64, side: Side, price: f64, qty: f64) -> NewOrderSingleCore {
        NewOrderSingleCore {
            order_id,
            client_order_id: order_id + 1_000_000,
            instrument_id: 1,
            side: side as u8,
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(price),
            quantity: Decimal::from_f64(qty),
            stop_price: Decimal::NULL,
        }
    }

    #[test]
    fn no_policy_accepts_anything() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy::default());
        let o = mk_order(1, Side::Buy, 1_000_000_000.0, 1_000_000_000.0);
        assert!(c.check(42, &o).is_ok());
    }

    #[test]
    fn notional_cap_rejects_large_orders() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            max_notional_per_order: Some(Decimal::from_f64(100_000.0)),
            ..RiskPolicy::default()
        });
        // 1000 * 200 = 200,000 > 100,000
        let err = c.check(1, &mk_order(1, Side::Buy, 1000.0, 200.0)).unwrap_err();
        assert!(matches!(err, RiskReject::NotionalExceeded { .. }));
        // 1000 * 50 = 50,000 passes
        assert!(c.check(1, &mk_order(2, Side::Buy, 1000.0, 50.0)).is_ok());
    }

    #[test]
    fn quantity_cap_rejects_fat_finger_shares() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            max_quantity_per_order: Some(Decimal::from_f64(1000.0)),
            ..RiskPolicy::default()
        });
        let err = c.check(1, &mk_order(1, Side::Buy, 10.0, 10_000.0)).unwrap_err();
        assert!(matches!(err, RiskReject::QuantityExceeded { .. }));
    }

    #[test]
    fn price_collar_bounds_deviations() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            collar_bps: Some(1000), // ±10%
            ..RiskPolicy::default()
        });
        c.set_reference(1, Decimal::from_f64(100.0));

        assert!(c.check(1, &mk_order(1, Side::Buy, 105.0, 10.0)).is_ok(), "within 10%");
        assert!(c.check(1, &mk_order(2, Side::Buy, 95.0, 10.0)).is_ok(), "within 10% low");

        let err = c.check(1, &mk_order(3, Side::Buy, 120.0, 10.0)).unwrap_err();
        assert!(matches!(err, RiskReject::PriceOutsideCollar { .. }));

        let err = c.check(1, &mk_order(4, Side::Sell, 80.0, 10.0)).unwrap_err();
        assert!(matches!(err, RiskReject::PriceOutsideCollar { .. }));
    }

    #[test]
    fn collar_without_reference_rejects() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            collar_bps: Some(500),
            ..RiskPolicy::default()
        });
        let err = c.check(1, &mk_order(1, Side::Buy, 100.0, 10.0)).unwrap_err();
        assert_eq!(err, RiskReject::NoReferencePrice);
    }

    #[test]
    fn stale_reference_rejects() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            collar_bps: Some(500),
            ..RiskPolicy::default()
        });
        c.set_reference(1, Decimal::from_f64(100.0));
        c.mark_reference_stale(1);
        let err = c.check(1, &mk_order(1, Side::Buy, 100.0, 10.0)).unwrap_err();
        assert_eq!(err, RiskReject::NoReferencePrice);
    }

    #[test]
    fn position_limit_blocks_runaway_accumulation() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            max_position: Some(Decimal::from_f64(100.0)),
            ..RiskPolicy::default()
        });
        // Accumulate 90 long
        c.on_fill(1, 1, Side::Buy, Decimal::from_f64(90.0));
        // Another 20 would project to 110 → reject.
        let err = c.check(1, &mk_order(1, Side::Buy, 10.0, 20.0)).unwrap_err();
        assert!(matches!(err, RiskReject::PositionWouldExceed { .. }));
        // 5 is fine (projects to 95).
        assert!(c.check(1, &mk_order(2, Side::Buy, 10.0, 5.0)).is_ok());
    }

    #[test]
    fn submission_throttle_enforces_per_window() {
        use std::sync::{Arc, Mutex};
        let clock = Arc::new(Mutex::new(Instant::now()));
        let c2 = clock.clone();
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            max_accepted_orders_per_window: Some(3),
            accepted_order_window: Duration::from_secs(1),
            ..RiskPolicy::default()
        })
        .with_clock(move || *c2.lock().unwrap());

        for i in 0..3u64 {
            let o = mk_order(i, Side::Buy, 10.0, 1.0);
            assert!(c.check(1, &o).is_ok());
            c.on_accepted(1, &o);
        }
        // 4th rejects.
        let err = c.check(1, &mk_order(4, Side::Buy, 10.0, 1.0)).unwrap_err();
        assert!(matches!(err, RiskReject::SubmissionThrottle { .. }));

        // After the window elapses, the budget resets.
        *clock.lock().unwrap() += Duration::from_secs(2);
        assert!(c.check(1, &mk_order(5, Side::Buy, 10.0, 1.0)).is_ok());
    }

    #[test]
    fn stp_rejects_self_cross() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            self_trade_prevention: SelfTradePreventionMode::RejectAggressor,
            ..RiskPolicy::default()
        });
        // Account 1 has a resting ask at 101.
        let ask = mk_order(100, Side::Sell, 101.0, 5.0);
        c.on_accepted(1, &ask);

        // Same account now sends a marketable buy at 102 — would cross.
        let err = c.check(1, &mk_order(200, Side::Buy, 102.0, 1.0)).unwrap_err();
        assert!(matches!(err, RiskReject::SelfTradeAttempt { resting_order_id: 100 }));

        // A different account's buy is fine.
        assert!(c.check(2, &mk_order(300, Side::Buy, 102.0, 1.0)).is_ok());
    }

    #[test]
    fn reject_codes_are_stable() {
        assert_eq!(
            RiskReject::NotionalExceeded {
                limit: Decimal::ZERO,
                actual: Decimal::ZERO
            }
            .as_code(),
            "risk:notional_exceeded"
        );
        assert_eq!(RiskReject::NoReferencePrice.as_code(), "risk:no_reference_price");
    }

    #[test]
    fn on_order_removed_releases_stp_slot() {
        let mut c = PreTradeRiskChecker::new(RiskPolicy {
            self_trade_prevention: SelfTradePreventionMode::RejectAggressor,
            ..RiskPolicy::default()
        });
        let ask = mk_order(100, Side::Sell, 101.0, 5.0);
        c.on_accepted(1, &ask);
        c.on_order_removed(1, 1, Side::Sell, 100);
        // Now a self-cross buy is not blocked.
        assert!(c.check(1, &mk_order(200, Side::Buy, 102.0, 1.0)).is_ok());
    }
}
