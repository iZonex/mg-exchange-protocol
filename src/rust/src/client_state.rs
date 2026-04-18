//! Client-side state management for trading terminals.
//!
//! # Why this exists
//!
//! Terminal vendors don't implement wire protocols from scratch — they
//! build on top of a client library that gives them:
//!
//! * **An `OrderManager`** that tracks every order's lifecycle as a
//!   state machine: PendingNew → New → (PartiallyFilled → Filled ∨
//!   Canceled ∨ Rejected). Applies `ExecutionReport` to the right order,
//!   keeps `leaves_qty` / `cum_qty` accurate.
//! * **A `PositionTracker`** that maintains net position + average
//!   price + realized P&L from the fill stream.
//! * **A `SubscriptionManager`** that remembers what the user subscribed
//!   to so the client can auto-resubscribe after a reconnect (when the
//!   server has forgotten).
//! * **An `OrderBookMirror`** that applies market-data updates to a
//!   local book view and handles snapshot-stitching.
//!
//! Before this module, every terminal vendor would have to build these
//! themselves. FIX ships OrderManager out of the box (QuickFIX,
//! OnixS) — it's table stakes.
//!
//! None of this is tied to the wire: the types are pure value structs
//! driven by the `ExecutionReport` / `Trade` / `OrderAdd` etc. cores.
//! The terminal's event loop pumps inbound messages through them.

use std::collections::HashMap;

use crate::messages::ExecutionReportCore;
use crate::types::{Decimal, ExecType, Side};

// ─── Order state machine ─────────────────────────────────────

/// Tracked state of a submitted order. Transitions are driven by the
/// server's `ExecutionReport` stream. The `Pending*` variants are
/// client-local — they cover the window between "I sent it" and "the
/// server ack'd it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderLifecycle {
    /// Sent, no ack yet.
    PendingNew,
    /// Server ack'd; resting on the book.
    New,
    /// Partially filled; `cum_qty < quantity`.
    PartiallyFilled,
    /// Fully filled; terminal state.
    Filled,
    /// Cancel requested but not yet confirmed.
    PendingCancel,
    /// Canceled by client or by server (incl. COD); terminal state.
    Canceled,
    /// Replace requested but not yet confirmed.
    PendingReplace,
    /// Server rejected the submission; terminal state.
    Rejected,
    /// Expired (GTD / IOC / FOK unfilled). Terminal state.
    Expired,
}

impl OrderLifecycle {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Filled | Self::Canceled | Self::Rejected | Self::Expired)
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::PendingNew
                | Self::New
                | Self::PartiallyFilled
                | Self::PendingCancel
                | Self::PendingReplace
        )
    }
}

/// Full client-side view of an order.
#[derive(Debug, Clone, Copy)]
pub struct TrackedOrder {
    pub order_id: u64,
    pub client_order_id: u64,
    pub instrument_id: u32,
    pub side: Side,
    pub quantity: Decimal,
    pub price: Decimal,
    pub leaves_qty: Decimal,
    pub cum_qty: Decimal,
    pub avg_fill_price: Decimal,
    pub state: OrderLifecycle,
}

impl TrackedOrder {
    fn new(order_id: u64, client_order_id: u64, instrument_id: u32, side: Side, quantity: Decimal, price: Decimal) -> Self {
        Self {
            order_id,
            client_order_id,
            instrument_id,
            side,
            quantity,
            price,
            leaves_qty: quantity,
            cum_qty: Decimal::ZERO,
            avg_fill_price: Decimal::NULL,
            state: OrderLifecycle::PendingNew,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderManagerError {
    /// Got an ExecutionReport for an order we don't know about.
    UnknownOrder { order_id: u64 },
    /// An illegal state transition was requested (e.g. Reject an already-Filled order).
    IllegalTransition { from: OrderLifecycle, attempt: &'static str },
}

/// Keeps a consistent view of every order the client has submitted.
///
/// Intended usage:
/// ```ignore
/// let mut om = OrderManager::new();
/// om.on_submit(order_core);               // before send
/// conn.send(order_bytes)?;
/// // ...
/// om.on_execution_report(er_core)?;       // after recv
/// ```
#[derive(Debug, Default)]
pub struct OrderManager {
    /// Primary index: server-assigned order id (populated once the
    /// initial ack arrives).
    by_server_id: HashMap<u64, TrackedOrder>,
    /// Secondary index: pre-ack lookup by `client_order_id`.
    by_client_id: HashMap<u64, u64>, // client_order_id → server_order_id
    /// Orders with `server_order_id == 0` (not yet ack'd).
    pending: HashMap<u64, TrackedOrder>, // client_order_id → TrackedOrder
}

impl OrderManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an order at submission time (before the server ack).
    pub fn on_submit(
        &mut self,
        client_order_id: u64,
        instrument_id: u32,
        side: Side,
        quantity: Decimal,
        price: Decimal,
    ) {
        let order = TrackedOrder::new(0, client_order_id, instrument_id, side, quantity, price);
        self.pending.insert(client_order_id, order);
    }

    /// Apply an incoming `ExecutionReport`. Handles first-ack promotion
    /// from `pending` into `by_server_id`, fill accumulation, and
    /// terminal-state transitions.
    pub fn on_execution_report(&mut self, er: &ExecutionReportCore) -> Result<TrackedOrder, OrderManagerError> {
        // Resolve which tracked order this relates to.
        let mut order = if let Some(o) = self.by_server_id.get(&er.order_id).copied() {
            o
        } else if er.client_order_id != 0 {
            // First ack: promote from pending.
            match self.pending.remove(&er.client_order_id) {
                Some(mut o) => {
                    o.order_id = er.order_id;
                    self.by_client_id.insert(er.client_order_id, er.order_id);
                    o
                }
                None => {
                    // Unsolicited ack — could be COD-initiated cancel of
                    // an order we never submitted. Attempt the ClOrdID
                    // index; otherwise surface.
                    return Err(OrderManagerError::UnknownOrder { order_id: er.order_id });
                }
            }
        } else {
            return Err(OrderManagerError::UnknownOrder { order_id: er.order_id });
        };

        let exec_type = ExecType::from_u8(er.exec_type);
        match exec_type {
            Some(ExecType::New) => {
                order.state = OrderLifecycle::New;
            }
            Some(ExecType::PartialFill) => {
                // Update cumulative + avg fill.
                order.cum_qty = er.cum_qty;
                order.leaves_qty = er.leaves_qty;
                if !er.last_px.is_null() && !er.last_qty.is_null() && er.last_qty.0 > 0 {
                    order.avg_fill_price = compute_avg_fill(
                        order.avg_fill_price,
                        order.cum_qty.0 - er.last_qty.0, // previous cum
                        er.last_px,
                        er.last_qty,
                    );
                }
                order.state = OrderLifecycle::PartiallyFilled;
            }
            Some(ExecType::Fill) => {
                order.cum_qty = er.cum_qty;
                order.leaves_qty = Decimal::ZERO;
                if !er.last_px.is_null() && !er.last_qty.is_null() && er.last_qty.0 > 0 {
                    order.avg_fill_price = compute_avg_fill(
                        order.avg_fill_price,
                        order.cum_qty.0 - er.last_qty.0,
                        er.last_px,
                        er.last_qty,
                    );
                }
                order.state = OrderLifecycle::Filled;
            }
            Some(ExecType::Canceled) => order.state = OrderLifecycle::Canceled,
            Some(ExecType::Replaced) => order.state = OrderLifecycle::New,
            Some(ExecType::Rejected) => order.state = OrderLifecycle::Rejected,
            Some(ExecType::Expired) => order.state = OrderLifecycle::Expired,
            _ => {}
        }

        self.by_server_id.insert(er.order_id, order);
        Ok(order)
    }

    pub fn on_pending_cancel(&mut self, server_order_id: u64) -> Result<(), OrderManagerError> {
        match self.by_server_id.get_mut(&server_order_id) {
            Some(o) => {
                if o.state.is_terminal() {
                    return Err(OrderManagerError::IllegalTransition {
                        from: o.state,
                        attempt: "pending_cancel",
                    });
                }
                o.state = OrderLifecycle::PendingCancel;
                Ok(())
            }
            None => Err(OrderManagerError::UnknownOrder { order_id: server_order_id }),
        }
    }

    pub fn get(&self, server_order_id: u64) -> Option<&TrackedOrder> {
        self.by_server_id.get(&server_order_id)
    }

    pub fn get_by_client_id(&self, client_order_id: u64) -> Option<&TrackedOrder> {
        self.by_client_id
            .get(&client_order_id)
            .and_then(|id| self.by_server_id.get(id))
            .or_else(|| self.pending.get(&client_order_id))
    }

    /// Iterate all live (non-terminal) orders — for UI rendering.
    pub fn live_orders(&self) -> impl Iterator<Item = &TrackedOrder> + '_ {
        self.by_server_id
            .values()
            .filter(|o| o.state.is_live())
            .chain(self.pending.values().filter(|o| o.state.is_live()))
    }

    pub fn len(&self) -> usize {
        self.by_server_id.len() + self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn compute_avg_fill(
    current_avg: Decimal,
    previous_cum: i64,
    last_px: Decimal,
    last_qty: Decimal,
) -> Decimal {
    if previous_cum <= 0 {
        return last_px;
    }
    // new_avg = (current_avg * prev_cum + last_px * last_qty) / (prev_cum + last_qty)
    let num = (current_avg.0 as i128 * previous_cum as i128
        + last_px.0 as i128 * last_qty.0 as i128)
        / Decimal::SCALE as i128;
    let den = (previous_cum + last_qty.0) as i128;
    if den == 0 {
        return last_px;
    }
    Decimal((num * Decimal::SCALE as i128 / den) as i64)
}

// ─── Position tracker ────────────────────────────────────────

/// Running position and P&L for one (account, instrument) pair.
#[derive(Debug, Clone, Copy)]
pub struct Position {
    pub net_qty: Decimal,
    pub avg_cost: Decimal,
    pub realized_pnl: Decimal,
}

impl Default for Position {
    fn default() -> Self {
        Self {
            net_qty: Decimal::ZERO,
            avg_cost: Decimal::ZERO,
            realized_pnl: Decimal::ZERO,
        }
    }
}

/// Pure-state position tracker driven by a fill stream. Terminal vendors
/// plug it into the `OrderManager` output or directly off `Trade`
/// messages, depending on whether they care about post-trade captures.
#[derive(Debug, Default)]
pub struct PositionTracker {
    positions: HashMap<u32, Position>,
}

impl PositionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a fill. `side` is the client's side of the fill.
    pub fn on_fill(&mut self, instrument_id: u32, side: Side, price: Decimal, quantity: Decimal) {
        let pos = self.positions.entry(instrument_id).or_default();
        let signed_qty = match side {
            Side::Buy => quantity.0,
            Side::Sell => -quantity.0,
        };

        if pos.net_qty.0 == 0 {
            // Opening position — avg_cost = fill price.
            pos.net_qty = Decimal(signed_qty);
            pos.avg_cost = price;
            return;
        }

        let same_side = (pos.net_qty.0 > 0 && signed_qty > 0)
            || (pos.net_qty.0 < 0 && signed_qty < 0);
        if same_side {
            // Accumulate — weighted-average cost update.
            let new_qty = pos.net_qty.0 + signed_qty;
            let num = (pos.avg_cost.0 as i128 * pos.net_qty.0.abs() as i128
                + price.0 as i128 * signed_qty.abs() as i128)
                / Decimal::SCALE as i128;
            pos.avg_cost = Decimal(
                (num * Decimal::SCALE as i128 / new_qty.unsigned_abs() as i128) as i64,
            );
            pos.net_qty = Decimal(new_qty);
            return;
        }

        // Closing (or flipping) — realize P&L on the closing portion.
        let closing_qty = signed_qty.unsigned_abs().min(pos.net_qty.0.unsigned_abs()) as i64;
        let direction = pos.net_qty.0.signum();
        // Long close: (sell_price - avg_cost) * qty. Short close: (avg_cost - buy_price) * qty.
        let pnl_per_unit = if direction > 0 {
            price.0 - pos.avg_cost.0
        } else {
            pos.avg_cost.0 - price.0
        };
        let pnl = (pnl_per_unit as i128 * closing_qty as i128 / Decimal::SCALE as i128) as i64;
        pos.realized_pnl = Decimal(pos.realized_pnl.0 + pnl);

        let new_net = pos.net_qty.0 + signed_qty;
        if new_net == 0 {
            pos.net_qty = Decimal::ZERO;
            pos.avg_cost = Decimal::ZERO;
        } else if new_net.signum() != direction {
            // Flipped to the other side — remaining qty opens a new position.
            pos.net_qty = Decimal(new_net);
            pos.avg_cost = price;
        } else {
            // Partial close — avg_cost unchanged.
            pos.net_qty = Decimal(new_net);
        }
    }

    pub fn get(&self, instrument_id: u32) -> Position {
        self.positions.get(&instrument_id).copied().unwrap_or_default()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u32, &Position)> {
        self.positions.iter()
    }
}

// ─── Subscription manager ────────────────────────────────────

/// Remembers what the client has subscribed to so it can auto-resume
/// after a reconnect. The server forgets subscriptions when a session
/// dies; this module bridges the gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Subscription {
    pub instrument_id: u32,
    /// Encoded as `SubscriptionType` from `messages.rs`.
    pub sub_type: u8,
    pub depth: u32,
}

#[derive(Debug, Default)]
pub struct SubscriptionManager {
    active: std::collections::HashSet<Subscription>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, sub: Subscription) -> bool {
        self.active.insert(sub)
    }

    pub fn remove(&mut self, sub: &Subscription) -> bool {
        self.active.remove(sub)
    }

    pub fn contains(&self, sub: &Subscription) -> bool {
        self.active.contains(sub)
    }

    /// All remembered subscriptions. Call on `Connection::on_reconnect`
    /// to reissue them to the freshly established session.
    pub fn all(&self) -> impl Iterator<Item = &Subscription> {
        self.active.iter()
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn clear(&mut self) {
        self.active.clear();
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Timestamp;

    fn mk_er(
        order_id: u64,
        client_order_id: u64,
        exec_type: ExecType,
        cum_qty: f64,
        leaves_qty: f64,
        last_px: Option<f64>,
        last_qty: Option<f64>,
    ) -> ExecutionReportCore {
        ExecutionReportCore {
            order_id,
            client_order_id,
            exec_id: 1,
            instrument_id: 1,
            side: Side::Buy as u8,
            exec_type: exec_type as u8,
            order_status: 0,
            _pad: 0,
            price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(10.0),
            leaves_qty: Decimal::from_f64(leaves_qty),
            cum_qty: Decimal::from_f64(cum_qty),
            last_px: last_px.map(Decimal::from_f64).unwrap_or(Decimal::NULL),
            last_qty: last_qty.map(Decimal::from_f64).unwrap_or(Decimal::NULL),
            transact_time: Timestamp::from_nanos(1_700_000_000_000_000_000),
        }
    }

    #[test]
    fn lifecycle_transitions_via_exec_reports() {
        let mut om = OrderManager::new();
        om.on_submit(500, 1, Side::Buy, Decimal::from_f64(10.0), Decimal::from_f64(100.0));
        assert!(om.get_by_client_id(500).unwrap().state == OrderLifecycle::PendingNew);

        // Server ack.
        let new = mk_er(1000, 500, ExecType::New, 0.0, 10.0, None, None);
        let o = om.on_execution_report(&new).unwrap();
        assert_eq!(o.state, OrderLifecycle::New);
        assert_eq!(o.order_id, 1000);

        // Partial fill.
        let pf = mk_er(1000, 500, ExecType::PartialFill, 4.0, 6.0, Some(100.0), Some(4.0));
        let o = om.on_execution_report(&pf).unwrap();
        assert_eq!(o.state, OrderLifecycle::PartiallyFilled);
        assert_eq!(o.cum_qty, Decimal::from_f64(4.0));
        assert_eq!(o.leaves_qty, Decimal::from_f64(6.0));

        // Full fill.
        let full = mk_er(1000, 500, ExecType::Fill, 10.0, 0.0, Some(100.5), Some(6.0));
        let o = om.on_execution_report(&full).unwrap();
        assert_eq!(o.state, OrderLifecycle::Filled);
        assert!(o.state.is_terminal());
        // Avg fill = (100 * 4 + 100.5 * 6) / 10 = 100.3
        assert!((o.avg_fill_price.to_f64() - 100.3).abs() < 0.001);
    }

    #[test]
    fn unsolicited_ack_surfaces_error() {
        let mut om = OrderManager::new();
        let er = mk_er(999, 0, ExecType::Canceled, 0.0, 0.0, None, None);
        let err = om.on_execution_report(&er).unwrap_err();
        assert!(matches!(err, OrderManagerError::UnknownOrder { order_id: 999 }));
    }

    #[test]
    fn live_orders_excludes_terminal() {
        let mut om = OrderManager::new();
        om.on_submit(1, 1, Side::Buy, Decimal::from_f64(1.0), Decimal::from_f64(10.0));
        om.on_submit(2, 1, Side::Buy, Decimal::from_f64(1.0), Decimal::from_f64(10.0));

        let er_1 = mk_er(100, 1, ExecType::New, 0.0, 1.0, None, None);
        om.on_execution_report(&er_1).unwrap();
        let er_2 = mk_er(200, 2, ExecType::Rejected, 0.0, 0.0, None, None);
        om.on_execution_report(&er_2).unwrap();

        let live: Vec<_> = om.live_orders().collect();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].order_id, 100);
    }

    #[test]
    fn position_tracker_accumulates_long() {
        let mut pt = PositionTracker::new();
        pt.on_fill(1, Side::Buy, Decimal::from_f64(100.0), Decimal::from_f64(10.0));
        pt.on_fill(1, Side::Buy, Decimal::from_f64(102.0), Decimal::from_f64(10.0));
        let p = pt.get(1);
        assert_eq!(p.net_qty, Decimal::from_f64(20.0));
        // Avg cost = (100 * 10 + 102 * 10) / 20 = 101.
        assert!((p.avg_cost.to_f64() - 101.0).abs() < 0.001);
        assert_eq!(p.realized_pnl, Decimal::ZERO);
    }

    #[test]
    fn position_tracker_realizes_pnl_on_close() {
        let mut pt = PositionTracker::new();
        pt.on_fill(1, Side::Buy, Decimal::from_f64(100.0), Decimal::from_f64(10.0));
        // Close at higher price → realize profit.
        pt.on_fill(1, Side::Sell, Decimal::from_f64(105.0), Decimal::from_f64(10.0));
        let p = pt.get(1);
        assert_eq!(p.net_qty, Decimal::ZERO);
        // P&L = (105 - 100) * 10 = 50.
        assert!((p.realized_pnl.to_f64() - 50.0).abs() < 0.01);
    }

    #[test]
    fn position_tracker_flips_and_opens_new() {
        let mut pt = PositionTracker::new();
        pt.on_fill(1, Side::Buy, Decimal::from_f64(100.0), Decimal::from_f64(5.0));
        // Sell 10 — closes the 5 long + opens 5 short at 110.
        pt.on_fill(1, Side::Sell, Decimal::from_f64(110.0), Decimal::from_f64(10.0));
        let p = pt.get(1);
        assert_eq!(p.net_qty, Decimal::from_f64(-5.0));
        assert_eq!(p.avg_cost, Decimal::from_f64(110.0));
        // Realized = (110 - 100) * 5 = 50 on the closing.
        assert!((p.realized_pnl.to_f64() - 50.0).abs() < 0.01);
    }

    #[test]
    fn subscription_manager_round_trip() {
        let mut sm = SubscriptionManager::new();
        let sub = Subscription { instrument_id: 42, sub_type: 1, depth: 0 };
        assert!(sm.add(sub));
        assert!(!sm.add(sub), "duplicate add must return false");
        assert!(sm.contains(&sub));
        assert_eq!(sm.len(), 1);

        assert!(sm.remove(&sub));
        assert!(!sm.contains(&sub));
    }

    #[test]
    fn subscription_manager_replay_on_reconnect() {
        let mut sm = SubscriptionManager::new();
        for id in [1u32, 42, 99] {
            sm.add(Subscription { instrument_id: id, sub_type: 1, depth: 10 });
        }
        // Replay after reconnect — terminal iterates and re-subscribes.
        let replayed: Vec<_> = sm.all().map(|s| s.instrument_id).collect();
        assert_eq!(replayed.len(), 3);
    }

    #[test]
    fn order_lifecycle_helpers() {
        assert!(OrderLifecycle::Filled.is_terminal());
        assert!(OrderLifecycle::Rejected.is_terminal());
        assert!(!OrderLifecycle::New.is_terminal());
        assert!(OrderLifecycle::PartiallyFilled.is_live());
        assert!(OrderLifecycle::PendingCancel.is_live());
        assert!(!OrderLifecycle::Canceled.is_live());
    }
}
