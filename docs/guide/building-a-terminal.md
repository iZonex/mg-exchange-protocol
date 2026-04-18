# Building a Trading Terminal on MGEP

This guide walks through the steps a terminal vendor takes to build a real
MGEP client. It assumes you have Rust ≥ 1.80 and a venue to talk to — use
the `mgep-sandbox` binary locally if you don't.

## 1. Connect and negotiate

```rust
use std::time::Duration;
use mgep::connection::{Connection, ConnectionConfig};
use mgep::session::SessionFlags;

let cfg = ConnectionConfig {
    session_id: 0xDEADBEEF,
    keepalive_ms: 1_000,
    // Ask the venue to cancel our open orders if the transport drops.
    // Standard practice for any risk-bearing flow.
    session_flags: SessionFlags::CANCEL_ON_DISCONNECT,
    ..Default::default()
};
let mut conn = Connection::connect("venue.example.com:9443", cfg)?;
```

Once `connect` returns, the session is in `Active`. The venue echoes
back the `journal_low_seq_num` in `EstablishAck` — if you ever reconnect
with a seq gap bigger than that, jump straight to snapshot recovery.

## 2. Allocate a correlation ID before every request

```rust
use mgep::correlation::CorrelationIdGenerator;

let corr_gen = CorrelationIdGenerator::new();
let correlation_id = corr_gen.next();           // never zero
```

Correlation IDs let you match the server's response back to your
user-space future/callback. Skipping this is fine for fire-and-forget
messages; for anything interactive (order status, RFQ) you need it.

## 3. Submit an order with ClOrdID idempotency

```rust
use mgep::codec::MessageBuffer;
use mgep::messages::NewOrderSingleCore;
use mgep::types::{Decimal, OrderType, Side, TimeInForce};

let mut client_order_id: u64 = 1;

let order = NewOrderSingleCore {
    order_id: 0,                  // server assigns
    client_order_id,              // MUST be non-zero and unique per session
    instrument_id: 42,
    side: Side::Buy as u8,
    order_type: OrderType::Limit as u8,
    time_in_force: TimeInForce::Day as u16,
    price: Decimal::from_f64(100.50),
    quantity: Decimal::from_f64(10.0),
    stop_price: Decimal::NULL,
};

let seq = conn.session_mut().next_seq();
let mut enc = MessageBuffer::with_capacity(256);
enc.encode_with_correlation(1, seq, correlation_id, &order, None);
conn.send(enc.as_slice())?;
client_order_id += 1;
```

### Retry safety

If `conn.send` times out or the socket closes mid-write, you can
**safely resubmit the same `(client_order_id, order_id)` pair**. The
venue's `IdempotencyStore` will return the original `ExecutionReport`
byte-exact — no duplicate order ever reaches the book.

**Don't** increment `client_order_id` on retry. That creates a new order.

## 4. Manage state with `OrderManager` and `PositionTracker`

```rust
use mgep::client_state::{OrderManager, PositionTracker, SubscriptionManager};
use mgep::messages::ExecutionReportCore;
use mgep::header::FullHeader;

let mut orders = OrderManager::new();
let mut positions = PositionTracker::new();

// On submit — record the pending order:
orders.on_submit(client_order_id, 42, Side::Buy,
                  Decimal::from_f64(10.0), Decimal::from_f64(100.50));

// On each inbound message:
loop {
    let msg = match conn.recv()? {
        Some(m) => m,
        None => continue,
    };
    let hdr = FullHeader::from_bytes(&msg);
    if hdr.message.schema_id == 0x0001
        && hdr.message.message_type == ExecutionReportCore::MESSAGE_TYPE
    {
        let core = ExecutionReportCore::from_bytes(
            &msg[mgep::header::CORE_BLOCK_OFFSET..]);
        let tracked = orders.on_execution_report(core)?;
        // React in UI — state machine transitioned.
        update_ui_order_row(&tracked);

        // Feed the position tracker on fills.
        if core.last_qty.0 > 0 {
            positions.on_fill(core.instrument_id,
                              Side::from_u8(core.side).unwrap(),
                              core.last_px, core.last_qty);
        }
    }
}
```

## 5. Market data: subscribe, handle gaps, recover via snapshot

```rust
use mgep::snapshot::RecoveryCoordinator;

// One coordinator per instrument you're showing.
let mut recovery = RecoveryCoordinator::new(42, /* initial_seq */ 1);

// Feed every real-time market-data message through the coordinator
// BEFORE applying it to your order-book mirror.
let action = recovery.feed_realtime(
    hdr.message.sequence_num,   // wire seq from the header
    &msg,
    /* sender_comp_id */ 1,
    conn.session_mut().next_seq(),
);
match action {
    RecoveryAction::Apply => book_mirror.apply(&msg),
    RecoveryAction::Drop => {}  // duplicate — ignore
    RecoveryAction::Buffer => {} // gap open, wait for snapshot
    RecoveryAction::RequestSnapshot(req_bytes) => {
        conn.send(&req_bytes)?;
    }
    RecoveryAction::Stall => {
        // Buffer overflowed — reconnect and resubscribe.
        reconnect_fully();
    }
}
```

When the `BookSnapshotBegin` / `Level` / `End` stream arrives, feed it
into the coordinator's `on_snapshot_begin` / `_level` / `_end` methods.
The `RecoveryCompletion.replay` list is the real-time buffer, filtered
down to messages the snapshot doesn't already cover — apply them in
order and you're caught up.

## 6. Handle rejects with typed errors

The raw wire reject is a `BusinessReject` with a `u8` reason and a flex
text field. Use `client_errors::parse_business_reject` to get a
pattern-matchable `ClientError`:

```rust
use mgep::client_errors::{parse_business_reject, ClientError};

let err = parse_business_reject(&msg);
match err {
    ClientError::RateLimited { suggested_retry, .. } => {
        // The venue is asking you to back off. Actually back off —
        // don't hammer. `suggested_retry` has a hint.
        std::thread::sleep(suggested_retry);
    }
    ClientError::MarketHalted { scope } => {
        show_banner(format!("Halted: {:?}", scope));
    }
    ClientError::RiskRejected { reason } => {
        // Pre-trade risk (position limit, collar, fat-finger) said no.
        show_user_error(err.user_message());
    }
    ClientError::DuplicateClOrdID => {
        // Your generator allocated the same ID twice. Bug.
    }
    ClientError::CancelRejected { reason } => {
        show_user_error(format!("Cancel: {:?}", reason));
    }
    ClientError::Other { text, .. } => {
        // Unknown reason — log and show the raw text.
        show_user_error(text.unwrap_or_default());
    }
    _ => {}
}
```

`err.is_retryable()` tells you at a glance whether a retry is
appropriate — only `RateLimited` currently.

## 7. Reconnect handling

If `conn.send` returns `io::ErrorKind::ConnectionReset` or your recv
loop stalls beyond keepalive × 3, the session is dead. On reconnect:

1. `Connection::connect` with the **same** `session_id` resumes state.
2. The venue's `EstablishAck` carries the current `next_seq_num` and
   `journal_low_seq_num`. Call `Session::assess_recovery(prev_expected, &ack)`:
   * `InSync` — you're caught up; nothing to do.
   * `CanRetransmit { from_seq, count }` — send a
     `RetransmitRequestCore`; the venue replays the gap.
   * `MustSnapshot { .. }` — the gap is bigger than the journal;
     go through the snapshot flow for every subscription.
3. Replay remembered subscriptions from your `SubscriptionManager`.
4. Orders with `OrderLifecycle::PendingNew` may or may not have reached
   the venue; the `IdempotencyStore` protects you on resubmit if the
   ClOrdID is the same.

## 8. Clock discipline & audit-grade emission

If you're a participant that emits trade reports or regulatory data,
pay attention to `ClockStatus` broadcasts. The venue sends them
periodically and on every quality transition. Gate your own audit
emission on `ClockQuality::RegulatoryGrade`:

```rust
use mgep::clock_discipline::{ClockQuality, ClockStatusCore};

let clock_ok = parsed_status.quality() == ClockQuality::RegulatoryGrade;
if !clock_ok {
    // Buffer non-urgent trade reports; the venue can't legally
    // timestamp them right now.
    queue_for_later(record);
}
```

## 9. Testing against a sandbox

Use `cargo run --bin mgep-sandbox` for a fake venue that:

* accepts any credentials
* fills orders at the midpoint after a random 1–20 ms delay
* emits a `ClockStatus` every second (RegulatoryGrade)
* accepts every `BookSnapshotRequest` with a pre-seeded book

This is not a simulator of market microstructure — it's a wire-level
sandbox so you can exercise your terminal end-to-end without a real
venue.

## 10. What you don't get out of the box

Things terminal vendors typically build on top (out of MGEP scope):

- **Historical data / candles** — fetch elsewhere, MGEP is live-only.
- **Auth beyond HMAC-PSK** — venue-specific (X.509, OAuth2, SAML).
- **Chart rendering** — UI toolkit concern.
- **Algo execution (TWAP/VWAP/implementation shortfall)** — write on
  top of `OrderManager`.
- **FIX gateway** — if you serve FIX clients, put a bridge in front.

## Cheat sheet

| Need | Module |
|---|---|
| Connect to a venue | `connection::Connection` |
| Encode/decode messages | `codec::MessageBuffer` |
| Allocate correlation IDs | `correlation::CorrelationIdGenerator` |
| Track orders | `client_state::OrderManager` |
| Track positions / P&L | `client_state::PositionTracker` |
| Remember subscriptions | `client_state::SubscriptionManager` |
| Typed reject errors | `client_errors::parse_business_reject` |
| Gap-fill / snapshot recovery | `snapshot::RecoveryCoordinator` |
| Clock-discipline gate | `clock_discipline::ClockMonitor` |
