//! `mgep-sandbox` — a wire-level fake venue for terminal development.
//!
//! What it does:
//!
//! * Accepts any credentials (no auth).
//! * Echoes `ExecutionReport { exec_type: New }` for every
//!   `NewOrderSingle` submission, after a configurable random delay.
//! * Implements the idempotency / rate-limit / COD / snapshot provider
//!   hooks so a terminal can exercise the full client-side flow.
//! * Serves book snapshots from a pre-seeded `OrderBook` (two-sided book
//!   at 100 ± N).
//!
//! What it does NOT do:
//!
//! * Simulate microstructure — no real matching, no depth changes,
//!   no time-of-day effects.
//! * Handle encryption (`SecurityLevel::None` only).
//! * Persist state across restarts.
//!
//! Run it with:
//!
//! ```
//! cargo run --bin mgep-sandbox -- --port 9443
//! ```

use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mgep::codec::MessageBuffer;
use mgep::header::{FullHeader, CORE_BLOCK_OFFSET};
use mgep::messages::{
    BookSnapshotRequestCore, ExecutionReportCore, NewOrderSingleCore,
};
use mgep::orderbook::OrderBook;
use mgep::server::{MgepServer, ServerConfig};
use mgep::snapshot::SnapshotGenerator;
use mgep::types::{Decimal, Side, Timestamp};

fn parse_args() -> (String, u16) {
    let args: Vec<String> = env::args().collect();
    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 9443;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                host = args[i + 1].clone();
                i += 2;
            }
            "--port" => {
                port = args[i + 1].parse().unwrap_or(9443);
                i += 2;
            }
            "-h" | "--help" => {
                eprintln!(
                    "mgep-sandbox — fake MGEP venue for terminal dev.\n\n\
                     USAGE:\n  mgep-sandbox [--host HOST] [--port PORT]\n\n\
                     Defaults: 127.0.0.1:9443"
                );
                std::process::exit(0);
            }
            _ => i += 1,
        }
    }
    (host, port)
}

fn main() -> std::io::Result<()> {
    let (host, port) = parse_args();
    let addr = format!("{}:{}", host, port);

    eprintln!("mgep-sandbox v0.2.0 — listening on {}", addr);
    eprintln!("  • No auth required (dev sandbox)");
    eprintln!("  • ExecutionReport returned for every NewOrderSingle");
    eprintln!("  • BookSnapshotRequest served from a pre-seeded book at 100.0");
    eprintln!("  • Ctrl-C to stop\n");

    let config = ServerConfig {
        keepalive_ms: 30_000,
        ..Default::default()
    };
    let mut server = MgepServer::bind(&addr, config)?;

    // Pre-seed a book with resting liquidity around 100.
    let book = Arc::new(Mutex::new(OrderBook::new(1)));
    {
        let mut b = book.lock().unwrap();
        for i in 0..10u64 {
            // Asks
            let ask = NewOrderSingleCore {
                order_id: 1_000 + i,
                client_order_id: 1_000 + i,
                instrument_id: 1,
                side: Side::Sell as u8,
                order_type: mgep::types::OrderType::Limit as u8,
                time_in_force: mgep::types::TimeInForce::Day as u16,
                price: Decimal::from_f64(100.0 + (i + 1) as f64 * 0.10),
                quantity: Decimal::from_f64(100.0),
                stop_price: Decimal::NULL,
            };
            let _ = b.submit(&ask);
            // Bids
            let bid = NewOrderSingleCore {
                order_id: 2_000 + i,
                client_order_id: 2_000 + i,
                instrument_id: 1,
                side: Side::Buy as u8,
                order_type: mgep::types::OrderType::Limit as u8,
                time_in_force: mgep::types::TimeInForce::Day as u16,
                price: Decimal::from_f64(100.0 - (i + 1) as f64 * 0.10),
                quantity: Decimal::from_f64(100.0),
                stop_price: Decimal::NULL,
            };
            let _ = b.submit(&bid);
        }
    }

    // Wire the snapshot provider — handlers never see BookSnapshotRequest.
    let book_clone = book.clone();
    let next_snapshot_id = std::sync::atomic::AtomicU64::new(1);
    server.set_snapshot_provider(Box::new(move |req: &BookSnapshotRequestCore| {
        let b = book_clone.lock().unwrap();
        let sid = next_snapshot_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SnapshotGenerator::default()
            .generate(&b, 0, 1, req.request_id, 1, sid, req.max_levels)
            .ok()
    }));

    // Poll loop: echo ExecutionReport on every NewOrderSingle submission.
    let start = Instant::now();
    let mut next_exec_id: u64 = 1_000_000;
    let mut handler = move |client_id: u64, msg: &[u8]| -> Option<Vec<u8>> {
        if msg.len() < FullHeader::SIZE + NewOrderSingleCore::SIZE {
            return None;
        }
        let hdr = FullHeader::from_bytes(msg);
        if hdr.message.schema_id != 0x0001
            || hdr.message.message_type != NewOrderSingleCore::MESSAGE_TYPE
        {
            return None;
        }
        let core = NewOrderSingleCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
        let exec_id = next_exec_id;
        next_exec_id += 1;
        let er = ExecutionReportCore {
            order_id: core.order_id.max(1_000_000),
            client_order_id: core.client_order_id,
            exec_id,
            instrument_id: core.instrument_id,
            side: core.side,
            exec_type: mgep::types::ExecType::New as u8,
            order_status: 0,
            _pad: 0,
            price: core.price,
            quantity: core.quantity,
            leaves_qty: core.quantity,
            cum_qty: Decimal::ZERO,
            last_px: Decimal::NULL,
            last_qty: Decimal::ZERO,
            transact_time: Timestamp::now(),
        };
        let mut out = MessageBuffer::with_capacity(256);
        out.encode(0, 1, &er, None);
        let elapsed = start.elapsed().as_millis();
        eprintln!(
            "[{:>6}ms] client={} clordid={} order_id={} → ExecReport(New) exec_id={}",
            elapsed, client_id, core.client_order_id, core.order_id, exec_id
        );
        Some(out.as_slice().to_vec())
    };

    loop {
        let _ = server.poll(&mut handler);
        // Drain COD cancels and log — a real venue would also cancel
        // them in its matching engine.
        let pending = server.poll_cancel_on_disconnect();
        for p in pending {
            eprintln!(
                "[sandbox] COD cancel: session={} order_id={} reason={:?}",
                p.session_id, p.order_id, p.reason
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
