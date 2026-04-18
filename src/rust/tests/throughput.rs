#![allow(unused_variables)]
//! Throughput test: measure raw messages/second over TCP.
//!
//! Single client, single server thread. Measures:
//! - Encode throughput (messages/sec)
//! - TCP send+recv throughput (messages/sec)
//! - End-to-end latency distribution

use mgep::codec::MessageBuffer;
use mgep::connection::{Connection, ConnectionConfig};

use mgep::messages::*;
use mgep::server::{MgepServer, ServerConfig};
use mgep::types::*;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn throughput_encode_decode() {
    let order = NewOrderSingleCore {
        order_id: 1, instrument_id: 42, side: 1, order_type: 2,
        client_order_id: 0,
        time_in_force: 1, price: Decimal::from_f64(150.25),
        quantity: Decimal::from_f64(100.0), stop_price: Decimal::NULL,
    };

    let count = 1_000_000u64;
    let mut enc = MessageBuffer::with_capacity(256);

    // Encode throughput
    let start = Instant::now();
    for i in 0..count {
        enc.reset();
        enc.encode(1, i as u64, &order, None);
    }
    let encode_elapsed = start.elapsed();
    let encode_mps = count as f64 / encode_elapsed.as_secs_f64();

    // Decode throughput
    enc.reset();
    enc.encode(1, 1, &order, None);
    let msg = enc.as_slice().to_vec();

    let start = Instant::now();
    for i in 0..count {
        let decoded = MessageBuffer::decode_new_order(&msg);
        std::hint::black_box(decoded.order_id);
    }
    let decode_elapsed = start.elapsed();
    let decode_mps = count as f64 / decode_elapsed.as_secs_f64();

    println!("\n=== Encode/Decode Throughput ===");
    println!("  Encode: {:.2}M msg/sec ({:.1} ns/msg)", encode_mps / 1e6, encode_elapsed.as_nanos() as f64 / count as f64);
    println!("  Decode: {:.2}M msg/sec ({:.1} ns/msg)", decode_mps / 1e6, decode_elapsed.as_nanos() as f64 / count as f64);
}

#[test]
fn throughput_tcp_roundtrip() {
    let server_config = ServerConfig {
        keepalive_ms: 30000,
        ..Default::default()
    };
    let mut server = MgepServer::bind("127.0.0.1:0", server_config).unwrap();
    let addr = server.local_addr().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let server_received = Arc::new(AtomicU64::new(0));
    let server_received2 = server_received.clone();

    let stop2 = stop.clone();
    let server_handle = std::thread::spawn(move || {
        let mut handler = move |_: u64, _: &[u8]| -> Option<Vec<u8>> {
            server_received2.fetch_add(1, Ordering::Relaxed);
            None
        };
        while !stop2.load(Ordering::Relaxed) {
            let _ = server.poll(&mut handler);
        }
    });

    std::thread::sleep(Duration::from_millis(50));

    let config = ConnectionConfig {
        session_id: 1,
        ..Default::default()
    };
    let mut conn = Connection::connect(addr, config).unwrap();

    let count = 100_000u64;
    let mut enc = MessageBuffer::with_capacity(256);

    let start = Instant::now();
    for i in 0..count {
        // Unique ClOrdID per iteration; server's idempotency store would
        // otherwise dedup every submission and the assertion would fail.
        let order = NewOrderSingleCore {
            order_id: i + 1, instrument_id: 42, side: 1, order_type: 2,
            client_order_id: i + 1,
            time_in_force: 1, price: Decimal::from_f64(150.25),
            quantity: Decimal::from_f64(100.0), stop_price: Decimal::NULL,
        };
        enc.reset();
        let seq = conn.session_mut().next_seq();
        enc.encode(1, seq, &order, None);
        conn.send(enc.as_slice()).unwrap();
    }
    let send_elapsed = start.elapsed();

    // Wait for server to process
    let deadline = Instant::now() + Duration::from_secs(10);
    while server_received.load(Ordering::Relaxed) < count {
        std::thread::sleep(Duration::from_millis(10));
        if Instant::now() > deadline {
            break;
        }
    }

    let total_elapsed = start.elapsed();
    let received = server_received.load(Ordering::Relaxed);
    let send_mps = count as f64 / send_elapsed.as_secs_f64();
    let e2e_mps = received as f64 / total_elapsed.as_secs_f64();

    println!("\n=== TCP Throughput ({} messages) ===", count);
    println!("  Send:     {:.2}M msg/sec ({:.1} ns/msg)", send_mps / 1e6, send_elapsed.as_nanos() as f64 / count as f64);
    println!("  Received: {} / {} ({:.1}%)", received, count, received as f64 / count as f64 * 100.0);
    println!("  End-to-end: {:.2}M msg/sec", e2e_mps / 1e6);

    assert!(received >= count * 99 / 100, "should receive at least 99% of messages, got {}/{}", received, count);

    conn.disconnect().unwrap();
    stop.store(true, Ordering::Relaxed);
    server_handle.join().unwrap();
}

#[test]
fn throughput_orderbook() {
    let mut book = mgep::orderbook::OrderBook::new(1);

    let count = 100_000u64;

    // Alternating buy/sell to force matching
    let start = Instant::now();
    for i in 0..count {
        let order = NewOrderSingleCore {
            order_id: i,
            client_order_id: 0,
            instrument_id: 1,
            side: if i % 2 == 0 { 1 } else { 2 },
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(1.0),
            stop_price: Decimal::NULL,
        };
        std::hint::black_box(book.submit(&order));
    }
    let elapsed = start.elapsed();
    let mps = count as f64 / elapsed.as_secs_f64();

    println!("\n=== Orderbook Throughput ({} orders) ===", count);
    println!("  {:.2}M orders/sec ({:.0} ns/order)", mps / 1e6, elapsed.as_nanos() as f64 / count as f64);
    println!("  Book depth: {} bids, {} asks, {} orders", book.bid_levels(), book.ask_levels(), book.order_count());
}
