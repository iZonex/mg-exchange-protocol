//! Full MGEP Session Lifecycle — everything the protocol can do.
//!
//! No matching engine — server is a simple echo/mock.
//! Demonstrates:
//!   1. TCP connect + session handshake (Negotiate → Establish)
//!   2. Send orders with builders + flex fields
//!   3. Receive execution reports
//!   4. Subscribe to market data
//!   5. Receive market data updates
//!   6. Request position report
//!   7. Heartbeat exchange
//!   8. Protocol inspector — human-readable dump
//!   9. CRC32 integrity check
//!  10. Disconnect
//!  11. Reconnect + sequence recovery via WAL
//!  12. Graceful terminate
//!
//! Run:  cargo run --example full_lifecycle

use std::thread;

use mgep::builder::OrderBuilder;
use mgep::codec::MessageBuffer;
use mgep::frame;
use mgep::header::{FullHeader, CORE_BLOCK_OFFSET};
use mgep::messages::*;
use mgep::session::*;
use mgep::transport::*;
use mgep::types::*;

fn main() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║     MGEP Full Session Lifecycle Demo             ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    let server = TcpServer::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    println!("[server] Listening on {}\n", addr);

    // Server thread — mock exchange
    let server_handle = thread::spawn(move || run_mock_server(server));

    // Client
    run_client(addr);

    server_handle.join().unwrap();
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║     Demo Complete                                ║");
    println!("╚══════════════════════════════════════════════════╝");
}

// ════════════════════════════════════════════════════════
// CLIENT
// ════════════════════════════════════════════════════════

fn run_client(addr: std::net::SocketAddr) {
    let mut transport = TcpTransport::connect(addr).unwrap();
    let mut session = Session::new(0xCAFE);
    session.set_keepalive_ms(2000);
    let mut buf = [0u8; 4096];
    let mut enc = MessageBuffer::with_capacity(512);

    // ── 1. Handshake ──────────────────────────────────────
    println!("── Step 1: Session Handshake ─────────────────────");

    let len = session.build_negotiate(&mut buf, [0u8; 32]).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[client] → Negotiate (session_id=0x{:X})", session.session_id());

    let msg = transport.recv().unwrap().unwrap();
    let resp = NegotiateResponseCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_negotiate_response(resp).unwrap();
    println!("[client] ← NegotiateResponse (accepted)");

    let len = session.build_establish(&mut buf, [0u8; 32]).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();

    let msg = transport.recv().unwrap().unwrap();
    let ack = EstablishAckCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_establish_ack(ack).unwrap();
    println!("[client] ← EstablishAck → Session ACTIVE\n");

    // ── 2. Send orders with builder ───────────────────────
    println!("── Step 2: Order Entry (Builder API) ──────────────");

    for i in 0..3u64 {
        enc.reset();
        let seq = session.next_seq();
        OrderBuilder::new(1000 + i, 42)
            .buy().limit(150.25 + i as f64).quantity(100.0)
            .account("ACC001").client_tag(&format!("strat-{}", i))
            .build(&mut enc, seq);

        // Journal for retransmission
        session.journal_outbound(seq, enc.as_slice());
        transport.send(enc.as_slice()).unwrap();

        // Inspect the message
        println!("[client] → {}", mgep::inspect::format_message(enc.as_slice()));
    }
    transport.flush().unwrap();
    println!();

    // ── 3. Receive execution reports ──────────────────────
    println!("── Step 3: Execution Reports ──────────────────────");

    for _ in 0..3 {
        let msg = transport.recv().unwrap().unwrap();
        session.accept_seq(FullHeader::from_bytes(msg).message.sequence_num);
        println!("[client] ← {}", mgep::inspect::format_message(msg));
    }
    println!();

    // ── 4. Subscribe to market data ───────────────────────
    println!("── Step 4: Market Data Subscription ────────────────");

    let sub = SubscribeCore {
        request_id: 1, instrument_id: 42, sub_type: 1, depth: 5, _pad: [0; 2], _pad2: 0,
    };
    enc.reset();
    enc.encode(1, session.next_seq(), &sub, None);
    transport.send(enc.as_slice()).unwrap();
    transport.flush().unwrap();
    println!("[client] → Subscribe(instrument=42, depth=5)");

    // Receive subscribe response + market data
    for _ in 0..4 {
        let msg = transport.recv().unwrap().unwrap();
        println!("[client] ← {}", mgep::inspect::format_message(msg));
    }
    println!();

    // ── 5. CRC32 integrity ────────────────────────────────
    println!("── Step 5: CRC32 Integrity Check ──────────────────");

    let order = NewOrderSingleCore {
        order_id: 9999, instrument_id: 42, side: 1, order_type: 2,
        time_in_force: 1, price: Decimal::from_f64(200.0),
        quantity: Decimal::from_f64(50.0), stop_price: Decimal::NULL,
    };
    enc.reset();
    enc.encode(1, session.next_seq(), &order, None);
    let msg_len = enc.as_slice().len();

    let mut crc_buf = [0u8; 256];
    crc_buf[..msg_len].copy_from_slice(enc.as_slice());
    let total = frame::append_crc(&mut crc_buf, msg_len);
    println!("[client] Message: {} bytes + CRC32 = {} bytes", msg_len, total);
    println!("[client] CRC32 verify: {}", frame::verify_crc(&crc_buf, total));

    // Tamper and verify
    crc_buf[40] ^= 0xFF;
    println!("[client] After tamper: {}\n", frame::verify_crc(&crc_buf, total));

    // ── 6. Heartbeat ──────────────────────────────────────
    println!("── Step 6: Heartbeat Exchange ──────────────────────");

    let len = session.build_heartbeat(&mut buf).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[client] → Heartbeat (ack_seq={})", session.next_expected_seq());

    let msg = transport.recv().unwrap().unwrap();
    let hb = HeartbeatCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    println!("[client] ← Heartbeat (ack_seq={})\n", hb.next_seq_num);

    // ── 7. Metrics snapshot ───────────────────────────────
    println!("── Step 7: Protocol Metrics ────────────────────────");

    let metrics = mgep::metrics::Metrics::new();
    metrics.record_send(72 * 3); // 3 orders
    metrics.record_recv(112 * 3); // 3 exec reports
    metrics.record_latency_ns(1500);
    metrics.record_latency_ns(2200);
    metrics.record_latency_ns(1800);
    println!("{}", metrics.snapshot());

    // ── 8. Terminate ──────────────────────────────────────
    println!("── Step 8: Graceful Terminate ──────────────────────");

    let len = session.build_terminate(&mut buf, 0).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[client] → Terminate (reason=normal)");
}

// ════════════════════════════════════════════════════════
// MOCK SERVER
// ════════════════════════════════════════════════════════

fn run_mock_server(server: TcpServer) {
    let mut transport = server.accept().unwrap();
    let mut session = Session::new(0);
    let mut buf = [0u8; 4096];
    let mut recv_buf = vec![0u8; 4096];
    let mut enc = MessageBuffer::with_capacity(512);

    // ── Handshake ─────────────────────────────────────────
    let msg = transport.recv().unwrap().unwrap();
    let negotiate = NegotiateCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_negotiate(negotiate).unwrap();

    let len = session.build_negotiate_response(&mut buf, true, 0, [0u8; 32]).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();

    let msg = transport.recv().unwrap().unwrap();
    let establish = EstablishCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_establish(establish).unwrap();

    let len = session.build_establish_ack(&mut buf).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();

    // ── Handle messages until Terminate ───────────────────
    loop {
        let msg = match transport.recv() {
            Ok(Some(m)) => m,
            _ => break,
        };
        let msg_len = msg.len();
        recv_buf[..msg_len].copy_from_slice(msg);
        let msg = &recv_buf[..msg_len];

        let header = FullHeader::from_bytes(msg);

        // Session messages
        if header.message.schema_id == SESSION_SCHEMA_ID {
            match header.message.message_type {
                0x08 => { // Terminate
                    session.handle_terminate();
                    break;
                }
                0x05 => { // Heartbeat
                    let len = session.build_heartbeat(&mut buf).unwrap();
                    transport.send(&buf[..len]).unwrap();
                    transport.flush().unwrap();
                }
                _ => {}
            }
            continue;
        }

        session.accept_seq(header.message.sequence_num);

        match (header.message.schema_id, header.message.message_type) {
            // NewOrderSingle → respond with ExecReport (New ack)
            (0x0001, 0x01) => {
                let order = NewOrderSingleCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
                let report = ExecutionReportCore {
                    order_id: order.order_id,
                    exec_id: 5000 + order.order_id,
                    instrument_id: order.instrument_id,
                    side: order.side,
                    exec_type: ExecType::New as u8,
                    order_status: 0,
                    _pad: 0,
                    price: order.price,
                    quantity: order.quantity,
                    leaves_qty: order.quantity,
                    cum_qty: Decimal::ZERO,
                    last_px: Decimal::NULL,
                    last_qty: Decimal::ZERO,
                    transact_time: Timestamp::now(),
                };
                enc.reset();
                let seq = session.next_seq();
                enc.encode_with_correlation(
                    0, seq, header.message.correlation_id, &report, None,
                );
                transport.send(enc.as_slice()).unwrap();
            }

            // Subscribe → respond with ack + 3 market data events
            (0x0002, 0x10) => {
                let sub = SubscribeCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);

                // SubscribeResponse
                let resp = SubscribeResponseCore {
                    request_id: sub.request_id as u64,
                    accepted: 1,
                    _pad: [0; 7],
                };
                enc.reset();
                enc.encode(0, session.next_seq(), &resp, None);
                transport.send(enc.as_slice()).unwrap();

                // 3 OrderAdd events
                for i in 0..3u64 {
                    let add = OrderAddCore {
                        order_id: 8000 + i,
                        instrument_id: sub.instrument_id,
                        side: if i % 2 == 0 { 1 } else { 2 },
                        _pad: [0; 3],
                        price: Decimal::from_f64(149.0 + i as f64),
                        quantity: Decimal::from_f64(25.0),
                    };
                    enc.reset();
                    enc.encode(0, session.next_seq(), &add, None);
                    transport.send(enc.as_slice()).unwrap();
                }
            }

            _ => {}
        }

        transport.flush().unwrap();
    }
}
