//! Full MGEP client/server example with session handshake.
//!
//! Demonstrates the complete session lifecycle:
//!   1. TCP connect
//!   2. Negotiate (client → server)
//!   3. NegotiateResponse (server → client)
//!   4. Establish (client → server)
//!   5. EstablishAck (server → client)
//!   6. Application messages (NewOrderSingle → ExecutionReport)
//!   7. Reject on invalid message
//!   8. Heartbeat exchange
//!   9. Terminate (client → server)
//!
//! Run:  cargo run --example client_server

use std::thread;

use mgep::codec::MessageBuffer;
use mgep::header::{FullHeader, CORE_BLOCK_OFFSET};
use mgep::messages::*;
use mgep::session::*;
use mgep::transport::*;
use mgep::types::*;

fn main() {
    println!("=== MGEP Client/Server Demo ===\n");

    let server = TcpServer::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    println!("[server] Listening on {}", addr);

    let server_handle = thread::spawn(move || {
        run_server(server);
    });

    run_client(addr);

    server_handle.join().unwrap();
    println!("\n=== Demo Complete ===");
}

fn run_client(addr: std::net::SocketAddr) {
    let mut transport = TcpTransport::connect(addr).unwrap();
    let mut session = Session::new(0xCAFE_BABE);
    session.set_keepalive_ms(1000);
    session.set_security_level(SecurityLevel::None);

    let mut buf = [0u8; 4096];

    // ── Step 1: Negotiate ────────────────────────────────────
    let len = session.build_negotiate(&mut buf, [0u8; 32]).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[client] → Negotiate (session_id=0x{:X})", session.session_id());

    // ── Step 2: NegotiateResponse ────────────────────────────
    let msg = transport.recv().unwrap().unwrap();
    let header = FullHeader::from_bytes(msg);
    assert_eq!(header.message.schema_id, SESSION_SCHEMA_ID);
    assert_eq!(header.message.message_type, SessionMsgType::NegotiateResponse as u16);
    let resp = NegotiateResponseCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_negotiate_response(resp).unwrap();
    println!("[client] ← NegotiateResponse (accepted, keepalive={}ms)", resp.keepalive_ms);

    // ── Step 3: Establish ────────────────────────────────────
    let len = session.build_establish(&mut buf, [0u8; 32]).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[client] → Establish (next_seq={})", session.next_outbound_seq());

    // ── Step 4: EstablishAck ─────────────────────────────────
    let msg = transport.recv().unwrap().unwrap();
    let header = FullHeader::from_bytes(msg);
    assert_eq!(header.message.message_type, SessionMsgType::EstablishAck as u16);
    let ack = EstablishAckCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_establish_ack(ack).unwrap();
    println!("[client] ← EstablishAck (server next_seq={})", ack.next_seq_num);
    println!("[client] Session ACTIVE\n");

    // ── Step 5: Send trading messages ────────────────────────
    let mut encoder = MessageBuffer::with_capacity(512);
    for i in 0..5u64 {
        let order = NewOrderSingleCore {
            order_id: 1000 + i,
            instrument_id: 42,
            side: if i % 2 == 0 { Side::Buy as u8 } else { Side::Sell as u8 },
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(150.25 + i as f64),
            quantity: Decimal::from_f64(100.0 * (i + 1) as f64),
            stop_price: Decimal::NULL,
        };

        let seq = session.next_seq();
        let mut flex_writer = mgep::flex::FlexWriter::new();
        flex_writer.put_string(1, "ACC001");
        flex_writer.put_string(2, &format!("tag-{}", i));
        let flex_data = flex_writer.build();

        encoder.reset();
        encoder.encode(1, seq, &order, Some(&flex_data));

        // Journal for potential retransmission
        session.journal_outbound(seq, encoder.as_slice());
        transport.send(encoder.as_slice()).unwrap();

        let side_str = if i % 2 == 0 { "BUY" } else { "SELL" };
        println!(
            "[client] → NewOrder seq={} id={} {} {} @ {} qty={}",
            seq, order.order_id, side_str, order.instrument_id,
            order.price, order.quantity
        );
    }
    transport.flush().unwrap();

    // ── Step 6: Receive ExecutionReports + possible Rejects ──
    for _ in 0..5 {
        let msg = transport.recv().unwrap().unwrap();
        let header = FullHeader::from_bytes(msg);
        assert_eq!(header.message.schema_id, 0x0001);

        match header.message.message_type {
            0x05 => {
                let report = ExecutionReportCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
                session.accept_seq(header.message.sequence_num);

                let exec_type = match report.exec_type() {
                    Some(ExecType::New) => "NEW",
                    Some(ExecType::Fill) => "FILL",
                    _ => "???",
                };
                println!(
                    "[client] ← ExecReport seq={} order={} exec={} last_px={} last_qty={}",
                    header.message.sequence_num, report.order_id, exec_type,
                    report.last_px, report.last_qty
                );
            }
            0x10 => {
                let reject = RejectCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
                session.accept_seq(header.message.sequence_num);

                let text = if header.frame.flags.has_flex() {
                    let flex = mgep::flex::FlexReader::new(
                        &msg[CORE_BLOCK_OFFSET + RejectCore::SIZE..],
                    );
                    flex.get_string(1).unwrap_or("").to_string()
                } else {
                    String::new()
                };

                println!(
                    "[client] ← Reject seq={} ref_seq={} reason={} text=\"{}\"",
                    header.message.sequence_num, reject.ref_seq_num,
                    reject.reject_reason, text
                );
            }
            other => {
                println!("[client] ← Unknown msg_type=0x{:02X}", other);
            }
        }
    }

    // ── Step 7: Heartbeat ────────────────────────────────────
    let len = session.build_heartbeat(&mut buf).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("\n[client] → Heartbeat (ack_seq={})", session.next_expected_seq());

    let msg = transport.recv().unwrap().unwrap();
    let header = FullHeader::from_bytes(msg);
    assert_eq!(header.message.message_type, SessionMsgType::Heartbeat as u16);
    let hb = HeartbeatCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    println!("[client] ← Heartbeat (ack_seq={})", hb.next_seq_num);

    // ── Step 8: Terminate ────────────────────────────────────
    let len = session.build_terminate(&mut buf, 0).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[client] → Terminate (reason=normal)");
}

fn run_server(server: TcpServer) {
    let mut transport = server.accept().unwrap();
    let mut session = Session::new(0);
    let mut buf = [0u8; 4096];
    let mut recv_buf = vec![0u8; 4096];
    let mut encoder = MessageBuffer::with_capacity(512);

    // ── Step 1: Negotiate ────────────────────────────────────
    let msg = transport.recv().unwrap().unwrap();
    let header = FullHeader::from_bytes(msg);
    assert_eq!(header.message.schema_id, SESSION_SCHEMA_ID);
    let negotiate = NegotiateCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_negotiate(negotiate).unwrap();
    println!(
        "[server] ← Negotiate (session_id=0x{:X}, keepalive={}ms)",
        negotiate.session_id, negotiate.keepalive_ms
    );

    // ── Step 2: NegotiateResponse ────────────────────────────
    let len = session.build_negotiate_response(&mut buf, true, 0, [0u8; 32]).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[server] → NegotiateResponse (accepted)");

    // ── Step 3: Establish ────────────────────────────────────
    let msg = transport.recv().unwrap().unwrap();
    let header = FullHeader::from_bytes(msg);
    assert_eq!(header.message.message_type, SessionMsgType::Establish as u16);
    let establish = EstablishCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_establish(establish).unwrap();
    println!("[server] ← Establish (client next_seq={})", establish.next_seq_num);

    // ── Step 4: EstablishAck ─────────────────────────────────
    let len = session.build_establish_ack(&mut buf).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[server] → EstablishAck");
    println!("[server] Session ACTIVE\n");

    // ── Step 5: Process orders ───────────────────────────────
    for _ in 0..5 {
        let msg = transport.recv().unwrap().unwrap();
        let msg_len = msg.len();
        recv_buf[..msg_len].copy_from_slice(msg);
        let msg = &recv_buf[..msg_len];

        let header = FullHeader::from_bytes(msg);
        assert_eq!(header.message.schema_id, 0x0001);
        assert_eq!(header.message.message_type, NewOrderSingleCore::MESSAGE_TYPE);

        let order = *NewOrderSingleCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
        let seq_num = header.message.sequence_num;
        session.accept_seq(seq_num);

        let account: String = if header.frame.flags.has_flex() {
            let flex = mgep::flex::FlexReader::new(
                &msg[CORE_BLOCK_OFFSET + NewOrderSingleCore::SIZE..],
            );
            flex.get_string(1).unwrap_or("???").to_string()
        } else {
            "???".to_string()
        };

        let side_str = match order.side() {
            Some(Side::Buy) => "BUY",
            Some(Side::Sell) => "SELL",
            _ => "???",
        };
        println!(
            "[server] ← NewOrder seq={} id={} {} acct={}",
            seq_num, order.order_id, side_str, account
        );

        // Build ExecutionReport using the generic encoder
        let report = ExecutionReportCore {
            order_id: order.order_id,
            exec_id: 5000 + order.order_id,
            instrument_id: order.instrument_id,
            side: order.side,
            exec_type: ExecType::Fill as u8,
            order_status: 2,
            _pad: 0,
            price: order.price,
            quantity: order.quantity,
            leaves_qty: Decimal::ZERO,
            cum_qty: order.quantity,
            last_px: order.price,
            last_qty: order.quantity,
            transact_time: Timestamp::now(),
        };

        let seq = session.next_seq();
        encoder.reset();
        encoder.encode(0, seq, &report, None);
        session.journal_outbound(seq, encoder.as_slice());
        transport.send(encoder.as_slice()).unwrap();
        println!("[server] → ExecReport seq={} FILL order={}", seq, order.order_id);
    }
    transport.flush().unwrap();

    // ── Step 6: Heartbeat ────────────────────────────────────
    let msg = transport.recv().unwrap().unwrap();
    let header = FullHeader::from_bytes(msg);
    assert_eq!(header.message.message_type, SessionMsgType::Heartbeat as u16);
    let hb = HeartbeatCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    println!("\n[server] ← Heartbeat (ack_seq={})", hb.next_seq_num);

    let len = session.build_heartbeat(&mut buf).unwrap();
    transport.send(&buf[..len]).unwrap();
    transport.flush().unwrap();
    println!("[server] → Heartbeat");

    // ── Step 7: Terminate ────────────────────────────────────
    let msg = transport.recv().unwrap().unwrap();
    let header = FullHeader::from_bytes(msg);
    assert_eq!(header.message.message_type, SessionMsgType::Terminate as u16);
    let term = TerminateCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
    session.handle_terminate();
    println!("[server] ← Terminate (reason={})", term.reason);
}
