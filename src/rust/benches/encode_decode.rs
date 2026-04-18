use criterion::{Criterion, black_box, criterion_group, criterion_main};
use mgep::codec::*;
use mgep::flex::FlexWriter;
use mgep::messages::*;
use mgep::types::*;

fn make_order() -> NewOrderSingleCore {
    NewOrderSingleCore {
        order_id: 123456789,
        client_order_id: 0,
        instrument_id: 42,
        side: Side::Buy as u8,
        order_type: OrderType::Limit as u8,
        time_in_force: TimeInForce::IOC as u16,
        price: Decimal::from_f64(150.25),
        quantity: Decimal::from_f64(100.0),
        stop_price: Decimal::NULL,
    }
}

fn bench_encode_core_only(c: &mut Criterion) {
    let order = make_order();
    let mut buffer = MessageBuffer::with_capacity(256);

    c.bench_function("encode_new_order_core", |b| {
        b.iter(|| {
            buffer.reset();
            black_box(buffer.encode_new_order(1, black_box(1), &order, None));
        });
    });
}

fn bench_decode_core_only(c: &mut Criterion) {
    let order = make_order();
    let mut buffer = MessageBuffer::with_capacity(256);
    buffer.encode_new_order(1, 1, &order, None);
    let msg = buffer.as_slice().to_vec();

    c.bench_function("decode_new_order_core", |b| {
        b.iter(|| {
            let decoded = MessageBuffer::decode_new_order(black_box(&msg));
            black_box(decoded.order_id);
            black_box(decoded.price);
        });
    });
}

fn bench_dispatch(c: &mut Criterion) {
    let order = make_order();
    let mut buffer = MessageBuffer::with_capacity(256);
    buffer.encode_new_order(1, 1, &order, None);
    let msg = buffer.as_slice().to_vec();

    c.bench_function("dispatch_message", |b| {
        b.iter(|| {
            let kind = dispatch_message(black_box(&msg));
            match kind {
                MessageKind::NewOrder(o) => black_box(o.order_id),
                _ => unreachable!(),
            };
        });
    });
}

fn bench_full_header_decode(c: &mut Criterion) {
    let order = make_order();
    let mut buffer = MessageBuffer::with_capacity(256);
    buffer.encode_new_order(1, 1, &order, None);
    let msg = buffer.as_slice().to_vec();

    c.bench_function("decode_full_header", |b| {
        b.iter(|| {
            let header = MessageBuffer::decode_full_header(black_box(&msg));
            black_box(header.message.schema_id);
            black_box(header.message.sequence_num);
        });
    });
}

fn bench_encode_with_flex(c: &mut Criterion) {
    let order = make_order();
    let mut flex_writer = FlexWriter::new();
    flex_writer.put_string(1, "ACCOUNT001");
    flex_writer.put_string(2, "client-tag-12345");
    flex_writer.put_decimal(3, Decimal::from_f64(25.0));
    let flex_data = flex_writer.build();
    let mut buffer = MessageBuffer::with_capacity(512);

    c.bench_function("encode_new_order_with_flex", |b| {
        b.iter(|| {
            buffer.reset();
            black_box(buffer.encode_new_order(1, black_box(1), &order, Some(&flex_data)));
        });
    });
}

fn bench_decode_flex_field(c: &mut Criterion) {
    let order = make_order();
    let mut flex_writer = FlexWriter::new();
    flex_writer.put_string(1, "ACCOUNT001");
    flex_writer.put_string(2, "client-tag-12345");
    flex_writer.put_decimal(3, Decimal::from_f64(25.0));
    let flex_data = flex_writer.build();

    let mut buffer = MessageBuffer::with_capacity(512);
    buffer.encode_new_order(1, 1, &order, Some(&flex_data));
    let msg = buffer.as_slice().to_vec();

    c.bench_function("decode_flex_string", |b| {
        b.iter(|| {
            let flex = MessageBuffer::decode_flex(black_box(&msg), NewOrderSingleCore::SIZE).unwrap();
            black_box(flex.get_string(1));
        });
    });
}

fn bench_execution_report_decode(c: &mut Criterion) {
    let report = ExecutionReportCore {
        order_id: 123456789,
        client_order_id: 0,
        exec_id: 987654321,
        instrument_id: 42,
        side: Side::Buy as u8,
        exec_type: ExecType::Fill as u8,
        order_status: 2,
        _pad: 0,
        price: Decimal::from_f64(150.25),
        quantity: Decimal::from_f64(100.0),
        leaves_qty: Decimal::ZERO,
        cum_qty: Decimal::from_f64(100.0),
        last_px: Decimal::from_f64(150.25),
        last_qty: Decimal::from_f64(100.0),
        transact_time: Timestamp::now(),
    };

    // Build a raw message buffer for ExecutionReport.
    // Layout matches codec::MessageBuffer::encode: 32-byte FullHeader + core.
    let total = 32 + ExecutionReportCore::SIZE;
    let mut msg = vec![0u8; total];
    msg[0..2].copy_from_slice(&0x474Du16.to_le_bytes()); // magic "MG"
    msg[2] = 0; // flags
    msg[3] = 1; // version
    msg[4..8].copy_from_slice(&(total as u32).to_le_bytes()); // message_size
    msg[8..10].copy_from_slice(&0x0001u16.to_le_bytes()); // schema_id
    msg[10..12].copy_from_slice(&0x0005u16.to_le_bytes()); // message_type
    msg[32..32 + ExecutionReportCore::SIZE].copy_from_slice(report.as_bytes());

    c.bench_function("decode_execution_report", |b| {
        b.iter(|| {
            let decoded = MessageBuffer::decode_execution_report(black_box(&msg));
            black_box(decoded.order_id);
            black_box(decoded.last_px);
            black_box(decoded.transact_time);
        });
    });
}

fn bench_hmac_sign(c: &mut Criterion) {
    let key = b"super-secret-exchange-key-2026!!";
    let hmac = mgep::auth::HmacSha256::new(key);

    let order = make_order();
    let mut codec = MessageBuffer::with_capacity(256);
    codec.encode_new_order(1, 1, &order, None);
    let msg_len = codec.as_slice().len();
    let mut buf = [0u8; 256];
    buf[..msg_len].copy_from_slice(codec.as_slice());

    c.bench_function("hmac_sign_new_order", |b| {
        b.iter(|| {
            let mut test_buf = buf;
            black_box(mgep::auth::sign_message(&mut test_buf, msg_len, &hmac));
        });
    });
}

fn bench_hmac_verify(c: &mut Criterion) {
    let key = b"super-secret-exchange-key-2026!!";
    let hmac = mgep::auth::HmacSha256::new(key);

    let order = make_order();
    let mut codec = MessageBuffer::with_capacity(256);
    codec.encode_new_order(1, 1, &order, None);
    let msg_len = codec.as_slice().len();
    let mut buf = [0u8; 256];
    buf[..msg_len].copy_from_slice(codec.as_slice());
    let total = mgep::auth::sign_message(&mut buf, msg_len, &hmac);

    c.bench_function("hmac_verify_new_order", |b| {
        b.iter(|| {
            black_box(mgep::auth::verify_message(black_box(&buf[..total]), &hmac));
        });
    });
}

fn bench_session_heartbeat(c: &mut Criterion) {
    // Fast-forward session to Active via proper handshake
    let mut session = mgep::session::Session::new(1);
    let mut buf = [0u8; 256];
    session.build_negotiate(&mut buf, [0u8; 32]).unwrap();
    let resp = mgep::session::NegotiateResponseCore {
        session_id: 1, keepalive_ms: 1000, security_level: 0,
        session_flags: 0, max_message_size: 4096,
        status: 0, reject_reason: 0, _pad: 0, public_key: [0u8; 32],
    };
    session.handle_negotiate_response(&resp).unwrap();
    session.build_establish(&mut buf, [0u8; 32]).unwrap();
    let ack = mgep::session::EstablishAckCore {
        session_id: 1, next_seq_num: 100,
        journal_low_seq_num: 0,
    };
    session.handle_establish_ack(&ack).unwrap();

    c.bench_function("build_heartbeat", |b| {
        b.iter(|| {
            let _ = black_box(session.build_heartbeat(&mut buf));
        });
    });
}

criterion_group!(
    benches,
    bench_encode_core_only,
    bench_decode_core_only,
    bench_dispatch,
    bench_full_header_decode,
    bench_encode_with_flex,
    bench_decode_flex_field,
    bench_execution_report_decode,
    bench_hmac_sign,
    bench_hmac_verify,
    bench_session_heartbeat,
);
criterion_main!(benches);
