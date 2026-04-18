//! Benchmarks for all MGEP features: encryption, compression, batching, shmem, orderbook.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use mgep::codec::MessageBuffer;
use mgep::messages::*;
use mgep::types::*;

fn make_order() -> NewOrderSingleCore {
    NewOrderSingleCore {
        order_id: 123456789, instrument_id: 42,
        client_order_id: 0,
        side: Side::Buy as u8, order_type: OrderType::Limit as u8,
        time_in_force: TimeInForce::IOC as u16,
        price: Decimal::from_f64(150.25), quantity: Decimal::from_f64(100.0),
        stop_price: Decimal::NULL,
    }
}

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let key = mgep::crypto::derive_key(b"bench-key", 1);
    let cipher = mgep::crypto::Aes128Gcm::new(&key);
    let order = make_order();
    let mut codec = MessageBuffer::with_capacity(256);
    codec.encode(1, 1, &order, None);
    let msg_len = codec.as_slice().len();

    c.bench_function("aes_gcm_encrypt_new_order", |b| {
        b.iter(|| {
            let mut buf = [0u8; 256];
            buf[..msg_len].copy_from_slice(codec.as_slice());
            let _ = black_box(mgep::crypto::encrypt_message(
                &mut buf, msg_len, &cipher, 1, 1, black_box(1),
            ));
        });
    });
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let key = mgep::crypto::derive_key(b"bench-key", 1);
    let cipher = mgep::crypto::Aes128Gcm::new(&key);
    let order = make_order();
    let mut codec = MessageBuffer::with_capacity(256);
    codec.encode(1, 1, &order, None);
    let msg_len = codec.as_slice().len();

    let mut encrypted = [0u8; 256];
    encrypted[..msg_len].copy_from_slice(codec.as_slice());
    let enc_len = mgep::crypto::encrypt_message(&mut encrypted, msg_len, &cipher, 1, 1, 1).unwrap();

    c.bench_function("aes_gcm_decrypt_new_order", |b| {
        b.iter(|| {
            let mut buf = [0u8; 256];
            buf[..enc_len].copy_from_slice(&encrypted[..enc_len]);
            let _ = black_box(mgep::crypto::decrypt_message(
                &mut buf, enc_len, &cipher, 1, 1, 1,
            ));
        });
    });
}

fn bench_lz4_compress(c: &mut Criterion) {
    // Large flex block (realistic BookSnapshot)
    let mut data = Vec::with_capacity(2000);
    for i in 0..100u64 {
        data.extend_from_slice(&i.to_le_bytes());
        data.extend_from_slice(&(100u64).to_le_bytes());
        data.extend_from_slice(&(50u64).to_le_bytes());
    }

    c.bench_function("lz4_compress_2400B", |b| {
        b.iter(|| {
            black_box(mgep::compress::lz4_compress(black_box(&data)));
        });
    });
}

fn bench_lz4_decompress(c: &mut Criterion) {
    let mut data = Vec::with_capacity(2000);
    for i in 0..100u64 {
        data.extend_from_slice(&i.to_le_bytes());
        data.extend_from_slice(&(100u64).to_le_bytes());
        data.extend_from_slice(&(50u64).to_le_bytes());
    }
    let compressed = mgep::compress::lz4_compress(&data).unwrap();

    c.bench_function("lz4_decompress_2400B", |b| {
        b.iter(|| {
            black_box(mgep::compress::lz4_decompress(black_box(&compressed), data.len()));
        });
    });
}

fn bench_batch_encode(c: &mut Criterion) {
    let order = make_order();
    let mut codec = MessageBuffer::with_capacity(256);
    codec.encode(1, 1, &order, None);
    let msg = codec.as_slice().to_vec();

    c.bench_function("batch_encode_50_orders", |b| {
        b.iter(|| {
            let mut batch = mgep::batch::BatchWriter::new(8192);
            for _ in 0..50 {
                batch.push(black_box(&msg));
            }
            black_box(batch.build(1, 1));
        });
    });
}

fn bench_batch_decode(c: &mut Criterion) {
    let order = make_order();
    let mut codec = MessageBuffer::with_capacity(256);
    codec.encode(1, 1, &order, None);
    let msg = codec.as_slice().to_vec();

    let mut batch = mgep::batch::BatchWriter::new(8192);
    for _ in 0..50 {
        batch.push(&msg);
    }
    let frame = batch.build(1, 1).to_vec();

    c.bench_function("batch_decode_50_orders", |b| {
        b.iter(|| {
            let reader = mgep::batch::BatchReader::new(black_box(&frame)).unwrap();
            for msg in reader {
                black_box(msg);
            }
        });
    });
}

fn bench_orderbook_insert(c: &mut Criterion) {
    c.bench_function("orderbook_insert_limit", |b| {
        b.iter(|| {
            let mut book = mgep::orderbook::OrderBook::new(1);
            for i in 0..100u64 {
                let order = NewOrderSingleCore {
                    order_id: i, instrument_id: 1,
                    client_order_id: 0,
                    side: if i % 2 == 0 { 1 } else { 2 },
                    order_type: OrderType::Limit as u8,
                    time_in_force: TimeInForce::Day as u16,
                    price: Decimal::from_f64(100.0 + (i % 10) as f64),
                    quantity: Decimal::from_f64(10.0),
                    stop_price: Decimal::NULL,
                };
                black_box(book.submit(&order));
            }
        });
    });
}

fn bench_orderbook_match(c: &mut Criterion) {
    c.bench_function("orderbook_match_aggressive", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let mut book = mgep::orderbook::OrderBook::new(1);
                // Seed 50 asks
                for i in 0..50u64 {
                    let sell = NewOrderSingleCore {
                        order_id: i, instrument_id: 1, side: 2,
                        client_order_id: 0,
                        order_type: 2, time_in_force: 1,
                        price: Decimal::from_f64(100.0 + i as f64),
                        quantity: Decimal::from_f64(10.0),
                        stop_price: Decimal::NULL,
                    };
                    book.submit(&sell);
                }
                // Aggressive buy sweeps
                let buy = NewOrderSingleCore {
                    order_id: 999, instrument_id: 1, side: 1,
                    client_order_id: 0,
                    order_type: 2, time_in_force: 1,
                    price: Decimal::from_f64(200.0),
                    quantity: Decimal::from_f64(500.0),
                    stop_price: Decimal::NULL,
                };
                black_box(book.submit(&buy));
            }
            start.elapsed()
        });
    });
}

fn bench_builder(c: &mut Criterion) {
    c.bench_function("builder_new_order_with_flex", |b| {
        b.iter(|| {
            let mut enc = MessageBuffer::with_capacity(512);
            mgep::builder::OrderBuilder::new(black_box(42), 7)
                .buy().limit(150.25).quantity(100.0)
                .tif_ioc()
                .account("ACCT001")
                .client_tag("strat-alpha")
                .build(&mut enc, 1);
            black_box(enc.as_slice());
        });
    });
}

fn bench_validation(c: &mut Criterion) {
    let order = make_order();
    let mut enc = MessageBuffer::with_capacity(256);
    enc.encode(1, 1, &order, None);
    let msg = enc.as_slice().to_vec();

    c.bench_function("validate_new_order", |b| {
        b.iter(|| {
            black_box(mgep::validate::validate_message(black_box(&msg)));
        });
    });
}

fn bench_inspect(c: &mut Criterion) {
    let order = make_order();
    let mut enc = MessageBuffer::with_capacity(256);
    enc.encode(1, 1, &order, None);
    let msg = enc.as_slice().to_vec();

    c.bench_function("inspect_format_message", |b| {
        b.iter(|| {
            black_box(mgep::inspect::format_message(black_box(&msg)));
        });
    });
}

fn bench_dispatch(c: &mut Criterion) {
    let order = make_order();
    let mut enc = MessageBuffer::with_capacity(256);
    enc.encode(1, 1, &order, None);
    let msg = enc.as_slice().to_vec();

    c.bench_function("dispatch_48_arm_match", |b| {
        b.iter(|| {
            match mgep::codec::dispatch_message(black_box(&msg)) {
                mgep::codec::MessageKind::NewOrder(o) => black_box(o.order_id),
                _ => unreachable!(),
            };
        });
    });
}

criterion_group!(
    benches,
    bench_aes_gcm_encrypt,
    bench_aes_gcm_decrypt,
    bench_lz4_compress,
    bench_lz4_decompress,
    bench_batch_encode,
    bench_batch_decode,
    bench_orderbook_insert,
    bench_orderbook_match,
    bench_builder,
    bench_validation,
    bench_inspect,
    bench_dispatch,
);
criterion_main!(benches);
