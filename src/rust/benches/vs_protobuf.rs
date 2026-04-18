//! MGEP vs Protobuf (prost) benchmark comparison.
//!
//! Compares encode/decode performance of the same NewOrderSingle message
//! in both MGEP (zero-copy binary) and Protobuf (prost) formats.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

// ============================================================================
// Protobuf definition (inline via prost)
// ============================================================================

/// Protobuf NewOrderSingle equivalent — generated-style struct via prost.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbNewOrderSingle {
    #[prost(uint64, tag = "1")]
    pub order_id: u64,
    #[prost(uint32, tag = "2")]
    pub instrument_id: u32,
    #[prost(enumeration = "PbSide", tag = "3")]
    pub side: i32,
    #[prost(enumeration = "PbOrderType", tag = "4")]
    pub order_type: i32,
    #[prost(enumeration = "PbTimeInForce", tag = "5")]
    pub time_in_force: i32,
    #[prost(int64, tag = "6")]
    pub price: i64, // fixed-point * 10^8
    #[prost(int64, tag = "7")]
    pub quantity: i64,
    #[prost(int64, tag = "8")]
    pub stop_price: i64,
    #[prost(string, tag = "9")]
    pub account: String,
    #[prost(string, tag = "10")]
    pub client_tag: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum PbSide {
    Buy = 1,
    Sell = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum PbOrderType {
    Market = 1,
    Limit = 2,
    Stop = 3,
    StopLimit = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum PbTimeInForce {
    Day = 1,
    Gtc = 2,
    Ioc = 3,
    Fok = 4,
    Gtd = 5,
}

/// Protobuf ExecutionReport equivalent.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbExecutionReport {
    #[prost(uint64, tag = "1")]
    pub order_id: u64,
    #[prost(uint64, tag = "2")]
    pub exec_id: u64,
    #[prost(uint32, tag = "3")]
    pub instrument_id: u32,
    #[prost(enumeration = "PbSide", tag = "4")]
    pub side: i32,
    #[prost(int32, tag = "5")]
    pub exec_type: i32,
    #[prost(int32, tag = "6")]
    pub order_status: i32,
    #[prost(int64, tag = "7")]
    pub price: i64,
    #[prost(int64, tag = "8")]
    pub quantity: i64,
    #[prost(int64, tag = "9")]
    pub leaves_qty: i64,
    #[prost(int64, tag = "10")]
    pub cum_qty: i64,
    #[prost(int64, tag = "11")]
    pub last_px: i64,
    #[prost(int64, tag = "12")]
    pub last_qty: i64,
    #[prost(uint64, tag = "13")]
    pub transact_time: u64,
    #[prost(string, tag = "14")]
    pub text: String,
    #[prost(uint64, tag = "15")]
    pub trade_id: u64,
}

// ============================================================================
// MGEP helpers
// ============================================================================

use mgep::codec::MessageBuffer;
use mgep::flex::FlexWriter;
use mgep::messages::*;
use mgep::types::*;

fn make_mgep_order() -> NewOrderSingleCore {
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

fn make_pb_order() -> PbNewOrderSingle {
    PbNewOrderSingle {
        order_id: 123456789,
        instrument_id: 42,
        side: PbSide::Buy as i32,
        order_type: PbOrderType::Limit as i32,
        time_in_force: PbTimeInForce::Ioc as i32,
        price: 15_025_000_000, // 150.25 * 10^8
        quantity: 10_000_000_000, // 100.0 * 10^8
        stop_price: i64::MIN,
        account: "ACCOUNT001".into(),
        client_tag: "client-tag-12345".into(),
    }
}

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_encode_mgep(c: &mut Criterion) {
    let order = make_mgep_order();
    let mut flex_writer = FlexWriter::new();
    flex_writer.put_string(1, "ACCOUNT001");
    flex_writer.put_string(2, "client-tag-12345");
    let flex_data = flex_writer.build();
    let mut buffer = MessageBuffer::with_capacity(512);

    c.bench_function("mgep_encode_new_order", |b| {
        b.iter(|| {
            buffer.reset();
            black_box(buffer.encode_new_order(1, black_box(1), &order, Some(&flex_data)));
        });
    });
}

fn bench_encode_protobuf(c: &mut Criterion) {
    let order = make_pb_order();
    let mut buf = Vec::with_capacity(128);

    c.bench_function("protobuf_encode_new_order", |b| {
        b.iter(|| {
            buf.clear();
            prost::Message::encode(black_box(&order), &mut buf).unwrap();
            black_box(buf.len());
        });
    });
}

fn bench_decode_mgep(c: &mut Criterion) {
    let order = make_mgep_order();
    let mut flex_writer = FlexWriter::new();
    flex_writer.put_string(1, "ACCOUNT001");
    flex_writer.put_string(2, "client-tag-12345");
    let flex_data = flex_writer.build();
    let mut buffer = MessageBuffer::with_capacity(512);
    buffer.encode_new_order(1, 1, &order, Some(&flex_data));
    let msg = buffer.as_slice().to_vec();

    c.bench_function("mgep_decode_new_order", |b| {
        b.iter(|| {
            let decoded = MessageBuffer::decode_new_order(black_box(&msg));
            black_box(decoded.order_id);
            black_box(decoded.price);
            black_box(decoded.quantity);
            // Also read flex
            let flex = MessageBuffer::decode_flex(&msg, NewOrderSingleCore::SIZE).unwrap();
            black_box(flex.get_string(1));
            black_box(flex.get_string(2));
        });
    });
}

fn bench_decode_protobuf(c: &mut Criterion) {
    let order = make_pb_order();
    let mut buf = Vec::with_capacity(128);
    prost::Message::encode(&order, &mut buf).unwrap();

    c.bench_function("protobuf_decode_new_order", |b| {
        b.iter(|| {
            let decoded: PbNewOrderSingle =
                prost::Message::decode(black_box(buf.as_slice())).unwrap();
            black_box(decoded.order_id);
            black_box(decoded.price);
            black_box(decoded.quantity);
            black_box(&decoded.account);
            black_box(&decoded.client_tag);
        });
    });
}

fn bench_encode_mgep_exec_report(c: &mut Criterion) {
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

    let total = 24 + ExecutionReportCore::SIZE;
    let mut msg = vec![0u8; total];

    c.bench_function("mgep_encode_exec_report", |b| {
        b.iter(|| {
            msg[..4].copy_from_slice(&(total as u32).to_le_bytes());
            msg[4..6].copy_from_slice(&0x0001u16.to_le_bytes());
            msg[6] = 1;
            msg[7] = 0;
            msg[8..10].copy_from_slice(&0x0005u16.to_le_bytes());
            msg[24..24 + ExecutionReportCore::SIZE].copy_from_slice(black_box(report.as_bytes()));
            black_box(&msg);
        });
    });
}

fn bench_encode_protobuf_exec_report(c: &mut Criterion) {
    let report = PbExecutionReport {
        order_id: 123456789,
        exec_id: 987654321,
        instrument_id: 42,
        side: PbSide::Buy as i32,
        exec_type: 2,
        order_status: 2,
        price: 15_025_000_000,
        quantity: 10_000_000_000,
        leaves_qty: 0,
        cum_qty: 10_000_000_000,
        last_px: 15_025_000_000,
        last_qty: 10_000_000_000,
        transact_time: 1700000000000000000,
        text: String::new(),
        trade_id: 0,
    };
    let mut buf = Vec::with_capacity(256);

    c.bench_function("protobuf_encode_exec_report", |b| {
        b.iter(|| {
            buf.clear();
            prost::Message::encode(black_box(&report), &mut buf).unwrap();
            black_box(buf.len());
        });
    });
}

fn bench_decode_mgep_exec_report(c: &mut Criterion) {
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

    let total = 24 + ExecutionReportCore::SIZE;
    let mut msg = vec![0u8; total];
    msg[..4].copy_from_slice(&(total as u32).to_le_bytes());
    msg[4..6].copy_from_slice(&0x0001u16.to_le_bytes());
    msg[6] = 1;
    msg[24..24 + ExecutionReportCore::SIZE].copy_from_slice(report.as_bytes());

    c.bench_function("mgep_decode_exec_report", |b| {
        b.iter(|| {
            let decoded = MessageBuffer::decode_execution_report(black_box(&msg));
            black_box(decoded.order_id);
            black_box(decoded.last_px);
            black_box(decoded.transact_time);
            black_box(decoded.cum_qty);
        });
    });
}

fn bench_decode_protobuf_exec_report(c: &mut Criterion) {
    let report = PbExecutionReport {
        order_id: 123456789,
        exec_id: 987654321,
        instrument_id: 42,
        side: PbSide::Buy as i32,
        exec_type: 2,
        order_status: 2,
        price: 15_025_000_000,
        quantity: 10_000_000_000,
        leaves_qty: 0,
        cum_qty: 10_000_000_000,
        last_px: 15_025_000_000,
        last_qty: 10_000_000_000,
        transact_time: 1700000000000000000,
        text: String::new(),
        trade_id: 0,
    };
    let mut buf = Vec::with_capacity(256);
    prost::Message::encode(&report, &mut buf).unwrap();

    c.bench_function("protobuf_decode_exec_report", |b| {
        b.iter(|| {
            let decoded: PbExecutionReport =
                prost::Message::decode(black_box(buf.as_slice())).unwrap();
            black_box(decoded.order_id);
            black_box(decoded.last_px);
            black_box(decoded.transact_time);
            black_box(decoded.cum_qty);
        });
    });
}

fn bench_wire_size(c: &mut Criterion) {
    // Show wire sizes in benchmark output
    let order = make_mgep_order();
    let mut flex_writer = FlexWriter::new();
    flex_writer.put_string(1, "ACCOUNT001");
    flex_writer.put_string(2, "client-tag-12345");
    let flex_data = flex_writer.build();
    let mut buffer = MessageBuffer::with_capacity(512);
    buffer.encode_new_order(1, 1, &order, Some(&flex_data));
    let mgep_size = buffer.as_slice().len();

    let pb_order = make_pb_order();
    let mut pb_buf = Vec::new();
    prost::Message::encode(&pb_order, &mut pb_buf).unwrap();
    let pb_size = pb_buf.len();

    println!("\n  Wire size comparison (NewOrderSingle + flex):");
    println!("    MGEP:     {} bytes (header={}, core={}, flex={})",
        mgep_size, 24, NewOrderSingleCore::SIZE, flex_data.len());
    println!("    Protobuf: {} bytes", pb_size);
    println!("    Ratio:    MGEP is {:.1}x vs Protobuf\n",
        mgep_size as f64 / pb_size as f64);

    // Dummy bench just to include sizes in report
    c.bench_function(&format!("wire_size_mgep_{}B_vs_protobuf_{}B", mgep_size, pb_size), |b| {
        b.iter(|| { black_box(mgep_size); black_box(pb_size); });
    });
}

criterion_group!(
    benches,
    bench_encode_mgep,
    bench_encode_protobuf,
    bench_decode_mgep,
    bench_decode_protobuf,
    bench_encode_mgep_exec_report,
    bench_encode_protobuf_exec_report,
    bench_decode_mgep_exec_report,
    bench_decode_protobuf_exec_report,
    bench_wire_size,
);
criterion_main!(benches);
