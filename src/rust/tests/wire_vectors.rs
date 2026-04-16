//! Wire format test vectors — golden bytes for cross-implementation verification.
//!
//! These are the canonical byte sequences that any MGEP implementation
//! (Rust, C, Python, Go, etc.) must produce for the given inputs.
//! If your implementation produces different bytes, it's incompatible.

use mgep::codec::MessageBuffer;
use mgep::frame::{self, FrameHeader};
use mgep::header::{FullHeader, CORE_BLOCK_OFFSET};
use mgep::messages::*;
use mgep::types::*;

/// Helper: encode a message and return hex string.
fn to_hex(buf: &[u8]) -> String {
    buf.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

#[test]
fn wire_vector_frame_header() {
    // Frame header: magic=MG, flags=0, version=1, size=32
    let fh = FrameHeader::new(frame::FrameFlags::NONE, 32);
    let bytes = fh.as_bytes();

    assert_eq!(bytes[0], 0x4D); // 'M'
    assert_eq!(bytes[1], 0x47); // 'G'
    assert_eq!(bytes[2], 0x00); // flags = none
    assert_eq!(bytes[3], 0x01); // version = 1
    assert_eq!(&bytes[4..8], &32u32.to_le_bytes()); // message_size = 32

    println!("Frame header (8B): {}", to_hex(bytes));
}

#[test]
fn wire_vector_full_header() {
    let header = FullHeader::new(
        0x0001,     // schema: trading
        0x01,       // msg_type: NewOrderSingle
        42,         // sender_comp_id
        1,          // sequence_num
        999,        // correlation_id
        72,         // message_size (32 header + 40 core)
        frame::FrameFlags::NONE,
    );

    let mut buf = vec![0u8; 32];
    header.write_to(&mut buf);

    // Verify byte-by-byte
    assert_eq!(buf[0], 0x4D); // magic 'M'
    assert_eq!(buf[1], 0x47); // magic 'G'
    assert_eq!(buf[2], 0x00); // flags
    assert_eq!(buf[3], 0x01); // version
    assert_eq!(&buf[4..8], &72u32.to_le_bytes()); // message_size

    assert_eq!(&buf[8..10], &0x0001u16.to_le_bytes()); // schema_id
    assert_eq!(&buf[10..12], &0x0001u16.to_le_bytes()); // message_type
    assert_eq!(&buf[12..16], &42u32.to_le_bytes()); // sender_comp_id
    assert_eq!(&buf[16..24], &1u64.to_le_bytes()); // sequence_num
    assert_eq!(&buf[24..32], &999u64.to_le_bytes()); // correlation_id

    println!("Full header (32B): {}", to_hex(&buf));
}

#[test]
fn wire_vector_new_order_single() {
    let order = NewOrderSingleCore {
        order_id: 1000,
        instrument_id: 42,
        side: Side::Buy as u8,     // 1
        order_type: OrderType::Limit as u8, // 2
        time_in_force: TimeInForce::Day as u16, // 1
        price: Decimal::from_f64(150.25),
        quantity: Decimal::from_f64(100.0),
        stop_price: Decimal::NULL,
    };

    let mut enc = MessageBuffer::with_capacity(256);
    enc.encode(1, 1, &order, None);
    let msg = enc.as_slice();

    // Total size: 32 (header) + 40 (core) = 72
    assert_eq!(msg.len(), 72);

    // Verify magic
    assert_eq!(msg[0], 0x4D);
    assert_eq!(msg[1], 0x47);

    // Verify core block starts at offset 32
    let core = &msg[CORE_BLOCK_OFFSET..];
    assert_eq!(&core[0..8], &1000u64.to_le_bytes()); // order_id
    assert_eq!(&core[8..12], &42u32.to_le_bytes()); // instrument_id
    assert_eq!(core[12], 1); // side = Buy
    assert_eq!(core[13], 2); // order_type = Limit

    // price = 150.25 * 10^8 = 15025000000
    let price_bytes = &core[16..24];
    let price_val = i64::from_le_bytes(price_bytes.try_into().unwrap());
    assert_eq!(price_val, 15_025_000_000);

    // quantity = 100.0 * 10^8 = 10000000000
    let qty_bytes = &core[24..32];
    let qty_val = i64::from_le_bytes(qty_bytes.try_into().unwrap());
    assert_eq!(qty_val, 10_000_000_000);

    // stop_price = NULL = i64::MIN
    let stop_bytes = &core[32..40];
    let stop_val = i64::from_le_bytes(stop_bytes.try_into().unwrap());
    assert_eq!(stop_val, i64::MIN);

    println!("NewOrderSingle (72B): {}", to_hex(msg));
    println!("  Core block (40B):   {}", to_hex(core));
}

#[test]
fn wire_vector_decimal_encoding() {
    // Canonical decimal encodings
    let cases: Vec<(f64, i64)> = vec![
        (0.0, 0),
        (1.0, 100_000_000),
        (100.5, 10_050_000_000),
        (150.25, 15_025_000_000),
        (-50.75, -5_075_000_000),
        (0.00000001, 1),   // minimum precision
        (92233720368.0, 9_223_372_036_800_000_000), // near max
    ];

    for (f, expected) in &cases {
        let d = Decimal::from_f64(*f);
        assert_eq!(d.0, *expected, "Decimal::from_f64({}) = {} (expected {})", f, d.0, expected);
    }

    // NULL sentinel
    assert_eq!(Decimal::NULL.0, i64::MIN);

    println!("Decimal encoding: value * 10^8 (i64 LE)");
    println!("  NULL sentinel: 0x{:016X} (i64::MIN)", i64::MIN as u64);
}

#[test]
fn wire_vector_crc32() {
    // CRC32 of known data
    assert_eq!(frame::crc32(b""), 0x00000000);
    assert_eq!(frame::crc32(b"123456789"), 0xCBF43926);
    let mgep_crc = frame::crc32(b"MGEP");
    // Verify deterministic — same input always gives same output
    assert_eq!(mgep_crc, frame::crc32(b"MGEP"));
    println!("CRC32(\"MGEP\") = 0x{:08X}", mgep_crc);

    // CRC32 of a real message
    let order = NewOrderSingleCore {
        order_id: 1, instrument_id: 1, side: 1, order_type: 2,
        time_in_force: 1, price: Decimal::from_f64(100.0),
        quantity: Decimal::from_f64(10.0), stop_price: Decimal::NULL,
    };
    let mut enc = MessageBuffer::with_capacity(256);
    enc.encode(1, 1, &order, None);
    let checksum = frame::crc32(enc.as_slice());

    println!("CRC32 of NewOrderSingle: 0x{:08X}", checksum);
    // This value must be identical in any implementation
    println!("  (verify this in your C/Python/Go implementation)");
}

#[test]
fn wire_vector_with_flex() {
    let order = NewOrderSingleCore {
        order_id: 42, instrument_id: 7, side: 1, order_type: 2,
        time_in_force: 1, price: Decimal::from_f64(100.0),
        quantity: Decimal::from_f64(10.0), stop_price: Decimal::NULL,
    };

    let mut flex = mgep::flex::FlexWriter::new();
    flex.put_string(1, "ACC001");
    flex.put_string(2, "order-tag-123");
    let flex_data = flex.build();

    let mut enc = MessageBuffer::with_capacity(512);
    enc.encode(1, 1, &order, Some(&flex_data));
    let msg = enc.as_slice();

    // Has flex flag
    assert_eq!(msg[2] & 0x08, 0x08); // HAS_FLEX flag

    // Flex block starts after core
    let flex_offset = CORE_BLOCK_OFFSET + NewOrderSingleCore::SIZE;
    let flex_count = u16::from_le_bytes([msg[flex_offset], msg[flex_offset + 1]]);
    assert_eq!(flex_count, 2);

    println!("NewOrderSingle with flex ({}B): {}", msg.len(), to_hex(msg));
    println!("  Flex block at offset {}: {} fields", flex_offset, flex_count);
}

#[test]
fn wire_vector_summary() {
    println!("\n══════════════════════════════════════════════");
    println!("MGEP Wire Format Test Vectors");
    println!("══════════════════════════════════════════════");
    println!();
    println!("Byte order:        Little-endian");
    println!("Magic bytes:       0x4D 0x47 ('MG')");
    println!("Frame header:      8 bytes at offset 0");
    println!("Message header:    24 bytes at offset 8");
    println!("Core block:        at offset 32 (CORE_BLOCK_OFFSET)");
    println!("Decimal encoding:  i64 * 10^8 (LE)");
    println!("Timestamp:         u64 nanoseconds since epoch (LE)");
    println!("NULL decimal:      0x{:016X} (i64::MIN)", i64::MIN as u64);
    println!("NULL timestamp:    0x{:016X} (u64::MAX)", u64::MAX);
    println!();
    println!("Header layout (32 bytes):");
    println!("  [0:2]   magic         = 0x474D");
    println!("  [2]     flags         = bitfield");
    println!("  [3]     version       = 1");
    println!("  [4:8]   message_size  = u32 LE");
    println!("  [8:10]  schema_id     = u16 LE");
    println!("  [10:12] message_type  = u16 LE");
    println!("  [12:16] sender_comp_id = u32 LE");
    println!("  [16:24] sequence_num  = u64 LE");
    println!("  [24:32] correlation_id = u64 LE");
}
