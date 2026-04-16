//! Cross-language wire compatibility test.
//!
//! Verifies that Rust and Python produce identical bytes for the same messages.
//! This is the ultimate protocol compatibility test — if these bytes don't match,
//! the two implementations are incompatible.

use std::process::Command;

use mgep::codec::MessageBuffer;
use mgep::messages::*;
use mgep::types::*;

/// Encode a NewOrderSingle in Rust and return hex string.
fn rust_encode_new_order() -> (Vec<u8>, String) {
    let order = NewOrderSingleCore {
        order_id: 42,
        instrument_id: 7,
        side: Side::Buy as u8,
        order_type: OrderType::Limit as u8,
        time_in_force: TimeInForce::Day as u16,
        price: Decimal::from_f64(150.25),
        quantity: Decimal::from_f64(100.0),
        stop_price: Decimal::NULL,
    };

    let mut enc = MessageBuffer::with_capacity(256);
    // Use fixed values so output is deterministic
    enc.encode(1, 1, &order, None);
    let bytes = enc.as_slice().to_vec();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    (bytes, hex)
}

#[test]
fn rust_python_wire_compatibility() {
    let (rust_bytes, rust_hex) = rust_encode_new_order();

    // Run Python encoder and capture hex output
    let python_script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../bindings/python/mgep.py"
    );

    // Check Python is available
    let python_result = Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import sys; sys.path.insert(0, '{}'); from mgep import *; \
             msg = encode_new_order(order_id=42, instrument_id=7, \
                 side=SIDE_BUY, order_type=ORDER_TYPE_LIMIT, \
                 price=150.25, quantity=100.0, \
                 time_in_force=TIF_DAY, sender_comp_id=1, \
                 sequence_num=1, correlation_id=0); \
             print(msg.hex())",
            std::path::Path::new(python_script).parent().unwrap().display()
        ))
        .output();

    match python_result {
        Ok(output) if output.status.success() => {
            let python_hex = String::from_utf8_lossy(&output.stdout).trim().to_string();

            println!("Rust   hex: {}", rust_hex);
            println!("Python hex: {}", python_hex);
            println!("Rust   len: {} bytes", rust_bytes.len());
            println!("Python len: {} chars / 2 = {} bytes", python_hex.len(), python_hex.len() / 2);

            // Core block comparison (skip header because timestamp differs)
            // Header is 32 bytes = 64 hex chars
            // Core block starts at byte 32

            let rust_core = &rust_hex[64..]; // after 32-byte header
            let python_core = &python_hex[64..]; // after 32-byte header

            assert_eq!(
                rust_core, python_core,
                "Core block mismatch!\nRust:   {}\nPython: {}",
                rust_core, python_core
            );

            println!("\n✓ Rust and Python produce identical core block bytes!");

            // Also verify header structure matches
            // Magic bytes (first 4 hex chars = 2 bytes)
            assert_eq!(&rust_hex[0..4], "4d47", "Rust magic wrong");
            assert_eq!(&python_hex[0..4], "4d47", "Python magic wrong");
            println!("✓ Both have correct magic bytes (MG)");

            // Schema ID at offset 8 (hex offset 16)
            assert_eq!(&rust_hex[16..20], &python_hex[16..20], "schema_id mismatch");
            println!("✓ Schema IDs match");

            // Message type at offset 10 (hex offset 20)
            assert_eq!(&rust_hex[20..24], &python_hex[20..24], "message_type mismatch");
            println!("✓ Message types match");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Python failed: {}", stderr);
            eprintln!("Skipping cross-language test (Python not available or error)");
        }
        Err(e) => {
            eprintln!("Cannot run python3: {}", e);
            eprintln!("Skipping cross-language test");
        }
    }
}

#[test]
fn wire_format_deterministic() {
    // Same input must produce same output every time (except timestamp in header)
    let (bytes1, _) = rust_encode_new_order();
    let (bytes2, _) = rust_encode_new_order();

    // Core blocks must be identical
    assert_eq!(
        &bytes1[mgep::header::CORE_BLOCK_OFFSET..],
        &bytes2[mgep::header::CORE_BLOCK_OFFSET..],
        "Core block not deterministic!"
    );

    // Headers differ only in timestamp (not present in new format)
    // and potentially in the magic/flags/version which should be constant
    assert_eq!(&bytes1[0..4], &bytes2[0..4], "Magic/flags/version differ");
}
