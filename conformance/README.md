# MGEP Conformance Test Vectors

Machine-readable test vectors for cross-implementation verification.

Any MGEP implementation in any language must produce identical bytes for these inputs and decode them to identical values. If your implementation disagrees with these vectors, it is not MGEP-compliant.

## Format

Each `.json` file contains test cases:

```json
{
  "test": "new_order_single_basic",
  "description": "NewOrderSingle with limit buy order",
  "input": {
    "schema_id": "0x0001",
    "message_type": "0x01",
    "sender_comp_id": 1,
    "sequence_num": 1,
    "correlation_id": 0,
    "fields": {
      "order_id": 42,
      "instrument_id": 7,
      "side": 1,
      "order_type": 2,
      "time_in_force": 1,
      "price_f64": 150.25,
      "quantity_f64": 100.0,
      "stop_price": "NULL"
    }
  },
  "expected_hex": "4d470001480000000100010001000000010000000000000000000000000000002a000000000000000700000001020100404e8f7f0300000000e40b54020000000000000000000080",
  "expected_size": 72,
  "expected_core_offset": 32,
  "field_checks": {
    "core[0:8]": "order_id = 42 (u64 LE)",
    "core[8:12]": "instrument_id = 7 (u32 LE)",
    "core[12]": "side = 1 (Buy)",
    "core[13]": "order_type = 2 (Limit)",
    "core[16:24]": "price = 15025000000 (150.25 * 10^8, i64 LE)",
    "core[24:32]": "quantity = 10000000000 (100.0 * 10^8, i64 LE)",
    "core[32:40]": "stop_price = -9223372036854775808 (NULL = i64::MIN)"
  }
}
```

## Running Conformance Tests

### Rust
```bash
cargo test --test wire_vectors
cargo test --test cross_language
```

### Python
```bash
python3 bindings/python/mgep.py
```

### Your Implementation
Parse the JSON test vectors, encode the `input` fields, compare against `expected_hex`.
