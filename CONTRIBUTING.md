# Contributing to MGEP

## Golden Rules

1. **Schema is the source of truth.** Wire format is defined in `schemas/*.mgep`. Hand-written Rust structs in `messages.rs` must match exactly. Any discrepancy is a bug.
2. **Wire compatibility is sacred.** Once released, core block field order and types NEVER change. Only additions via optional (flex) fields.
3. **Every message type needs a wire test vector.** Golden bytes in `tests/wire_vectors.rs` that any implementation (Rust, C, Python) must reproduce identically.
4. **Cross-language verification before merge.** Changes to wire format must pass: Rust encode → Python decode → same values. Python encode → Rust decode → same values.

## How to Add a New Message

1. **Define in schema.** Add message to the appropriate `schemas/*.mgep` file:
   ```
   message MyNewMessage {
       "What this message does."
       
       field_name    type    required    "description"
       
       optional {
           extra_field    string    "optional field"
       }
   }
   ```

2. **Add Rust struct.** In `src/messages.rs`, add a `define_core!` call with the exact wire layout. Field order matters — it determines byte offsets.

3. **Add to dispatch.** In `src/codec.rs`:
   - Add `impl_core_block!(MyNewMessageCore);`
   - Add arm to `dispatch_message()` match
   - Add variant to `MessageKind` enum

4. **Add wire test vector.** In `tests/wire_vectors.rs`, create a test that encodes the message with known field values and asserts exact byte values at specific offsets.

5. **Update Python bindings.** In `bindings/python/mgep.py`, add the ctypes struct and decode function.

6. **Run full verification:**
   ```bash
   cargo test                                    # all Rust tests
   python3 bindings/python/mgep.py               # Python self-test  
   cargo test --test cross_language               # cross-language wire compat
   cargo test --test wire_vectors                 # golden bytes
   cargo bench --no-run                           # benchmarks compile
   cargo run --example full_lifecycle             # example still works
   ```

## How to Add a New Optional Field to Existing Message

This is the safe way to evolve the schema without breaking compatibility:

1. **Add to `optional { }` block** in the schema file. New fields go at the end.
2. **Flex field IDs are assigned in order.** The N-th optional field gets `@id=N`. Don't reorder.
3. **Old code ignores unknown flex fields.** This is by design — flex block reader skips unknown IDs.
4. **Never move a field from optional to core.** That changes the wire format.

## How to Change Core Block Fields

**Don't.** After release, core block layout is frozen for that message type. If you need different fields:
- Add new optional fields to the flex block
- Or define a new message type (e.g., `NewOrderSingleV2`)

Before release, core block changes are allowed but require:
1. Update `messages.rs` struct
2. Update all tests that construct that struct
3. Update wire test vectors
4. Update Python bindings
5. Update C headers via codegen
6. Run full verification

## Wire Format Rules

- **Byte order:** Little-endian everywhere. No exceptions.
- **Alignment:** Core block fields are naturally aligned (u64 at 8-byte boundary, u32 at 4-byte). Codegen adds padding automatically.
- **Core block sizes:** Always a multiple of 8 bytes.
- **Magic bytes:** Every frame starts with `0x4D 0x47` ("MG"). No exceptions.
- **Null values:** Decimal NULL = `i64::MIN` (0x8000000000000000). Timestamp NULL = `u64::MAX`.
- **Enum values:** Start at 1, not 0. Zero means "not set" / invalid.

## Schema ID Assignment

| Range | Usage |
|---|---|
| 0x0000 | Session layer (reserved) |
| 0x0001 | Trading |
| 0x0002 | Market data |
| 0x0003 | Quotes |
| 0x0004 | Post-trade |
| 0x0005 | Risk |
| 0x0006–0x00FF | Reserved for future MGEP schemas |
| 0x0100–0xFFFE | User-defined / custom schemas |
| 0xFFFF | Batch wrapper (reserved) |

## Message Type Assignment

Within each schema, message types are assigned sequentially starting from 0x01. Gaps are allowed (e.g., if a message is deprecated, its type ID is retired, never reused).

## Error Handling

- **Session Reject (0x0001/0x10):** Protocol violation. Malformed message, unknown type, sequence error.
- **Business Reject (0x0001/0x11):** Valid message but can't process. Insufficient funds, unknown instrument, etc.
- **OrderCancelReject:** Specific to cancel/replace failures. Has `CancelRejectReason` enum.

When in doubt, send a BusinessReject with a descriptive `text` flex field.

## Version Compatibility

- `version` byte in frame header indicates the protocol version.
- Current version: 1.
- Version 1 implementations must reject messages with `version > 1`.
- Future versions will document migration paths.

## Code Style

- `cargo fmt` before commit
- `cargo clippy` must pass with zero warnings  
- No `unsafe` without a `// SAFETY:` comment explaining why it's sound
- All public APIs need doc comments
- Tests for every new function

## Release Checklist

Before any release:

- [ ] All tests pass (`cargo test`)
- [ ] Zero warnings (`cargo test 2>&1 | grep warning | grep -v generated`)
- [ ] Wire test vectors cover every message type
- [ ] Cross-language test passes (Rust ↔ Python)
- [ ] Python bindings self-test passes
- [ ] C headers generate without errors
- [ ] Example runs end-to-end
- [ ] Benchmarks show no regression
- [ ] CHANGELOG updated
- [ ] Version bumped in Cargo.toml
- [ ] Documentation updated for new/changed messages
- [ ] Schema files and messages.rs are in sync
