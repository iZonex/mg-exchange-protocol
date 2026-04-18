# Contributing to MGEP

## Golden Rules

1. **Schema is the source of truth.** Wire format is defined in `schemas/*.mgep`. Hand-written Rust structs in `messages.rs` must match exactly. Any discrepancy is a bug.
2. **Wire compatibility is sacred — post-1.0.** Once MGEP tags `1.0.0`, core block field order and types NEVER change; only additions via optional (flex) fields. Before `1.0.0` the Pre-1.0 Exception in `VERSIONING.md` applies: core-block changes are allowed but MUST be enumerated under `⚠️ Breaking wire changes` in `CHANGELOG.md` so operators bump all peers simultaneously.
3. **Every message type needs a wire test vector.** Golden bytes in `tests/wire_vectors.rs` that any binding (Rust, C, C++, Java, C#, TypeScript, Python) must reproduce identically. Size assertions in each binding's test suite catch drift early.
4. **Cross-language verification before merge.** Changes to wire format must pass the per-binding size checks and the Rust↔Python cross_language test. Adding a new binding requires porting the same set of checks.

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

5. **Update all language bindings.** For every language under `bindings/`, port the struct, bump `SIZE`, adjust tests. Current bindings:
   - `bindings/c/mgep.h` + `.c` + `test_mgep.c`
   - `bindings/cpp/mgep.hpp` + `test_mgep.cpp` (wraps C; usually no-op)
   - `bindings/java/src/main/java/com/mgep/Mgep.java` + `MgepTest.java`
   - `bindings/csharp/Mgep.cs`
   - `bindings/typescript/src/mgep.ts` + `test/mgep.test.ts`
   - `bindings/python/mgep.py`

6. **Run full verification:**
   ```bash
   cd src/rust
   cargo test --all-targets                       # all Rust tests (default features)
   cargo test --lib --no-default-features          # no-experimental-transports build
   cargo clippy --lib -- -D warnings               # zero clippy warnings
   cargo test --test cross_language                # Rust↔Python wire compat
   cargo test --test wire_vectors                  # golden bytes
   cargo bench --no-run                            # benchmarks compile

   # Other bindings
   cc -std=c11 -Wall -Wextra -Werror -o /tmp/t  bindings/c/mgep.c bindings/c/test_mgep.c && /tmp/t
   (cd bindings/java && javac -d out src/main/java/com/mgep/*.java src/test/java/com/mgep/*.java && java -cp out com.mgep.MgepTest)
   deno test --allow-read bindings/typescript/test/mgep.test.ts
   ```

## How to Add a New Optional Field to Existing Message

This is the safe way to evolve the schema without breaking compatibility:

1. **Add to `optional { }` block** in the schema file. New fields go at the end.
2. **Flex field IDs are assigned in order.** The N-th optional field gets `@id=N`. Don't reorder.
3. **Old code ignores unknown flex fields.** This is by design — flex block reader skips unknown IDs.
4. **Never move a field from optional to core.** That changes the wire format.

## How to Change Core Block Fields

**After `1.0.0` — don't.** Core block layout is frozen. Use flex fields or
define a new message type (e.g., `NewOrderSingleV2`).

**Before `1.0.0`** (Pre-1.0 Exception in `VERSIONING.md`), core block
changes are allowed but require ALL of:

1. Update `messages.rs` `define_core!` with new fields + `size` constant
2. Update every struct literal in the codebase (bulk-fix via grep)
3. Update wire test vectors in `tests/wire_vectors.rs`
4. Update every language binding (C / C++ / Java / C# / TypeScript / Python)
5. Update `docs/spec/*.md` — at minimum `01-wire-format.md` and
   `mgep-v1.0.md` Appendix A
6. Add a `### Breaking Changes` entry in `CHANGELOG.md` under the current
   `[Unreleased]` section, enumerating size deltas
7. Run full verification (all bindings green + clippy clean)

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

- [ ] `cargo test --all-targets` passes (default features)
- [ ] `cargo test --lib --no-default-features` passes (stable transports only)
- [ ] `cargo build --all-targets` — zero warnings
- [ ] `cargo clippy --lib` — zero warnings (or `--fix` where autofix is safe)
- [ ] Wire test vectors cover every modified message type
- [ ] Cross-language size tests green: C / C++ / Java / TypeScript
- [ ] Python bindings cross-language test green
- [ ] `mgep-sandbox` binary builds + runs (`--help` at minimum)
- [ ] Example binaries run end-to-end (`cargo run --example full_lifecycle`)
- [ ] Benchmarks compile and show no regression vs last release
- [ ] `CHANGELOG.md` has a new section (not `[Unreleased]`) with the version
- [ ] Breaking wire changes (pre-1.0) enumerated under `⚠️ Breaking wire changes`
- [ ] `Cargo.toml` version bumped
- [ ] `docs/spec/*.md` reflect any schema / core-block changes
- [ ] `schemas/*.mgep` and `messages.rs` are in sync (sizes, field order)
- [ ] All language bindings' README tables match current sizes
- [ ] Git tag planned (`v0.X.Y`) matches CHANGELOG heading and `Cargo.toml` version
