# MGEP Wire Format Specification

**Version:** 0.1.0-draft
**Date:** 2026-04-16
**Status:** Draft

---

## 1. Design Philosophy

MGEP wire format is built on three principles:

1. **Hot path is zero-cost** — Fields accessed on every message (type, size, sequence)
   are at fixed byte offsets. Reading them is a pointer dereference, not a parse.

2. **Security is not optional** — Every message carries an authentication tag.
   Encryption is opt-in but designed to cost < 1 microsecond with AES-NI.

3. **Schemas evolve without breaking** — A dual-zone layout separates stable "core"
   fields (fixed offsets) from extensible "flex" fields (indexed access).

---

## 2. Byte Order

All multi-byte integers are **little-endian** (native for x86/x86-64/ARM64-LE).
This eliminates byte-swapping on 99%+ of trading infrastructure.

---

## 3. Message Layout

Every MGEP message has this structure:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Frame Header (8 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Header (24 bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Core Block (fixed layout)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Flex Block (indexed fields, capped at 32) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Auth Tag (16 bytes, optional)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Combined header (frame + message): **32 bytes** — exactly half a cache line.
Minimum message size is therefore **32 bytes**; messages shorter than this
MUST be rejected as malformed.

---

## 4. Frame Header (8 bytes)

The frame header provides transport-level framing. It is designed to be
processable by hardware (FPGA/SmartNIC) without understanding message content.

```
Offset  Size  Field           Description
------  ----  -----           -----------
0       2     magic           0x474D ("MG" in little-endian). MUST match.
2       1     flags           Bit flags (see below)
3       1     version         Wire protocol version. Current: 1.
4       4     message_size    Total message size in bytes (incl. frame header,
                              optional CRC32 trailer NOT counted)
```

### Flags byte

```
bit 0: has_auth_tag   — 1 = HMAC-SHA256 16-byte tag appended
bit 1: encrypted      — 1 = core + flex blocks are AES-128-GCM encrypted
bit 2: compressed     — 1 = flex block is LZ4-compressed
bit 3: has_flex       — 1 = flex block present (otherwise core-only)
bit 4: has_crc        — 1 = CRC32 trailer appended (4 bytes after body)
bit 5: has_replication — 1 = replication header follows frame (HA deployments)
bit 6-7: reserved
```

### Design Rationale
- `magic` at offset 0: hardware/FPGA instant framing without parsing state
- `version` at offset 3: decoder rejects unknown wire versions before touching body
- `message_size` as u32 at offset 4: unambiguous body length for fragmentation-aware transports
- `flags` byte: single branch to determine processing path

---

## 5. Message Header (24 bytes)

Application-level header present in every message. Follows the frame header
at offset 8.

```
Offset  Size  Type  Field             Description
------  ----  ----  -----             -----------
8       2     u16   schema_id         Schema identifier (0x0000 session, 0x0001 trading, 0x0002 market_data, …)
10      2     u16   message_type      Type within schema (e.g. NewOrder=0x01)
12      4     u32   sender_comp_id    Sender component ID
16      8     u64   sequence_num      Monotonic message sequence number
24      8     u64   correlation_id    Request/response linkage (0 = none)
```

### Design Rationale
- `schema_id + message_type` packed at offset 8: 4-byte dispatch key, one load
- `sequence_num` as u64 at offset 16: no practical wraparound, gap detection without body access
- `correlation_id` at offset 24: echoed by server onto handler responses so clients can match
  responses to in-flight requests (see [`correlation.rs`](../../src/rust/src/correlation.rs))
- **No wire-level `timestamp` field** — MGEP timestamps are per-message in the core block
  (e.g. `ExecutionReport.transact_time`). Clock discipline governs these per [§6](06-clock-discipline.md)
- Total combined header: 32 bytes. Fits in half a cache line.

---

## 6. Core Block (variable size, fixed layout per schema)

The core block contains fields that are accessed on the hot path.
Each message type defines its own core block layout with fixed field offsets.

**Rules:**
- All fields are at schema-defined fixed byte offsets
- Fields are naturally aligned (u16 at even offset, u32 at 4-byte, u64 at 8-byte)
- No variable-length data in core block
- Unused optional fields use sentinel null values (see Section 10)

### Example: NewOrderSingle Core Block

Core block begins at offset 32 (immediately after the 32-byte combined
header).

```
Offset  Size  Type  Field             Description
------  ----  ----  -----             -----------
32      8     u64   order_id          Exchange-assigned order ID (0 on submit,
                                      echoed back in ExecutionReport)
40      8     u64   client_order_id   Client-assigned unique ID. REQUIRED,
                                      MUST be non-zero. Used for idempotent
                                      retry — see §6 Order Reliability.
48      4     u32   instrument_id     Instrument numeric ID
52      1     u8    side              1=Buy, 2=Sell
53      1     u8    order_type        1=Market, 2=Limit, 3=Stop, 4=StopLimit
54      2     u16   time_in_force     1=Day, 2=GTC, 3=IOC, 4=FOK, 5=GTD
56      8     i64   price             Price × 10⁸ fixed-point (DECIMAL_NULL = i64::MIN)
64      8     i64   quantity          Quantity × 10⁸ (fractional shares/contracts OK)
72      8     i64   stop_price        Stop price × 10⁸ (DECIMAL_NULL if not applicable)
```

**Core block size for NewOrderSingle: 48 bytes**
**Total with headers (no flex, no auth): 80 bytes** (vs 200-400 bytes for FIX text equivalent)

Note: size grew from 40B in v0.1.0 to 48B in v0.2.0 with the addition of the
required `client_order_id` field for server-side idempotent retry. See
`CHANGELOG.md` `[0.2.0]` and `VERSIONING.md` Pre-1.0 Exception.

### Price Representation
Prices use **fixed-point i64 with 10^8 scaling factor** (8 decimal places).
- Covers all asset classes (equities, crypto with 8 decimals, FX with pip precision)
- Integer arithmetic only — no floating point errors
- Range: +/- 92,233,720,368.54775807 (sufficient for any financial instrument)
- NULL value: `i64::MIN` (0x8000000000000000)

---

## 7. Flex Block (variable size, indexed access)

The flex block provides schema evolution and extensibility. It uses a **field index**
approach inspired by FlatBuffers vtables but optimized for our use case.

### Structure

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| flex_count (u16) | field entries...            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| field data area                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Field Entry (4 bytes each)
```
Offset  Size  Field         Description
------  ----  -----         -----------
0       2     field_id      Field identifier (1-65535)
2       2     offset        Byte offset from start of field data area
```

### Field Data Format
Each field in the data area is prefixed with a 1-byte type tag:
```
Type Tag  Type          Size
--------  ----          ----
0x01      u8            1
0x02      u16           2
0x03      u32           4
0x04      u64           8
0x05      i8            1
0x06      i16           2
0x07      i32           4
0x08      i64           8
0x09      f64           8
0x0A      bool          1
0x0B      string        2 (length prefix) + N bytes (UTF-8)
0x0C      bytes         2 (length prefix) + N bytes
0x0D      decimal       8 (i64, same as price encoding)
0x0E      timestamp     8 (u64, nanos since epoch)
0x0F      group         4 (count u16 + entry_size u16) + N * entry_size
```

### Lookup Performance
- Field count is known from `flex_count`
- Field entries are sorted by `field_id`
- For <= 8 fields: linear scan (cache-friendly, ~10-20 ns)
- For > 8 fields: binary search (O(log n), ~20-40 ns)
- Flex fields are NOT on the hot path — they carry supplementary data

### Schema Evolution Rules
1. **Post-1.0:** Core block fields are NEVER removed or reordered (append-only for core). Pre-1.0, per `VERSIONING.md` Pre-1.0 Exception, core-block changes are allowed but MUST be documented in `CHANGELOG.md`.
2. Flex fields can be added in any schema version
3. Flex fields can be deprecated (decoders ignore unknown field_ids)
4. A field can be promoted from flex to core in a new major version (post-1.0) or a minor version (pre-1.0)

---

## 8. Auth Tag (16 bytes, optional)

When `flags.has_auth_tag` is set, the last 16 bytes of the message contain
an authentication tag.

### Authentication Modes

#### Mode 1: HMAC-SHA256 (truncated to 128-bit)
- Pre-shared key between participants
- HMAC computed over: frame header + message header + core block + flex block
- Tag: first 16 bytes of HMAC-SHA256 output
- **Overhead: ~200-500 ns** with AES-NI (SHA-NI on newer CPUs)

#### Mode 2: AES-128-GCM AEAD
- When `flags.encrypted` is set
- Key established via session handshake (X25519 ECDH + HKDF)
- Nonce: sequence_num (4 bytes) + sender_comp_id (2 bytes) + 6 zero bytes
- AAD (Additional Authenticated Data): frame header (always in plaintext)
- Encrypts: message header + core block + flex block
- Tag: 16-byte GCM authentication tag
- **Overhead: ~300-800 ns** with AES-NI hardware acceleration

#### Mode 3: No authentication
- For use within trusted networks (colocation, internal systems)
- `flags.has_auth_tag = 0`
- **Overhead: 0 ns**

### Security Level Selection
```
Level 0: No auth, no encryption     — trusted network (colo, IPC)
Level 1: HMAC auth, no encryption   — authenticated but readable (colo with audit)
Level 2: AEAD (encrypt + auth)      — full security (WAN, untrusted network)
```

Participants negotiate security level during session establishment.

---

## 9. Session Layer

MGEP defines a lightweight session layer for connection management.

### Session Messages (schema_id = 0x0000)

| message_type | Name | Direction | Purpose |
|-------------|------|-----------|---------|
| 0x01 | Negotiate | Client->Server | Initiate session, propose parameters |
| 0x02 | NegotiateResponse | Server->Client | Accept/reject, confirm parameters |
| 0x03 | Establish | Client->Server | Start sequenced messaging |
| 0x04 | EstablishAck | Server->Client | Confirm session established |
| 0x05 | Heartbeat | Bidirectional | Keepalive |
| 0x06 | RetransmitRequest | Either | Request message replay (seq range) |
| 0x07 | Retransmission | Either | Replayed messages follow |
| 0x08 | Terminate | Either | Graceful session end |
| 0x09 | Sequence | Either | Next expected sequence number |

### Negotiate Message Core Block
```
Offset  Size  Type     Field               Description
------  ----  ----     -----               -----------
24      8     u64      session_id          Unique session identifier
32      4     u32      keepalive_ms        Heartbeat interval in milliseconds
36      1     u8       security_level      0=none, 1=HMAC, 2=AEAD
37      1     u8       max_schema_version  Highest schema version supported
38      2     u16      max_message_size    Maximum message size in bytes
40      32    [u8;32]  public_key          X25519 public key (for ECDH, if security >= 2)
```

### Sequence Number Management
- 32-bit sequence numbers per direction (4 billion messages before wrap)
- Gap detection: if received seq > expected, request retransmission
- Heartbeat carries current sequence as implicit ack
- No complex resend logic — just range-based retransmit

---

## 10. Null Values (Sentinels)

Optional fields in the core block use sentinel values instead of presence bitmaps
(avoids the indirection of checking a bitmap before reading a field).

| Type | Null Sentinel | Notes |
|------|--------------|-------|
| u8 | 0xFF | |
| u16 | 0xFFFF | |
| u32 | 0xFFFFFFFF | |
| u64 | 0xFFFFFFFFFFFFFFFF | |
| i8 | -128 (0x80) | i8::MIN |
| i16 | -32768 (0x8000) | i16::MIN |
| i32 | -2147483648 (0x80000000) | i32::MIN |
| i64 | -9223372036854775808 (0x8000...) | i64::MIN |
| f64 | NaN (quiet NaN) | |

This matches SBE's approach and allows zero-cost null checks
(`value == SENTINEL` is a single comparison instruction).

---

## 11. Comparison With Existing Formats

### Wire Size (NewOrderSingle equivalent)

| Protocol | Size (bytes) | Notes |
|----------|-------------|-------|
| FIX 4.2 text | 250-400 | Tag-value ASCII |
| Protobuf | 60-90 | Varint encoding |
| SBE | 50-70 | Fixed layout |
| **MGEP** | **80** | 32 header + 48 core |
| **MGEP + auth** | **96** | + 16-byte auth tag |
| ITCH Add Order | 36 | No auth, no session, no idempotency |
| OUCH Enter Order | 47-49 | No auth |

### Expected Encode/Decode Performance

| Operation | SBE | MGEP (projected) | Protobuf | FIX text |
|-----------|-----|-------------------|----------|----------|
| Encode core | 50-150 ns | **30-80 ns** | 500-2000 ns | 2-10 us |
| Decode core | 50-150 ns | **20-50 ns** | 300-1000 ns | 5-50 us |
| Encode + HMAC | N/A | **250-600 ns** | N/A | N/A |
| Decode + verify | N/A | **250-600 ns** | N/A | N/A |

**Why MGEP core can be faster than SBE:**
1. No SBE header overhead (SBE has 8-byte message header + 4-byte block length per group)
2. Core block IS the struct — no wrapper layers
3. Encoder can be a single `memcpy` from a pre-populated struct
4. Natural alignment means no padding surprises

---

## 12. Message Type Catalog (Initial)

### Trading Messages (schema_id = 0x0001)

| message_type | Name | Direction |
|-------------|------|-----------|
| 0x01 | NewOrderSingle | Client->Exchange |
| 0x02 | OrderCancelRequest | Client->Exchange |
| 0x03 | OrderCancelReplaceRequest | Client->Exchange |
| 0x04 | OrderMassCancelRequest | Client->Exchange |
| 0x05 | ExecutionReport | Exchange->Client |
| 0x06 | OrderCancelReject | Exchange->Client |
| 0x07 | BusinessReject | Exchange->Client |

### Market Data Messages (schema_id = 0x0002)

| message_type | Name | Direction |
|-------------|------|-----------|
| 0x01 | OrderAdd | Exchange->Client |
| 0x02 | OrderModify | Exchange->Client |
| 0x03 | OrderDelete | Exchange->Client |
| 0x04 | OrderExecuted | Exchange->Client |
| 0x05 | Trade | Exchange->Client |
| 0x06 | BookSnapshot | Exchange->Client |
| 0x07 | InstrumentDefinition | Exchange->Client |
| 0x08 | TradingStatus | Exchange->Client |

---

## 13. Design Decisions Log

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Byte order | Little-endian | Big-endian (network order) | 99%+ of trading hardware is x86/ARM-LE |
| Price encoding | Fixed-point i64 * 10^8 | Decimal128, f64, BCD | Integer math, no FP errors, 8 decimals covers all assets |
| Null values | Sentinel values | Presence bitmap, Optional wrapper | Single comparison vs bitmap lookup + branch |
| Header size | 32 bytes (8 frame + 24 msg) | 16 bytes, 32 bytes | Half a cache line, carries dispatch + seq + correlation_id |
| Flex block | Field index + data area, capped at 32 fields | SBE-style groups, Protobuf-style varint | Sorted index enables binary search; cap bounds worst-case lookup |
| Auth tag | 16 bytes (128-bit) | 32 bytes (256-bit), variable | 128-bit is standard; fixed size = predictable; layered HMAC also available |
| Sequence numbers | 64-bit | 32-bit, 64-bit | No practical wraparound |
| Timestamp | u64 nanos per message body | Implicit from session, struct | PTP-discipline gate decides regulatory acceptability (see §6) |
