# MGEP v1.0 Protocol Specification

## Status: Draft

## 1. Introduction

MG Exchange Protocol (MGEP) is a binary protocol for exchange trading systems. It provides zero-copy message encoding, authenticated encryption, session management with sequence tracking, and a schema language for code generation.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2. Wire Format

### 2.1 Byte Order

All multi-byte integers MUST be encoded in little-endian byte order.

### 2.2 Frame Header (8 bytes)

Every MGEP message begins with an 8-byte frame header:

```
Offset  Size  Type    Field          Description
0       2     u16     magic          MUST be 0x474D (ASCII "MG" in LE)
2       1     u8      flags          Bitfield (see 2.4)
3       1     u8      version        Protocol version. MUST be 1.
4       4     u32     message_size   Total size in bytes including this header,
                                     excluding optional CRC32 trailer.
```

An implementation MUST reject any message where `magic != 0x474D`.

An implementation MUST reject any message where `version` is greater than the maximum version it supports.

`message_size` MUST be at least 32 (minimum header size). An implementation MUST reject messages where `message_size < 32` or `message_size` exceeds the configured maximum (default 65536).

### 2.3 Message Header (24 bytes)

Immediately following the frame header:

```
Offset  Size  Type    Field            Description
8       2     u16     schema_id        Schema identifier (message family)
10      2     u16     message_type     Message type within schema
12      4     u32     sender_comp_id   Sender component identifier
16      8     u64     sequence_num     Monotonically increasing sequence number
24      8     u64     correlation_id   Client-assigned ID echoed in responses.
                                       0 if not applicable.
```

### 2.4 Flags Byte

```
Bit   Mask   Name             Description
0     0x01   HAS_AUTH_TAG     16-byte HMAC or GCM tag appended after payload
1     0x02   ENCRYPTED        Payload is AES-128-GCM encrypted
2     0x04   COMPRESSED       Payload is LZ4 compressed
3     0x08   HAS_FLEX         Optional (flex) block is present after core block
4     0x10   HAS_CRC          4-byte CRC32 trailer appended after payload
5     0x20   HAS_REPLICATION  Replication header precedes this frame
6     0x40   BATCH            This frame contains multiple batched messages
7     —      Reserved         MUST be 0
```

### 2.5 Core Block

The core block begins at byte offset 32 (CORE_BLOCK_OFFSET). Its layout is fixed per (schema_id, message_type) pair and MUST NOT change after release.

All fields are naturally aligned:
- u8 fields: 1-byte aligned
- u16 fields: 2-byte aligned
- u32 fields: 4-byte aligned
- u64/i64 fields: 8-byte aligned

Implementations insert padding bytes as needed. Core block total size MUST be a multiple of 8 bytes.

### 2.6 Optional (Flex) Block

Present only when `HAS_FLEX` flag is set. Immediately follows the core block.

```
Offset  Size  Type    Field
0       2     u16     field_count     Number of field entries
2       4*N   entry[] field_entries   Sorted by field_id ascending
2+4*N   var   u8[]    field_data      Raw field data
```

Each field entry:
```
Offset  Size  Type    Field
0       2     u16     field_id        Unique field identifier (1–65535)
2       2     u16     data_offset     Byte offset into field_data area
```

Field data is prefixed with a 1-byte type tag:
```
Tag    Type        Payload
0x01   u8          1 byte
0x02   u16         2 bytes (LE)
0x03   u32         4 bytes (LE)
0x04   u64         8 bytes (LE)
0x08   i64         8 bytes (LE)
0x0B   string      2-byte length (LE) + UTF-8 data
0x0C   bytes       2-byte length (LE) + raw data
0x0D   decimal     8 bytes (i64 LE, fixed-point)
0x0E   timestamp   8 bytes (u64 LE, nanoseconds)
```

Receivers MUST ignore field IDs they do not recognize. This enables forward-compatible schema evolution.

### 2.7 CRC32 Trailer

Present only when `HAS_CRC` flag is set. 4 bytes appended after the payload (after flex block if present, after auth tag if present).

CRC32 is computed over all bytes from offset 0 to the end of payload (before the CRC itself). Uses the ISO 3309 / ITU-T V.42 polynomial (same as Ethernet).

CRC32 provides error detection only, NOT integrity protection. For integrity, use HMAC-SHA256 (security level 1) or AES-128-GCM (security level 2).

## 3. Data Types

### 3.1 Decimal

Fixed-point signed integer: `value = raw_i64 / 100,000,000` (scale factor 10^8).

This provides 8 decimal places of precision with range ±92,233,720,368.54775807.

**NULL sentinel:** `i64::MIN` (0x8000000000000000). Implementations MUST check for NULL before interpreting the value.

### 3.2 Timestamp

Unsigned 64-bit integer representing nanoseconds since Unix epoch (1970-01-01T00:00:00Z).

**NULL sentinel:** `u64::MAX` (0xFFFFFFFFFFFFFFFF).

Clock source SHOULD be `clock_gettime(CLOCK_REALTIME)` or equivalent. For regulated venues, timestamps MUST be synchronized to UTC within 100 microseconds per MiFID II RTS 25.

### 3.3 Enumerations

Enum values are encoded as unsigned integers (typically u8). Value 0 is reserved and MUST NOT be used — it indicates "not set" or invalid.

## 4. Schema Identifiers

| ID | Schema | Description |
|----|--------|-------------|
| 0x0000 | session | Session control messages |
| 0x0001 | trading | Order entry and execution |
| 0x0002 | market_data | Order book, trades, subscriptions |
| 0x0003 | quotes | Pre-trade quoting and RFQ |
| 0x0004 | post_trade | Trade capture, allocation, settlement |
| 0x0005 | risk | Positions, collateral, margin |
| 0x0006–0x00FF | — | Reserved for future MGEP use |
| 0x0100–0xFFFE | — | User-defined schemas |
| 0xFFFF | batch | Batch message wrapper |

## 5. Session Layer

### 5.1 State Machine

```
Client:                              Server:
Disconnected                         Disconnected
    │ Negotiate →                        │ ← Negotiate
    ▼                                    ▼
Negotiating                          Negotiating
    │ ← NegotiateResponse                │ NegotiateResponse →
    ▼                                    ▼
Negotiated                           Negotiated
    │ Establish →                        │ ← Establish
    ▼                                    ▼
Establishing                         Establishing
    │ ← EstablishAck                     │ EstablishAck →
    ▼                                    ▼
Active ◄──────────────────────────► Active
    │                                    │
    ▼ Terminate                          ▼ Terminate
Terminating                          Terminating
```

Implementations MUST enforce state transitions. Calling an operation in the wrong state MUST return an error.

### 5.2 Sequence Numbers

- Sequence numbers are u64 and start at 1.
- Each side maintains independent outbound and expected inbound sequences.
- A receiver detects gaps when `received_seq > expected_seq`.
- On gap detection, the receiver SHOULD send a RetransmitRequest.
- Duplicate sequences (received_seq < expected_seq) SHOULD be silently ignored.

### 5.3 Heartbeat

Implementations MUST send a Heartbeat message if no other message has been sent within the keepalive interval (negotiated during session setup, default 1000ms).

An implementation SHOULD consider the peer timed out if no message is received within 3x the keepalive interval.

### 5.4 Session Flags

Negotiated during Negotiate/NegotiateResponse:

| Bit | Name | Description |
|-----|------|-------------|
| 0x01 | CANCEL_ON_DISCONNECT | Cancel all open orders on session loss |
| 0x02 | ENABLE_CRC | Attach CRC32 to all messages |
| 0x04 | ENABLE_COMPRESSION | Compress large messages |

## 6. Security

### 6.1 Level 0: None

No authentication or encryption. For trusted networks and IPC only.

### 6.2 Level 1: HMAC-SHA256

Message authentication using truncated HMAC-SHA256 (16-byte tag).

HMAC input: bytes from offset 8 to end of payload (excludes frame header and tag).

The tag is appended after the payload. Frame header `message_size` includes the tag. `HAS_AUTH_TAG` flag MUST be set.

### 6.3 Level 2: AES-128-GCM

Authenticated encryption of the payload.

**Key derivation:**
```
key = HKDF-SHA256(salt=session_id[8B], IKM=pre_shared_key, info="mgep-aes128"||0x01)[0:16]
```

**Nonce (12 bytes):**
```
nonce[0:4]  = session_id truncated to 4 bytes (LE)
nonce[4:8]  = sender_comp_id (u32 LE)
nonce[8:12] = sequence_num truncated to 4 bytes (LE)
```

Nonce uniqueness is guaranteed by monotonic sequence numbers. After SequenceReset, implementations MUST derive a new key using `derive_key_with_epoch()` to prevent nonce reuse.

**Encrypt scope:** Bytes from offset 8 to end of payload (message header + core + flex). Frame header stays cleartext for transport routing.

**Wire format:** `[FrameHeader 8B cleartext][encrypted payload][GCM tag 16B]`

Both `HAS_AUTH_TAG` and `ENCRYPTED` flags MUST be set.

Implementations MUST verify the GCM tag before processing the decrypted payload.

## 7. Message Encoding

### 7.1 Generic Encode

```
1. Construct FullHeader (32 bytes) with magic, flags, schema_id, message_type,
   sender_comp_id, sequence_num, correlation_id, message_size.
2. Write core block at offset 32.
3. If optional fields present: write flex block, set HAS_FLEX flag.
4. If security level 1: compute HMAC, append tag, set HAS_AUTH_TAG.
5. If security level 2: encrypt payload, append GCM tag, set flags.
6. If CRC enabled: compute CRC32, append 4 bytes, set HAS_CRC.
7. Send the complete message.
```

### 7.2 Generic Decode

```
1. Read frame header (8 bytes). Validate magic and version.
2. Read message_size. Validate range.
3. Read remaining bytes (message_size - 8).
4. If HAS_CRC: verify and strip CRC32 trailer.
5. If ENCRYPTED: decrypt payload, verify GCM tag.
6. If HAS_AUTH_TAG and not ENCRYPTED: verify HMAC tag.
7. Read message header at offset 8.
8. Dispatch by (schema_id, message_type) to appropriate core block decoder.
9. If HAS_FLEX: parse flex block after core block.
```

## 8. Transport

MGEP is transport-agnostic. The reference implementation supports:

- **TCP:** Length-prefixed framing using `message_size` from frame header.
- **UDP Multicast:** One datagram per message. Max 1472 bytes (MTU safe).
- **WebSocket:** Binary frames (opcode 0x02). One WS frame per MGEP message.
- **Shared Memory:** Lock-free ring buffer with 8-byte aligned entries.

TCP implementations MUST set `TCP_NODELAY` to minimize latency.

## 9. Conformance

An implementation is MGEP-compliant if:

1. It correctly encodes and decodes all mandatory message types for its schema.
2. Its wire output matches the conformance test vectors byte-for-byte.
3. It enforces session state machine transitions.
4. It correctly implements the security level it claims to support.
5. It handles unknown message types by returning Unknown (not crashing).
6. It handles truncated messages by returning Malformed (not crashing).
7. It ignores unknown flex field IDs without error.

## Appendix A: Message Type Quick Reference

### Trading (0x0001)
| Type | Name |
|------|------|
| 0x01 | NewOrderSingle |
| 0x02 | OrderCancelRequest |
| 0x03 | OrderCancelReplaceRequest |
| 0x04 | OrderMassCancelRequest |
| 0x05 | ExecutionReport |
| 0x06 | OrderCancelReject |
| 0x07 | OrderStatusRequest |
| 0x08 | OrderMassCancelReport |
| 0x09 | NewOrderCross |
| 0x0A | OrderMassStatusRequest |
| 0x10 | Reject |
| 0x11 | BusinessReject |

### Session (0x0000)
| Type | Name |
|------|------|
| 0x01 | Negotiate |
| 0x02 | NegotiateResponse |
| 0x03 | Establish |
| 0x04 | EstablishAck |
| 0x05 | Heartbeat |
| 0x06 | RetransmitRequest |
| 0x07 | Retransmission |
| 0x08 | Terminate |
| 0x0B | SequenceReset |
| 0x0C | NotApplied |
| 0x0D | TestRequest |
