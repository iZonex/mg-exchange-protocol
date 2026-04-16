# MGEP — MG Exchange Protocol

Ultra-low-latency binary protocol for exchange trading. Zero-copy, FPGA-friendly, full exchange lifecycle.

## Why MGEP?

| | FIX | SBE | ITCH | **MGEP** |
|---|---|---|---|---|
| Decode speed | 5-50 μs | 50 ns | 50 ns | **< 1 ns** |
| Schema evolution | Breaks parsers | Append-only | None | **Core + optional** |
| Encryption | External TLS | None | None | **Built-in AES-GCM** |
| Full lifecycle | Yes | Encoding only | MD only | **Yes** |
| Zero external deps | N/A | N/A | N/A | **Yes** |

## Quick Start

```bash
# Build and test
cd src/rust
cargo test

# Run the exchange demo
cargo run --example client_server

# Generate Rust code from schemas
cargo run --bin mgep-codegen -- ../../schemas/trading.mgep

# Generate C headers
cargo run --bin mgep-codegen -- --c ../../schemas/trading.mgep > mgep_trading.h
```

## Schema Example

```
message NewOrderSingle {
    "Submit a new order to the exchange."

    order_id        id          required    "Exchange-assigned order ID"
    instrument_id   instrument  required
    side            Side        required
    price           price       nullable    "Required for limit orders"
    quantity        qty         required

    optional {
        account         string      "Trading account"
        client_order_id string      "Client-assigned order ID"
    }
}
```

No hex IDs, no padding, no C types. Human-readable schemas, machine-generated code.

## Wire Format

```
Frame Header (8 bytes):
  [0:2]   magic = 0x4D47 ("MG")
  [2]     flags (AUTH|ENC|COMP|FLEX|CRC|REPL|BATCH)
  [3]     version
  [4:8]   message_size (u32 LE)

Message Header (24 bytes):
  [8:10]  schema_id (u16 LE)
  [10:12] message_type (u16 LE)
  [12:16] sender_comp_id (u32 LE)
  [16:24] sequence_num (u64 LE)
  [24:32] correlation_id (u64 LE)

Core Block: fixed-offset fields at byte 32
Optional Block: flex fields (extensible, schema-evolved)
CRC32 Trailer: optional 4 bytes
```

Total header: 32 bytes — half a cache line.

## Schemas

| Schema | Messages | Coverage |
|---|---|---|
| **common** | — | Shared enums (Side, OrderType, ExecType) |
| **trading** | 11 | Order entry, execution, cancel, cross, rejects |
| **market_data** | 13 | Book updates, trades, OHLCV stats, subscriptions |
| **quotes** | 6 | RFQ, quotes, mass quote, IOI |
| **post_trade** | 7 | Trade capture, allocation, confirmation, settlement |
| **risk** | 9 | Positions, collateral, margin, liquidation |

## Transports

| Transport | Latency | Module |
|---|---|---|
| Shared memory (mmap) | 100-300 ns | `shmem.rs` |
| Raw TCP | 10-50 μs | `transport.rs` |
| UDP multicast | ~1 μs | `multicast.rs` |
| WebSocket binary | 50-100 μs | `websocket.rs` |

## Architecture

```
schemas/*.mgep          → Schema definitions (source of truth)
    ↓ mgep-codegen
src/rust/src/
    ├── types.rs        — Decimal, Timestamp
    ├── frame.rs        — 8-byte frame header with magic + CRC
    ├── header.rs       — 24-byte message header with correlation ID
    ├── messages.rs     — 48 zero-copy message structs
    ├── codec.rs        — Generic encode/decode + 48-arm dispatch
    ├── flex.rs         — Extensible optional fields
    ├── session.rs      — State machine, reconnect, replay journal
    ├── auth.rs         — HMAC-SHA256
    ├── crypto.rs       — AES-128-GCM (pluggable)
    ├── transport.rs    — TCP with framing
    ├── websocket.rs    — WebSocket binary transport
    ├── multicast.rs    — UDP multicast + gap detection
    ├── shmem.rs        — Shared memory ring buffer
    ├── batch.rs        — Message batching
    ├── replication.rs  — Raft-native replication header
    ├── multiplex.rs    — Stream multiplexing
    ├── compress.rs     — LZ4 compression
    ├── connection.rs   — Auto-reconnect client
    ├── server.rs       — Multi-client server
    ├── async_server.rs — Non-blocking reactor server
    ├── reactor.rs      — kqueue/epoll event loop
    ├── orderbook.rs    — Price-time priority matching engine
    ├── pool.rs         — Lock-free buffer pool
    ├── builder.rs      — Fluent message builders
    ├── inspect.rs      — Protocol inspector
    ├── validate.rs     — Field validation
    ├── metrics.rs      — Latency/throughput counters
    └── error.rs        — Error types
```

## Security

Three levels, per-session:

- **Level 0**: None (colocation, IPC)
- **Level 1**: HMAC-SHA256 message authentication
- **Level 2**: AES-128-GCM authenticated encryption

Session features: cancel-on-disconnect, CRC checksums, compression negotiation.

## Code Generation

```bash
# Rust structs
mgep-codegen schemas/trading.mgep

# C headers with packed structs
mgep-codegen --c schemas/trading.mgep

# Full Rust module from all schemas
mgep-codegen --module schemas/*.mgep
```

## License

Apache-2.0
