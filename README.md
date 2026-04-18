# MGEP — MG Exchange Protocol

Ultra-low-latency binary protocol for exchange trading. Zero-copy core-block decode, explicit reliability primitives, built-in AEAD security.

> **Status: v0.2.0-alpha.** Greenfield research project, **not** production-ready. The wire format and Rust reference implementation are converging toward the v1.0 spec; server dispatch integration (rate limiting, idempotent order submission, cancel-on-disconnect enforcement, key rotation handshake) is in progress. See [Production Readiness](#production-readiness) below for an honest checklist.

## Why MGEP?

| | FIX | SBE | ITCH | **MGEP** |
|---|---|---|---|---|
| Core-block decode | 5-50 μs | 50 ns | 50 ns | **~1 ns (zero-copy cast)** |
| Schema evolution | Breaks parsers | Append-only | None | **Core + bounded flex** |
| Encryption | External TLS | None | None | **AES-128-GCM + epoch rotation** |
| Idempotent order entry | Via ClOrdID | N/A | Via ClOrdID | **ClOrdID required in core block** |
| Snapshot / gap-fill | Custom | Custom | Rich | **Built-in BookSnapshot flow** |
| Zero external deps (Rust) | N/A | N/A | N/A | **Yes** |

Decode figures are for the zero-copy core-block cast only — full message encode (header + core + flex + CRC) benchmarks at ~20–40 ns, still ahead of SBE on comparable hardware. See `benches/` for reproducible numbers.

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

    order_id        id          required    "Exchange-assigned order ID (0 on submit)"
    client_order_id id          required    "Client-assigned ID; server dedups retries"
    instrument_id   instrument  required
    side            Side        required
    order_type      OrderType   required
    time_in_force   TimeInForce
    price           price       nullable    "Required for limit orders"
    quantity        qty         required
    stop_price      price       nullable

    optional {
        account         string      "Trading account"
        client_tag      string      "Free-form client tag"
        # Regulatory (MiFID II / RegNMS)
        lei             string      "Legal Entity Identifier"
        order_capacity  string
    }
}
```

No hex IDs, no padding, no C types. Human-readable schemas, machine-generated code.
Optional-section fields are capped at 32 per message — preserves zero-copy decode guarantees under adversarial input.

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
| **common** | — | Shared enums (Side, OrderType, ExecType, TradingPhase) |
| **trading** | 11 | Order entry with ClOrdID idempotency, execution, cancel, cross, rejects |
| **market_data** | 18 | Book updates, trades, OHLCV stats, subscriptions, snapshot/recovery flow |
| **quotes** | 6 | RFQ, quotes, mass quote, IOI |
| **post_trade** | 7 | Trade capture, allocation, confirmation, settlement |
| **risk** | 9 | Positions, collateral, margin, liquidation |

## Transports

| Transport | Latency | Module | Status |
|---|---|---|---|
| Raw TCP | 10-50 μs | `transport.rs` | **Stable** |
| UDP multicast | ~1 μs | `multicast.rs` | **Stable** (gap detection + snapshot recovery) |
| Shared memory (mmap) | 100-300 ns | `shmem.rs` | **Alpha** — SPSC only; feature-gated |
| WebSocket binary | 50-100 μs | `websocket.rs` | **Experimental** — feature-gated |

Alpha / experimental transports sit behind the `experimental-transports` cargo feature,
which is **on by default** so existing users aren't surprised. Production deployments
that want a minimal attack surface should build with `--no-default-features` — the
stable TCP + multicast path compiles and tests cleanly without them.

## Architecture

```
schemas/*.mgep          → Schema definitions (source of truth)
    ↓ mgep-codegen
src/rust/src/
    # Wire-format core
    ├── types.rs                  — Decimal, Timestamp, shared enums (Side, ExecType, …)
    ├── frame.rs                  — 8-byte frame header with magic + CRC32
    ├── header.rs                 — 24-byte message header with correlation ID
    ├── messages.rs               — 53 zero-copy message structs
    ├── core_macro.rs             — `define_core!` macro for wire-struct boilerplate
    ├── codec.rs                  — Generic encode/decode + MessageKind dispatch
    ├── flex.rs                   — Extensible optional fields (32-field cap)
    ├── builder.rs                — Fluent message builders (OrderBuilder, …)
    ├── inspect.rs                — Protocol inspector (human-readable dump)
    ├── validate.rs               — Field validation framework
    ├── error.rs                  — Shared error types

    # Session layer + reliability
    ├── session.rs                — State machine, sequence tracking, replay journal w/ watermark
    ├── snapshot.rs               — BookSnapshotGenerator + client RecoveryCoordinator
    ├── idempotency.rs            — ClOrdID dedup store (time + capacity bounded)
    ├── cancel_on_disconnect.rs   — Per-session order tracking + grace period
    ├── rate_limit.rs             — Token-bucket L7 limiter (session + account buckets)
    ├── correlation.rs            — Request/response matching primitives

    # Security
    ├── auth.rs                   — HMAC-SHA256 message authentication
    ├── crypto.rs                 — AES-128-GCM primitive (AES-NI + pure-Rust)
    ├── crypto_session.rs         — Epoch rotation, nonce enforcement, HSM KeyProvider trait
    ├── aesni.rs                  — AES-NI hardware-accelerated path

    # Risk, compliance, operations
    ├── risk_checks.rs            — Pre-trade notional/qty/position/collar/STP/throttle
    ├── audit.rs                  — AuditRecord chain + AuditGate (clock-quality gated)
    ├── kill_switch.rs            — Four-scope halt registry + order-entry gate
    ├── drop_copy.rs              — Read-only compliance fanout channel
    ├── entitlements.rs           — Depth/latency tier market-data authorization
    ├── clock_discipline.rs       — PTP/NTP source + ClockQuality taxonomy
    ├── linux_ptp_probe.rs        — Linux clock_adjtime/PHC probe (feature-gated)

    # High availability
    ├── ha.rs                     — Raft-style leader election + log replication
    ├── ha_replication.rs         — Fencing token + StateStreamer/Applier + FailoverDecision
    ├── replication.rs            — Raft-native replication header
    ├── wal.rs                    — Write-ahead log (journal persistence)

    # Client-side
    ├── connection.rs             — Auto-reconnect client wrapping Session + transport
    ├── client_state.rs           — OrderManager + PositionTracker + SubscriptionManager
    ├── client_errors.rs          — Typed ClientError over BusinessReject flex codes

    # Server framework
    ├── server.rs                 — Multi-client server (all the above wired in)
    ├── async_server.rs           — Non-blocking reactor server
    ├── reactor.rs                — kqueue/epoll event loop

    # Transports
    ├── transport.rs              — TCP with framing
    ├── multicast.rs              — UDP multicast + GapDetector
    ├── websocket.rs              — WebSocket binary (experimental, feature-gated)
    ├── shmem.rs                  — Shared memory SPSC ring (alpha, feature-gated)

    # Gateways
    ├── fix_gateway.rs            — FIX 4.4 subset translation (Logon/NewOrder/ExecReport)

    # Performance + infrastructure
    ├── batch.rs                  — Message batching
    ├── compress.rs               — LZ4 compression
    ├── multiplex.rs              — Stream multiplexing
    ├── pool.rs                   — Lock-free buffer pool
    ├── metrics.rs                — Latency/throughput/error counters

    # Code generation (schema → Rust / C)
    └── codegen/                  — Parser + Rust/C generators (`mgep-codegen` binary)
```

## Security

Three levels, per-session:

- **Level 0**: None (colocation, IPC)
- **Level 1**: HMAC-SHA256 message authentication
- **Level 2**: AES-128-GCM authenticated encryption with **epoch-based key rotation**

Key rotation triggers: message count, byte count, wall-clock duration, or explicit
admin/compromise signal. Nonces are `(epoch, sender_comp_id, seq_in_epoch)` — strict
monotonicity enforced on both outbound and inbound, replay attacks rejected at the
cipher layer. Master key lives behind a pluggable `KeyProvider` trait so production
deployments drop in an HSM / KMS adapter.

## Building a terminal on MGEP

See [`docs/guide/building-a-terminal.md`](docs/guide/building-a-terminal.md) for a
10-step walkthrough: connect, submit orders with ClOrdID idempotency, track
state with `OrderManager`/`PositionTracker`, handle gaps via
`RecoveryCoordinator`, parse typed rejects, reconnect safely.

For local dev, run the **sandbox venue** which accepts any credentials and
echoes `ExecutionReport(New)` for every submission:

```bash
cd src/rust
cargo run --bin mgep-sandbox -- --port 9443
```

Point your terminal at `127.0.0.1:9443` and iterate without needing a real
venue.

## Language bindings

| Language | Location | Coverage | Tests |
|---|---|---|---|
| **Rust** | `src/rust/` | Full (reference implementation) | 353 |
| **C** | `bindings/c/` | Wire format, encode/decode, flex parser | 38 |
| **C++** | `bindings/cpp/` | Header-only C++20 wrapper over C | 26 |
| **Java** | `bindings/java/` | Pure-JVM via `ByteBuffer` (JDK 17+) | 22 |
| **C#** | `bindings/csharp/` | Pure-managed via `StructLayout` (.NET 8) | — |
| **TypeScript** | `bindings/typescript/` | `DataView`/`Uint8Array` (Node/Deno/Bun/browser) | 30 |
| **Python** | `bindings/python/` | ctypes, cross-language wire-compat test | — |

Every binding covers the core message set (NewOrderSingle, ExecutionReport,
BusinessReject, BookSnapshot*, ClockStatus) plus the flex-field parser so
terminal vendors can consume rich reject reasons (`rate_limited:...`,
`halt:...`, `risk:...`) without parsing raw bytes.

## Pre-trade risk & compliance

The venue applies layered pre-trade controls before any order reaches the
matching engine:

| Check | Module | Enforced at |
|---|---|---|
| Rate limit (msgs/bytes, session + account) | `rate_limit` | dispatch |
| Kill-switch (market / instrument / account / session) | `kill_switch` | server gate |
| Idempotent ClOrdID (duplicate retry → replay cached response) | `idempotency` | server gate |
| Position limit / notional cap / quantity cap | `risk_checks` | server gate |
| Fat-finger price collar | `risk_checks` | server gate |
| Self-trade prevention | `risk_checks` | server gate |

Compliance visibility is provided via the **drop-copy channel** (`drop_copy`
module): read-only real-time audit fan-out to authorized subscribers,
scope-filtered by account/instrument/venue-wide and role-filtered
(ComplianceOfficer sees kill-switch events; traders do not). See
[`docs/spec/07-audit-and-halts.md`](docs/spec/07-audit-and-halts.md) for
retention + storage requirements (WORM, Merkle-chained audit).

## Reliability

Operational primitives that make the protocol safe for real exchange deployment:

- **Idempotent order entry** — `client_order_id` is required in the core block; the
  server deduplicates retries within a sliding time + capacity window and returns the
  original `ExecutionReport` byte-exact.
- **Market data snapshot + gap-fill** — clients detect sequence gaps via `GapDetector`,
  request a `BookSnapshot` over the TCP recovery channel, buffer live updates during
  recovery, and replay only the delta once the snapshot applies (CRC-validated).
- **Replay journal with watermarks** — `EstablishAck` carries `journal_low_seq_num` so
  reconnecting clients know up front whether a retransmit can cover the gap, or
  whether they must fall back to snapshot recovery. No more silent message loss.
- **Cancel-on-disconnect** — negotiated flag drives a per-session order tracker; on
  transport loss / peer timeout / explicit terminate, pending orders are canceled
  after a configurable grace period (which a clean reconnect aborts).
- **L7 rate limiting** — hierarchical token buckets (per-session and per-account,
  in messages/sec and bytes/sec). Rejections surface as `BusinessReject` with a
  specific dimension code; throttle mode is available for backpressure.

## Production Readiness

| Area | Status |
|---|---|
| Wire format (frame + 32-byte header + core + flex) | Stable |
| Rust reference impl (types, codec, session, crypto) | Stable |
| Zero-copy decode benchmarks | Verified |
| TCP + UDP multicast transports | Stable |
| Shared memory transport | Alpha |
| WebSocket transport | Experimental |
| ClOrdID dedup, snapshot recovery, COD, rate limit, key rotation (primitives) | Implemented + tested |
| Server dispatch wiring for the above | **In progress** |
| Regulatory audit trail + kill-switch | Not started |
| PTP / hardware-timestamp integration | Not started |
| Language bindings beyond Rust | Python (ctypes) only |
| Conformance suite / interop with non-Rust clients | Not started |

**Do not deploy MGEP to a customer-facing exchange.** This is a reference implementation
for protocol research; it demonstrates how the reliability primitives should be shaped,
not a turn-key trading backbone.

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
