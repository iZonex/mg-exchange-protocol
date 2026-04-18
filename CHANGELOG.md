# Changelog

All notable changes to the MGEP protocol will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [0.2.0] — 2026-04-18

Production-hardening release. Substantial wire-format **breaking changes** (pre-1.0,
allowed under the pre-1.0 exception in `VERSIONING.md`), server-side reliability
primitives fully wired into the dispatch path, six new language bindings, and two
new spec chapters.

### ⚠️ Breaking wire changes

Pre-1.0 wire changes — existing v0.1.0 receivers WILL mis-decode v0.2.0 senders
and vice versa. Bump all peers simultaneously. After v1.0.0 the freeze rule in
`VERSIONING.md` Rule 1 applies.

- `NewOrderSingleCore` grew **40 → 48 bytes**. New required field `client_order_id: u64`
  inserted after `order_id` (offset 8). Used for idempotent retry; non-zero required.
  The old optional-flex `client_order_id: string` (flex field id 2) is removed;
  remaining flex fields renumbered (`client_tag` now 2, not 3).
- `ExecutionReportCore` grew **80 → 88 bytes**. New required field `client_order_id: u64`
  at offset 8. Server echoes the originating order's `client_order_id` so clients
  can correlate partial fills without relying on `order_id` alone.
- `OrderCancelRejectCore` grew **24 → 32 bytes**. New required field `client_order_id: u64`
  at offset 8.
- `EstablishAckCore` grew **16 → 24 bytes**. New required field `journal_low_seq_num: u64`
  at offset 16. Server reports the lowest replay-journal seq it can retransmit so
  reconnecting clients can decide between retransmit vs snapshot recovery. The
  silently-broken `_pad: u32` field (struct was actually 24 bytes, `SIZE = 16` was
  wrong) is fixed.
- `SessionFlags` is now persistently stored on the `Session` and plumbed through
  `Negotiate` / `NegotiateResponse`. Previously the flag was never captured post-
  handshake; `CANCEL_ON_DISCONNECT` is now actually enforced.

### New message types

All additive; receivers that don't know them should log and ignore (per `VERSIONING.md`
Rule 4).

- Session schema (`0x0000`):
  - `ClockStatus` `0x0E` — 40 bytes. Broadcast 1 Hz + on quality transition. §6.
  - `KeyRotationRequest` `0x0F` — 16 bytes. Initiates AES-GCM epoch rotation.
  - `KeyRotationAck` `0x10` — 16 bytes. Peer confirms rotation readiness.
- Market-data schema (`0x0002`):
  - `BookSnapshotRequest` `0x30` — 16 bytes. Client requests full-book snapshot
    for gap recovery.
  - `BookSnapshotBegin` `0x31` — 40 bytes. Snapshot stream header with
    `last_applied_seq` and `snapshot_id`.
  - `BookSnapshotLevel` `0x32` — 40 bytes. Per-price-level entry.
  - `BookSnapshotEnd` `0x33` — 32 bytes. Stream terminator with CRC32 over level
    payloads + level count.
  - `BookSnapshotReject` `0x34` — 16 bytes. Server refuses snapshot with reason.

### Reliability primitives (new)

All implemented as standalone modules with full test coverage, then wired into the
server dispatch path:

- **Market-data gap-fill**: `SnapshotGenerator` + `SnapshotAssembler` +
  `RecoveryCoordinator` enable client-side snapshot-based recovery when the
  sequence gap exceeds the replay journal window. Slow-consumer guard on the
  server prevents backlog from blocking the matching hot path.
- **Order idempotency**: `IdempotencyStore` dedupes `(session_id, client_order_id)`
  with a time + capacity window. Retries return the original `ExecutionReport`
  byte-exact. Zero ClOrdID is reserved — submission rejected with a
  `BusinessReject` tagged `invalid_client_order_id:zero_reserved`.
- **Cancel-on-disconnect**: `CancelOnDisconnectManager` tracks orders per session
  and, on transport loss / peer timeout / explicit terminate, cancels them after
  a configurable grace period (clean reconnect within grace aborts cancellation).
- **Replay journal watermarks**: Journal now tracks `(low, high)` water marks;
  `JournalLookup` distinguishes *never-existed* from *overwritten-by-wrap*.
  `handle_retransmit_request_v2` returns an explicit `JournalExhausted` outcome
  that the server maps to `SequenceReset(reason=JournalExhausted)`.
- **L7 rate limiting**: `RateLimiter` with hierarchical token buckets (session +
  account, messages + bytes). Rejections emit `BusinessReject` with
  `business_reason=1` and flex `text = dimension.as_code()` — no more
  silent-drop-by-stop-reading.
- **AES-GCM nonce safety + key rotation**: `SessionCipher` enforces strict
  monotonic seq within an epoch, refuses reuse. Rotation policy fires on message
  count / byte count / duration. Two-phase handshake via `KeyRotationRequest` /
  `Ack`. `KeyProvider` trait abstracts the master key source for HSM integration.
- **Request/response correlation**: `CorrelationIdGenerator` + `CorrelationTable`
  + server-side echo of incoming `correlation_id` onto handler responses.

### Compliance & risk (new)

- **Clock discipline**: `ClockMonitor` + `ClockSourceProbe` trait track the host
  clock's PTP/NTP/monotonic source and MiFID II `ClockQuality` (RegulatoryGrade
  / OperationalGrade / BestEffort / Unreliable). Audit emission is gated on
  `RegulatoryGrade` for regulator-bound events. `LinuxPtpProbe` shipped for
  Linux hosts behind the `linux-ptp` cargo feature.
- **Audit trail**: `AuditRecord` (80-byte `#[repr(C)]`) with monotonic
  `audit_seq`, `prev_digest` hash chain, `clock_quality` captured at emission,
  role-based authz on privileged events (kill-switch family). `AuditLogger`
  trait for pluggable WORM / Kafka / DB sinks.
- **Kill-switch**: `KillSwitchState` with four scopes (MarketWide / Instrument /
  Account / Session), role-gated halt/resume, most-specific-first gate at order
  entry. `BusinessReject` codes pin the scope so clients can back off
  correctly.
- **Pre-trade risk**: `PreTradeRiskChecker` with notional cap, quantity cap,
  position limit, fat-finger price collar, submission throttle, and
  self-trade prevention. Rejection codes stable across the wire.
- **Drop-copy channel**: `DropCopyPublisher` fans audit records to authorized
  read-only subscribers. Scope-filtered (All / Account / Instrument / AccountSet),
  role-filtered (privileged events only to privileged roles), slow-consumer
  eviction.
- **Market-data entitlements**: `EntitlementRegistry` with depth/latency tiers,
  per-instrument filters, trades-only grants, time-bounded expiry, additive
  multi-grant combination.

### High availability (new)

- `FencingToken` monotonic id for takeover ordering.
- `StateStreamer` / `StateApplier` with split-brain protection + monotonic
  delta-seq enforcement.
- `FailoverDecision` watchdog with configurable miss-threshold.

### Gateways & ecosystem

- **FIX 4.4 subset**: `fix_gateway.rs` provides a minimal translation layer
  (Logon, Heartbeat, NewOrderSingle, ExecutionReport, Cancel) with ClOrdID
  string → u64 interning. Not a full FIX engine — bridge pattern only.
- **`mgep-sandbox` binary**: standalone fake venue for terminal-vendor
  integration testing. Accepts any credentials, echoes ExecutionReport(New),
  snapshot provider pre-seeded.

### Language bindings (new)

| Language | Coverage | Tests |
|---|---|---|
| C11 | 8 message types + encoder + flex parser | 38 |
| C++20 | header-only wrapper over C | 26 |
| Java 17+ | pure-JVM via ByteBuffer | 22 |
| C# (.NET 8) | pure-managed via StructLayout | shipped |
| TypeScript | DataView/Uint8Array (Node/Deno/Bun/browser) | 30 |
| Python | expanded from 2 → 11 message types | cross-language wire test |

### Tightened invariants

- Flex block hard-capped at 32 fields. Reader clamps hostile `count`. Writer's
  fallible `try_put_*` API returns `FlexError::TooManyFields` past the cap.
  Zero-copy + sub-microsecond lookup guarantee no longer rests on client
  politeness.
- `AES-GCM` nonce layout changed: `[epoch 4B][sender_comp_id 4B][seq_in_epoch 4B]`.
  Epoch in the nonce is defense-in-depth against bugs that might reuse a key.
- `client_order_id == 0` is reserved. Submissions with a zero value are rejected
  loudly with `BusinessReject` rather than silently accepted.

### Server integration (wiring)

Every new primitive was integrated into `server.rs` / `async_server.rs`:

- `MgepServer` owns `RateLimiter`, `IdempotencyStore`, `CancelOnDisconnectManager`,
  `KillSwitchState`, optional `AuditGate`, and an optional `SnapshotProvider`
  closure.
- `poll_client` gates every inbound non-session message through the rate limiter,
  the kill-switch, and (for NewOrderSingle) the idempotency store.
- `disconnect_client_with_reason` routes the precise disconnect reason
  (TransportClose / PeerTimeout / ExplicitTerminate / ServerInitiated) to COD
  and the audit pipeline.
- `ServerConfig` gains `rate_limit: RateLimitConfig`, `idempotency_capacity` +
  `idempotency_window`, `cancel_on_disconnect_grace`. The legacy
  `rate_limit_per_sec` shortcut remains for backward compatibility but folds
  into the new policy.

### Spec documentation (new)

- `docs/spec/06-clock-discipline.md` — MiFID II / SEC Reg SCI-aligned clock
  requirements, ClockSource / ClockQuality taxonomy, wire layout, Linux PTP
  deployment guide.
- `docs/spec/07-audit-and-halts.md` — AuditRecord wire layout, AuditAction /
  AuditReason / HaltReason tables, storage recommendations (WORM, RFC 3161
  Merkle timestamps), retention.
- `docs/guide/building-a-terminal.md` — 10-step walkthrough for vendors
  integrating MGEP into a trading client.

### Cargo features

- `default = ["experimental-transports"]` — on by default for back-compat.
- `experimental-transports` — gates `shmem` (SPSC) and `websocket`. Production
  deployments building `--no-default-features` reduce attack surface.
- `linux-ptp` — gates the `LinuxPtpProbe` implementation. Linux-only by cfg.

### Quality

- 353 Rust tests (lib + integration) + 116 cross-language tests (C, C++, Java,
  TypeScript) all passing.
- `cargo build --all-targets` clean.
- `cargo build --no-default-features` clean.

---

## [0.1.0] — initial

### Wire Format
- Frame header: `[magic:u16 "MG"][flags:u8][version:u8][message_size:u32]` (8 bytes)
- Message header: `[schema_id:u16][message_type:u16][sender_comp_id:u32][sequence_num:u64][correlation_id:u64]` (24 bytes)
- Total header: 32 bytes (half cache line)
- CRC32 trailer (optional, flag-controlled)
- Magic bytes: 0x4D47 ("MG")

### Schemas
- `common.mgep` — 6 shared enums (Side, OrderType, TimeInForce, ExecType, OrderStatus, TradingPhase)
- `trading.mgep` — 12 messages (NewOrder, Cancel, Replace, MassCancel, ExecReport, Rejects, CrossOrder, StatusRequest)
- `market_data.mgep` — 13 messages (OrderBook updates, Trade, Statistics, Subscriptions, InstrumentDef, SecurityList)
- `quotes.mgep` — 7 messages (QuoteRequest, Quote, QuoteReplace, QuoteCancel, MassQuote, MassQuoteAck, IOI)
- `post_trade.mgep` — 7 messages (TradeCaptureReport, Allocation, Confirmation, Settlement)
- `risk.mgep` — 9 messages (Positions, Collateral, Margin, MarginCall)

### Security
- Level 0: None (colocation)
- Level 1: HMAC-SHA256 message authentication
- Level 2: AES-128-GCM authenticated encryption (with AES-NI hardware acceleration)
- HKDF key derivation with epoch rotation for SequenceReset safety

### Session
- Enforced state machine: Disconnected → Negotiating → Negotiated → Establishing → Active → Terminating
- Sequence tracking (u64, no practical wraparound)
- Replay journal with WAL persistence
- RetransmitRequest / Retransmission / NotApplied gap handling
- TestRequest for RTT measurement
- SequenceReset with epoch-based key rotation
- SessionStatus reporting
- Cancel-on-disconnect session flag

### Transports
- TCP with length-prefixed framing
- WebSocket binary (RFC 6455)
- UDP multicast with gap detection
- Shared memory ring buffer (IPC)
- Message batching

### Codegen
- Schema language: human-readable, semantic types, import, constraints
- Rust code generation (structs, enums, CoreBlock, dispatch)
- C header generation (packed structs, _Static_assert, inline decoders)
- Python bindings (ctypes, zero-dependency)

### Infrastructure
- Non-blocking reactor (kqueue/epoll)
- Async server with non-blocking handshake
- Connection wrapper with auto-reconnect
- Buffer pool (lock-free)
- Message builders (fluent API)
- Protocol inspector (human-readable dump)
- Message validation framework
- Metrics counters (latency, throughput, errors)
- LZ4 compression
- Replication header (Raft-native)
- Stream multiplexing
- Write-ahead log
