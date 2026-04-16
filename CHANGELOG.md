# Changelog

All notable changes to the MGEP protocol will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
