# MGEP Market Data Specification

## Overview

Market data in MGEP uses `schema_id = 0x0002`. Supports full depth-of-book order-by-order feed, trade reports, statistics, and instrument reference data.

## Subscription Model

### Subscribe (0x10)

Client sends `Subscribe` to request market data for an instrument.

Fields:
- `request_id`: client-assigned correlation ID
- `instrument_id`: target instrument
- `sub_type`: subscription type (OrderByOrder=1, TopOfBook=2, Trades=3, Stats=4)
- `depth`: 0 = full book, N = top N levels

### SubscribeResponse (0x12)

Server responds with accept/reject:
- `status`: 0=accepted, 1=rejected
- `reject_reason`: 0=none, 1=unknown_instrument, 2=rate_limit, 3=not_entitled

### Unsubscribe (0x11)

Client cancels a subscription by `request_id` + `instrument_id`.

## Incremental Feed Messages

These are pushed after subscription is accepted:

| Message | Type | Size | Description |
|---------|------|------|-------------|
| OrderAdd | 0x01 | 32B | New order added to book |
| OrderModify | 0x02 | 24B | Price/quantity changed |
| OrderDelete | 0x03 | 8B | Order removed from book |
| OrderExecuted | 0x04 | 32B | Order (partially) filled |
| Trade | 0x05 | 40B | Trade report |
| TradingStatus | 0x08 | 8B | Phase change (PreOpen, Continuous, Halt) |

## Snapshot Recovery Flow

Multi-message streaming snapshot. A single message cannot carry a full
order book (MTU bound at 1472 bytes per UDP datagram; book can have
thousands of levels), so snapshots are split: one `Begin`, N `Level`s,
one `End` with a CRC32 over the concatenated level payloads.

Wire protocol (all in the `market_data` schema `0x0002`):

```
client → server (TCP recovery channel):
    BookSnapshotRequest   (0x30, 16 B)

server → client:
    BookSnapshotBegin     (0x31, 40 B)
    BookSnapshotLevel     (0x32, 40 B) × level_count
    BookSnapshotEnd       (0x33, 32 B)

on refusal:
    BookSnapshotReject    (0x34, 16 B)
```

### `BookSnapshotRequest` (0x30)

| Field | Type | Description |
|---|---|---|
| `request_id` | `id` | Client correlation ID. Echoed in Begin. |
| `instrument_id` | `instrument` | Target book. |
| `max_levels` | `count` | `0` = full depth, `N` = top N levels per side. |

### `BookSnapshotBegin` (0x31)

Declares the snapshot boundary. Client buffers all real-time updates
from now until `End` arrives.

| Field | Type | Description |
|---|---|---|
| `request_id` | `id` | Echoed from Request. |
| `instrument_id` | `instrument` | |
| `last_applied_seq` | `u64` | Market-data seq this snapshot is consistent with. Client drops all updates with `seq ≤ last_applied_seq` after applying. |
| `level_count` | `count` | Number of `Level` messages that will follow. |
| `snapshot_id` | `id` | Unique per snapshot session; echoed in every Level and End. |

### `BookSnapshotLevel` (0x32)

One aggregated price level.

| Field | Type | Description |
|---|---|---|
| `snapshot_id` | `id` | Matches Begin. |
| `level_index` | `count` | Monotonic `0..level_count-1`. Detects drops. |
| `side` | `Side` | Buy or Sell. |
| `price` | `price` | Aggregate price level. |
| `quantity` | `qty` | Total resting quantity at this price. |
| `order_count` | `count` | Number of resting orders at this price. |

Bids are emitted highest-price-first, then asks lowest-price-first.

### `BookSnapshotEnd` (0x33)

Terminator with integrity check. Client validates CRC32 over the
concatenated `Level` payloads in order; if it doesn't match, the
snapshot is discarded and a fresh request is issued.

| Field | Type | Description |
|---|---|---|
| `snapshot_id` | `id` | Matches Begin. |
| `final_seq` | `u64` | Must equal `Begin.last_applied_seq`. |
| `checksum` | `u64` | CRC32 over concatenated Level core payloads (high 32 bits reserved). |
| `level_count` | `count` | Echoes Begin.level_count for paranoia. |

### `BookSnapshotReject` (0x34)

| Field | Type | Description |
|---|---|---|
| `request_id` | `id` | Echoed from Request. |
| `reason_code` | `u8` | `1`=UnknownInstrument, `2`=RateLimited, `3`=Unavailable, `4`=TooLarge. |

### Client stitching algorithm

1. On `GapDetector` detecting a gap that cannot be covered by
   retransmit (seq below journal low-water), issue
   `BookSnapshotRequest`.
2. Continue receiving real-time updates; buffer them pending `End`.
3. On `End`: verify CRC and level_count. If good, apply the snapshot,
   then drain the buffer discarding any message with
   `seq ≤ last_applied_seq`, apply the rest in order.
4. Mark the gap filled in `GapDetector` and resume normal flow.

### Slow-consumer protection

A client that falls further behind than the server's send-backlog
threshold (configurable per-subscription) gets disconnected with
`SequenceReset(reason=SlowConsumer)` rather than held back. The
matching hot path is never slowed by backlogged consumers.

### MarketStatistics (0x20)

OHLCV + extras. 72-byte core:
- `open_price`, `high_price`, `low_price`, `close_price`
- `vwap`, `total_volume`, `total_turnover`, `open_interest`
- Flex: `num_trades`, `prev_close`

## Instrument Reference

### InstrumentDefinition (0x07)

Push on subscription or request. Core: `instrument_id`, `tick_size`, `lot_size`, `min_price`, `max_price`.
Flex: `symbol`, `name`, `currency`, `exchange`, `isin`.

### SecurityListRequest (0x21)

Query available instruments. Flex filters: `symbol_filter` (wildcard), `exchange_filter`.

### SecurityListResponse (0x22)

Returns `total_instruments` count. Individual instruments follow as `InstrumentDefinition` messages.

## Multicast Delivery

Market data can be delivered via UDP multicast (`multicast.rs`):

- One datagram = one MGEP message
- Max payload: 1472 bytes (MTU safe)
- Gap detection via `GapDetector` (sequence tracking)
- Recovery: issue `BookSnapshotRequest` (0x30) on the TCP recovery
  channel; consume the `Begin/Level*/End` stream back (see
  [§ Snapshot Recovery Flow](#snapshot-recovery-flow))

### Slow Consumer

If consumer falls behind, server sends `SequenceReset` (session layer).
Consumer must re-subscribe and request a fresh `BookSnapshot`.

## Message Batching

Multiple market data events per TCP write / UDP datagram via `BatchWriter`:

```
[Batch frame header] [BatchHeader: count=50] [Msg1] [Msg2] ... [Msg50]
```

Schema: `0xFFFF`, type: `0x01`. Each inner message is a complete MGEP frame.
