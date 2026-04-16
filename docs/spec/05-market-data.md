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

## Snapshots

### BookSnapshot (0x06)

Full order book state. Core: `instrument_id`, `bid_count`, `ask_count`, `snapshot_seq`.
Bid/ask levels are in the flex block as serialized byte arrays.

Use after: initial subscription, gap recovery, reconnection.

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
- Recovery: request `BookSnapshot` via TCP recovery channel

### Slow Consumer

If consumer falls behind, server sends `SequenceReset` (session layer).
Consumer must re-subscribe and request a fresh `BookSnapshot`.

## Message Batching

Multiple market data events per TCP write / UDP datagram via `BatchWriter`:

```
[Batch frame header] [BatchHeader: count=50] [Msg1] [Msg2] ... [Msg50]
```

Schema: `0xFFFF`, type: `0x01`. Each inner message is a complete MGEP frame.
