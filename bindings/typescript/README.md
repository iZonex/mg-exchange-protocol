# MGEP TypeScript bindings

Zero-dependency wire bindings for Node / Deno / Bun / browsers.
Mirrors the C# and Java bindings feature-for-feature using
`DataView` and `Uint8Array`.

## Coverage

* Wire constants, enums, schema / message-type codes
* `decodeHeader` returning a typed `FullHeader`
* Trading: `decodeNewOrder`, `decodeExecReport`, `decodeBusinessReject`
* Market data: `decodeSnapshotBegin` / `SnapshotLevel` / `SnapshotEnd`
* Session: `decodeClockStatus` + `isRegulatoryGrade`
* `encodeNewOrder(params)` → `Uint8Array`
* `parseFlexString(buf, coreSize, fieldId)` for optional text fields
* Decimal helpers (`encodeDecimal` / `decodeDecimal`) using `bigint`

## Usage

```ts
import {
  encodeNewOrder, decodeHeader, decodeExecReport, parseFlexString,
  Side, OrderType, MSG, SCHEMA, ExecutionReportSize,
  BusinessRejectSize,
} from "@mgep/bindings";

// Encode
const bytes = encodeNewOrder({
  orderId: 0n, clientOrderId: 42n, instrumentId: 7,
  side: Side.Buy, orderType: OrderType.Limit,
  price: 150.25, quantity: 100.0,
});
socket.send(bytes);

// Decode inbound
const hdr = decodeHeader(buf);
if (hdr?.schemaId === SCHEMA.Trading && hdr?.messageType === MSG.ExecReport) {
  const er = decodeExecReport(buf);
  console.log("Fill at", Number(er.lastPx) / 1e8);
}

// Typed rejects
if (hdr?.messageType === MSG.BusinessReject) {
  const reason = parseFlexString(buf, BusinessRejectSize);
  if (reason?.startsWith("rate_limited:")) { /* back off */ }
}
```

## Running the tests

Framework-free — runs on any modern JS runtime:

```bash
# Deno
deno test --allow-read test/mgep.test.ts

# Bun
bun test/mgep.test.ts

# Node (22+ with type-stripping)
node --experimental-strip-types test/mgep.test.ts
```

## What's not here

Same exclusions as the C# / Java bindings:

* No connection management — wire primitives only.
* No client-side state (OrderManager / PositionTracker). Port from
  `src/rust/src/client_state.rs` if needed.
* No AES-GCM encryption path.
* Numbers ≥ 2⁵³ use `bigint` — `orderId`, `clientOrderId`, `price`,
  `quantity`, etc. — because JS numbers can't safely represent them.

## Wire size verification

Struct sizes asserted in `test/mgep.test.ts`. Core-block size changes
on the Rust side must be mirrored here and will break the test.

Current sizes:

| Message | Bytes |
|---|---|
| NewOrderSingle | 48 |
| ExecutionReport | 88 |
| BusinessReject | 16 |
| BookSnapshotBegin | 40 |
| BookSnapshotLevel | 40 |
| BookSnapshotEnd | 32 |
| ClockStatus | 40 |
