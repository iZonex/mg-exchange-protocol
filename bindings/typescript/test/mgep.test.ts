// Framework-free tests for MGEP TypeScript bindings. Runnable with:
//   node --experimental-strip-types test/mgep.test.ts   (Node 22+)
//   deno test test/mgep.test.ts                          (Deno)
//   bun test test/mgep.test.ts                           (Bun)

import {
  MAGIC,
  VERSION,
  FULL_HEADER_SIZE,
  CORE_BLOCK_OFFSET,
  DECIMAL_NULL,
  Side,
  OrderType,
  TimeInForce,
  SCHEMA,
  MSG,
  NewOrderSingleSize,
  ExecutionReportSize,
  BusinessRejectSize,
  BookSnapshotBeginSize,
  BookSnapshotLevelSize,
  BookSnapshotEndSize,
  ClockStatusSize,
  encodeDecimal,
  decodeDecimal,
  encodeNewOrder,
  decodeHeader,
  decodeNewOrder,
} from "../src/mgep.ts";

let passed = 0;
let failed = 0;

function assertEq<T>(a: T, b: T, name: string): void {
  if (a === b) {
    passed++;
    console.log(`PASS: ${name}`);
  } else {
    failed++;
    console.log(`FAIL: ${name} — ${String(a)} !== ${String(b)}`);
  }
}

function assertClose(a: number, b: number, tol: number, name: string): void {
  if (Math.abs(a - b) < tol) {
    passed++;
    console.log(`PASS: ${name}`);
  } else {
    failed++;
    console.log(`FAIL: ${name} — ${a} !≈ ${b}`);
  }
}

function assertTruthy(cond: unknown, name: string): void {
  if (cond) {
    passed++;
    console.log(`PASS: ${name}`);
  } else {
    failed++;
    console.log(`FAIL: ${name}`);
  }
}

// ─── Size checks ────────────────────────────────────────────

assertEq(NewOrderSingleSize, 48, "NewOrderSingle size");
assertEq(ExecutionReportSize, 88, "ExecutionReport size");
assertEq(BusinessRejectSize, 16, "BusinessReject size");
assertEq(BookSnapshotBeginSize, 40, "BookSnapshotBegin size");
assertEq(BookSnapshotLevelSize, 40, "BookSnapshotLevel size");
assertEq(BookSnapshotEndSize, 32, "BookSnapshotEnd size");
assertEq(ClockStatusSize, 40, "ClockStatus size");

// ─── Decimal roundtrip ──────────────────────────────────────

assertEq(encodeDecimal(150.25), 15_025_000_000n, "decimal encode");
assertClose(decodeDecimal(15_025_000_000n) as number, 150.25, 1e-9, "decimal decode");
assertEq(encodeDecimal(null), DECIMAL_NULL, "null sentinel");
assertEq(decodeDecimal(DECIMAL_NULL), null, "null roundtrip");

// ─── New order encode + decode ──────────────────────────────

const bytes = encodeNewOrder({
  orderId: 42n,
  clientOrderId: 99n,
  instrumentId: 7,
  side: Side.Buy,
  orderType: OrderType.Limit,
  price: 150.25,
  quantity: 100.0,
  timeInForce: TimeInForce.Day,
  senderCompId: 1,
  sequenceNum: 1n,
  correlationId: 0n,
});
assertEq(bytes.length, FULL_HEADER_SIZE + NewOrderSingleSize, "encoded size");

const hdr = decodeHeader(bytes);
assertTruthy(hdr !== null && hdr.valid, "header valid");
assertEq(hdr!.magic, MAGIC, "magic");
assertEq(hdr!.version, VERSION, "version");
assertEq(hdr!.schemaId, SCHEMA.Trading, "schema_id");
assertEq(hdr!.messageType, MSG.NewOrder, "message_type");

const order = decodeNewOrder(bytes);
assertEq(order.orderId, 42n, "order_id");
assertEq(order.clientOrderId, 99n, "client_order_id");
assertEq(order.instrumentId, 7, "instrument_id");
assertEq(order.side, Side.Buy, "side");
assertEq(order.orderType, OrderType.Limit, "order_type");
assertClose(decodeDecimal(order.price) as number, 150.25, 1e-9, "price");
assertClose(decodeDecimal(order.quantity) as number, 100.0, 1e-9, "quantity");
assertEq(order.stopPrice, DECIMAL_NULL, "stop_price null");

// ─── Header validation ──────────────────────────────────────

assertEq(decodeHeader(new Uint8Array(16)), null, "short buffer rejected");
const zero = new Uint8Array(FULL_HEADER_SIZE);
const zeroHdr = decodeHeader(zero);
assertTruthy(zeroHdr !== null && !zeroHdr.valid, "zero-magic invalid");

// ─── Wire-offset verification ───────────────────────────────

// Byte 0..2 should be MAGIC little-endian: 0x4D, 0x47.
assertEq(bytes[0], 0x4d, "magic byte 0");
assertEq(bytes[1], 0x47, "magic byte 1");

// Offset 32 (CORE_BLOCK_OFFSET) is start of core. order_id=42 → 0x2A at offset 32.
assertEq(bytes[CORE_BLOCK_OFFSET], 0x2a, "order_id byte 0");

console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  // eslint-disable-next-line no-undef
  (globalThis as { process?: { exit: (code: number) => void } }).process?.exit(1);
}
