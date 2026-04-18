// MGEP TypeScript bindings — pure DataView/Uint8Array wire layout.
//
// Zero dependencies; runs in Node, Deno, Bun, and browsers. Mirrors the
// C# / Java bindings feature-for-feature:
//   * wire constants + enums
//   * header accessors
//   * core-block decoders for the 8 most-used message types
//   * encoder for NewOrderSingle
//   * flex string parser for optional text fields
//
// MGEP's #[repr(C)] core blocks map directly onto byte offsets here.
// Everything is little-endian; we use the `true` argument on DataView
// getters to enforce LE.

// ═══════════════════════════════════════════════════════════════
// Wire constants
// ═══════════════════════════════════════════════════════════════

export const MAGIC = 0x474D; // "MG"
export const VERSION = 1;
export const FRAME_HEADER_SIZE = 8;
export const FULL_HEADER_SIZE = 32;
export const CORE_BLOCK_OFFSET = 32;

export const DECIMAL_SCALE = 100_000_000n;
export const DECIMAL_NULL = -(2n ** 63n);

export const SCHEMA = {
  Session: 0x0000,
  Trading: 0x0001,
  MarketData: 0x0002,
  Quotes: 0x0003,
  PostTrade: 0x0004,
  Risk: 0x0005,
} as const;

export const MSG = {
  // Trading
  NewOrder: 0x01,
  ExecReport: 0x05,
  CancelReject: 0x06,
  BusinessReject: 0x11,
  // Market data
  BookSnapshotRequest: 0x30,
  BookSnapshotBegin: 0x31,
  BookSnapshotLevel: 0x32,
  BookSnapshotEnd: 0x33,
  // Session
  Heartbeat: 0x05,
  Terminate: 0x08,
  ClockStatus: 0x0e,
} as const;

export const Side = {
  Buy: 1,
  Sell: 2,
} as const;
export type SideValue = (typeof Side)[keyof typeof Side];

export const OrderType = {
  Market: 1,
  Limit: 2,
  Stop: 3,
  StopLimit: 4,
} as const;
export type OrderTypeValue = (typeof OrderType)[keyof typeof OrderType];

export const TimeInForce = {
  Day: 1,
  GTC: 2,
  IOC: 3,
  FOK: 4,
  GTD: 5,
} as const;

export const ExecType = {
  New: 0,
  PartialFill: 1,
  Fill: 2,
  Canceled: 4,
  Replaced: 5,
  Rejected: 8,
} as const;

// ═══════════════════════════════════════════════════════════════
// Decimal helpers
// ═══════════════════════════════════════════════════════════════

export function encodeDecimal(value: number | null): bigint {
  if (value === null || Number.isNaN(value)) return DECIMAL_NULL;
  // Avoid float drift by going through Math.round.
  return BigInt(Math.round(value * Number(DECIMAL_SCALE)));
}

export function decodeDecimal(raw: bigint): number | null {
  if (raw === DECIMAL_NULL) return null;
  return Number(raw) / Number(DECIMAL_SCALE);
}

// ═══════════════════════════════════════════════════════════════
// Header
// ═══════════════════════════════════════════════════════════════

export interface FullHeader {
  magic: number;
  flags: number;
  version: number;
  messageSize: number;
  schemaId: number;
  messageType: number;
  senderCompId: number;
  sequenceNum: bigint;
  correlationId: bigint;
  valid: boolean;
}

export function decodeHeader(buf: Uint8Array): FullHeader | null {
  if (buf.length < FULL_HEADER_SIZE) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, FULL_HEADER_SIZE);
  const magic = dv.getUint16(0, true);
  const flags = dv.getUint8(2);
  const version = dv.getUint8(3);
  const messageSize = dv.getUint32(4, true);
  const schemaId = dv.getUint16(8, true);
  const messageType = dv.getUint16(10, true);
  const senderCompId = dv.getUint32(12, true);
  const sequenceNum = dv.getBigUint64(16, true);
  const correlationId = dv.getBigUint64(24, true);
  return {
    magic,
    flags,
    version,
    messageSize,
    schemaId,
    messageType,
    senderCompId,
    sequenceNum,
    correlationId,
    valid: magic === MAGIC,
  };
}

// ═══════════════════════════════════════════════════════════════
// Trading core blocks
// ═══════════════════════════════════════════════════════════════

export interface NewOrderSingle {
  orderId: bigint;
  clientOrderId: bigint;
  instrumentId: number;
  side: number;
  orderType: number;
  timeInForce: number;
  price: bigint;
  quantity: bigint;
  stopPrice: bigint;
}
export const NewOrderSingleSize = 48;

export function decodeNewOrder(buf: Uint8Array): NewOrderSingle {
  const dv = new DataView(buf.buffer, buf.byteOffset + CORE_BLOCK_OFFSET, NewOrderSingleSize);
  return {
    orderId: dv.getBigUint64(0, true),
    clientOrderId: dv.getBigUint64(8, true),
    instrumentId: dv.getUint32(16, true),
    side: dv.getUint8(20),
    orderType: dv.getUint8(21),
    timeInForce: dv.getUint16(22, true),
    price: dv.getBigInt64(24, true),
    quantity: dv.getBigInt64(32, true),
    stopPrice: dv.getBigInt64(40, true),
  };
}

export interface ExecutionReport {
  orderId: bigint;
  clientOrderId: bigint;
  execId: bigint;
  instrumentId: number;
  side: number;
  execType: number;
  orderStatus: number;
  price: bigint;
  quantity: bigint;
  leavesQty: bigint;
  cumQty: bigint;
  lastPx: bigint;
  lastQty: bigint;
  transactTime: bigint;
}
export const ExecutionReportSize = 88;

export function decodeExecReport(buf: Uint8Array): ExecutionReport {
  const dv = new DataView(buf.buffer, buf.byteOffset + CORE_BLOCK_OFFSET, ExecutionReportSize);
  return {
    orderId: dv.getBigUint64(0, true),
    clientOrderId: dv.getBigUint64(8, true),
    execId: dv.getBigUint64(16, true),
    instrumentId: dv.getUint32(24, true),
    side: dv.getUint8(28),
    execType: dv.getUint8(29),
    orderStatus: dv.getUint8(30),
    // byte 31: _pad
    price: dv.getBigInt64(32, true),
    quantity: dv.getBigInt64(40, true),
    leavesQty: dv.getBigInt64(48, true),
    cumQty: dv.getBigInt64(56, true),
    lastPx: dv.getBigInt64(64, true),
    lastQty: dv.getBigInt64(72, true),
    transactTime: dv.getBigUint64(80, true),
  };
}

export interface BusinessReject {
  refSeqNum: number;
  refMsgType: number;
  businessReason: number;
  orderId: bigint;
}
export const BusinessRejectSize = 16;

export function decodeBusinessReject(buf: Uint8Array): BusinessReject {
  const dv = new DataView(buf.buffer, buf.byteOffset + CORE_BLOCK_OFFSET, BusinessRejectSize);
  return {
    refSeqNum: dv.getUint32(0, true),
    refMsgType: dv.getUint8(4),
    businessReason: dv.getUint8(5),
    // bytes 6..8: _pad
    orderId: dv.getBigUint64(8, true),
  };
}

// ═══════════════════════════════════════════════════════════════
// Market-data snapshot
// ═══════════════════════════════════════════════════════════════

export interface BookSnapshotBegin {
  requestId: bigint;
  instrumentId: number;
  lastAppliedSeq: bigint;
  levelCount: number;
  snapshotId: bigint;
}
export const BookSnapshotBeginSize = 40;

export function decodeSnapshotBegin(buf: Uint8Array): BookSnapshotBegin {
  const dv = new DataView(buf.buffer, buf.byteOffset + CORE_BLOCK_OFFSET, BookSnapshotBeginSize);
  return {
    requestId: dv.getBigUint64(0, true),
    instrumentId: dv.getUint32(8, true),
    lastAppliedSeq: dv.getBigUint64(16, true),
    levelCount: dv.getUint32(24, true),
    snapshotId: dv.getBigUint64(32, true),
  };
}

export interface BookSnapshotLevel {
  snapshotId: bigint;
  levelIndex: number;
  side: number;
  price: bigint;
  quantity: bigint;
  orderCount: number;
}
export const BookSnapshotLevelSize = 40;

export function decodeSnapshotLevel(buf: Uint8Array): BookSnapshotLevel {
  const dv = new DataView(buf.buffer, buf.byteOffset + CORE_BLOCK_OFFSET, BookSnapshotLevelSize);
  return {
    snapshotId: dv.getBigUint64(0, true),
    levelIndex: dv.getUint32(8, true),
    side: dv.getUint8(12),
    // bytes 13..16: _pad
    price: dv.getBigInt64(16, true),
    quantity: dv.getBigInt64(24, true),
    orderCount: dv.getUint32(32, true),
    // bytes 36..40: _pad2
  };
}

export interface BookSnapshotEnd {
  snapshotId: bigint;
  finalSeq: bigint;
  checksum: bigint;
  levelCount: number;
}
export const BookSnapshotEndSize = 32;

export function decodeSnapshotEnd(buf: Uint8Array): BookSnapshotEnd {
  const dv = new DataView(buf.buffer, buf.byteOffset + CORE_BLOCK_OFFSET, BookSnapshotEndSize);
  return {
    snapshotId: dv.getBigUint64(0, true),
    finalSeq: dv.getBigUint64(8, true),
    checksum: dv.getBigUint64(16, true),
    levelCount: dv.getUint32(24, true),
    // bytes 28..32: _pad
  };
}

// ═══════════════════════════════════════════════════════════════
// Session: ClockStatus
// ═══════════════════════════════════════════════════════════════

export interface ClockStatus {
  source: number;
  quality: number;
  observedAt: bigint;
  lastSync: bigint;
  estimatedDriftNs: bigint;
  referenceClockId: bigint;
}
export const ClockStatusSize = 40;

export function decodeClockStatus(buf: Uint8Array): ClockStatus {
  const dv = new DataView(buf.buffer, buf.byteOffset + CORE_BLOCK_OFFSET, ClockStatusSize);
  return {
    source: dv.getUint8(0),
    quality: dv.getUint8(1),
    // bytes 2..8: _pad
    observedAt: dv.getBigUint64(8, true),
    lastSync: dv.getBigUint64(16, true),
    estimatedDriftNs: dv.getBigUint64(24, true),
    referenceClockId: dv.getBigUint64(32, true),
  };
}

/** Quality code 1 == RegulatoryGrade in clock_discipline.rs. */
export function isRegulatoryGrade(status: ClockStatus): boolean {
  return status.quality === 1;
}

// ═══════════════════════════════════════════════════════════════
// Encoder
// ═══════════════════════════════════════════════════════════════

export interface EncodeOrderParams {
  orderId: bigint;
  clientOrderId: bigint;
  instrumentId: number;
  side: SideValue;
  orderType: OrderTypeValue;
  price: number | null;
  quantity: number;
  timeInForce?: number;
  stopPrice?: number | null;
  senderCompId?: number;
  sequenceNum?: bigint;
  correlationId?: bigint;
}

export function encodeNewOrder(p: EncodeOrderParams): Uint8Array {
  const total = FULL_HEADER_SIZE + NewOrderSingleSize;
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);

  // Frame header
  dv.setUint16(0, MAGIC, true);
  dv.setUint8(2, 0); // flags
  dv.setUint8(3, VERSION);
  dv.setUint32(4, total, true);
  // Message header
  dv.setUint16(8, SCHEMA.Trading, true);
  dv.setUint16(10, MSG.NewOrder, true);
  dv.setUint32(12, p.senderCompId ?? 1, true);
  dv.setBigUint64(16, p.sequenceNum ?? 1n, true);
  dv.setBigUint64(24, p.correlationId ?? 0n, true);
  // Core block
  dv.setBigUint64(32, p.orderId, true);
  dv.setBigUint64(40, p.clientOrderId, true);
  dv.setUint32(48, p.instrumentId, true);
  dv.setUint8(52, p.side);
  dv.setUint8(53, p.orderType);
  dv.setUint16(54, p.timeInForce ?? TimeInForce.Day, true);
  dv.setBigInt64(56, encodeDecimal(p.price), true);
  dv.setBigInt64(64, encodeDecimal(p.quantity), true);
  dv.setBigInt64(72, encodeDecimal(p.stopPrice ?? null), true);

  return buf;
}

// ═══════════════════════════════════════════════════════════════
// Flex string parser
// ═══════════════════════════════════════════════════════════════

/**
 * Parse an optional flex-block string by field_id. Returns null if
 * absent or malformed.
 *
 * Layout: [count:u16][(id:u16, offset:u16)*][data area]
 * Data: [type:u8][len:u16][utf8 bytes...]
 */
export function parseFlexString(
  buf: Uint8Array,
  coreSize: number,
  fieldId = 1,
): string | null {
  const flexStart = CORE_BLOCK_OFFSET + coreSize;
  if (buf.length < flexStart + 2) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset);
  let count = dv.getUint16(flexStart, true);
  if (count > 32) count = 32; // mirror Rust MAX_FLEX_FIELDS
  const dataStart = flexStart + 2 + count * 4;
  for (let i = 0; i < count; i++) {
    const p = flexStart + 2 + i * 4;
    if (p + 4 > buf.length) return null;
    const fid = dv.getUint16(p, true);
    const foff = dv.getUint16(p + 2, true);
    if (fid === fieldId) {
      const pos = dataStart + foff;
      if (pos + 3 > buf.length) return null;
      if (buf[pos] !== 0x0b) return null; // FlexType::String
      const slen = dv.getUint16(pos + 1, true);
      const start = pos + 3;
      if (start + slen > buf.length) return null;
      const bytes = buf.subarray(start, start + slen);
      return new TextDecoder("utf-8").decode(bytes);
    }
  }
  return null;
}
