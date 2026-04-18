/*
 * MGEP Java bindings — pure-JVM wire layout via ByteBuffer.
 *
 * Scope mirrors the C# binding at bindings/csharp/Mgep.cs:
 *   - Wire constants + enums
 *   - Header accessors (FrameHeader, MessageHeader, FullHeader)
 *   - Core-block decoders for the 8 most-used message types
 *   - Encoder for NewOrderSingle
 *   - Flex string parser for optional text fields
 *
 * Design notes:
 *   - Pure Java, no JNI. All I/O happens in caller's transport.
 *   - Decoders take a ByteBuffer positioned anywhere in the message;
 *     the caller is responsible for positioning at CORE_BLOCK_OFFSET.
 *   - Little-endian order enforced everywhere — MGEP wire format is LE.
 *
 * Tested against JDK 17+. Should work on Android via desugaring.
 */
package com.mgep;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public final class Mgep {
    private Mgep() {}

    // ═══════════════════════════════════════════════════════════
    // Wire constants
    // ═══════════════════════════════════════════════════════════

    public static final short MAGIC = 0x474D; // "MG"
    public static final byte VERSION = 1;
    public static final int FRAME_HEADER_SIZE = 8;
    public static final int FULL_HEADER_SIZE = 32;
    public static final int CORE_BLOCK_OFFSET = 32;

    public static final long DECIMAL_SCALE = 100_000_000L;
    public static final long DECIMAL_NULL = Long.MIN_VALUE;

    public static final int SCHEMA_SESSION = 0x0000;
    public static final int SCHEMA_TRADING = 0x0001;
    public static final int SCHEMA_MARKET_DATA = 0x0002;

    // Trading msg types
    public static final int MSG_NEW_ORDER = 0x01;
    public static final int MSG_EXEC_REPORT = 0x05;
    public static final int MSG_CANCEL_REJECT = 0x06;
    public static final int MSG_BUSINESS_REJECT = 0x11;
    // Market-data msg types
    public static final int MSG_BOOK_SNAPSHOT_REQUEST = 0x30;
    public static final int MSG_BOOK_SNAPSHOT_BEGIN = 0x31;
    public static final int MSG_BOOK_SNAPSHOT_LEVEL = 0x32;
    public static final int MSG_BOOK_SNAPSHOT_END = 0x33;
    // Session msg types
    public static final int MSG_CLOCK_STATUS = 0x0E;

    // Enums (wire bytes)
    public static final byte SIDE_BUY = 1;
    public static final byte SIDE_SELL = 2;

    public static final byte ORDER_TYPE_MARKET = 1;
    public static final byte ORDER_TYPE_LIMIT = 2;
    public static final byte ORDER_TYPE_STOP = 3;

    public static final short TIF_DAY = 1;
    public static final short TIF_GTC = 2;
    public static final short TIF_IOC = 3;

    public static final byte EXEC_TYPE_NEW = 0;
    public static final byte EXEC_TYPE_PARTIAL = 1;
    public static final byte EXEC_TYPE_FILL = 2;
    public static final byte EXEC_TYPE_CANCELED = 4;

    // ═══════════════════════════════════════════════════════════
    // Header accessors
    // ═══════════════════════════════════════════════════════════

    /** Decoded view of the 32-byte MGEP FullHeader. */
    public static final class FullHeader {
        public final short magic;
        public final byte flags;
        public final byte version;
        public final int messageSize;
        public final int schemaId;
        public final int messageType;
        public final int senderCompId;
        public final long sequenceNum;
        public final long correlationId;

        private FullHeader(short magic, byte flags, byte version, int messageSize,
                           int schemaId, int messageType, int senderCompId,
                           long sequenceNum, long correlationId) {
            this.magic = magic;
            this.flags = flags;
            this.version = version;
            this.messageSize = messageSize;
            this.schemaId = schemaId;
            this.messageType = messageType;
            this.senderCompId = senderCompId;
            this.sequenceNum = sequenceNum;
            this.correlationId = correlationId;
        }

        public boolean isValid() { return magic == MAGIC; }

        public static FullHeader decode(byte[] msg) {
            if (msg.length < FULL_HEADER_SIZE) return null;
            ByteBuffer b = ByteBuffer.wrap(msg, 0, FULL_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
            short mag = b.getShort();
            byte fl = b.get();
            byte ver = b.get();
            int sz = b.getInt();
            int sid = Short.toUnsignedInt(b.getShort());
            int mt = Short.toUnsignedInt(b.getShort());
            int sender = b.getInt();
            long seq = b.getLong();
            long corr = b.getLong();
            return new FullHeader(mag, fl, ver, sz, sid, mt, sender, seq, corr);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Decimal helpers
    // ═══════════════════════════════════════════════════════════

    public static long encodeDecimal(double value) {
        if (Double.isNaN(value)) return DECIMAL_NULL;
        return (long) (value * DECIMAL_SCALE);
    }

    public static double decodeDecimal(long raw) {
        return raw == DECIMAL_NULL ? Double.NaN : (double) raw / DECIMAL_SCALE;
    }

    // ═══════════════════════════════════════════════════════════
    // Trading core blocks
    // ═══════════════════════════════════════════════════════════

    public static final class NewOrderSingle {
        public static final int SIZE = 48;

        public final long orderId;
        public final long clientOrderId;
        public final int instrumentId;
        public final byte side;
        public final byte orderType;
        public final short timeInForce;
        public final long price;
        public final long quantity;
        public final long stopPrice;

        public NewOrderSingle(long orderId, long clientOrderId, int instrumentId,
                              byte side, byte orderType, short tif,
                              long price, long quantity, long stopPrice) {
            this.orderId = orderId;
            this.clientOrderId = clientOrderId;
            this.instrumentId = instrumentId;
            this.side = side;
            this.orderType = orderType;
            this.timeInForce = tif;
            this.price = price;
            this.quantity = quantity;
            this.stopPrice = stopPrice;
        }

        public double priceAsDouble() { return decodeDecimal(price); }
        public double quantityAsDouble() { return decodeDecimal(quantity); }

        public static NewOrderSingle decode(byte[] msg) {
            ByteBuffer b = ByteBuffer.wrap(msg, CORE_BLOCK_OFFSET, SIZE).order(ByteOrder.LITTLE_ENDIAN);
            long oid = b.getLong();
            long cloid = b.getLong();
            int inst = b.getInt();
            byte side = b.get();
            byte ot = b.get();
            short tif = b.getShort();
            long price = b.getLong();
            long qty = b.getLong();
            long stop = b.getLong();
            return new NewOrderSingle(oid, cloid, inst, side, ot, tif, price, qty, stop);
        }
    }

    public static final class ExecutionReport {
        public static final int SIZE = 88;

        public final long orderId;
        public final long clientOrderId;
        public final long execId;
        public final int instrumentId;
        public final byte side;
        public final byte execType;
        public final byte orderStatus;
        public final long price;
        public final long quantity;
        public final long leavesQty;
        public final long cumQty;
        public final long lastPx;
        public final long lastQty;
        public final long transactTime;

        private ExecutionReport(long orderId, long clientOrderId, long execId, int instrumentId,
                                byte side, byte execType, byte orderStatus,
                                long price, long quantity, long leavesQty, long cumQty,
                                long lastPx, long lastQty, long transactTime) {
            this.orderId = orderId;
            this.clientOrderId = clientOrderId;
            this.execId = execId;
            this.instrumentId = instrumentId;
            this.side = side;
            this.execType = execType;
            this.orderStatus = orderStatus;
            this.price = price;
            this.quantity = quantity;
            this.leavesQty = leavesQty;
            this.cumQty = cumQty;
            this.lastPx = lastPx;
            this.lastQty = lastQty;
            this.transactTime = transactTime;
        }

        public double lastPxAsDouble() { return decodeDecimal(lastPx); }

        public static ExecutionReport decode(byte[] msg) {
            ByteBuffer b = ByteBuffer.wrap(msg, CORE_BLOCK_OFFSET, SIZE).order(ByteOrder.LITTLE_ENDIAN);
            long orderId = b.getLong();
            long clordid = b.getLong();
            long execId = b.getLong();
            int inst = b.getInt();
            byte side = b.get();
            byte execType = b.get();
            byte status = b.get();
            b.get(); // _pad
            long price = b.getLong();
            long qty = b.getLong();
            long leaves = b.getLong();
            long cum = b.getLong();
            long lastPx = b.getLong();
            long lastQty = b.getLong();
            long txTime = b.getLong();
            return new ExecutionReport(orderId, clordid, execId, inst, side, execType, status,
                                       price, qty, leaves, cum, lastPx, lastQty, txTime);
        }
    }

    public static final class BusinessReject {
        public static final int SIZE = 16;
        public final int refSeqNum;
        public final byte refMsgType;
        public final byte businessReason;
        public final long orderId;

        public BusinessReject(int refSeqNum, byte refMsgType, byte businessReason, long orderId) {
            this.refSeqNum = refSeqNum;
            this.refMsgType = refMsgType;
            this.businessReason = businessReason;
            this.orderId = orderId;
        }

        public static BusinessReject decode(byte[] msg) {
            ByteBuffer b = ByteBuffer.wrap(msg, CORE_BLOCK_OFFSET, SIZE).order(ByteOrder.LITTLE_ENDIAN);
            int ref = b.getInt();
            byte mt = b.get();
            byte reason = b.get();
            b.getShort(); // _pad
            long oid = b.getLong();
            return new BusinessReject(ref, mt, reason, oid);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Market-data snapshot
    // ═══════════════════════════════════════════════════════════

    public static final class BookSnapshotBegin {
        public static final int SIZE = 40;
        public final long requestId;
        public final int instrumentId;
        public final long lastAppliedSeq;
        public final int levelCount;
        public final long snapshotId;

        private BookSnapshotBegin(long requestId, int instrumentId, long lastAppliedSeq,
                                  int levelCount, long snapshotId) {
            this.requestId = requestId;
            this.instrumentId = instrumentId;
            this.lastAppliedSeq = lastAppliedSeq;
            this.levelCount = levelCount;
            this.snapshotId = snapshotId;
        }

        public static BookSnapshotBegin decode(byte[] msg) {
            ByteBuffer b = ByteBuffer.wrap(msg, CORE_BLOCK_OFFSET, SIZE).order(ByteOrder.LITTLE_ENDIAN);
            long req = b.getLong();
            int inst = b.getInt();
            b.getInt(); // _pad
            long lastSeq = b.getLong();
            int lvlCount = b.getInt();
            b.getInt(); // _pad2
            long sid = b.getLong();
            return new BookSnapshotBegin(req, inst, lastSeq, lvlCount, sid);
        }
    }

    public static final class BookSnapshotLevel {
        public static final int SIZE = 40;
        public final long snapshotId;
        public final int levelIndex;
        public final byte side;
        public final long price;
        public final long quantity;
        public final int orderCount;

        private BookSnapshotLevel(long snapshotId, int levelIndex, byte side,
                                  long price, long quantity, int orderCount) {
            this.snapshotId = snapshotId;
            this.levelIndex = levelIndex;
            this.side = side;
            this.price = price;
            this.quantity = quantity;
            this.orderCount = orderCount;
        }

        public double priceAsDouble() { return decodeDecimal(price); }
        public double quantityAsDouble() { return decodeDecimal(quantity); }

        public static BookSnapshotLevel decode(byte[] msg) {
            ByteBuffer b = ByteBuffer.wrap(msg, CORE_BLOCK_OFFSET, SIZE).order(ByteOrder.LITTLE_ENDIAN);
            long sid = b.getLong();
            int idx = b.getInt();
            byte side = b.get();
            b.get(); b.get(); b.get(); // _pad[3]
            long price = b.getLong();
            long qty = b.getLong();
            int oc = b.getInt();
            b.getInt(); // _pad2
            return new BookSnapshotLevel(sid, idx, side, price, qty, oc);
        }
    }

    public static final class BookSnapshotEnd {
        public static final int SIZE = 32;
        public final long snapshotId;
        public final long finalSeq;
        public final long checksum;
        public final int levelCount;

        private BookSnapshotEnd(long snapshotId, long finalSeq, long checksum, int levelCount) {
            this.snapshotId = snapshotId;
            this.finalSeq = finalSeq;
            this.checksum = checksum;
            this.levelCount = levelCount;
        }

        public static BookSnapshotEnd decode(byte[] msg) {
            ByteBuffer b = ByteBuffer.wrap(msg, CORE_BLOCK_OFFSET, SIZE).order(ByteOrder.LITTLE_ENDIAN);
            long sid = b.getLong();
            long fs = b.getLong();
            long cs = b.getLong();
            int lc = b.getInt();
            b.getInt(); // _pad
            return new BookSnapshotEnd(sid, fs, cs, lc);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Session: ClockStatus
    // ═══════════════════════════════════════════════════════════

    public static final class ClockStatus {
        public static final int SIZE = 40;
        public final byte source;
        public final byte quality;
        public final long observedAt;
        public final long lastSync;
        public final long estimatedDriftNs;
        public final long referenceClockId;

        private ClockStatus(byte source, byte quality, long observedAt, long lastSync,
                            long estimatedDriftNs, long referenceClockId) {
            this.source = source;
            this.quality = quality;
            this.observedAt = observedAt;
            this.lastSync = lastSync;
            this.estimatedDriftNs = estimatedDriftNs;
            this.referenceClockId = referenceClockId;
        }

        /** Quality code 1 == RegulatoryGrade (see clock_discipline.rs). */
        public boolean isRegulatoryGrade() { return quality == 1; }

        public static ClockStatus decode(byte[] msg) {
            ByteBuffer b = ByteBuffer.wrap(msg, CORE_BLOCK_OFFSET, SIZE).order(ByteOrder.LITTLE_ENDIAN);
            byte src = b.get();
            byte q = b.get();
            for (int i = 0; i < 6; i++) b.get(); // _pad[6]
            long obs = b.getLong();
            long last = b.getLong();
            long drift = b.getLong();
            long ref = b.getLong();
            return new ClockStatus(src, q, obs, last, drift, ref);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Encoder — NewOrderSingle
    // ═══════════════════════════════════════════════════════════

    public static byte[] encodeNewOrder(long orderId, long clientOrderId, int instrumentId,
                                        byte side, byte orderType, double price, double quantity,
                                        short timeInForce, int senderCompId, long sequenceNum,
                                        long correlationId) {
        int total = FULL_HEADER_SIZE + NewOrderSingle.SIZE;
        ByteBuffer b = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);

        // Frame
        b.putShort(MAGIC);
        b.put((byte) 0); // flags
        b.put(VERSION);
        b.putInt(total);
        // Message header
        b.putShort((short) SCHEMA_TRADING);
        b.putShort((short) MSG_NEW_ORDER);
        b.putInt(senderCompId);
        b.putLong(sequenceNum);
        b.putLong(correlationId);
        // Core block
        b.putLong(orderId);
        b.putLong(clientOrderId);
        b.putInt(instrumentId);
        b.put(side);
        b.put(orderType);
        b.putShort(timeInForce);
        b.putLong(encodeDecimal(price));
        b.putLong(encodeDecimal(quantity));
        b.putLong(DECIMAL_NULL); // stop_price

        return b.array();
    }

    // ═══════════════════════════════════════════════════════════
    // Flex string parser
    // ═══════════════════════════════════════════════════════════

    /**
     * Read an optional flex-block string by field_id. Returns null when
     * the field is absent or the buffer is malformed.
     *
     * Flex layout: [count:u16][(id:u16, offset:u16)*][data area]
     * Data area: [type:u8][len:u16][bytes...]
     */
    public static String parseFlexString(byte[] msg, int coreSize, int fieldId) {
        int flexStart = CORE_BLOCK_OFFSET + coreSize;
        if (msg.length < flexStart + 2) return null;
        ByteBuffer b = ByteBuffer.wrap(msg).order(ByteOrder.LITTLE_ENDIAN);
        b.position(flexStart);
        int count = Short.toUnsignedInt(b.getShort());
        if (count > 32) count = 32; // mirror MAX_FLEX_FIELDS
        int data = flexStart + 2 + count * 4;
        for (int i = 0; i < count; i++) {
            int p = flexStart + 2 + i * 4;
            if (p + 4 > msg.length) return null;
            int fid = Short.toUnsignedInt(b.getShort(p));
            int foff = Short.toUnsignedInt(b.getShort(p + 2));
            if (fid == fieldId) {
                int pos = data + foff;
                if (pos + 3 > msg.length) return null;
                if (msg[pos] != 0x0B) return null; // FlexType::String
                int slen = Short.toUnsignedInt(b.getShort(pos + 1));
                int start = pos + 3;
                if (start + slen > msg.length) return null;
                return new String(msg, start, slen, StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
