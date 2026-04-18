"""
MGEP Protocol - Python Bindings

Zero-copy decode of MGEP binary messages using ctypes.
No compilation needed — reads raw bytes directly.

Usage:
    from mgep import *

    # Decode a message from raw bytes
    buf = socket.recv(4096)
    header = FullHeader.from_buffer(buf)
    print(f"schema={header.schema_id:#06x} type={header.message_type:#04x} seq={header.sequence_num}")

    if header.schema_id == SCHEMA_TRADING and header.message_type == MSG_NEW_ORDER:
        order = NewOrderSingle.from_buffer(buf, CORE_BLOCK_OFFSET)
        print(f"order_id={order.order_id} price={order.price_as_float()}")

    # Encode a message
    msg = encode_new_order(
        order_id=42, instrument_id=7,
        side=SIDE_BUY, order_type=ORDER_TYPE_LIMIT,
        price=150.25, quantity=100.0,
    )
    socket.send(msg)
"""

import struct
from ctypes import *

# ═══════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════

MAGIC = 0x474D  # "MG"
VERSION = 1
FRAME_HEADER_SIZE = 8
MESSAGE_HEADER_SIZE = 24
FULL_HEADER_SIZE = 32
CORE_BLOCK_OFFSET = 32

DECIMAL_SCALE = 100_000_000  # 10^8
DECIMAL_NULL = -(2**63)      # i64::MIN
TIMESTAMP_NULL = 2**64 - 1   # u64::MAX

# Schema IDs
SCHEMA_SESSION = 0x0000
SCHEMA_TRADING = 0x0001
SCHEMA_MARKET_DATA = 0x0002
SCHEMA_QUOTES = 0x0003
SCHEMA_POST_TRADE = 0x0004
SCHEMA_RISK = 0x0005

# Trading message types
MSG_NEW_ORDER = 0x01
MSG_CANCEL_REQUEST = 0x02
MSG_CANCEL_REPLACE = 0x03
MSG_MASS_CANCEL_REQUEST = 0x04
MSG_EXECUTION_REPORT = 0x05
MSG_CANCEL_REJECT = 0x06
MSG_ORDER_STATUS_REQUEST = 0x07
MSG_MASS_CANCEL_REPORT = 0x08
MSG_NEW_ORDER_CROSS = 0x09
MSG_BUSINESS_REJECT = 0x11

# Market-data message types
MSG_BOOK_SNAPSHOT_REQUEST = 0x30
MSG_BOOK_SNAPSHOT_BEGIN = 0x31
MSG_BOOK_SNAPSHOT_LEVEL = 0x32
MSG_BOOK_SNAPSHOT_END = 0x33
MSG_BOOK_SNAPSHOT_REJECT = 0x34

# Session message types
MSG_HEARTBEAT = 0x05
MSG_RETRANSMIT_REQUEST = 0x06
MSG_RETRANSMISSION = 0x07
MSG_TERMINATE = 0x08
MSG_SEQUENCE_RESET = 0x0B
MSG_CLOCK_STATUS = 0x0E
MSG_KEY_ROTATION_REQUEST = 0x0F
MSG_KEY_ROTATION_ACK = 0x10

# Enums
SIDE_BUY = 1
SIDE_SELL = 2

ORDER_TYPE_MARKET = 1
ORDER_TYPE_LIMIT = 2
ORDER_TYPE_STOP = 3
ORDER_TYPE_STOP_LIMIT = 4

TIF_DAY = 1
TIF_GTC = 2
TIF_IOC = 3
TIF_FOK = 4
TIF_GTD = 5

EXEC_TYPE_NEW = 0
EXEC_TYPE_PARTIAL_FILL = 1
EXEC_TYPE_FILL = 2
EXEC_TYPE_CANCELED = 4
EXEC_TYPE_REPLACED = 5
EXEC_TYPE_REJECTED = 8

# Flags
FLAG_HAS_AUTH = 0x01
FLAG_ENCRYPTED = 0x02
FLAG_COMPRESSED = 0x04
FLAG_HAS_FLEX = 0x08
FLAG_HAS_CRC = 0x10

# ═══════════════════════════════════════════════
# Wire structures (ctypes, little-endian)
# ═══════════════════════════════════════════════

class FrameHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("magic", c_uint16),
        ("flags", c_uint8),
        ("version", c_uint8),
        ("message_size", c_uint32),
    ]

    def is_valid(self):
        return self.magic == MAGIC

    @classmethod
    def from_buffer(cls, buf, offset=0):
        return cls.from_buffer_copy(buf[offset:offset + sizeof(cls)])


class MessageHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("schema_id", c_uint16),
        ("message_type", c_uint16),
        ("sender_comp_id", c_uint32),
        ("sequence_num", c_uint64),
        ("correlation_id", c_uint64),
    ]

    @classmethod
    def from_buffer(cls, buf, offset=FRAME_HEADER_SIZE):
        return cls.from_buffer_copy(buf[offset:offset + sizeof(cls)])


class FullHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("magic", c_uint16),
        ("flags", c_uint8),
        ("version", c_uint8),
        ("message_size", c_uint32),
        ("schema_id", c_uint16),
        ("message_type", c_uint16),
        ("sender_comp_id", c_uint32),
        ("sequence_num", c_uint64),
        ("correlation_id", c_uint64),
    ]

    def is_valid(self):
        return self.magic == MAGIC

    def has_flex(self):
        return bool(self.flags & FLAG_HAS_FLEX)

    @classmethod
    def from_buffer(cls, buf, offset=0):
        return cls.from_buffer_copy(buf[offset:offset + sizeof(cls)])

    def __repr__(self):
        return (f"Header(schema=0x{self.schema_id:04X} type=0x{self.message_type:02X} "
                f"seq={self.sequence_num} corr={self.correlation_id} size={self.message_size})")


# ═══════════════════════════════════════════════
# Trading messages
# ═══════════════════════════════════════════════

class NewOrderSingle(LittleEndianStructure):
    """NewOrderSingle core block — 48 bytes."""
    _pack_ = 1
    _fields_ = [
        ("order_id", c_uint64),
        ("client_order_id", c_uint64),
        ("instrument_id", c_uint32),
        ("side", c_uint8),
        ("order_type", c_uint8),
        ("time_in_force", c_uint16),
        ("price", c_int64),
        ("quantity", c_int64),
        ("stop_price", c_int64),
    ]

    SIZE = 48

    def price_as_float(self):
        return None if self.price == DECIMAL_NULL else self.price / DECIMAL_SCALE

    def quantity_as_float(self):
        return self.quantity / DECIMAL_SCALE

    def side_str(self):
        return {1: "Buy", 2: "Sell"}.get(self.side, "?")

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])

    def __repr__(self):
        return (f"NewOrder(id={self.order_id} inst={self.instrument_id} "
                f"{self.side_str()} price={self.price_as_float()} qty={self.quantity_as_float()})")


class ExecutionReport(LittleEndianStructure):
    """ExecutionReport core block — 88 bytes."""
    _pack_ = 1
    _fields_ = [
        ("order_id", c_uint64),
        ("client_order_id", c_uint64),
        ("exec_id", c_uint64),
        ("instrument_id", c_uint32),
        ("side", c_uint8),
        ("exec_type", c_uint8),
        ("order_status", c_uint8),
        ("_pad", c_uint8),
        ("price", c_int64),
        ("quantity", c_int64),
        ("leaves_qty", c_int64),
        ("cum_qty", c_int64),
        ("last_px", c_int64),
        ("last_qty", c_int64),
        ("transact_time", c_uint64),
    ]

    SIZE = 88

    def last_px_as_float(self):
        return None if self.last_px == DECIMAL_NULL else self.last_px / DECIMAL_SCALE

    def exec_type_str(self):
        return {0: "New", 1: "PartialFill", 2: "Fill", 4: "Canceled",
                5: "Replaced", 8: "Rejected", 12: "Expired"}.get(self.exec_type, "?")

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])

    def __repr__(self):
        return (f"ExecReport(order={self.order_id} exec={self.exec_id} "
                f"{self.exec_type_str()} last_px={self.last_px_as_float()})")


# ═══════════════════════════════════════════════
# Encoder
# ═══════════════════════════════════════════════

def _decimal(value):
    """Convert float to MGEP decimal (i64 * 10^8)."""
    if value is None:
        return DECIMAL_NULL
    return int(value * DECIMAL_SCALE)


def encode_header(schema_id, message_type, sender_comp_id, sequence_num,
                  correlation_id, message_size, flags=0):
    """Encode a 32-byte MGEP header."""
    return struct.pack('<HBBI HHIQQ',
        MAGIC, flags, VERSION, message_size,
        schema_id, message_type, sender_comp_id,
        sequence_num, correlation_id)


def encode_new_order(order_id, instrument_id, side, order_type,
                     price=None, quantity=0.0, stop_price=None,
                     time_in_force=TIF_DAY, sender_comp_id=1,
                     sequence_num=1, correlation_id=0, client_order_id=0):
    """Encode a complete NewOrderSingle message.

    `client_order_id` is the client-assigned unique order ID used for
    idempotent retry (see spec §6 "Order Entry Reliability"). Pass a unique
    u64 per submission; repeated submissions with the same value within the
    server's dedup window will return the original response.
    """
    core = struct.pack('<QQIBBh qqq',
        order_id, client_order_id, instrument_id, side, order_type, time_in_force,
        _decimal(price), _decimal(quantity), _decimal(stop_price))

    total = FULL_HEADER_SIZE + len(core)
    header = encode_header(SCHEMA_TRADING, MSG_NEW_ORDER,
                          sender_comp_id, sequence_num, correlation_id, total)
    return header + core


# ═══════════════════════════════════════════════
# Market-data: snapshot recovery (schema 0x0002)
# ═══════════════════════════════════════════════

class BookSnapshotRequest(LittleEndianStructure):
    """BookSnapshotRequest core block — 16 bytes."""
    _pack_ = 1
    _fields_ = [
        ("request_id", c_uint64),
        ("instrument_id", c_uint32),
        ("max_levels", c_uint32),
    ]
    SIZE = 16

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])


class BookSnapshotBegin(LittleEndianStructure):
    """BookSnapshotBegin core block — 40 bytes."""
    _pack_ = 1
    _fields_ = [
        ("request_id", c_uint64),
        ("instrument_id", c_uint32),
        ("_pad", c_uint8 * 4),
        ("last_applied_seq", c_uint64),
        ("level_count", c_uint32),
        ("_pad2", c_uint8 * 4),
        ("snapshot_id", c_uint64),
    ]
    SIZE = 40

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])


class BookSnapshotLevel(LittleEndianStructure):
    """BookSnapshotLevel core block — 40 bytes."""
    _pack_ = 1
    _fields_ = [
        ("snapshot_id", c_uint64),
        ("level_index", c_uint32),
        ("side", c_uint8),
        ("_pad", c_uint8 * 3),
        ("price", c_int64),
        ("quantity", c_int64),
        ("order_count", c_uint32),
        ("_pad2", c_uint8 * 4),
    ]
    SIZE = 40

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])

    def price_as_float(self):
        return None if self.price == DECIMAL_NULL else self.price / DECIMAL_SCALE


class BookSnapshotEnd(LittleEndianStructure):
    """BookSnapshotEnd core block — 32 bytes."""
    _pack_ = 1
    _fields_ = [
        ("snapshot_id", c_uint64),
        ("final_seq", c_uint64),
        ("checksum", c_uint64),
        ("level_count", c_uint32),
        ("_pad", c_uint8 * 4),
    ]
    SIZE = 32

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])


# ═══════════════════════════════════════════════
# Session-layer messages (schema 0x0000)
# ═══════════════════════════════════════════════

class ClockStatus(LittleEndianStructure):
    """ClockStatus core block — 40 bytes."""
    _pack_ = 1
    _fields_ = [
        ("source", c_uint8),
        ("quality", c_uint8),
        ("_pad", c_uint8 * 6),
        ("observed_at", c_uint64),
        ("last_sync", c_uint64),
        ("estimated_drift_ns", c_uint64),
        ("reference_clock_id", c_uint64),
    ]
    SIZE = 40

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])

    def is_regulatory_grade(self):
        # Quality code 1 == RegulatoryGrade in the Rust impl.
        return self.quality == 1


class KeyRotationRequest(LittleEndianStructure):
    """KeyRotationRequest core block — 16 bytes."""
    _pack_ = 1
    _fields_ = [
        ("session_id", c_uint64),
        ("next_epoch", c_uint32),
        ("reason", c_uint8),
        ("_pad", c_uint8 * 3),
    ]
    SIZE = 16


class KeyRotationAck(LittleEndianStructure):
    """KeyRotationAck core block — 16 bytes."""
    _pack_ = 1
    _fields_ = [
        ("session_id", c_uint64),
        ("epoch", c_uint32),
        ("status", c_uint8),
        ("_pad", c_uint8 * 3),
    ]
    SIZE = 16


class BusinessReject(LittleEndianStructure):
    """BusinessReject core block — 16 bytes. Followed by optional flex
    `text` (field_id=1) with a machine-readable reason code like
    `rate_limited:session_msgs` or `halt:instrument:42`."""
    _pack_ = 1
    _fields_ = [
        ("ref_seq_num", c_uint32),
        ("ref_msg_type", c_uint8),
        ("business_reason", c_uint8),
        ("_pad", c_uint8 * 2),
        ("order_id", c_uint64),
    ]
    SIZE = 16

    @classmethod
    def from_buffer(cls, buf, offset=CORE_BLOCK_OFFSET):
        return cls.from_buffer_copy(buf[offset:offset + cls.SIZE])


def decode_message(buf):
    """Decode any MGEP message. Returns (header, core_struct) or (header, None)."""
    if len(buf) < FULL_HEADER_SIZE:
        return None, None

    header = FullHeader.from_buffer(buf)
    if not header.is_valid():
        return None, None

    dispatch = {
        (SCHEMA_TRADING, MSG_NEW_ORDER): NewOrderSingle,
        (SCHEMA_TRADING, MSG_EXECUTION_REPORT): ExecutionReport,
        (SCHEMA_TRADING, MSG_BUSINESS_REJECT): BusinessReject,
        (SCHEMA_MARKET_DATA, MSG_BOOK_SNAPSHOT_REQUEST): BookSnapshotRequest,
        (SCHEMA_MARKET_DATA, MSG_BOOK_SNAPSHOT_BEGIN): BookSnapshotBegin,
        (SCHEMA_MARKET_DATA, MSG_BOOK_SNAPSHOT_LEVEL): BookSnapshotLevel,
        (SCHEMA_MARKET_DATA, MSG_BOOK_SNAPSHOT_END): BookSnapshotEnd,
        (SCHEMA_SESSION, MSG_CLOCK_STATUS): ClockStatus,
        (SCHEMA_SESSION, MSG_KEY_ROTATION_REQUEST): KeyRotationRequest,
        (SCHEMA_SESSION, MSG_KEY_ROTATION_ACK): KeyRotationAck,
    }

    key = (header.schema_id, header.message_type)
    cls = dispatch.get(key)
    if cls and len(buf) >= CORE_BLOCK_OFFSET + cls.SIZE:
        return header, cls.from_buffer(buf)

    return header, None


def parse_flex_string(buf, core_size, field_id=1):
    """Extract an optional flex string from a message buffer.

    MGEP flex: `[count:u16][(id:u16, offset:u16)*][data area]`.
    `core_size` is the size of the message's core block so we know
    where flex starts. Returns `None` if the field is absent.
    """
    flex_start = CORE_BLOCK_OFFSET + core_size
    if len(buf) < flex_start + 2:
        return None
    count = struct.unpack_from("<H", buf, flex_start)[0]
    # Clamp — reader-side hard cap mirrors MAX_FLEX_FIELDS in Rust.
    count = min(count, 32)
    entries = flex_start + 2
    data = entries + count * 4
    for i in range(count):
        fid, foff = struct.unpack_from("<HH", buf, entries + i * 4)
        if fid == field_id:
            # Type tag is 1 byte (FlexType::String = 0x0B), then u16 length.
            pos = data + foff
            if pos + 3 > len(buf):
                return None
            if buf[pos] != 0x0B:
                return None
            slen = struct.unpack_from("<H", buf, pos + 1)[0]
            start = pos + 3
            if start + slen > len(buf):
                return None
            return buf[start:start + slen].decode("utf-8", errors="replace")
    return None


# ═══════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    # Encode
    msg = encode_new_order(
        order_id=42, instrument_id=7,
        side=SIDE_BUY, order_type=ORDER_TYPE_LIMIT,
        price=150.25, quantity=100.0,
    )
    print(f"Encoded NewOrder: {len(msg)} bytes")
    print(f"  Hex: {msg.hex()}")

    # Decode
    header, order = decode_message(msg)
    print(f"  {header}")
    print(f"  {order}")

    # Verify
    assert header.is_valid()
    assert header.schema_id == SCHEMA_TRADING
    assert header.message_type == MSG_NEW_ORDER
    assert order.order_id == 42
    assert order.instrument_id == 7
    assert order.side == SIDE_BUY
    assert abs(order.price_as_float() - 150.25) < 0.01
    assert abs(order.quantity_as_float() - 100.0) < 0.01

    print("\n✓ Python MGEP bindings work!")
