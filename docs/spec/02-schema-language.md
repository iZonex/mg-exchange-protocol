# MGEP Schema Definition Language

**Version:** 0.1.0-draft
**Date:** 2026-04-16
**Status:** Draft

---

## 1. Overview

MGEP schemas define message layouts, field types, and versioning rules.
Schemas are written in a custom DSL (`.mgep` files) that is designed to be:

- Human-readable and concise
- Unambiguous for code generation
- Version-aware with explicit evolution rules

Code generators produce encoders/decoders for target languages (Rust, C, C++, Java, Go, Python).

---

## 2. Schema File Format

```mgep
# MGEP Schema Definition
# Lines starting with # are comments

@schema trading
@id 0x0001
@version 3

# --- Enums ---

enum Side : u8 {
    Buy  = 1
    Sell = 2
}

enum OrderType : u8 {
    Market    = 1
    Limit     = 2
    Stop      = 3
    StopLimit = 4
}

enum TimeInForce : u16 {
    Day = 1
    GTC = 2
    IOC = 3
    FOK = 4
    GTD = 5
}

enum ExecType : u8 {
    New           = 0
    PartialFill   = 1
    Fill          = 2
    Canceled      = 4
    Replaced      = 5
    Rejected      = 8
    Expired       = 12
}

# --- Messages ---

message NewOrderSingle {
    @type 0x01
    @since 1

    # Core block (fixed layout, hot path)
    core {
        order_id       : u64            # Client order ID
        instrument_id  : u32            # Instrument numeric ID
        side           : Side           # Buy/Sell
        order_type     : OrderType      # Market, Limit, etc.
        time_in_force  : TimeInForce    # Day, GTC, IOC, etc.
        price          : decimal        # Limit price (NULL if market)
        quantity        : decimal        # Order quantity
        stop_price     : decimal        # Stop trigger price (NULL if N/A)
    }

    # Flex block (extensible, not on hot path)
    flex {
        account        : string   @id=1  @since=1   # Trading account
        client_tag     : string   @id=2  @since=1   # Free-form client tag
        max_show       : decimal  @id=3  @since=2   # Iceberg display quantity
        expire_time    : timestamp @id=4 @since=2   # GTD expiration
        self_trade_prevention : u8 @id=5 @since=3   # STP mode
    }
}

message OrderCancelRequest {
    @type 0x02
    @since 1

    core {
        order_id       : u64            # Original order to cancel
        cancel_id      : u64            # Cancel request ID
        instrument_id  : u32            # Instrument (for validation)
        side           : Side           # Side (for validation)
    }
}

message OrderCancelReplaceRequest {
    @type 0x03
    @since 1

    core {
        order_id       : u64            # Original order to replace
        replace_id     : u64            # Replace request ID
        instrument_id  : u32            # Instrument
        side           : Side           # Side
        order_type     : OrderType      # New order type
        time_in_force  : TimeInForce    # New TIF
        price          : decimal        # New price
        quantity        : decimal        # New quantity
        stop_price     : decimal        # New stop price
    }
}

message ExecutionReport {
    @type 0x05
    @since 1

    core {
        order_id       : u64            # Client order ID
        exec_id        : u64            # Execution ID (exchange-assigned)
        instrument_id  : u32            # Instrument
        side           : Side           # Side
        exec_type      : ExecType       # What happened
        _pad1          : u8             # Alignment padding
        _pad2          : u16            # Alignment padding
        order_status   : u8             # Current order status
        _pad3          : u8             # Alignment padding
        _pad4          : u16            # Alignment padding
        price          : decimal        # Order price
        quantity        : decimal        # Order quantity
        leaves_qty     : decimal        # Remaining quantity
        cum_qty        : decimal        # Cumulative filled quantity
        last_px        : decimal        # Last fill price (NULL if no fill)
        last_qty       : decimal        # Last fill quantity (NULL if no fill)
        transact_time  : timestamp      # Exchange timestamp of event
    }

    flex {
        text           : string   @id=1  @since=1   # Rejection reason text
        trade_id       : u64      @id=2  @since=1   # Trade ID (if fill)
        fee            : decimal  @id=3  @since=2   # Trading fee
        fee_currency   : string   @id=4  @since=2   # Fee currency
    }
}
```

---

## 3. Type System

### Primitive Types
| Type | Size | Description |
|------|------|-------------|
| `u8` | 1 | Unsigned 8-bit integer |
| `u16` | 2 | Unsigned 16-bit integer |
| `u32` | 4 | Unsigned 32-bit integer |
| `u64` | 8 | Unsigned 64-bit integer |
| `i8` | 1 | Signed 8-bit integer |
| `i16` | 2 | Signed 16-bit integer |
| `i32` | 4 | Signed 32-bit integer |
| `i64` | 8 | Signed 64-bit integer |
| `f64` | 8 | IEEE 754 double-precision float |
| `bool` | 1 | Boolean (0=false, 1=true) |

### Derived Types
| Type | Size | Description |
|------|------|-------------|
| `decimal` | 8 | Fixed-point i64 * 10^8 |
| `timestamp` | 8 | Nanoseconds since Unix epoch (u64) |
| `string` | variable | UTF-8 string (flex block only) |
| `bytes` | variable | Raw byte array (flex block only) |

### Rules
- `string` and `bytes` are only allowed in flex blocks (variable length)
- `decimal` and `timestamp` are aliases for `i64` and `u64` with semantic meaning
- Enum types must specify their underlying integer type

---

## 4. Alignment Rules

Fields in core blocks are naturally aligned:
- `u8`, `i8`, `bool`: any offset
- `u16`, `i16`: even offset (2-byte aligned)
- `u32`, `i32`, `f32`: 4-byte aligned
- `u64`, `i64`, `f64`, `decimal`, `timestamp`: 8-byte aligned

The code generator automatically inserts `_pad` fields where needed.
Explicit padding is also allowed for documentation purposes.

---

## 5. Schema Versioning

### Rules
1. `@version` increments when fields are added
2. Core block fields are APPEND-ONLY — never removed or reordered
3. Core block can only grow (new fields at the end)
4. Flex fields can be added at any version (with `@since` annotation)
5. Decoders MUST ignore unknown flex field IDs
6. A field's `@since` version indicates the minimum schema version that includes it

### Backward Compatibility
- Decoder v3 receiving message v1: core block is smaller, flex fields with @since > 1 absent
- Decoder v1 receiving message v3: ignores extra core bytes, ignores unknown flex fields

### Breaking Changes (Major Version)
When a breaking change is needed (rare):
- Increment `@id` (new schema_id)
- Both old and new schemas can coexist on the wire
- Migration period: servers send both formats, clients upgrade

---

## 6. Code Generation

The `mgep-codegen` tool reads `.mgep` files and generates:

### Rust Output
```rust
// Auto-generated by mgep-codegen. DO NOT EDIT.

#[repr(C, packed)]
pub struct NewOrderSingleCore {
    pub order_id: u64,
    pub instrument_id: u32,
    pub side: Side,
    pub order_type: OrderType,
    pub time_in_force: TimeInForce,
    pub price: Decimal,
    pub quantity: Decimal,
    pub stop_price: Decimal,
}

impl NewOrderSingleCore {
    pub const SIZE: usize = 40;

    /// Zero-copy decode: cast buffer pointer to struct reference
    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Zero-copy encode: cast struct reference to byte slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                Self::SIZE,
            )
        }
    }
}
```

### C Output
```c
// Auto-generated by mgep-codegen. DO NOT EDIT.

#pragma pack(push, 1)
typedef struct {
    uint64_t order_id;
    uint32_t instrument_id;
    uint8_t  side;
    uint8_t  order_type;
    uint16_t time_in_force;
    int64_t  price;
    int64_t  quantity;
    int64_t  stop_price;
} mgep_new_order_single_core_t;
#pragma pack(pop)

static inline const mgep_new_order_single_core_t*
mgep_new_order_single_decode(const uint8_t* buf) {
    return (const mgep_new_order_single_core_t*)buf;
}
```

---

## 7. Schema Registry

Schemas can be distributed via:
1. **Static compilation** — schemas bundled with the application
2. **Schema registry** — HTTP/gRPC service that serves schemas by id+version
3. **In-band** — schema definitions sent during session Negotiate phase

For ultra-low-latency, static compilation is required.
Schema registry is for operational tooling and development.
