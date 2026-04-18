/*
 * MGEP C bindings — public API.
 *
 * C11 header. No external dependencies beyond <stdint.h>, <stddef.h>.
 * Struct layouts mirror the Rust `#[repr(C)]` core blocks byte-for-byte;
 * the compiler is required to preserve field order and avoid padding
 * beyond what we spell out (`_pad*` fields are explicit).
 *
 * Endianness: MGEP wire is little-endian. On big-endian hosts, you
 * MUST swap on read/write — the helpers here assume LE. (This is
 * fine for x86_64 / aarch64 / most ARM; rare elsewhere.)
 */

#ifndef MGEP_H
#define MGEP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════
 * Wire constants
 * ═══════════════════════════════════════════════════════════════ */

#define MGEP_MAGIC              0x474Du  /* "MG" little-endian */
#define MGEP_VERSION            1
#define MGEP_FRAME_HEADER_SIZE  8
#define MGEP_FULL_HEADER_SIZE   32
#define MGEP_CORE_BLOCK_OFFSET  32
#define MGEP_MAX_FLEX_FIELDS    32

#define MGEP_DECIMAL_SCALE      100000000LL
#define MGEP_DECIMAL_NULL       INT64_MIN

/* Schema IDs */
#define MGEP_SCHEMA_SESSION     0x0000
#define MGEP_SCHEMA_TRADING     0x0001
#define MGEP_SCHEMA_MARKET_DATA 0x0002

/* Trading message types */
#define MGEP_MSG_NEW_ORDER       0x01
#define MGEP_MSG_EXEC_REPORT     0x05
#define MGEP_MSG_CANCEL_REJECT   0x06
#define MGEP_MSG_BUSINESS_REJECT 0x11

/* Market-data message types */
#define MGEP_MSG_SNAPSHOT_REQUEST 0x30
#define MGEP_MSG_SNAPSHOT_BEGIN   0x31
#define MGEP_MSG_SNAPSHOT_LEVEL   0x32
#define MGEP_MSG_SNAPSHOT_END     0x33

/* Session message types */
#define MGEP_MSG_CLOCK_STATUS     0x0E

/* Enums (wire bytes) */
#define MGEP_SIDE_BUY   1
#define MGEP_SIDE_SELL  2

#define MGEP_OT_MARKET  1
#define MGEP_OT_LIMIT   2
#define MGEP_OT_STOP    3

#define MGEP_TIF_DAY    1
#define MGEP_TIF_GTC    2
#define MGEP_TIF_IOC    3
#define MGEP_TIF_FOK    4

#define MGEP_EXEC_NEW       0
#define MGEP_EXEC_PARTIAL   1
#define MGEP_EXEC_FILL      2
#define MGEP_EXEC_CANCELED  4

#if defined(__GNUC__) || defined(__clang__)
#  define MGEP_PACKED __attribute__((packed, aligned(1)))
#else
#  pragma pack(push, 1)
#  define MGEP_PACKED
#endif

/* ═══════════════════════════════════════════════════════════════
 * Headers
 * ═══════════════════════════════════════════════════════════════ */

typedef struct MGEP_PACKED {
    uint16_t magic;
    uint8_t  flags;
    uint8_t  version;
    uint32_t message_size;
} mgep_frame_header_t;

typedef struct MGEP_PACKED {
    uint16_t schema_id;
    uint16_t message_type;
    uint32_t sender_comp_id;
    uint64_t sequence_num;
    uint64_t correlation_id;
} mgep_message_header_t;

typedef struct MGEP_PACKED {
    mgep_frame_header_t   frame;
    mgep_message_header_t message;
} mgep_full_header_t;

/* ═══════════════════════════════════════════════════════════════
 * Trading core blocks
 * ═══════════════════════════════════════════════════════════════ */

typedef struct MGEP_PACKED {
    uint64_t order_id;
    uint64_t client_order_id;
    uint32_t instrument_id;
    uint8_t  side;
    uint8_t  order_type;
    uint16_t time_in_force;
    int64_t  price;
    int64_t  quantity;
    int64_t  stop_price;
} mgep_new_order_t;

#define MGEP_NEW_ORDER_SIZE 48

typedef struct MGEP_PACKED {
    uint64_t order_id;
    uint64_t client_order_id;
    uint64_t exec_id;
    uint32_t instrument_id;
    uint8_t  side;
    uint8_t  exec_type;
    uint8_t  order_status;
    uint8_t  _pad;
    int64_t  price;
    int64_t  quantity;
    int64_t  leaves_qty;
    int64_t  cum_qty;
    int64_t  last_px;
    int64_t  last_qty;
    uint64_t transact_time;
} mgep_exec_report_t;

#define MGEP_EXEC_REPORT_SIZE 88

typedef struct MGEP_PACKED {
    uint32_t ref_seq_num;
    uint8_t  ref_msg_type;
    uint8_t  business_reason;
    uint8_t  _pad[2];
    uint64_t order_id;
} mgep_business_reject_t;

#define MGEP_BUSINESS_REJECT_SIZE 16

/* ═══════════════════════════════════════════════════════════════
 * Market data — snapshot
 * ═══════════════════════════════════════════════════════════════ */

typedef struct MGEP_PACKED {
    uint64_t request_id;
    uint32_t instrument_id;
    uint32_t max_levels;
} mgep_snapshot_request_t;

#define MGEP_SNAPSHOT_REQUEST_SIZE 16

typedef struct MGEP_PACKED {
    uint64_t request_id;
    uint32_t instrument_id;
    uint8_t  _pad[4];
    uint64_t last_applied_seq;
    uint32_t level_count;
    uint8_t  _pad2[4];
    uint64_t snapshot_id;
} mgep_snapshot_begin_t;

#define MGEP_SNAPSHOT_BEGIN_SIZE 40

typedef struct MGEP_PACKED {
    uint64_t snapshot_id;
    uint32_t level_index;
    uint8_t  side;
    uint8_t  _pad[3];
    int64_t  price;
    int64_t  quantity;
    uint32_t order_count;
    uint8_t  _pad2[4];
} mgep_snapshot_level_t;

#define MGEP_SNAPSHOT_LEVEL_SIZE 40

typedef struct MGEP_PACKED {
    uint64_t snapshot_id;
    uint64_t final_seq;
    uint64_t checksum;
    uint32_t level_count;
    uint8_t  _pad[4];
} mgep_snapshot_end_t;

#define MGEP_SNAPSHOT_END_SIZE 32

/* ═══════════════════════════════════════════════════════════════
 * Session
 * ═══════════════════════════════════════════════════════════════ */

typedef struct MGEP_PACKED {
    uint8_t  source;
    uint8_t  quality;
    uint8_t  _pad[6];
    uint64_t observed_at;
    uint64_t last_sync;
    uint64_t estimated_drift_ns;
    uint64_t reference_clock_id;
} mgep_clock_status_t;

#define MGEP_CLOCK_STATUS_SIZE 40

#if !defined(__GNUC__) && !defined(__clang__)
#  pragma pack(pop)
#endif

/* ═══════════════════════════════════════════════════════════════
 * Decimal helpers
 * ═══════════════════════════════════════════════════════════════ */

/* Return MGEP_DECIMAL_NULL when `value` is NaN (caller passes NaN sentinel). */
int64_t mgep_encode_decimal(double value);

/* Return 0.0 and set *is_null = 1 when raw == MGEP_DECIMAL_NULL. */
double  mgep_decode_decimal(int64_t raw, int *is_null);

/* ═══════════════════════════════════════════════════════════════
 * Header helpers
 * ═══════════════════════════════════════════════════════════════ */

/*
 * Decode the first MGEP_FULL_HEADER_SIZE bytes of `buf` into `out`.
 * Returns:
 *    0 on success (header looks valid — magic matches)
 *   -1 if buf_len < MGEP_FULL_HEADER_SIZE
 *   -2 if magic doesn't match
 * The struct is populated regardless of the magic check so the caller
 * can still inspect malformed traffic for logging.
 */
int mgep_decode_header(const uint8_t *buf, size_t buf_len, mgep_full_header_t *out);

/* ═══════════════════════════════════════════════════════════════
 * NewOrderSingle encoder
 * ═══════════════════════════════════════════════════════════════ */

/*
 * Write a fully framed NewOrderSingle into `out_buf`. The caller must
 * provide at least (MGEP_FULL_HEADER_SIZE + MGEP_NEW_ORDER_SIZE) bytes.
 *
 * `price`, `quantity`, `stop_price` are already-encoded i64 decimal
 * values (use `mgep_encode_decimal` on human inputs first).
 * Pass MGEP_DECIMAL_NULL for price (market orders) or stop_price (no stop).
 *
 * Returns the number of bytes written, or -1 on out_len too small.
 */
int mgep_encode_new_order(
    uint8_t *out_buf, size_t out_len,
    uint64_t order_id, uint64_t client_order_id,
    uint32_t instrument_id,
    uint8_t side, uint8_t order_type, uint16_t time_in_force,
    int64_t price, int64_t quantity, int64_t stop_price,
    uint32_t sender_comp_id, uint64_t sequence_num, uint64_t correlation_id);

/* ═══════════════════════════════════════════════════════════════
 * Core-block decoders (zero-copy — return pointer into `buf`)
 * ═══════════════════════════════════════════════════════════════ */

const mgep_new_order_t *mgep_decode_new_order(const uint8_t *buf, size_t buf_len);
const mgep_exec_report_t *mgep_decode_exec_report(const uint8_t *buf, size_t buf_len);
const mgep_business_reject_t *mgep_decode_business_reject(const uint8_t *buf, size_t buf_len);
const mgep_snapshot_begin_t *mgep_decode_snapshot_begin(const uint8_t *buf, size_t buf_len);
const mgep_snapshot_level_t *mgep_decode_snapshot_level(const uint8_t *buf, size_t buf_len);
const mgep_snapshot_end_t *mgep_decode_snapshot_end(const uint8_t *buf, size_t buf_len);
const mgep_clock_status_t *mgep_decode_clock_status(const uint8_t *buf, size_t buf_len);

/* ═══════════════════════════════════════════════════════════════
 * Flex field parser
 * ═══════════════════════════════════════════════════════════════ */

/*
 * Read an optional flex string by `field_id` from the message `buf`
 * (full message including headers). `core_size` is the size of the
 * message's core block — i.e. MGEP_BUSINESS_REJECT_SIZE for a
 * BusinessReject.
 *
 * On success: writes the string start into `*out_ptr`, its length into
 * `*out_len`, and returns 0. The returned pointer is a view into `buf`;
 * don't free it, and the string is NOT null-terminated.
 *
 * On absence / malformed input: returns -1 and leaves `*out_ptr` /
 * `*out_len` untouched.
 */
int mgep_parse_flex_string(
    const uint8_t *buf, size_t buf_len, size_t core_size,
    uint16_t field_id,
    const char **out_ptr, size_t *out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MGEP_H */
