/*
 * MGEP C bindings — implementation.
 *
 * Pure C11. Uses memcpy + unsigned-arithmetic for endianness so the
 * compiler can optimize to single loads/stores on LE hosts.
 */

#include "mgep.h"

#include <math.h>
#include <string.h>

/* ─── Decimal ───────────────────────────────────────────────── */

int64_t mgep_encode_decimal(double value) {
    /* C NaN check is `x != x`. */
    if (value != value) return MGEP_DECIMAL_NULL;
    return (int64_t)(value * (double)MGEP_DECIMAL_SCALE);
}

double mgep_decode_decimal(int64_t raw, int *is_null) {
    if (raw == MGEP_DECIMAL_NULL) {
        if (is_null) *is_null = 1;
        return 0.0;
    }
    if (is_null) *is_null = 0;
    return (double)raw / (double)MGEP_DECIMAL_SCALE;
}

/* ─── Little-endian read/write helpers ──────────────────────── */

static inline uint16_t read_u16_le(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static inline void write_u16_le(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void write_u32_le(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static inline void write_u64_le(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }
static inline void write_i64_le(uint8_t *p, int64_t v)  { memcpy(p, &v, 8); }

/* ─── Header ────────────────────────────────────────────────── */

int mgep_decode_header(const uint8_t *buf, size_t buf_len, mgep_full_header_t *out) {
    if (buf_len < MGEP_FULL_HEADER_SIZE) return -1;
    /* Struct is packed, layout matches the wire exactly. */
    memcpy(out, buf, sizeof(*out));
    if (out->frame.magic != MGEP_MAGIC) return -2;
    return 0;
}

/* ─── Encoder — NewOrderSingle ──────────────────────────────── */

int mgep_encode_new_order(
    uint8_t *out_buf, size_t out_len,
    uint64_t order_id, uint64_t client_order_id,
    uint32_t instrument_id,
    uint8_t side, uint8_t order_type, uint16_t time_in_force,
    int64_t price, int64_t quantity, int64_t stop_price,
    uint32_t sender_comp_id, uint64_t sequence_num, uint64_t correlation_id
) {
    const size_t total = MGEP_FULL_HEADER_SIZE + MGEP_NEW_ORDER_SIZE;
    if (out_len < total) return -1;

    /* Frame header */
    write_u16_le(out_buf + 0, MGEP_MAGIC);
    out_buf[2] = 0;            /* flags */
    out_buf[3] = MGEP_VERSION;
    write_u32_le(out_buf + 4, (uint32_t)total);

    /* Message header */
    write_u16_le(out_buf + 8,  MGEP_SCHEMA_TRADING);
    write_u16_le(out_buf + 10, MGEP_MSG_NEW_ORDER);
    write_u32_le(out_buf + 12, sender_comp_id);
    write_u64_le(out_buf + 16, sequence_num);
    write_u64_le(out_buf + 24, correlation_id);

    /* Core block */
    uint8_t *core = out_buf + MGEP_CORE_BLOCK_OFFSET;
    write_u64_le(core + 0,  order_id);
    write_u64_le(core + 8,  client_order_id);
    write_u32_le(core + 16, instrument_id);
    core[20] = side;
    core[21] = order_type;
    write_u16_le(core + 22, time_in_force);
    write_i64_le(core + 24, price);
    write_i64_le(core + 32, quantity);
    write_i64_le(core + 40, stop_price);

    return (int)total;
}

/* ─── Decoders (zero-copy) ──────────────────────────────────── */

#define MGEP_DECODER(RET_T, FN, SIZE_CONST) \
    const RET_T *FN(const uint8_t *buf, size_t buf_len) { \
        if (buf_len < MGEP_CORE_BLOCK_OFFSET + (SIZE_CONST)) return NULL; \
        return (const RET_T *)(buf + MGEP_CORE_BLOCK_OFFSET); \
    }

MGEP_DECODER(mgep_new_order_t,         mgep_decode_new_order,         MGEP_NEW_ORDER_SIZE)
MGEP_DECODER(mgep_exec_report_t,       mgep_decode_exec_report,       MGEP_EXEC_REPORT_SIZE)
MGEP_DECODER(mgep_business_reject_t,   mgep_decode_business_reject,   MGEP_BUSINESS_REJECT_SIZE)
MGEP_DECODER(mgep_snapshot_begin_t,    mgep_decode_snapshot_begin,    MGEP_SNAPSHOT_BEGIN_SIZE)
MGEP_DECODER(mgep_snapshot_level_t,    mgep_decode_snapshot_level,    MGEP_SNAPSHOT_LEVEL_SIZE)
MGEP_DECODER(mgep_snapshot_end_t,      mgep_decode_snapshot_end,      MGEP_SNAPSHOT_END_SIZE)
MGEP_DECODER(mgep_clock_status_t,      mgep_decode_clock_status,      MGEP_CLOCK_STATUS_SIZE)

/* ─── Flex string parser ────────────────────────────────────── */

#define FLEX_ENTRY_SIZE      4
#define FLEX_TYPE_STRING     0x0B

int mgep_parse_flex_string(
    const uint8_t *buf, size_t buf_len, size_t core_size,
    uint16_t field_id,
    const char **out_ptr, size_t *out_len
) {
    const size_t flex_start = MGEP_CORE_BLOCK_OFFSET + core_size;
    if (buf_len < flex_start + 2) return -1;

    uint16_t count = read_u16_le(buf + flex_start);
    if (count > MGEP_MAX_FLEX_FIELDS) count = MGEP_MAX_FLEX_FIELDS;
    const size_t entries_start = flex_start + 2;
    const size_t data_start = entries_start + (size_t)count * FLEX_ENTRY_SIZE;
    if (buf_len < data_start) return -1;

    for (uint16_t i = 0; i < count; ++i) {
        const size_t p = entries_start + (size_t)i * FLEX_ENTRY_SIZE;
        const uint16_t fid = read_u16_le(buf + p);
        if (fid != field_id) continue;
        const uint16_t foff = read_u16_le(buf + p + 2);
        const size_t pos = data_start + foff;
        if (pos + 3 > buf_len) return -1;
        if (buf[pos] != FLEX_TYPE_STRING) return -1;
        const uint16_t slen = read_u16_le(buf + pos + 1);
        const size_t start = pos + 3;
        if (start + slen > buf_len) return -1;
        *out_ptr = (const char *)(buf + start);
        *out_len = slen;
        return 0;
    }
    return -1;
}
