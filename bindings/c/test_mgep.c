/* Framework-free test harness for MGEP C bindings.
 * Build:
 *   cc -std=c11 -Wall -Wextra -Werror -o test_mgep mgep.c test_mgep.c
 *   ./test_mgep
 */

#include "mgep.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_passed = 0;
static int g_failed = 0;

#define ASSERT_EQ_INT(a, b, name) do {                                        \
    long long _a = (long long)(a);                                            \
    long long _b = (long long)(b);                                            \
    if (_a == _b) { g_passed++; printf("PASS: %s\n", (name)); }               \
    else { g_failed++; printf("FAIL: %s — %lld != %lld\n", (name), _a, _b); }  \
} while (0)

#define ASSERT_CLOSE(a, b, tol, name) do {                                    \
    double _a = (a); double _b = (b);                                         \
    if (fabs(_a - _b) < (tol)) { g_passed++; printf("PASS: %s\n", (name)); }  \
    else { g_failed++; printf("FAIL: %s — %f !~= %f\n", (name), _a, _b); }    \
} while (0)

#define ASSERT_TRUE(c, name) do {                                             \
    if (c) { g_passed++; printf("PASS: %s\n", (name)); }                      \
    else { g_failed++; printf("FAIL: %s\n", (name)); }                        \
} while (0)

static void test_sizes(void) {
    ASSERT_EQ_INT(sizeof(mgep_full_header_t), MGEP_FULL_HEADER_SIZE, "FullHeader size");
    ASSERT_EQ_INT(sizeof(mgep_new_order_t), MGEP_NEW_ORDER_SIZE, "NewOrderSingle size");
    ASSERT_EQ_INT(sizeof(mgep_exec_report_t), MGEP_EXEC_REPORT_SIZE, "ExecutionReport size");
    ASSERT_EQ_INT(sizeof(mgep_business_reject_t), MGEP_BUSINESS_REJECT_SIZE, "BusinessReject size");
    ASSERT_EQ_INT(sizeof(mgep_snapshot_begin_t), MGEP_SNAPSHOT_BEGIN_SIZE, "SnapshotBegin size");
    ASSERT_EQ_INT(sizeof(mgep_snapshot_level_t), MGEP_SNAPSHOT_LEVEL_SIZE, "SnapshotLevel size");
    ASSERT_EQ_INT(sizeof(mgep_snapshot_end_t), MGEP_SNAPSHOT_END_SIZE, "SnapshotEnd size");
    ASSERT_EQ_INT(sizeof(mgep_clock_status_t), MGEP_CLOCK_STATUS_SIZE, "ClockStatus size");
}

static void test_decimal_roundtrip(void) {
    int64_t enc = mgep_encode_decimal(150.25);
    ASSERT_EQ_INT(enc, 15025000000LL, "decimal encode");

    int is_null = 0;
    double dec = mgep_decode_decimal(enc, &is_null);
    ASSERT_TRUE(!is_null, "decode non-null flag");
    ASSERT_CLOSE(dec, 150.25, 1e-9, "decimal roundtrip");

    /* NaN → NULL sentinel. */
    int64_t nan_enc = mgep_encode_decimal(NAN);
    ASSERT_EQ_INT(nan_enc, MGEP_DECIMAL_NULL, "NaN encoded as NULL");

    double nulled = mgep_decode_decimal(MGEP_DECIMAL_NULL, &is_null);
    ASSERT_TRUE(is_null, "NULL sentinel decode sets is_null");
    (void)nulled;
}

static void test_new_order_roundtrip(void) {
    uint8_t buf[256] = {0};
    int n = mgep_encode_new_order(
        buf, sizeof(buf),
        /*order_id*/ 42, /*client_order_id*/ 99,
        /*instrument_id*/ 7,
        MGEP_SIDE_BUY, MGEP_OT_LIMIT, MGEP_TIF_DAY,
        mgep_encode_decimal(150.25),
        mgep_encode_decimal(100.0),
        MGEP_DECIMAL_NULL,
        /*sender*/ 1, /*seq*/ 1, /*corr*/ 0);
    ASSERT_EQ_INT(n, MGEP_FULL_HEADER_SIZE + MGEP_NEW_ORDER_SIZE, "encoded size");

    /* Byte-level checks on the frame/header prefix. */
    ASSERT_EQ_INT(buf[0], 0x4D, "magic byte 0");
    ASSERT_EQ_INT(buf[1], 0x47, "magic byte 1");
    ASSERT_EQ_INT(buf[3], MGEP_VERSION, "version byte");

    mgep_full_header_t hdr;
    ASSERT_EQ_INT(mgep_decode_header(buf, (size_t)n, &hdr), 0, "header decode ok");
    ASSERT_EQ_INT(hdr.message.schema_id, MGEP_SCHEMA_TRADING, "schema_id");
    ASSERT_EQ_INT(hdr.message.message_type, MGEP_MSG_NEW_ORDER, "message_type");

    const mgep_new_order_t *o = mgep_decode_new_order(buf, (size_t)n);
    ASSERT_TRUE(o != NULL, "core decode non-null");
    ASSERT_EQ_INT(o->order_id, 42, "order_id");
    ASSERT_EQ_INT(o->client_order_id, 99, "client_order_id");
    ASSERT_EQ_INT(o->instrument_id, 7, "instrument_id");
    ASSERT_EQ_INT(o->side, MGEP_SIDE_BUY, "side");
    ASSERT_EQ_INT(o->order_type, MGEP_OT_LIMIT, "order_type");
    ASSERT_EQ_INT(o->time_in_force, MGEP_TIF_DAY, "tif");
    ASSERT_CLOSE((double)o->price / 1e8, 150.25, 1e-6, "price");
    ASSERT_CLOSE((double)o->quantity / 1e8, 100.0, 1e-6, "quantity");
    ASSERT_EQ_INT(o->stop_price, MGEP_DECIMAL_NULL, "stop_price null");
}

static void test_too_small_buffers(void) {
    uint8_t small[10] = {0};
    ASSERT_EQ_INT(mgep_encode_new_order(small, sizeof(small),
                                        1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0),
                  -1, "encode rejects small buffer");

    mgep_full_header_t hdr;
    ASSERT_EQ_INT(mgep_decode_header(small, sizeof(small), &hdr), -1, "short header rejected");

    const mgep_new_order_t *o = mgep_decode_new_order(small, sizeof(small));
    ASSERT_TRUE(o == NULL, "short core returns NULL");
}

static void test_magic_mismatch(void) {
    uint8_t buf[64] = {0};
    buf[0] = 0xAB;  /* wrong magic */
    buf[1] = 0xCD;
    mgep_full_header_t hdr;
    ASSERT_EQ_INT(mgep_decode_header(buf, sizeof(buf), &hdr), -2, "bad magic rejected");
}

static void test_flex_string_parser(void) {
    /*
     * Hand-construct a BusinessReject followed by a flex block:
     *   count = 1
     *   entry: field_id=1, offset=0
     *   data: type=0x0B, len=2, "hi"
     */
    uint8_t buf[MGEP_FULL_HEADER_SIZE + MGEP_BUSINESS_REJECT_SIZE + 2 + 4 + 3 + 2];
    memset(buf, 0, sizeof(buf));

    /* Frame magic so the buffer is at least "looks valid" — not required for flex parsing. */
    buf[0] = 0x4D; buf[1] = 0x47;

    const size_t flex_start = MGEP_CORE_BLOCK_OFFSET + MGEP_BUSINESS_REJECT_SIZE;
    buf[flex_start + 0] = 1;    /* count low */
    buf[flex_start + 1] = 0;    /* count high */
    /* entry */
    buf[flex_start + 2] = 1;    /* field_id low */
    buf[flex_start + 3] = 0;    /* field_id high */
    buf[flex_start + 4] = 0;    /* offset low */
    buf[flex_start + 5] = 0;    /* offset high */
    /* data at flex_start + 6 */
    buf[flex_start + 6] = 0x0B; /* FlexType::String */
    buf[flex_start + 7] = 2;    /* len low */
    buf[flex_start + 8] = 0;    /* len high */
    buf[flex_start + 9] = 'h';
    buf[flex_start + 10] = 'i';

    const char *p = NULL;
    size_t len = 0;
    int rc = mgep_parse_flex_string(buf, sizeof(buf), MGEP_BUSINESS_REJECT_SIZE, 1, &p, &len);
    ASSERT_EQ_INT(rc, 0, "flex parser found field");
    ASSERT_EQ_INT(len, 2, "flex string length");
    ASSERT_TRUE(p != NULL && p[0] == 'h' && p[1] == 'i', "flex string contents");

    /* Unknown field → not found. */
    rc = mgep_parse_flex_string(buf, sizeof(buf), MGEP_BUSINESS_REJECT_SIZE, 99, &p, &len);
    ASSERT_EQ_INT(rc, -1, "unknown field returns -1");
}

int main(void) {
    test_sizes();
    test_decimal_roundtrip();
    test_new_order_roundtrip();
    test_too_small_buffers();
    test_magic_mismatch();
    test_flex_string_parser();

    printf("\nResults: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
