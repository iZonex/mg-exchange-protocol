# MGEP C bindings

C11 single-library. Two files:

* `mgep.h` — public API, constants, struct layouts (`__attribute__((packed))`)
* `mgep.c` — encoder, decoders, flex parser

Zero external dependencies beyond `<stdint.h>`, `<stddef.h>`, `<string.h>`.
Works on GCC / Clang / MSVC. Little-endian hosts only (x86_64 / aarch64 /
ARMv8 — covers 100% of real trading hardware).

## Coverage

* Full header (`FrameHeader` + `MessageHeader`)
* Trading: `NewOrderSingle`, `ExecutionReport`, `BusinessReject`
* Market data: `BookSnapshotRequest/Begin/Level/End`
* Session: `ClockStatus`
* Encoder for `NewOrderSingle`
* Decimal roundtrip helpers
* Flex string parser (`mgep_parse_flex_string`) for typed reject codes

## Usage

```c
#include "mgep.h"

// Encode
uint8_t buf[128];
int n = mgep_encode_new_order(
    buf, sizeof(buf),
    /*order_id*/ 0, /*client_order_id*/ 42,
    /*instrument_id*/ 7,
    MGEP_SIDE_BUY, MGEP_OT_LIMIT, MGEP_TIF_DAY,
    mgep_encode_decimal(150.25),
    mgep_encode_decimal(100.0),
    MGEP_DECIMAL_NULL,  // stop_price
    /*sender*/ 1, /*seq*/ 1, /*corr*/ 0);
send(sock, buf, n, 0);

// Decode inbound
mgep_full_header_t hdr;
if (mgep_decode_header(rcv_buf, rcv_len, &hdr) == 0 &&
    hdr.message.schema_id == MGEP_SCHEMA_TRADING &&
    hdr.message.message_type == MGEP_MSG_EXEC_REPORT) {
    const mgep_exec_report_t *er = mgep_decode_exec_report(rcv_buf, rcv_len);
    int is_null;
    double last_px = mgep_decode_decimal(er->last_px, &is_null);
    printf("Fill at %.4f\n", last_px);
}

// Typed reject
if (hdr.message.message_type == MGEP_MSG_BUSINESS_REJECT) {
    const char *reason; size_t reason_len;
    if (mgep_parse_flex_string(
            rcv_buf, rcv_len, MGEP_BUSINESS_REJECT_SIZE,
            /*field_id*/ 1, &reason, &reason_len) == 0) {
        if (reason_len >= 13 && memcmp(reason, "rate_limited:", 13) == 0) {
            // back off
        }
    }
}
```

## Building

```bash
cc -std=c11 -Wall -Wextra -Werror -c mgep.c -o mgep.o
# or as a library
cc -std=c11 -shared -fPIC mgep.c -o libmgep.so
```

## Running tests

```bash
cc -std=c11 -Wall -Wextra -Werror -o test_mgep mgep.c test_mgep.c
./test_mgep
# Expected: 38 passed, 0 failed
```

## Wire size verification

`test_mgep.c::test_sizes()` asserts every struct size against the
spec constants. Rust-side core-block growth must update both the C
struct and the `MGEP_*_SIZE` define; the test fails if they drift.

## What's not here

Same exclusions as the Java / C# / TS bindings: no connection
management, no client-side state (OrderManager / PositionTracker),
no AES-GCM. Use the Rust reference for those concerns, or port the
patterns when you need them natively.
