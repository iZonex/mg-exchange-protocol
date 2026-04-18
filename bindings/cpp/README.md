# MGEP C++ bindings

Header-only **C++20** wrapper over the C bindings. Zero runtime
dependencies beyond the standard library. C++20 is required for
`std::span` — downgrading is possible by replacing spans with
`(const uint8_t*, size_t)` pairs.

Wraps `bindings/c/mgep.h` with:

* Scoped enums (`mgep::Side::Buy`, `mgep::OrderType::Limit`, ...)
* `std::optional<T*>` decoders instead of raw nullable pointers
* `std::span<const uint8_t>` input — works with `std::vector`,
  `std::array`, C arrays, network-buffer views
* `NewOrderParams` struct for clean encode-site call syntax
* `std::string_view` flex-field parser

## Usage

```cpp
#include "mgep.hpp"

// Encode
mgep::NewOrderParams p{};
p.order_id = 0;
p.client_order_id = 42;
p.instrument_id = 7;
p.side = mgep::Side::Buy;
p.order_type = mgep::OrderType::Limit;
p.price = 150.25;
p.quantity = 100.0;

auto bytes = mgep::encode_new_order(p);
socket.send(bytes.data(), bytes.size());

// Decode
if (auto hdr = mgep::decode_header(rcv_span);
    hdr && hdr->message.schema_id == MGEP_SCHEMA_TRADING) {
    if (auto er = mgep::decode_exec_report(rcv_span)) {
        auto last_px = mgep::decode_decimal((*er)->last_px);
        if (last_px) std::cout << "Fill at " << *last_px << "\n";
    }
}

// Typed reject
if (auto reason = mgep::parse_flex_string(rcv_span, MGEP_BUSINESS_REJECT_SIZE)) {
    if (reason->starts_with("rate_limited:")) {
        // back off
    }
}
```

## Building

```bash
# Compile the C object separately, then link into your C++ target:
cc  -std=c11   -Wall -Wextra -Werror -c ../c/mgep.c -o mgep_c.o
c++ -std=c++20 -Wall -Wextra -Werror -o myapp myapp.cpp mgep_c.o -I../c
```

## Running tests

```bash
cc  -std=c11   -Wall -Wextra -Werror -c ../c/mgep.c -o mgep_c.o
c++ -std=c++20 -Wall -Wextra -Werror \
    -o test_mgep_cpp test_mgep.cpp mgep_c.o -I../c
./test_mgep_cpp
# Expected: 26 passed, 0 failed
```

## Zero-allocation encoding

`encode_new_order` returns a `std::vector` (one allocation). For
latency-sensitive paths, use `encode_new_order_into` with a caller-
provided buffer:

```cpp
std::uint8_t stack_buf[128];
if (auto n = mgep::encode_new_order_into(stack_buf, p)) {
    socket.send(stack_buf, *n);
}
```

## What's not here

Same exclusions as the other bindings: no connection management,
no client-side state, no AES-GCM. The C++ wrapper is the ergonomic
face; storage and concurrency are the caller's problem.
