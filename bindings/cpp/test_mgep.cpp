// Framework-free C++ test harness for the MGEP C++ bindings.
// Build:
//   c++ -std=c++17 -Wall -Wextra -Werror -o test_mgep_cpp \
//       test_mgep.cpp ../c/mgep.c -I../c
//   ./test_mgep_cpp

#include "mgep.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace {

int passed = 0;
int failed = 0;

template <typename A, typename B>
void assert_eq(const A& a, const B& b, const char* name) {
    if (static_cast<long long>(a) == static_cast<long long>(b)) {
        ++passed;
        std::printf("PASS: %s\n", name);
    } else {
        ++failed;
        std::printf("FAIL: %s — %lld != %lld\n", name,
                    static_cast<long long>(a), static_cast<long long>(b));
    }
}

void assert_close(double a, double b, double tol, const char* name) {
    if (std::fabs(a - b) < tol) {
        ++passed;
        std::printf("PASS: %s\n", name);
    } else {
        ++failed;
        std::printf("FAIL: %s — %f !~= %f\n", name, a, b);
    }
}

void assert_true(bool cond, const char* name) {
    if (cond) {
        ++passed;
        std::printf("PASS: %s\n", name);
    } else {
        ++failed;
        std::printf("FAIL: %s\n", name);
    }
}

void test_sizes() {
    assert_eq(sizeof(mgep::FullHeader), MGEP_FULL_HEADER_SIZE, "FullHeader size");
    assert_eq(sizeof(mgep::NewOrderSingle), MGEP_NEW_ORDER_SIZE, "NewOrderSingle size");
    assert_eq(sizeof(mgep::ExecutionReport), MGEP_EXEC_REPORT_SIZE, "ExecutionReport size");
    assert_eq(sizeof(mgep::BusinessReject), MGEP_BUSINESS_REJECT_SIZE, "BusinessReject size");
    assert_eq(sizeof(mgep::ClockStatus), MGEP_CLOCK_STATUS_SIZE, "ClockStatus size");
}

void test_decimal() {
    assert_eq(mgep::encode_decimal(150.25), 15025000000LL, "decimal encode");
    auto dec = mgep::decode_decimal(15025000000LL);
    assert_true(dec.has_value(), "decimal decode non-null");
    assert_close(*dec, 150.25, 1e-9, "decimal roundtrip");
    auto null_decoded = mgep::decode_decimal(MGEP_DECIMAL_NULL);
    assert_true(!null_decoded.has_value(), "NULL sentinel decodes to nullopt");
}

void test_encode_decode() {
    mgep::NewOrderParams p{};
    p.order_id = 42;
    p.client_order_id = 99;
    p.instrument_id = 7;
    p.side = mgep::Side::Buy;
    p.order_type = mgep::OrderType::Limit;
    p.time_in_force = mgep::TimeInForce::Day;
    p.price = 150.25;
    p.quantity = 100.0;
    p.sender_comp_id = 1;
    p.sequence_num = 1;

    auto bytes = mgep::encode_new_order(p);
    assert_eq(bytes.size(),
              static_cast<std::size_t>(MGEP_FULL_HEADER_SIZE + MGEP_NEW_ORDER_SIZE),
              "encoded size");

    auto hdr = mgep::decode_header(bytes);
    assert_true(hdr.has_value(), "header decoded");
    assert_eq(hdr->message.schema_id, MGEP_SCHEMA_TRADING, "schema_id");
    assert_eq(hdr->message.message_type, MGEP_MSG_NEW_ORDER, "message_type");

    auto order_opt = mgep::decode_new_order(bytes);
    assert_true(order_opt.has_value(), "order decoded non-null");
    const auto* order = *order_opt;
    assert_eq(order->order_id, 42, "order_id");
    assert_eq(order->client_order_id, 99, "client_order_id");
    assert_eq(order->side, static_cast<std::uint8_t>(mgep::Side::Buy), "side");
    assert_close(static_cast<double>(order->price) / 1e8, 150.25, 1e-6, "price");
    assert_eq(order->stop_price, MGEP_DECIMAL_NULL, "stop_price null");
}

void test_encode_into_buffer() {
    std::uint8_t buf[128] = {0};
    mgep::NewOrderParams p{};
    p.order_id = 1;
    p.client_order_id = 1;
    p.instrument_id = 1;
    p.side = mgep::Side::Sell;
    p.order_type = mgep::OrderType::Market;
    p.price = 0.0;
    p.quantity = 5.0;

    auto n = mgep::encode_new_order_into(buf, p);
    assert_true(n.has_value(), "encode into buffer succeeds");
    assert_eq(*n, static_cast<std::size_t>(MGEP_FULL_HEADER_SIZE + MGEP_NEW_ORDER_SIZE),
              "encode_into bytes written");

    std::uint8_t tiny[10] = {0};
    auto none = mgep::encode_new_order_into(tiny, p);
    assert_true(!none.has_value(), "encode_into rejects small buffer");
}

void test_short_buffer_rejects() {
    std::uint8_t short_buf[8] = {0};
    auto hdr = mgep::decode_header(short_buf);
    assert_true(!hdr.has_value(), "short buffer yields nullopt");
    auto order = mgep::decode_new_order(short_buf);
    assert_true(!order.has_value(), "short core yields nullopt");
}

void test_is_regulatory_grade() {
    mgep::ClockStatus cs{};
    cs.quality = 1;
    assert_true(mgep::is_regulatory_grade(cs), "quality=1 → regulatory");
    cs.quality = 2;
    assert_true(!mgep::is_regulatory_grade(cs), "quality=2 → not regulatory");
}

}  // namespace

int main() {
    test_sizes();
    test_decimal();
    test_encode_decode();
    test_encode_into_buffer();
    test_short_buffer_rejects();
    test_is_regulatory_grade();

    std::printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
