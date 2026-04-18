// MGEP C++ bindings — idiomatic header-only wrapper over the C layer.
//
// Requires C++17. Links against `mgep.c` (or bring it in as a sibling
// translation unit). Zero runtime dependencies.
//
// Design:
//   * The C header's POD structs are used directly; we don't re-define
//     them, we re-expose them in the `mgep` namespace for ergonomic
//     access.
//   * Strong-typed enums (scoped) replace the C preprocessor constants.
//   * Encoders return `std::vector<std::uint8_t>` or write into a
//     caller-provided `std::span<std::uint8_t>`.
//   * Decoders take a `std::span<const std::uint8_t>` and return
//     `std::optional<T>` — `nullopt` on short / malformed buffers.
//   * Flex parser returns `std::optional<std::string_view>`.

#ifndef MGEP_HPP
#define MGEP_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

extern "C" {
#include "mgep.h"
}

namespace mgep {

// ═══════════════════════════════════════════════════════════════
// Strong-typed enums
// ═══════════════════════════════════════════════════════════════

enum class Side : std::uint8_t {
    Buy = MGEP_SIDE_BUY,
    Sell = MGEP_SIDE_SELL,
};

enum class OrderType : std::uint8_t {
    Market = MGEP_OT_MARKET,
    Limit = MGEP_OT_LIMIT,
    Stop = MGEP_OT_STOP,
};

enum class TimeInForce : std::uint16_t {
    Day = MGEP_TIF_DAY,
    GTC = MGEP_TIF_GTC,
    IOC = MGEP_TIF_IOC,
    FOK = MGEP_TIF_FOK,
};

enum class ExecType : std::uint8_t {
    New = MGEP_EXEC_NEW,
    PartialFill = MGEP_EXEC_PARTIAL,
    Fill = MGEP_EXEC_FILL,
    Canceled = MGEP_EXEC_CANCELED,
};

enum class SchemaId : std::uint16_t {
    Session = MGEP_SCHEMA_SESSION,
    Trading = MGEP_SCHEMA_TRADING,
    MarketData = MGEP_SCHEMA_MARKET_DATA,
};

// ═══════════════════════════════════════════════════════════════
// Re-export C structs into the namespace
// ═══════════════════════════════════════════════════════════════

using FrameHeader = ::mgep_frame_header_t;
using MessageHeader = ::mgep_message_header_t;
using FullHeader = ::mgep_full_header_t;

using NewOrderSingle = ::mgep_new_order_t;
using ExecutionReport = ::mgep_exec_report_t;
using BusinessReject = ::mgep_business_reject_t;

using BookSnapshotRequest = ::mgep_snapshot_request_t;
using BookSnapshotBegin = ::mgep_snapshot_begin_t;
using BookSnapshotLevel = ::mgep_snapshot_level_t;
using BookSnapshotEnd = ::mgep_snapshot_end_t;

using ClockStatus = ::mgep_clock_status_t;

// ═══════════════════════════════════════════════════════════════
// Decimal helpers
// ═══════════════════════════════════════════════════════════════

inline std::int64_t encode_decimal(double value) noexcept {
    return mgep_encode_decimal(value);
}

/// Decode an i64 decimal. Returns `nullopt` if the raw value is the
/// NULL sentinel.
inline std::optional<double> decode_decimal(std::int64_t raw) noexcept {
    int is_null = 0;
    double v = mgep_decode_decimal(raw, &is_null);
    if (is_null) return std::nullopt;
    return v;
}

// ═══════════════════════════════════════════════════════════════
// Header
// ═══════════════════════════════════════════════════════════════

/// Decode the 32-byte MGEP full header. `nullopt` if the buffer is
/// too short or the magic bytes don't match.
inline std::optional<FullHeader> decode_header(
    std::span<const std::uint8_t> buf) noexcept {
    FullHeader h{};
    const int rc = mgep_decode_header(buf.data(), buf.size(), &h);
    if (rc != 0) return std::nullopt;
    return h;
}

// ═══════════════════════════════════════════════════════════════
// Encoders
// ═══════════════════════════════════════════════════════════════

struct NewOrderParams {
    std::uint64_t order_id = 0;
    std::uint64_t client_order_id = 0;
    std::uint32_t instrument_id = 0;
    Side side = Side::Buy;
    OrderType order_type = OrderType::Limit;
    TimeInForce time_in_force = TimeInForce::Day;
    double price = 0.0;
    double quantity = 0.0;
    std::optional<double> stop_price = std::nullopt;
    std::uint32_t sender_comp_id = 1;
    std::uint64_t sequence_num = 1;
    std::uint64_t correlation_id = 0;
};

/// Encode a NewOrderSingle into a freshly allocated vector.
inline std::vector<std::uint8_t> encode_new_order(const NewOrderParams& p) {
    std::vector<std::uint8_t> out(
        MGEP_FULL_HEADER_SIZE + MGEP_NEW_ORDER_SIZE);
    const int n = mgep_encode_new_order(
        out.data(), out.size(),
        p.order_id, p.client_order_id, p.instrument_id,
        static_cast<std::uint8_t>(p.side),
        static_cast<std::uint8_t>(p.order_type),
        static_cast<std::uint16_t>(p.time_in_force),
        encode_decimal(p.price),
        encode_decimal(p.quantity),
        p.stop_price.has_value() ? encode_decimal(*p.stop_price)
                                  : MGEP_DECIMAL_NULL,
        p.sender_comp_id, p.sequence_num, p.correlation_id);
    if (n < 0) out.clear();
    return out;
}

/// Encode into a caller-provided buffer (zero allocation). Returns the
/// number of bytes written, or `nullopt` on out-of-space.
inline std::optional<std::size_t> encode_new_order_into(
    std::span<std::uint8_t> buf, const NewOrderParams& p) noexcept {
    const int n = mgep_encode_new_order(
        buf.data(), buf.size(),
        p.order_id, p.client_order_id, p.instrument_id,
        static_cast<std::uint8_t>(p.side),
        static_cast<std::uint8_t>(p.order_type),
        static_cast<std::uint16_t>(p.time_in_force),
        encode_decimal(p.price),
        encode_decimal(p.quantity),
        p.stop_price.has_value() ? encode_decimal(*p.stop_price)
                                  : MGEP_DECIMAL_NULL,
        p.sender_comp_id, p.sequence_num, p.correlation_id);
    if (n < 0) return std::nullopt;
    return static_cast<std::size_t>(n);
}

// ═══════════════════════════════════════════════════════════════
// Decoders
// ═══════════════════════════════════════════════════════════════

template <typename T>
inline std::optional<const T*> wrap_ptr(const T* p) noexcept {
    if (!p) return std::nullopt;
    return p;
}

inline std::optional<const NewOrderSingle*> decode_new_order(
    std::span<const std::uint8_t> buf) noexcept {
    return wrap_ptr(mgep_decode_new_order(buf.data(), buf.size()));
}

inline std::optional<const ExecutionReport*> decode_exec_report(
    std::span<const std::uint8_t> buf) noexcept {
    return wrap_ptr(mgep_decode_exec_report(buf.data(), buf.size()));
}

inline std::optional<const BusinessReject*> decode_business_reject(
    std::span<const std::uint8_t> buf) noexcept {
    return wrap_ptr(mgep_decode_business_reject(buf.data(), buf.size()));
}

inline std::optional<const BookSnapshotBegin*> decode_snapshot_begin(
    std::span<const std::uint8_t> buf) noexcept {
    return wrap_ptr(mgep_decode_snapshot_begin(buf.data(), buf.size()));
}

inline std::optional<const BookSnapshotLevel*> decode_snapshot_level(
    std::span<const std::uint8_t> buf) noexcept {
    return wrap_ptr(mgep_decode_snapshot_level(buf.data(), buf.size()));
}

inline std::optional<const BookSnapshotEnd*> decode_snapshot_end(
    std::span<const std::uint8_t> buf) noexcept {
    return wrap_ptr(mgep_decode_snapshot_end(buf.data(), buf.size()));
}

inline std::optional<const ClockStatus*> decode_clock_status(
    std::span<const std::uint8_t> buf) noexcept {
    return wrap_ptr(mgep_decode_clock_status(buf.data(), buf.size()));
}

/// ClockStatus quality byte 1 == RegulatoryGrade.
inline bool is_regulatory_grade(const ClockStatus& s) noexcept {
    return s.quality == 1;
}

// ═══════════════════════════════════════════════════════════════
// Flex string parser
// ═══════════════════════════════════════════════════════════════

/// Parse an optional flex-block string by `field_id`. The returned
/// view borrows from `buf` — keep `buf` alive.
inline std::optional<std::string_view> parse_flex_string(
    std::span<const std::uint8_t> buf,
    std::size_t core_size,
    std::uint16_t field_id = 1) noexcept {
    const char* p = nullptr;
    std::size_t len = 0;
    const int rc = mgep_parse_flex_string(
        buf.data(), buf.size(), core_size, field_id, &p, &len);
    if (rc != 0) return std::nullopt;
    return std::string_view(p, len);
}

}  // namespace mgep

#endif  // MGEP_HPP
