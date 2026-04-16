# MGEP Performance Benchmarks

## Methodology

- **Tool:** Criterion.rs (statistical benchmarking with warmup, 100 samples per benchmark)
- **Build:** `cargo bench` (release mode, optimizations enabled)
- **Hardware:** Apple M-series (ARM64), single core
- **Measurement:** Wall-clock time via `std::time::Instant`
- **Reproducibility:** `cargo bench --bench encode_decode --bench full_stack`

All numbers are median (p50) with [lower bound, upper bound] confidence interval.

## Core Protocol (encode_decode benchmark)

| Operation | p50 | Description |
|---|---|---|
| **Decode NewOrder core** | **0.84 ns** | Zero-copy pointer cast, read order_id + price |
| **Dispatch (48 arms)** | **0.98 ns** | Match (schema_id, msg_type), try_from_bytes |
| **Encode NewOrder core** | **1.17 ns** | Write 32B header + 40B core to pre-allocated buffer |
| **Decode FullHeader** | **1.65 ns** | Read frame + message header (32 bytes) |
| **Decode ExecReport** | **1.47 ns** | Zero-copy 80-byte core block |
| **Validate NewOrder** | **4.69 ns** | Field range checks (side, order_type, qty > 0) |
| **Encode + flex** | **6.96 ns** | Core + 2 flex string fields |
| **Decode flex string** | **12.2 ns** | Find field by ID + read string |
| **Build heartbeat** | **16.4 ns** | Session heartbeat construction |

## Security (encode_decode benchmark)

| Operation | p50 | Description |
|---|---|---|
| **HMAC-SHA256 sign** | **1.45 μs** | Pure-Rust SHA-256, 64B message |
| **HMAC-SHA256 verify** | **1.44 μs** | Sign + constant-time compare |
| **AES-128-GCM encrypt** | **6.44 μs** | Pure-Rust AES + GCM (no AES-NI on ARM) |
| **AES-128-GCM decrypt** | **6.39 μs** | Decrypt + verify tag |

Note: AES-GCM with AES-NI hardware acceleration (x86_64) is expected to be 10-50x faster.

## Infrastructure (full_stack benchmark)

| Operation | p50 | Description |
|---|---|---|
| **Batch encode 50 msgs** | **185 ns** | 3.7 ns per message amortized |
| **Batch decode 50 msgs** | **121 ns** | 2.4 ns per message amortized |
| **Builder (order+flex)** | **191 ns** | Fluent API: `.buy().limit(150.25).quantity(100)` |
| **Inspector format** | **293 ns** | Human-readable message dump |
| **LZ4 compress 2.4KB** | **1.96 μs** | ~1.2 GB/s throughput |
| **LZ4 decompress 2.4KB** | **2.01 μs** | ~1.2 GB/s throughput |
| **Orderbook insert 100** | **4.94 μs** | 49 ns per order, BTreeMap-based |
| **Orderbook match sweep** | **4.22 μs** | Aggressive buy vs 50 resting asks |

## Throughput (integration tests, debug build)

| Scenario | Throughput | Notes |
|---|---|---|
| Encode NewOrder | 16.6M msg/sec | Single-threaded |
| Decode NewOrder | 97.8M msg/sec | Zero-copy, no allocation |
| TCP send+recv 100K msgs | 220K msg/sec | Blocking server, loopback |
| 20 clients × 5K orders | 100K orders total | Concurrent TCP, all delivered |

## vs Protobuf (prost)

| Operation | MGEP | Protobuf | Speedup |
|---|---|---|---|
| Encode NewOrder | 1.17 ns | 84 ns | **72x** |
| Decode NewOrder | 0.84 ns | 112 ns | **133x** |
| Encode ExecReport | 1.47 ns | 59 ns | **40x** |
| Decode ExecReport | 1.47 ns | 65 ns | **44x** |

Wire size: MGEP 72B vs Protobuf 64B (MGEP is 1.1x larger due to fixed 32B header).

## How to Reproduce

```bash
cd src/rust

# Core benchmarks
cargo bench --bench encode_decode

# Full stack benchmarks  
cargo bench --bench full_stack

# Protobuf comparison
cargo bench --bench vs_protobuf

# Throughput tests (prints results)
cargo test --test throughput -- --nocapture
```
