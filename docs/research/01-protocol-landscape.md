# Exchange Protocol Landscape Research

**Date:** 2026-04-16
**Status:** Complete
**Author:** MG Exchange Protocol Team

---

## 1. Executive Summary

This document surveys the current landscape of exchange trading protocols, covering traditional
finance (TradFi), cryptocurrency markets, and emerging technologies. The goal is to identify
gaps and opportunities for a new protocol that is faster, more secure, and more accessible
than existing solutions.

**Key Finding:** There is no protocol that simultaneously achieves:
- Ultra-low latency (sub-microsecond encode/decode)
- Security by default (zero-overhead encryption)
- Open standard (not tied to a single exchange)
- Easy integration (modern tooling, multi-language SDKs)
- Schema evolution (backward/forward compatible changes)

This gap is the opportunity for MGEP (MG Exchange Protocol).

---

## 2. Protocol Survey

### 2.1 FIX Protocol (Financial Information eXchange)

**Type:** Order entry + Market data
**Encoding:** Text-based tag=value (ASCII, SOH-delimited)
**Current Version:** FIX Latest (continuously updated); FIX 4.2 most deployed

#### History
- 1992: Created by Fidelity Investments and Salomon Brothers
- 2000: FIX 4.2 — most widely deployed version
- 2006: FIX 5.0 / FIXT 1.1 — separated transport and application layers
- 2009+: FIX 5.0 SP2 — extension packs (MiFID II, LEI, OTC derivatives)
- Now: "FIX Latest" model — continuous specification updates

#### Performance
| Metric | Value |
|--------|-------|
| Parse time | 5-50 us per message |
| Wire size (NewOrderSingle) | 200-400 bytes |
| Wire size (ExecutionReport) | 500-1500 bytes |
| Round-trip overhead | 10-100 us vs binary |
| Throughput | 50K-200K msg/s per connection |

#### Security
- TLS/SSL standard (adds 50-200 us to connection setup)
- Session-level auth: CompID/SubID pairs, password in Logon
- IP whitelisting at network level
- Many firms use unencrypted in colocation (latency tradeoff)

#### Strengths
- Universal adoption (280+ FIX Trading Community members)
- Rich message set covering full trade lifecycle
- Flexible and extensible (custom tags)
- Large ecosystem of engines, tools, certifiers
- Session-layer reliability (sequence numbers, gap fill)

#### Weaknesses
- Text encoding is slow and verbose
- String-based field lookup is CPU-intensive
- Not suitable for ultra-low-latency without heavy optimization
- Complex specification leads to interoperability issues

---

### 2.2 FAST Protocol (FIX Adapted for Streaming)

**Type:** Market data compression
**Encoding:** Binary with delta encoding and stop-bit integers
**Published:** 2006 by FIX Trading Community

#### How It Works
- Presence Map (PMAP): bitmap indicating which fields are present
- Stop-bit encoding: variable-length integers (high bit = continuation)
- Template-based: encoder/decoder must share templates
- Operators: constant, default, copy, increment, delta, tail

#### Performance
| Metric | Value |
|--------|-------|
| Compression ratio | 5:1 to 10:1 vs FIX text |
| Decode time | 1-10 us per message |
| Wire size (market data update) | 20-60 bytes |
| Throughput | 500K-1M+ msg/s per feed |

#### Adoption
- Moscow Exchange (MOEX), ASX, JSE
- CME (historical, now migrated to SBE/MDP 3.0)
- **Status: Declining** — being superseded by SBE

#### Weaknesses
- Stop-bit encoding is CPU-unfriendly (branch-heavy)
- Stateful: decoder tracks previous values (complex recovery)
- Not parallelizable due to sequential dependencies

---

### 2.3 ITCH Protocol (Nasdaq)

**Type:** Market data (full order book depth)
**Encoding:** Pure binary, fixed-length messages
**Current Version:** ITCH 5.0
**Transport:** UDP multicast (MoldUDP64)

#### Message Sizes
| Message Type | Size (bytes) |
|-------------|-------------|
| Add Order | 36 |
| Order Executed | 31 |
| Order Cancel | 23 |
| Order Delete | 19 |
| Trade | 44 |

#### Performance
| Metric | Value |
|--------|-------|
| Parse time | 50-200 ns (struct cast) |
| Peak throughput | 100K+ msg/s |
| Daily volume | Tens of millions of messages |

#### Security
- No encryption (performance)
- Network-level access control (colocation only)
- Subscription managed out-of-band

#### Strengths
- Extremely fast parsing (fixed-length = struct cast)
- Very compact wire format
- Full order book depth (every event)
- Simple to implement

#### Weaknesses
- UDP = no guaranteed delivery (gap detection + recovery needed)
- No encryption
- Nasdaq-specific (not universal standard)

---

### 2.4 OUCH Protocol (Nasdaq)

**Type:** Order entry
**Encoding:** Binary, fixed-length messages
**Current Version:** OUCH 5.0
**Transport:** TCP (SoupBinTCP)

#### Performance
| Metric | Value |
|--------|-------|
| Message size (Enter Order) | 47-49 bytes |
| Parse time | Sub-microsecond (struct read) |
| Round-trip (order to ack) | Low tens of microseconds |
| Throughput | 100K+ orders/s per connection |

#### Strengths
- Minimal protocol overhead
- Simple message set
- SoupBinTCP is lightweight and reliable

#### Weaknesses
- Limited functionality vs FIX
- Nasdaq-specific
- No encryption

---

### 2.5 BATS BOE2 (Cboe Binary Order Entry)

**Type:** Order entry
**Encoding:** Binary with bitfield presence maps
**Used by:** Cboe (BZX, BYX, EDGX, EDGA, Options, Futures, Europe)

#### Key Innovation
Bitfield presence maps: optional fields are entirely absent from wire when not used
(not zero-filled). More compact than fixed-layout for messages with many optional fields.

#### Performance
| Metric | Value |
|--------|-------|
| Message size | 30-60 bytes (variable) |
| Parse time | Sub-microsecond |
| Matching engine latency | Low tens of microseconds |

---

### 2.6 CME iLink 3 / MDP 3.0

**Type:** Order entry (iLink 3) + Market data (MDP 3.0)
**Encoding:** SBE (Simple Binary Encoding)
**Launched:** 2019-2020

#### Performance
| Metric | Value |
|--------|-------|
| Message size | 40-100 bytes |
| Parse time | Sub-microsecond (SBE) |
| Matching engine latency | 1-5 us |
| End-to-end (colocation) | Tens of microseconds |

#### Security
- HMAC-SHA256 authentication at session establishment
- No per-message encryption (latency)
- Network-level security in colocation

#### Significance
iLink 3 represents the state-of-the-art in exchange protocol design. The migration
from FIX text (iLink 2) to SBE (iLink 3) is the template for industry modernization.

---

### 2.7 EOBI / ETI (Deutsche Borse / Eurex T7)

**Type:** Market data (EOBI) + Order entry (ETI)
**Encoding:** Binary fixed-length
**Platform:** T7 matching engine

| Metric | Value |
|--------|-------|
| Matching engine latency | Sub-10 microseconds |
| Wire format | Compact binary (ITCH-like) |
| Scope | Eurex derivatives + Xetra equities |

---

### 2.8 SBE (Simple Binary Encoding)

**Type:** Serialization format (not a complete protocol)
**Standard:** FIX Trading Community
**Design goal:** Zero-copy, streaming field access, no allocation

#### Encoding Details
- Schema-defined (XML schemas, code generation)
- Fixed-length fields at fixed byte offsets
- Little-endian (native for x86 = no byte swap)
- Structure: header -> root block -> repeating groups -> var-length data
- NOT self-describing (decoder needs schema)

#### Benchmark Comparison
| Format | Encode (ns) | Decode (ns) | Size (bytes) | Zero-copy |
|--------|------------|------------|-------------|-----------|
| **SBE** | 50-150 | 50-150 | 40-80 | Yes |
| Protobuf | 500-2000 | 300-1000 | 50-100 | No |
| FlatBuffers | 100-300 | 50-200 | 60-120 | Yes |
| Cap'n Proto | 100-200 | 50-150 | 60-100 | Yes |
| FIX text | 2000-10000 | 5000-50000 | 200-500 | No |
| MessagePack | 300-1000 | 200-800 | 50-90 | No |
| FAST | 500-2000 | 500-2000 | 20-60 | No |

#### Weaknesses
- Schema evolution is constrained (fixed offsets)
- Not self-describing
- Smaller tooling ecosystem than Protobuf

---

### 2.9 Aeron

**Type:** Messaging transport
**Creator:** Martin Thompson (LMAX Disruptor)
**Design:** Lock-free, zero-copy, memory-mapped

#### Performance
| Mode | Latency | Throughput |
|------|---------|------------|
| IPC (shared memory) | 100-300 ns (p99) | 10M+ msg/s |
| UDP LAN | 5-20 us | 1M+ msg/s |
| Cluster (Raft) | Higher | Lower |

#### Adoption
- LSEG (London Stock Exchange Group)
- Major banks and HFT firms
- Often paired with SBE for encoding

#### Significance for MGEP
Aeron is a transport, not a protocol. MGEP should be designed to work
optimally over Aeron (as well as raw TCP/UDP).

---

### 2.10 Crypto Exchange Protocols

#### WebSocket + JSON (Dominant)
| Exchange | WS Market Data | WS Order Entry | Format |
|----------|---------------|----------------|--------|
| Binance | Yes | Yes | JSON |
| Coinbase | Yes | No (REST) | JSON |
| Kraken | Yes | Yes (v2) | JSON |
| OKX | Yes | Yes | JSON |
| Bybit | Yes | Yes | JSON |

**Latency:** 1-100 ms (vs microseconds for TradFi)
**Throughput:** 1K-10K msg/s (rate limited)

#### gRPC/Protobuf (Emerging)
- Some crypto exchanges offer gRPC for institutional access
- Better than JSON but not competitive with SBE for latency
- HTTP/2 overhead: 10-100 us per call

---

## 3. Acceleration Technologies

### 3.1 Kernel Bypass
| Technology | Approach | Latency Savings |
|------------|----------|-----------------|
| OpenOnload (Xilinx/AMD) | Userspace TCP/UDP stack | Kernel 10us -> 1-3us |
| DPDK | Poll-mode drivers, dedicated cores | Similar to OpenOnload |
| ef_vi | Direct NIC access API | Lowest possible in software |
| io_uring | Async I/O, shared ring buffers | Improving, not yet competitive |
| XDP/eBPF | Fast packet processing at driver | Good for filtering/routing |

### 3.2 FPGA
- Wire-to-wire latency: **0.5-5 us** (tick-to-trade)
- Used for: market data parsing, order book, signal generation, order construction
- Vendors: Xilinx/AMD Alveo, Intel Agilex, Algo-Logic, Enyx
- Cost: $500K-$5M+ for competitive system
- Trend: HLS making development more accessible

### 3.3 Hardware Encryption
- **AES-NI:** CPU instruction set for AES operations, ~1 cycle per byte
- **MACsec (802.1AE):** Layer 2 encryption in switch hardware, sub-microsecond
- **QAT (Quick Assist):** Intel offload for crypto operations
- **Implication for MGEP:** encryption can be near-zero-cost with proper hardware utilization

---

## 4. Gap Analysis

### 4.1 The TradFi-Crypto Divide
```
TradFi:   [ITCH/OUCH/SBE] ---- FAST ---- [FIX 4.2] ---- GAP ---- [Crypto WS+JSON]
Speed:     ~100ns parse          ~5us       ~50us                     ~10ms
Security:  None (colo)           None       TLS optional              TLS default
Openness:  Proprietary           Open       Open standard             Open but fragmented
```

**Nobody occupies the middle ground** — fast enough for serious trading, secure by default,
open standard, easy to integrate.

### 4.2 Schema Evolution Problem
- SBE: fast but rigid schemas (fixed offsets break on field insertion)
- Protobuf: flexible schemas but not zero-copy (varint decoding, allocation)
- FlatBuffers: zero-copy + vtable indirection (one dereference per field access)
- **Opportunity:** hybrid approach — fixed hot-path fields + extensible cold section

### 4.3 Security Model Gap
- TradFi: "security = firewall" (no protocol-level encryption)
- Crypto: "security = TLS" (high overhead)
- **Opportunity:** protocol-native authentication + optional hardware-accelerated encryption
  with near-zero overhead using AES-NI/MACsec

### 4.4 Fragmentation
- Every exchange = different binary protocol (ITCH, OUCH, BOE, ETI, iLink...)
- FIX is universal but slow
- **Opportunity:** universal binary protocol with exchange-specific message extensions

---

## 5. Design Requirements for MGEP

Based on this research, MGEP must achieve:

### Performance Targets
| Metric | Target | Rationale |
|--------|--------|-----------|
| Encode/decode | < 50 ns | Beat SBE (50-150 ns) |
| Wire size (order) | < 40 bytes minimal | Competitive with ITCH/OUCH |
| Throughput | > 10M msg/s | Match Aeron capability |
| Zero-copy | Required | Eliminate allocation overhead |

### Security Targets
| Feature | Target |
|---------|--------|
| Authentication | HMAC-SHA256 minimum, Ed25519 preferred |
| Encryption | Optional AES-256-GCM with AES-NI (< 1us overhead) |
| Integrity | Per-message HMAC or AEAD tag |
| Key exchange | X25519 ECDH or pre-shared keys |

### Usability Targets
| Feature | Target |
|---------|--------|
| Schema evolution | Add fields without breaking existing decoders |
| Languages | Rust, C/C++, Java, Go, Python (SDK) |
| Documentation | RFC-style spec + reference implementation |
| Certification | Automated conformance test suite |

### Architecture Targets
| Feature | Target |
|---------|--------|
| Transport | Agnostic (TCP, UDP, Aeron, shared memory) |
| Encoding | Binary, little-endian, fixed offsets for hot fields |
| Session layer | Lightweight (< SoupBinTCP complexity) |
| Extensibility | Exchange-specific message types via schema extensions |
