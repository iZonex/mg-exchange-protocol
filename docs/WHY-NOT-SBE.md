# Why MGEP Instead of SBE/ITCH/OUCH/FIX?

Honest technical comparison. No marketing.

## vs SBE (Simple Binary Encoding)

SBE is MGEP's closest competitor. Both are zero-copy binary with fixed-offset core blocks.

| Aspect | SBE | MGEP | Winner |
|---|---|---|---|
| Core block decode | Zero-copy cast | Zero-copy cast | Tie |
| Schema evolution | Append-only to root block. Can't insert fields. | Core frozen + flex block for new fields. Old readers ignore new flex fields. | MGEP |
| Repeating groups | 4-byte header per group, nested | Packed in flex block (no nesting overhead) | Depends on use |
| Schema language | XML (verbose, needs tooling to read) | Human-readable `.mgep` format | MGEP |
| Built-in encryption | None | AES-128-GCM with pluggable backend | MGEP |
| Session layer | None (SBE is encoding-only, FIXP adds session) | Full session with retransmit, replay, reconnect | MGEP |
| Full exchange lifecycle | No (needs FIXP + FIX semantics on top) | Yes (48 message types: orders, MD, quotes, post-trade, risk) | MGEP |
| Production deployments | CME, LSE, 10+ years | None yet | SBE |
| Code generators | Java, C++, C#, Go, Rust, Python | Rust, C, Python | SBE |
| Maturity | Battle-tested since 2014 | Pre-release | SBE |

**When to use SBE:** You already have FIXP infrastructure and need only encoding.
**When to use MGEP:** You want a complete protocol (encoding + session + lifecycle) with built-in security.

## vs ITCH (Nasdaq)

| Aspect | ITCH 5.0 | MGEP |
|---|---|---|
| Direction | One-way (exchange → client) | Bidirectional |
| Scope | Market data only | Full lifecycle |
| Schema evolution | None. New version = new spec. | Flex block, backward compatible |
| Message identification | Fixed 1-byte type code | 2-byte schema + 2-byte type |
| Field types | Fixed-width, spec-defined | Semantic types (id, price, qty) |

**ITCH is not a competitor** — it's a one-way market data feed format. MGEP covers ITCH's use case (order book updates, trades) plus everything else.

## vs OUCH (Nasdaq)

| Aspect | OUCH | MGEP |
|---|---|---|
| Direction | Bidirectional (order entry) | Bidirectional (everything) |
| Scope | Order entry only | Full lifecycle |
| Session | Login + heartbeat | Full state machine with retransmit |
| Security | None (relies on network) | HMAC-SHA256 / AES-128-GCM |

**OUCH is simple and fast but limited.** No market data, no post-trade, no risk management. MGEP covers OUCH's use case and more.

## vs FIX (4.4 / 5.0 SP2)

| Aspect | FIX | MGEP |
|---|---|---|
| Encoding | Text tag=value (slow) | Binary zero-copy (sub-nanosecond) |
| Parse latency | 5–50 μs | < 1 ns (core block) |
| Schema evolution | Breaks parsers | Core frozen + flex extensible |
| Encryption | External TLS | Built-in per-message AEAD |
| Message coverage | 93+ types, 30 years | 48 types, focused on exchange use |
| Industry adoption | Universal | None yet |

**FIX is slow but universal.** Every trading firm has a FIX parser. MGEP is 1000x faster but has zero ecosystem. The path: MGEP for internal exchange matching + FIX gateway for external connectivity.

## The Honest Assessment

**MGEP is better on paper.** Faster encoding, cleaner schema evolution, built-in security, complete lifecycle coverage.

**SBE has 10 years of production.** MGEP has zero.

The question is not "is MGEP technically better?" (it is, in several dimensions). The question is "is it worth switching?" That depends on your specific needs:

- Starting a new exchange from scratch? MGEP makes sense.
- Adding a binary feed to an existing FIX exchange? Consider SBE with FIXP.
- Need built-in encryption without TLS? MGEP is the only option.
- Need a proven, safe choice? Use SBE.
