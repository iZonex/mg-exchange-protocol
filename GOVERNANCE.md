# MGEP Governance

## Current Model: BDFL (Benevolent Dictator for Life)

The protocol is currently maintained by a single core team. All design decisions go through internal review.

## Enhancement Proposals (MGEP-NNN)

All protocol changes are tracked through numbered enhancement proposals:

```
v0.1.0 — foundational
  MGEP-001: Initial wire format specification
  MGEP-002: Session layer and state machine
  MGEP-003: Security levels (HMAC-SHA256, AES-128-GCM)
  MGEP-004: Schema language design
  MGEP-005: Market data subscription model

v0.2.0 — production hardening (see CHANGELOG.md [0.2.0])
  MGEP-006: ClOrdID-based idempotency (NewOrderSingle core growth)
  MGEP-007: EstablishAck journal_low_seq_num + snapshot-vs-retransmit recovery
  MGEP-008: Market-data snapshot recovery flow (types 0x30–0x34)
  MGEP-009: Cancel-on-disconnect runtime enforcement
  MGEP-010: L7 rate limiting (token-bucket, session + account)
  MGEP-011: AES-GCM epoch rotation + wire handshake (0x0F/0x10)
  MGEP-012: Clock discipline + ClockStatus (0x0E), MiFID II gate
  MGEP-013: Audit record chain + role-based kill-switch
  MGEP-014: Pre-trade risk controls (SEC Rule 15c3-5 aligned)
  MGEP-015: Drop-copy compliance channel
  MGEP-016: Market-data entitlement framework
  MGEP-017: HA fencing + replicated state
  MGEP-018: FIX 4.4 gateway subset
  MGEP-019: Flex block hard-cap (32 fields)
  MGEP-020: Native bindings (C, C++, Java, C#, TypeScript)
```

### Proposal Format

Each MGEP proposal must include:

1. **Motivation** — Why is this change needed?
2. **Design** — Technical specification with wire format details
3. **Backward Compatibility** — What breaks? What doesn't?
4. **Rejected Alternatives** — What was considered and why not?
5. **Test Plan** — How to verify correctness?

### Status Lifecycle

```
Draft → Review → Accepted → Implemented → Released
                → Rejected (with reason)
                → Withdrawn
```

## Future: Committee Governance

The reference implementation lives in Rust (`src/rust/`). Other languages
currently ship as **wire-level bindings** (C, C++, Java, C#, TypeScript,
Python) that share the Rust sizing contract via per-binding tests —
they are not independent implementations of the full protocol.

Once **two independent protocol implementations** exist (end-to-end
session + reliability, not just wire decoders), governance transitions
to a technical committee with:

- At least one representative from each independent implementation
- Consensus required for wire format changes
- BDFL retains veto on security-critical decisions

## Decision Principles

1. **Performance over features.** Don't add complexity that slows the hot path.
2. **Compatibility over elegance.** A working upgrade path beats a clean redesign.
3. **Spec over code.** The specification document is authoritative. If code disagrees with spec, code is wrong.
4. **Prove it with numbers.** Claims require benchmarks. Benchmarks require methodology.
