# MGEP Governance

## Current Model: BDFL (Benevolent Dictator for Life)

The protocol is currently maintained by a single core team. All design decisions go through internal review.

## Enhancement Proposals (MGEP-NNN)

All protocol changes are tracked through numbered enhancement proposals:

```
MGEP-001: Initial wire format specification
MGEP-002: Session layer and state machine
MGEP-003: Security levels (HMAC-SHA256, AES-128-GCM)
MGEP-004: Schema language design
MGEP-005: Market data subscription model
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

Once two independent MGEP implementations exist (e.g., Rust + C++ or Rust + Java), governance transitions to a technical committee with:

- At least one representative from each independent implementation
- Consensus required for wire format changes
- BDFL retains veto on security-critical decisions

## Decision Principles

1. **Performance over features.** Don't add complexity that slows the hot path.
2. **Compatibility over elegance.** A working upgrade path beats a clean redesign.
3. **Spec over code.** The specification document is authoritative. If code disagrees with spec, code is wrong.
4. **Prove it with numbers.** Claims require benchmarks. Benchmarks require methodology.
