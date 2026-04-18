# Audit Trail & Kill-Switch (MGEP Spec §7)

Trading venues MUST retain an immutable, timestamped record of every
material event and MUST expose an operator-level halt mechanism. This
section specifies both.

## 7.1 Requirements

A conformant MGEP venue:

1. SHALL emit exactly one `AuditRecord` per material event (submission,
   ack, reject, cancel, replace, fill, expire, mass-cancel, session loss,
   halt, resume, compliance override, risk breach).
2. SHALL reject regulator-grade events (§6 `ClockQuality::RegulatoryGrade`)
   when the clock is not disciplined to that grade. The refusal itself is
   logged (operationally) but the business action MUST be rejected.
3. SHALL chain records via `prev_digest` so a regulator can verify
   ordering and detect deletion from the archived log.
4. SHALL restrict kill-switch actions (`KillSwitchHalt`,
   `KillSwitchResume`, `ComplianceOverride`) to privileged roles
   (`RiskOfficer`, `ComplianceOfficer`, `SystemOperator`, `Venue`).
5. SHALL broadcast `MarketHaltNotification` on every halt / resume
   transition AND periodically (at least once per second while any halt
   is active) so late-joining clients see current state.
6. SHALL reject order submissions whose (session, account, instrument)
   intersects any active halt; the rejection MUST cite the most specific
   halt scope in the `BusinessReject.business_reason` field.

## 7.2 `AuditRecord` (80 bytes)

```
offset  size  field
  0      8    audit_seq           monotonic within this audit stream
  8      8    timestamp           ns since epoch, clock §6 compliant
 16      8    actor_id            session / account / operator id
 24      8    subject_id          order / trade / cancel id, 0 if n/a
 32      4    instrument_id       0 for venue-wide actions
 36      1    action              AuditAction u8
 37      1    actor_role          ActorRole u8
 38      1    clock_quality       ClockQuality u8 (§6)
 39      1    _pad
 40      2    reason              AuditReason u16
 42      2    _pad
 44     16    payload_digest      16-byte hash of the full event payload
 60     16    prev_digest         payload_digest of the previous record
```

### `AuditAction` (u8)

| Code | Name | Regulatory-grade clock required? |
|---|---|---|
| 1 | OrderSubmit | Yes |
| 2 | OrderAck | Yes |
| 3 | OrderReject | Yes |
| 4 | OrderCancel | Yes |
| 5 | OrderReplace | Yes |
| 6 | Fill | Yes |
| 7 | PartialFill | Yes |
| 8 | Expire | Yes |
| 9 | MassCancel | Yes |
| 10 | SessionLost | No (operational) |
| 11 | KillSwitchHalt | Yes |
| 12 | KillSwitchResume | Yes |
| 13 | ComplianceOverride | Yes |
| 14 | RiskBreach | No (operational) |

### `AuditReason` (u16)

| Code | Name |
|---|---|
| 0 | Normal |
| 1 | RegulatoryCancel |
| 2 | SessionCancelOnDisconnect |
| 3 | RateLimited |
| 4 | DuplicateClOrdID |
| 5 | MarketHalted |
| 6 | RiskCheckFailed |
| 7 | SelfTradePrevented |
| 8 | ClockSkew |
| 9 | PeerTimeout |
| 10 | KillSwitchTripped |
| ≥ 0x8000 | VenueDefined |

## 7.3 Kill-switch scopes

Halts apply to one of four scopes, most-specific-first at gate time:

| Scope | Use case |
|---|---|
| `MarketWide` | Circuit breaker, venue incident, regulator-requested halt. |
| `Instrument(u32)` | Pending-news, LULD, single-symbol volatility. |
| `Account(u64)` | Participant risk breach, compliance lock. |
| `Session(u64)` | Specific algo misbehaving; don't disrupt the account as a whole. |

When multiple halts apply, the order-gate returns the most specific — so
audit records and `BusinessReject` codes attribute rejection to the
right level.

### `HaltReason` (u8)

| Code | Name |
|---|---|
| 1 | CircuitBreaker |
| 2 | RegulatoryHalt |
| 3 | OperationalIncident |
| 4 | RiskAction |
| 5 | Scheduled |
| 6 | Drill |
| 255 | VenueDefined |

## 7.4 Authorization

Only privileged roles may trip or resume the kill-switch. The check is
applied at two layers:

1. `KillSwitchState::halt()` / `::resume()` — in-memory gate.
2. `AuditGate::emit()` — audit-layer gate.

Both reject `ActorRole::Trader` and `ActorRole::MarketMaker`. The double
gate is intentional; a bug in one must not be sufficient to bypass the
other.

## 7.5 Storage recommendation

The audit log is append-only. Production deployments SHOULD:

* Persist to WORM (Write-Once-Read-Many) storage. AWS S3 Object Lock,
  Azure Immutable Blob, on-prem NFS + lockd, or a `chattr +a` Linux file.
* Retain records for the full regulatory retention window (MiFID II: 5
  years; SEC: 3–5 years depending on record class).
* Replicate synchronously to at least one other availability zone before
  the corresponding business action ACKs to the client — otherwise a
  crash can result in a trade with no audit entry.
* Publish a periodic Merkle root of the last N records to an external
  trusted timestamp authority (RFC 3161) so regulators can verify the
  chain has not been retroactively trimmed.

MGEP ships `InMemoryAuditLogger` (tests / dev) and a `FailingAuditLogger`
(deliberate "fail loud" placeholder). Durable sinks are a deployment
concern; the trait `AuditLogger::append` is the integration point.
