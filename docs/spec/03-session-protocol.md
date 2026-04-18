# MGEP Session Protocol Specification

## Overview

The MGEP session layer manages connection lifecycle, sequence tracking, heartbeat, and retransmission. All session messages use `schema_id = 0x0000`.

## State Machine

```
Client:                          Server:
Disconnected                     Disconnected
    │ build_negotiate                │ handle_negotiate
    ▼                                ▼
Negotiating                      Negotiating
    │ handle_negotiate_response      │ build_negotiate_response
    ▼                                ▼
Negotiated                       Negotiated
    │ build_establish                │ handle_establish
    ▼                                ▼
Establishing                     Establishing
    │ handle_establish_ack           │ build_establish_ack
    ▼                                ▼
Active ◄────────────────────────► Active
    │                                │
    ├─► Retransmitting ──►Active     ├─► handle retransmit
    │                                │
    │ build_terminate                │ handle_terminate
    ▼                                ▼
Terminating                      Terminating
```

Every transition is enforced — calling a method in the wrong state returns `SessionError::InvalidState`.

## Message Types

| Type | Code | Direction | Core Size | Description |
|------|------|-----------|-----------|-------------|
| Negotiate | 0x01 | C→S | 48B | Client proposes session parameters |
| NegotiateResponse | 0x02 | S→C | 56B | Server accepts/rejects |
| Establish | 0x03 | C→S | 48B | Start sequenced messaging |
| EstablishAck | 0x04 | S→C | 24B | Server confirms session + reports `journal_low_seq_num` |
| Heartbeat | 0x05 | Both | 8B | Keepalive with implicit seq ack |
| RetransmitRequest | 0x06 | Both | 8B | Request replay of missed messages |
| Retransmission | 0x07 | Both | 8B | Header before replayed messages |
| Terminate | 0x08 | Both | 8B | Graceful session end |
| Sequence | 0x09 | Both | — | Reserved |
| SessionStatus | 0x0A | Both | 24B | Session state report |
| SequenceReset | 0x0B | Both | 8B | Reset sequence numbers (see reason codes below) |
| NotApplied | 0x0C | S→C | 8B | Messages received but not applied |
| TestRequest | 0x0D | Both | — | RTT measurement probe |
| ClockStatus | 0x0E | S→C | 40B | Clock discipline broadcast (see [§6](06-clock-discipline.md)) |
| KeyRotationRequest | 0x0F | Both | 16B | Announce AES-GCM epoch rotation |
| KeyRotationAck | 0x10 | Both | 16B | Peer confirms rotation readiness |

## Sequence Tracking

- Each side maintains `next_outbound_seq` (starts at 1, monotonically increasing).
- Each side tracks `next_expected_seq` from the peer.
- Gap detection: if received seq > expected, a gap exists.
- Retransmission: send `RetransmitRequest(from_seq, count)`, peer replays from journal.
- NotApplied (iLink3-style): server notifies client that messages were received but not applied due to gap. Client decides whether to retransmit or cancel.

## Replay Journal

- Ring buffer of `DEFAULT_REPLAY_CAPACITY` (4096) outbound messages.
- `journal_outbound(seq, msg)` stores a copy.
- `get_journaled(seq)` retrieves by sequence number (back-compat).
- `lookup_journaled(seq)` returns a rich `JournalLookup` enum that
  distinguishes `Found` / `BelowWatermark { low }` / `AboveWatermark { high }`
  / `Empty`. Clients must consult this instead of the collapsed
  `Option<&[u8]>` — a `None` from the old API conflates "never produced"
  with "overwritten by wrap", which historically caused silent message
  loss on reconnect.
- Low / high watermarks track the recoverable range. When `journal_low_water`
  advances past a requested seq, `RetransmitRequestCore` is answered with
  `SequenceReset(reason=JournalExhausted=3)` so the client falls back to
  snapshot recovery instead of getting an empty response.

## `EstablishAck` Watermark Contract

`EstablishAckCore` carries `journal_low_seq_num` (`u64`, offset 16). On
reconnect, the client computes `Session::assess_recovery(prev_expected, &ack)`
which returns one of:

- `InSync` — nothing to recover.
- `CanRetransmit { from_seq, count }` — gap lies within the journal; send
  a `RetransmitRequest`.
- `MustSnapshot { missing_from, earliest_available }` — gap extends below
  the journal's low-water; client MUST fall back to snapshot recovery
  (see [§5 Market Data](05-market-data.md) for the snapshot flow).

## Key Rotation Handshake

AES-GCM encrypted sessions (`SecurityLevel::Encrypted`) rotate their key
periodically to stay within the NIST-recommended key-use envelope. The
two-phase handshake:

```
initiator:                              peer:
  SessionCipher::begin_rotation()
  build_key_rotation_request() ─►
                                        handle_key_rotation_request()
                                        SessionCipher::begin_rotation()
                                ◄─ build_key_rotation_ack(status=0)
  handle_key_rotation_ack()
  SessionCipher::commit_rotation()
  (next outbound uses epoch + 1)        SessionCipher::commit_rotation()
```

Rotation triggers: message-count threshold, byte-count threshold,
wall-clock duration, `SequenceReset`, administrative, or
compromise-suspected. Between `begin` and `commit` the initiator
continues encrypting under the CURRENT epoch — no messages are
dropped across the transition.

If the peer rejects (`KeyRotationAck.status=1`), the initiator calls
`abort_rotation()` and stays on the current epoch. Operators should
page on repeated rejects.

## `SequenceReset` Reason Codes

| Code | Name | Semantics |
|---|---|---|
| 0 | Admin | Operator-initiated. |
| 1 | SlowConsumer | Peer fell too far behind; was disconnected. |
| 2 | Reconnect | New session; reset counters. |
| 3 | JournalExhausted | Requested retransmit below low-water; fall back to snapshot recovery. |

## `ClockStatus` Broadcast

Servers MUST broadcast `ClockStatus` (type `0x0E`, 40 bytes) on every
session channel at least once per second, and immediately on any
`ClockQuality` transition. Consumers gate any regulator-grade emission
(audit records, post-trade reports) on
`ClockQuality::RegulatoryGrade`. See [§6 Clock Discipline](06-clock-discipline.md).

## Reconnection

1. Connection drops → `reset_to_disconnected()`
2. Preserves: session_id, sequences, replay journal
3. Re-negotiate with same session_id
4. Establish carries `next_seq_num` — peer detects gaps
5. Automatic retransmit request for missed messages

## Heartbeat & Timeout

- `needs_heartbeat(now)`: true if `keepalive_ms` elapsed since last send.
- `peer_timed_out(now)`: true if 3x `keepalive_ms` elapsed since last receive.
- Heartbeat carries `next_seq_num` as implicit acknowledgment.

## Security Levels

| Level | Value | Description |
|-------|-------|-------------|
| None | 0 | No auth (trusted network / IPC) |
| Authenticated | 1 | HMAC-SHA256 per message |
| Encrypted | 2 | AES-128-GCM AEAD |

Negotiated during session setup via `security_level` field.
