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
| EstablishAck | 0x04 | S→C | 16B | Server confirms session |
| Heartbeat | 0x05 | Both | 8B | Keepalive with implicit seq ack |
| RetransmitRequest | 0x06 | Both | 8B | Request replay of missed messages |
| Retransmission | 0x07 | Both | 8B | Header before replayed messages |
| Terminate | 0x08 | Both | 8B | Graceful session end |
| Sequence | 0x09 | Both | — | Reserved |
| SessionStatus | 0x0A | Both | 24B | Session state report |
| SequenceReset | 0x0B | Both | 8B | Reset sequence numbers |
| NotApplied | 0x0C | S→C | 8B | Messages received but not applied |

## Sequence Tracking

- Each side maintains `next_outbound_seq` (starts at 1, monotonically increasing).
- Each side tracks `next_expected_seq` from the peer.
- Gap detection: if received seq > expected, a gap exists.
- Retransmission: send `RetransmitRequest(from_seq, count)`, peer replays from journal.
- NotApplied (iLink3-style): server notifies client that messages were received but not applied due to gap. Client decides whether to retransmit or cancel.

## Replay Journal

- Ring buffer of `DEFAULT_REPLAY_CAPACITY` (4096) outbound messages.
- `journal_outbound(seq, msg)` stores a copy.
- `get_journaled(seq)` retrieves by sequence number.
- Wraps around: old messages are overwritten.

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
