# MGEP Security Specification

## Overview

MGEP provides three security levels, selectable per session:

- **Level 0 (None)**: No authentication. For trusted networks and IPC.
- **Level 1 (Authenticated)**: HMAC-SHA256 message authentication.
- **Level 2 (Encrypted)**: AES-128-GCM AEAD encryption + authentication +
  **epoch-based key rotation** (see §4).

## 1. Level 1: HMAC-SHA256

### Construction

```
tag = HMAC-SHA256(key, message_body)[0..16]
```

- Key: pre-shared, any length (hashed to 64 bytes if >64).
- Input: message body = bytes from offset 8 (after FrameHeader) to end of core+flex.
- Output: 16-byte truncated tag appended after the message.
- Frame header updated: `message_size += 16`, `flags |= HAS_AUTH_TAG`.

### Wire Format

```
[FrameHeader 8B] [MessageHeader 24B] [Core] [Flex?] [HMAC tag 16B]
```

### Verification

1. Read `message_size` from frame header.
2. Extract tag = last 16 bytes.
3. Compute HMAC over bytes `[8..message_size-16]`.
4. Constant-time comparison.

## 2. Level 2: AES-128-GCM

### Key Derivation

```
key = HKDF-SHA256(
    salt = session_id (8 bytes, LE) || epoch (4 bytes, LE),
    IKM  = master_pre_shared_key,
    info = "mgep-aes128" || 0x01
)[0..16]
```

Both peers derive independently; the derived key never crosses the wire.
The master key lives behind the [`KeyProvider`](../../src/rust/src/crypto_session.rs)
trait — production deployments implement a thin adapter over HSM / KMS so
the master never exposes plaintext bytes to Rust memory.

### Nonce Construction (12 bytes)

```
nonce[0..4]  = epoch (LE)              ← defense in depth
nonce[4..8]  = sender_comp_id (LE)     ← distinguishes the two peers
nonce[8..12] = seq_in_epoch (LE)       ← resets on rotation
```

Uniqueness is enforced by **strict monotonic `seq_in_epoch`** on both
encrypt and decrypt paths: a repeat of any `seq_in_epoch` within an epoch
is refused with `CryptoError::NonceReuse`. Even if a bug reused a key,
`epoch` in the nonce prevents reuse across rotations.

**CRITICAL:** Reusing a nonce with the same key breaks GCM
confidentiality — MGEP's session cipher closes this hole by (1) rotating
keys on the triggers below and (2) refusing encrypt calls with
non-monotonic seq.

### Encrypt Scope

- AAD (authenticated, not encrypted): FrameHeader (8 bytes)
- Encrypted: MessageHeader + Core + Flex
- Frame header stays cleartext for transport-level routing.

### Wire Format

```
[FrameHeader 8B cleartext] [Encrypted payload (MessageHeader + body)] [GCM tag 16B]
```

Frame flags: `HAS_AUTH_TAG | ENCRYPTED`.

### Pluggable Implementation

```rust
pub trait AeadCipher {
    fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], len: usize) -> Result<usize, AeadError>;
    fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], len: usize) -> Result<usize, AeadError>;
}
```

Reference: pure-Rust `Aes128Gcm`. Production: swap in a hardware-accelerated
impl (AES-NI is the default on x86_64; ARMv8 Crypto Extensions for aarch64).

## 3. `KeyProvider` trait (HSM / KMS integration)

```rust
pub trait KeyProvider: Send + Sync {
    fn derive_session_key(&self, session_id: u64, epoch: u32) -> [u8; 16];
}
```

In-memory PSK impl ships by default. Production deployments MUST replace it
with an adapter that calls into Vault / AWS CloudHSM / Google Cloud KMS /
Azure Key Vault / on-prem HSM — the master key never exists in Rust process
memory.

## 4. Key Rotation Handshake

AES-128-GCM sessions rotate keys periodically to stay within the
NIST-recommended key-use envelope. Rotation triggers:

| Trigger | Default |
|---|---|
| Messages per epoch | 2²⁸ (≈ 268M) |
| Bytes per epoch | 64 GiB |
| Wall-clock duration | 1 hour |
| SequenceReset | Always |
| Administrative signal | Always |
| CompromiseSuspected | Always |

Tighter thresholds are configurable via [`RotationPolicy`](../../src/rust/src/crypto_session.rs).

### Two-phase wire handshake

```
initiator                                       peer
    │                                             │
    │ SessionCipher::begin_rotation(reason)       │
    │                                             │
    │ build_key_rotation_request(next_epoch) ──►  │
    │                                             │  handle_key_rotation_request()
    │                                             │  SessionCipher::begin_rotation()
    │                                             │
    │                          ◄── build_key_rotation_ack(epoch, status=0)
    │                                             │
    │ handle_key_rotation_ack()                   │
    │ SessionCipher::commit_rotation()            │  SessionCipher::commit_rotation()
    │                                             │
    │ next outbound uses epoch+1                  │  next outbound uses epoch+1
```

Wire message sizes: `KeyRotationRequestCore` = 16 B, `KeyRotationAckCore` = 16 B.
Both live in the session schema (`0x0000`) as types `0x0F` and `0x10`
respectively; see [§3 Session Protocol](03-session-protocol.md).

Between `begin` and `commit` the initiator continues encrypting under the
**current** epoch — no messages drop across the transition.

If the peer rejects (`KeyRotationAck.status = 1`), the initiator calls
`abort_rotation()` and stays on the current epoch. Repeated rejects SHOULD
page ops.

## 5. Session Authentication

During `Establish`, the client sends `credentials[32]`:

- Level 0: zeros.
- Level 1+: `credentials[0..16] = HMAC-SHA256(auth_key, session_id)`.
- Server verifies before accepting the session.

The `auth_key` is held by the client and the server out-of-band — typically
provisioned via the billing / onboarding flow. MGEP does not itself
mediate key distribution.

## 6. Replay protection

Every inbound message's `sequence_num` is checked against the session's
`next_expected_seq`. Gaps trigger `RetransmitRequest`; duplicates are
silently dropped. On encrypted sessions, the `SessionCipher` additionally
refuses any `seq_in_epoch` that repeats — so a replay attack replaying a
legitimate ciphertext would be caught at the cipher layer even if the
session layer didn't notice.
