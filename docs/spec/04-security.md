# MGEP Security Specification

## Overview

MGEP provides three security levels, selectable per session:

- **Level 0 (None)**: No authentication. For trusted networks and IPC.
- **Level 1 (Authenticated)**: HMAC-SHA256 message authentication.
- **Level 2 (Encrypted)**: AES-128-GCM AEAD encryption + authentication.

## Level 1: HMAC-SHA256

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
[FrameHeader 8B] [MessageHeader 16B] [Core] [Flex?] [HMAC tag 16B]
```

### Verification

1. Read `message_size` from frame header.
2. Extract tag = last 16 bytes.
3. Compute HMAC over bytes [8..message_size-16].
4. Constant-time comparison.

## Level 2: AES-128-GCM

### Key Derivation

```
key = HKDF-SHA256(
    salt = session_id (8 bytes, LE),
    IKM  = pre_shared_key,
    info = "mgep-aes128" || 0x01
)[0..16]
```

### Nonce Construction (12 bytes)

```
nonce[0..4]  = session_id truncated to 4 bytes (LE)
nonce[4..6]  = sender_comp_id (LE)
nonce[6..8]  = 0x0000
nonce[8..12] = sequence_num (LE)
```

Uniqueness: sequence numbers are monotonic within a session and never repeat.

**CRITICAL**: Reusing a nonce with the same key breaks GCM security. Sequence reset must use a new key.

### Encrypt Scope

- AAD (authenticated, not encrypted): FrameHeader (8 bytes)
- Encrypted: MessageHeader + Core + Flex
- Frame header stays cleartext for transport-level routing.

### Wire Format

```
[FrameHeader 8B cleartext] [Encrypted payload] [GCM tag 16B]
```

Frame flags: `HAS_AUTH_TAG | ENCRYPTED`.

### Pluggable Implementation

```rust
pub trait AeadCipher {
    fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], len: usize) -> Result<usize, AeadError>;
    fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], len: usize) -> Result<usize, AeadError>;
}
```

Reference: pure-Rust `Aes128Gcm`. Production: swap in hardware-backed AES-NI implementation.

## Session Authentication

During Establish, the client sends `credentials[32]`:
- Level 0: zeros.
- Level 1+: `credentials[0..16] = HMAC-SHA256(auth_key, session_id)`.
- Server verifies before accepting the session.
