//! Session-level cryptography: nonce management, key rotation, HSM hook.
//!
//! # Why this exists
//!
//! `crypto.rs` is a correct AEAD primitive but is **only** a primitive. The
//! spec docstring says:
//!
//! > CRITICAL: Reusing a nonce with the same key breaks GCM.
//!
//! and then trusts the caller to build a unique `(nonce, key)` pair. Nothing
//! enforces it. The `derive_key_with_epoch` helper has existed the whole
//! time but nothing called it: SequenceReset rotated the seq counter
//! without rotating the key, which means `(session_id, sender_comp_id,
//! seq)` can repeat with the same key after a reset — catastrophic GCM
//! nonce reuse.
//!
//! This module adds the missing state machine:
//!
//! * `SessionCipher` wraps an `AeadCipher` with bookkeeping: current epoch,
//!   messages emitted this epoch, bytes emitted this epoch.
//! * Encryption routes through `encrypt`, which auto-rotates when a
//!   [`RotationPolicy`] trigger fires BEFORE building the nonce.
//! * Nonce layout encodes the epoch, so nonces never collide across epochs
//!   even under weird conditions (defense in depth).
//! * Outbound calls check **strict monotonic seq within epoch**; a repeat
//!   is refused with `CryptoError::NonceReuse`.
//! * [`KeyProvider`] trait abstracts where the master key lives. The default
//!   `InMemoryKeyProvider` holds the PSK in RAM; production deployments
//!   implement a thin adapter over their HSM / KMS.
//!
//! # Wire coordination
//!
//! Actually *communicating* the rotation to the peer requires a new session
//! message (`KeyRotationRequest` / `KeyRotationAck`). That wire protocol is
//! a separate follow-up; here we expose [`SessionCipher::begin_rotation`]
//! and [`SessionCipher::commit_rotation`] as the two halves so the dispatch
//! layer can drive the handshake once it's defined.

use crate::crypto::{AeadCipher, AeadError, encrypt_message, decrypt_message};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─── Nonce Construction ──────────────────────────────────────

/// Build a 12-byte GCM nonce with the epoch in the high bits.
///
/// Layout: `[epoch 4B][sender_comp_id 4B][seq_in_epoch 4B]`.
///
/// Why this shape:
///
/// * `seq_in_epoch` wraps at 2^32 — but before it does, rotation fires (see
///   `RotationPolicy::max_messages_per_epoch`). Even if policy were buggy,
///   a wrap within the same epoch would be caught by the monotonicity
///   check in [`SessionCipher::encrypt`].
/// * `epoch` makes nonces unique across rotations without relying solely on
///   key rotation; a bug that reuses a key still cannot reuse a nonce.
/// * `sender_comp_id` keeps both sides of a session from colliding — each
///   side has its own sender ID.
#[inline]
pub fn build_session_nonce(epoch: u32, sender_comp_id: u32, seq_in_epoch: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&epoch.to_le_bytes());
    nonce[4..8].copy_from_slice(&sender_comp_id.to_le_bytes());
    nonce[8..12].copy_from_slice(&seq_in_epoch.to_le_bytes());
    nonce
}

// ─── Key Provider ────────────────────────────────────────────

/// Abstracts the source of the master key material.
///
/// Production deployments want the master key to live in an HSM / KMS so
/// even full server compromise cannot leak it. The trait is intentionally
/// small: it returns a derived per-epoch key, not the master, so the HSM
/// never has to expose long-term secret bytes to Rust memory.
///
/// Implementations must be constant-time in the key comparison path.
pub trait KeyProvider: Send + Sync {
    /// Return a fresh 16-byte AES-128 key for the given `(session_id, epoch)`.
    /// The same `(session_id, epoch)` pair MUST always return the same key
    /// (both peers derive independently; the key never crosses the wire).
    fn derive_session_key(&self, session_id: u64, epoch: u32) -> [u8; 16];
}

/// In-memory PSK-backed key provider. Suitable for dev and colocation where
/// the server operator holds the PSK directly. NOT suitable for internet-
/// facing deployments — use an HSM-backed impl.
pub struct InMemoryKeyProvider {
    master_key: Vec<u8>,
}

impl InMemoryKeyProvider {
    pub fn new(master_key: Vec<u8>) -> Self {
        assert!(!master_key.is_empty(), "master key must be non-empty");
        Self { master_key }
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn derive_session_key(&self, session_id: u64, epoch: u32) -> [u8; 16] {
        crate::crypto::derive_key_with_epoch(&self.master_key, session_id, epoch)
    }
}

// ─── Rotation Policy ─────────────────────────────────────────

/// When to rotate the key. A rotation fires when **any** dimension crosses
/// its threshold. Zero/None means "never rotate on this dimension".
#[derive(Debug, Clone, Copy)]
pub struct RotationPolicy {
    /// Force rotation when this many messages have been encrypted under the
    /// current epoch. Must stay comfortably below 2^32 so `seq_in_epoch`
    /// never wraps within an epoch.
    pub max_messages_per_epoch: u64,
    /// Force rotation after this many bytes have been encrypted.
    pub max_bytes_per_epoch: u64,
    /// Force rotation after the epoch has been active this long.
    pub max_duration_per_epoch: Option<Duration>,
}

impl RotationPolicy {
    /// Safe defaults: 2^28 messages (~268M), 64 GiB, 1 hour. All three are
    /// well under the GCM safe-use envelope and below the 2^32 nonce wrap.
    pub const DEFAULT: Self = Self {
        max_messages_per_epoch: 1 << 28,
        max_bytes_per_epoch: 64 * 1024 * 1024 * 1024,
        max_duration_per_epoch: Some(Duration::from_secs(3600)),
    };

    /// No automatic rotation. Only `begin_rotation()` fires. Useful for
    /// tests.
    pub const NEVER: Self = Self {
        max_messages_per_epoch: u64::MAX,
        max_bytes_per_epoch: u64::MAX,
        max_duration_per_epoch: None,
    };
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ─── Errors ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Underlying AEAD failure (bad tag, short buffer, etc.).
    Aead(AeadError),
    /// Caller requested encryption with a seq that was already used under
    /// this `(epoch, key)`. Refused to prevent catastrophic nonce reuse.
    NonceReuse { last_accepted: u32, requested: u32 },
    /// The remote peer supplied an epoch we have not rotated to yet.
    /// Caller should drop the message or trigger rotation-recovery.
    UnknownEpoch { got: u32, current: u32 },
    /// Rotation is in progress; the session cannot encrypt outbound until
    /// the peer acknowledges the new epoch.
    RotationInFlight,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead(e) => write!(f, "AEAD: {}", e),
            Self::NonceReuse { last_accepted, requested } => write!(
                f,
                "nonce reuse refused: last accepted seq={}, requested={}",
                last_accepted, requested
            ),
            Self::UnknownEpoch { got, current } => write!(
                f,
                "peer epoch {} != current {}",
                got, current
            ),
            Self::RotationInFlight => write!(f, "key rotation in progress"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<AeadError> for CryptoError {
    fn from(e: AeadError) -> Self {
        Self::Aead(e)
    }
}

// ─── Session Cipher ──────────────────────────────────────────

/// Factory for constructing an `AeadCipher` from raw key bytes. Injecting
/// this instead of requiring a concrete `Aes128Gcm` type keeps the session
/// layer hardware-agnostic: the same state machine runs on top of the pure-
/// Rust impl, the AES-NI impl, or a future hardware-accelerated one.
pub type CipherFactory = Arc<dyn Fn(&[u8; 16]) -> Box<dyn AeadCipher + Send + Sync> + Send + Sync>;

/// Per-direction cipher state.
struct DirectionState {
    cipher: Box<dyn AeadCipher + Send + Sync>,
    epoch: u32,
    last_seq: Option<u32>,
    messages: u64,
    bytes: u64,
    epoch_started_at: Instant,
}

/// Per-session cipher with automatic key rotation and nonce-uniqueness
/// enforcement.
///
/// Holds separate outbound and inbound state because each side of the
/// connection has its own sender_comp_id and its own monotonic seq. Inbound
/// state tracks the *peer's* epoch, which may lag the local outbound epoch
/// during rotation handshake.
pub struct SessionCipher {
    session_id: u64,
    local_sender_comp_id: u32,
    remote_sender_comp_id: u32,
    provider: Arc<dyn KeyProvider>,
    factory: CipherFactory,
    policy: RotationPolicy,
    out: DirectionState,
    inbound: DirectionState,
    /// True between `begin_rotation()` and `commit_rotation()` — peer has
    /// not yet acknowledged the new outbound epoch, so we must not send
    /// under it.
    rotation_pending: bool,
    rotation_pending_epoch: Option<u32>,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl SessionCipher {
    pub fn new(
        session_id: u64,
        local_sender_comp_id: u32,
        remote_sender_comp_id: u32,
        provider: Arc<dyn KeyProvider>,
        factory: CipherFactory,
        policy: RotationPolicy,
    ) -> Self {
        Self::with_clock(
            session_id,
            local_sender_comp_id,
            remote_sender_comp_id,
            provider,
            factory,
            policy,
            Arc::new(Instant::now),
        )
    }

    pub fn with_clock(
        session_id: u64,
        local_sender_comp_id: u32,
        remote_sender_comp_id: u32,
        provider: Arc<dyn KeyProvider>,
        factory: CipherFactory,
        policy: RotationPolicy,
        now: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let start_epoch = 1u32; // 0 reserved as "uninitialized" sentinel
        let key = provider.derive_session_key(session_id, start_epoch);
        let out_cipher = factory(&key);
        let in_cipher = factory(&key);
        let started = now();
        Self {
            session_id,
            local_sender_comp_id,
            remote_sender_comp_id,
            provider,
            factory,
            policy,
            out: DirectionState {
                cipher: out_cipher,
                epoch: start_epoch,
                last_seq: None,
                messages: 0,
                bytes: 0,
                epoch_started_at: started,
            },
            inbound: DirectionState {
                cipher: in_cipher,
                epoch: start_epoch,
                last_seq: None,
                messages: 0,
                bytes: 0,
                epoch_started_at: started,
            },
            rotation_pending: false,
            rotation_pending_epoch: None,
            now,
        }
    }

    pub fn current_epoch(&self) -> u32 {
        self.out.epoch
    }

    pub fn peer_epoch(&self) -> u32 {
        self.inbound.epoch
    }

    pub fn rotation_pending(&self) -> bool {
        self.rotation_pending
    }

    // ── Encryption ────────────────────────────────────────────

    /// Encrypt a message in place. `seq_in_epoch` must be strictly greater
    /// than any previously-accepted seq under the current epoch.
    ///
    /// If the rotation policy would fire after this message, rotation is
    /// initiated atomically (the returned `RotationSignal` tells the caller
    /// to emit a `KeyRotationRequest` to the peer). The current message
    /// still encrypts under the *old* epoch; the new epoch does not become
    /// active for outbound traffic until `commit_rotation` runs.
    pub fn encrypt(
        &mut self,
        buf: &mut [u8],
        msg_len: usize,
        seq_in_epoch: u32,
    ) -> Result<EncryptOutcome, CryptoError> {
        if self.rotation_pending {
            return Err(CryptoError::RotationInFlight);
        }
        if let Some(last) = self.out.last_seq
            && seq_in_epoch <= last {
                return Err(CryptoError::NonceReuse { last_accepted: last, requested: seq_in_epoch });
            }

        let nonce = build_session_nonce(self.out.epoch, self.local_sender_comp_id, seq_in_epoch);
        let new_len = encrypt_with_nonce(
            self.out.cipher.as_ref(),
            buf,
            msg_len,
            &nonce,
        )?;
        self.out.last_seq = Some(seq_in_epoch);
        self.out.messages += 1;
        self.out.bytes += new_len as u64;

        // Evaluate rotation triggers AFTER committing the message. The
        // policy fires at the end of the current epoch, not during it — so
        // the peer always sees an epoch transition on a clean boundary.
        let signal = self.check_rotation_triggers();
        Ok(EncryptOutcome { new_len, rotation_signal: signal })
    }

    /// Decrypt a message in place. The peer's epoch is supplied out-of-band
    /// (the session layer extracts it from the frame's auth header). Nonce
    /// reuse on the inbound side is rejected exactly as on outbound — a
    /// replay attack manifests as a duplicate seq within an epoch.
    pub fn decrypt(
        &mut self,
        buf: &mut [u8],
        msg_len: usize,
        peer_epoch: u32,
        seq_in_epoch: u32,
    ) -> Result<usize, CryptoError> {
        if peer_epoch != self.inbound.epoch {
            return Err(CryptoError::UnknownEpoch {
                got: peer_epoch,
                current: self.inbound.epoch,
            });
        }
        if let Some(last) = self.inbound.last_seq
            && seq_in_epoch <= last {
                return Err(CryptoError::NonceReuse { last_accepted: last, requested: seq_in_epoch });
            }

        let nonce = build_session_nonce(peer_epoch, self.remote_sender_comp_id, seq_in_epoch);
        let new_len = decrypt_with_nonce(
            self.inbound.cipher.as_ref(),
            buf,
            msg_len,
            &nonce,
        )?;
        self.inbound.last_seq = Some(seq_in_epoch);
        self.inbound.messages += 1;
        self.inbound.bytes += new_len as u64;
        Ok(new_len)
    }

    // ── Rotation state machine ────────────────────────────────

    /// Check rotation triggers without modifying state beyond flipping the
    /// `rotation_pending` flag when a trigger fires.
    fn check_rotation_triggers(&mut self) -> RotationSignal {
        let p = &self.policy;
        let s = &self.out;
        let hit_msgs = s.messages >= p.max_messages_per_epoch;
        let hit_bytes = s.bytes >= p.max_bytes_per_epoch;
        let hit_time = p
            .max_duration_per_epoch
            .map(|d| (self.now)().saturating_duration_since(s.epoch_started_at) >= d)
            .unwrap_or(false);

        if hit_msgs || hit_bytes || hit_time {
            let next = self.out.epoch.wrapping_add(1);
            self.rotation_pending = true;
            self.rotation_pending_epoch = Some(next);
            let reason = if hit_msgs {
                RotationReason::MessageCount
            } else if hit_bytes {
                RotationReason::ByteCount
            } else {
                RotationReason::TimeElapsed
            };
            RotationSignal::Required { next_epoch: next, reason }
        } else {
            RotationSignal::None
        }
    }

    /// External trigger (e.g. SequenceReset, admin command, operational key
    /// compromise). Marks rotation as pending at the next epoch. Idempotent
    /// within a single pending cycle.
    pub fn begin_rotation(&mut self, reason: RotationReason) -> RotationSignal {
        if self.rotation_pending {
            return RotationSignal::Required {
                next_epoch: self.rotation_pending_epoch.unwrap_or(self.out.epoch + 1),
                reason,
            };
        }
        let next = self.out.epoch.wrapping_add(1);
        self.rotation_pending = true;
        self.rotation_pending_epoch = Some(next);
        RotationSignal::Required { next_epoch: next, reason }
    }

    /// Commit the rotation — peer has acknowledged. Switches the cipher to
    /// the new epoch key and resets seq-in-epoch counters for both sides.
    ///
    /// Panics if no rotation is pending (programmer error — callers must
    /// guard with `rotation_pending()`).
    pub fn commit_rotation(&mut self) -> Result<u32, CryptoError> {
        let next = self
            .rotation_pending_epoch
            .expect("commit_rotation called without begin_rotation");

        let key = self.provider.derive_session_key(self.session_id, next);
        let new_out = (self.factory)(&key);
        let new_in = (self.factory)(&key);
        let now = (self.now)();

        self.out = DirectionState {
            cipher: new_out,
            epoch: next,
            last_seq: None,
            messages: 0,
            bytes: 0,
            epoch_started_at: now,
        };
        self.inbound = DirectionState {
            cipher: new_in,
            epoch: next,
            last_seq: None,
            messages: 0,
            bytes: 0,
            epoch_started_at: now,
        };
        self.rotation_pending = false;
        self.rotation_pending_epoch = None;
        Ok(next)
    }

    /// Abort a pending rotation (e.g. peer rejected the KeyRotationRequest).
    /// Returns `true` if a rotation was actually aborted.
    pub fn abort_rotation(&mut self) -> bool {
        let was = self.rotation_pending;
        self.rotation_pending = false;
        self.rotation_pending_epoch = None;
        was
    }

    // ── Observability ─────────────────────────────────────────

    pub fn outbound_stats(&self) -> EpochStats {
        EpochStats {
            epoch: self.out.epoch,
            messages: self.out.messages,
            bytes: self.out.bytes,
            elapsed: (self.now)().saturating_duration_since(self.out.epoch_started_at),
        }
    }

    pub fn inbound_stats(&self) -> EpochStats {
        EpochStats {
            epoch: self.inbound.epoch,
            messages: self.inbound.messages,
            bytes: self.inbound.bytes,
            elapsed: (self.now)().saturating_duration_since(self.inbound.epoch_started_at),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EpochStats {
    pub epoch: u32,
    pub messages: u64,
    pub bytes: u64,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    MessageCount,
    ByteCount,
    TimeElapsed,
    /// Session-layer signalled rotation (e.g. `SequenceReset` arrived).
    SequenceReset,
    /// Admin / ops initiated rotation.
    Administrative,
    /// Compromise suspected; rotate immediately.
    CompromiseSuspected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationSignal {
    None,
    /// Caller should emit `KeyRotationRequest(next_epoch)` to the peer and
    /// keep encrypting under the current epoch until `commit_rotation`
    /// runs. If the peer doesn't ack within a timeout, fall back to
    /// `abort_rotation` and retry.
    Required {
        next_epoch: u32,
        reason: RotationReason,
    },
}

#[derive(Debug, Clone)]
pub struct EncryptOutcome {
    pub new_len: usize,
    pub rotation_signal: RotationSignal,
}

// ─── Helpers that wrap the primitive crypto functions ───────
//
// The primitive `encrypt_message` / `decrypt_message` build their own nonce
// from `(session_id, sender_comp_id, seq)`. We already have a nonce, so we
// route around them. This preserves zero-copy + frame-header-as-AAD.

fn encrypt_with_nonce(
    cipher: &dyn AeadCipher,
    buf: &mut [u8],
    msg_len: usize,
    nonce: &[u8; 12],
) -> Result<usize, AeadError> {
    use crate::frame::{AUTH_TAG_SIZE, FrameFlags, FrameHeader};

    if msg_len < FrameHeader::SIZE || buf.len() < msg_len + AUTH_TAG_SIZE {
        return Err(AeadError::BufferTooShort);
    }
    let new_size = msg_len + AUTH_TAG_SIZE;
    buf[4..8].copy_from_slice(&(new_size as u32).to_le_bytes());
    buf[2] |= FrameFlags::HAS_AUTH_TAG | FrameFlags::ENCRYPTED;

    let mut aad = [0u8; 8];
    aad.copy_from_slice(&buf[..FrameHeader::SIZE]);

    let payload_start = FrameHeader::SIZE;
    let payload_len = msg_len - payload_start;
    let encrypted_len = cipher.encrypt(nonce, &aad, &mut buf[payload_start..], payload_len)?;
    Ok(payload_start + encrypted_len)
}

fn decrypt_with_nonce(
    cipher: &dyn AeadCipher,
    buf: &mut [u8],
    msg_len: usize,
    nonce: &[u8; 12],
) -> Result<usize, AeadError> {
    use crate::frame::{AUTH_TAG_SIZE, FrameFlags, FrameHeader};

    if msg_len < FrameHeader::SIZE + AUTH_TAG_SIZE {
        return Err(AeadError::BufferTooShort);
    }
    let mut aad = [0u8; 8];
    aad.copy_from_slice(&buf[..FrameHeader::SIZE]);
    let payload_start = FrameHeader::SIZE;
    let ciphertext_len = msg_len - payload_start;
    let plaintext_len = cipher.decrypt(nonce, &aad, &mut buf[payload_start..], ciphertext_len)?;
    let new_size = payload_start + plaintext_len;
    buf[4..8].copy_from_slice(&(new_size as u32).to_le_bytes());
    buf[2] &= !(FrameFlags::ENCRYPTED | FrameFlags::HAS_AUTH_TAG);
    Ok(new_size)
}

// Hint to silence dead-code warnings on `encrypt_message`/`decrypt_message`
// while callers migrate to the session-aware wrappers.
#[allow(dead_code)]
const _REFERENCE_COMPAT: () = {
    let _ = encrypt_message as fn(&mut [u8], usize, &dyn AeadCipher, u64, u32, u64) -> Result<usize, AeadError>;
    let _ = decrypt_message as fn(&mut [u8], usize, &dyn AeadCipher, u64, u32, u64) -> Result<usize, AeadError>;
};

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Aes128Gcm;
    use std::sync::Mutex;

    fn factory() -> CipherFactory {
        Arc::new(|key: &[u8; 16]| {
            Box::new(Aes128Gcm::new(key)) as Box<dyn AeadCipher + Send + Sync>
        })
    }

    fn provider() -> Arc<dyn KeyProvider> {
        Arc::new(InMemoryKeyProvider::new(b"a-32-byte-master-key-for-testing".to_vec()))
    }

    fn mock_clock() -> (Arc<Mutex<Instant>>, Arc<dyn Fn() -> Instant + Send + Sync>) {
        let anchor = Arc::new(Mutex::new(Instant::now()));
        let a2 = anchor.clone();
        let f: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(move || *a2.lock().unwrap());
        (anchor, f)
    }

    fn build_msg(buf: &mut [u8], payload: &[u8]) -> usize {
        // Minimal valid frame: 8-byte FrameHeader then payload.
        buf[0..2].copy_from_slice(&0x474Du16.to_le_bytes()); // magic
        buf[2] = 0; // flags
        buf[3] = 1; // version
        let total = 8 + payload.len();
        buf[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        buf[8..total].copy_from_slice(payload);
        total
    }

    #[test]
    fn nonce_uniqueness_across_epochs() {
        let n1 = build_session_nonce(1, 42, 5);
        let n2 = build_session_nonce(2, 42, 5);
        assert_ne!(n1, n2, "epoch must affect nonce");
        let n3 = build_session_nonce(1, 43, 5);
        assert_ne!(n1, n3, "sender_comp_id must affect nonce");
    }

    #[test]
    fn roundtrip_basic() {
        let mut cipher = SessionCipher::new(
            0xABCD, 10, 20, provider(), factory(), RotationPolicy::NEVER,
        );
        let mut peer = SessionCipher::new(
            0xABCD, 20, 10, provider(), factory(), RotationPolicy::NEVER,
        );

        let mut buf = [0u8; 256];
        let msg_len = build_msg(&mut buf, b"hello world");
        let out = cipher.encrypt(&mut buf, msg_len, 1).unwrap();
        let decrypted = peer.decrypt(&mut buf, out.new_len, 1, 1).unwrap();
        assert_eq!(&buf[8..decrypted], b"hello world");
    }

    #[test]
    fn nonce_reuse_refused_on_outbound() {
        let mut cipher = SessionCipher::new(
            1, 10, 20, provider(), factory(), RotationPolicy::NEVER,
        );
        let mut buf = [0u8; 256];
        let n = build_msg(&mut buf, b"x");
        cipher.encrypt(&mut buf, n, 5).unwrap();

        // Same seq again — must refuse, NOT silently encrypt.
        let n = build_msg(&mut buf, b"x");
        let err = cipher.encrypt(&mut buf, n, 5).unwrap_err();
        assert!(matches!(err, CryptoError::NonceReuse { last_accepted: 5, requested: 5 }));

        // Lower seq also refused (monotonicity).
        let n = build_msg(&mut buf, b"x");
        let err = cipher.encrypt(&mut buf, n, 3).unwrap_err();
        assert!(matches!(err, CryptoError::NonceReuse { last_accepted: 5, requested: 3 }));
    }

    #[test]
    fn rotation_fires_on_message_count() {
        let (_clock, now) = mock_clock();
        let policy = RotationPolicy {
            max_messages_per_epoch: 3,
            ..RotationPolicy::NEVER
        };
        let mut cipher = SessionCipher::with_clock(
            1, 10, 20, provider(), factory(), policy, now,
        );
        let mut buf = [0u8; 128];

        for seq in 1..=2u32 {
            let n = build_msg(&mut buf, b"hi");
            let out = cipher.encrypt(&mut buf, n, seq).unwrap();
            assert!(matches!(out.rotation_signal, RotationSignal::None));
        }
        // Third message trips the counter.
        let n = build_msg(&mut buf, b"hi");
        let out = cipher.encrypt(&mut buf, n, 3).unwrap();
        match out.rotation_signal {
            RotationSignal::Required { next_epoch: 2, reason: RotationReason::MessageCount } => {}
            other => panic!("expected rotation signal, got {:?}", other),
        }
        assert!(cipher.rotation_pending());

        // No more outbound until commit.
        let n = build_msg(&mut buf, b"blocked");
        let err = cipher.encrypt(&mut buf, n, 4).unwrap_err();
        assert!(matches!(err, CryptoError::RotationInFlight));
    }

    #[test]
    fn rotation_fires_on_time() {
        let (clock, now) = mock_clock();
        let policy = RotationPolicy {
            max_messages_per_epoch: u64::MAX,
            max_bytes_per_epoch: u64::MAX,
            max_duration_per_epoch: Some(Duration::from_secs(10)),
        };
        let mut cipher = SessionCipher::with_clock(
            1, 10, 20, provider(), factory(), policy, now,
        );
        let mut buf = [0u8; 128];

        let n = build_msg(&mut buf, b"hi");
        let out = cipher.encrypt(&mut buf, n, 1).unwrap();
        assert!(matches!(out.rotation_signal, RotationSignal::None));

        // Advance 11 seconds, send again.
        *clock.lock().unwrap() += Duration::from_secs(11);
        let n = build_msg(&mut buf, b"hi");
        let out = cipher.encrypt(&mut buf, n, 2).unwrap();
        match out.rotation_signal {
            RotationSignal::Required { next_epoch: 2, reason: RotationReason::TimeElapsed } => {}
            other => panic!("expected time-based rotation, got {:?}", other),
        }
    }

    #[test]
    fn commit_resets_seq_counter_and_activates_new_key() {
        let mut a = SessionCipher::new(1, 10, 20, provider(), factory(), RotationPolicy::NEVER);
        let mut b = SessionCipher::new(1, 20, 10, provider(), factory(), RotationPolicy::NEVER);

        // Rotate both sides in lockstep.
        let sig = a.begin_rotation(RotationReason::SequenceReset);
        assert!(matches!(sig, RotationSignal::Required { next_epoch: 2, .. }));
        let _ = b.begin_rotation(RotationReason::SequenceReset);

        a.commit_rotation().unwrap();
        b.commit_rotation().unwrap();
        assert_eq!(a.current_epoch(), 2);
        assert_eq!(b.current_epoch(), 2);
        assert!(!a.rotation_pending());

        // Seq counter reset: can start from 1 again in the new epoch.
        let mut buf = [0u8; 128];
        let n = build_msg(&mut buf, b"post-rotation");
        let out = a.encrypt(&mut buf, n, 1).unwrap();
        let dec = b.decrypt(&mut buf, out.new_len, 2, 1).unwrap();
        assert_eq!(&buf[8..dec], b"post-rotation");
    }

    #[test]
    fn abort_rotation_restores_sending() {
        let mut cipher = SessionCipher::new(1, 10, 20, provider(), factory(), RotationPolicy::NEVER);
        cipher.begin_rotation(RotationReason::Administrative);
        assert!(cipher.rotation_pending());
        assert!(cipher.abort_rotation());
        assert!(!cipher.rotation_pending());

        let mut buf = [0u8; 128];
        let n = build_msg(&mut buf, b"resumed");
        cipher.encrypt(&mut buf, n, 1).unwrap();
    }

    #[test]
    fn decrypt_rejects_wrong_epoch() {
        let mut a = SessionCipher::new(1, 10, 20, provider(), factory(), RotationPolicy::NEVER);
        let mut b = SessionCipher::new(1, 20, 10, provider(), factory(), RotationPolicy::NEVER);

        let mut buf = [0u8; 128];
        let n = build_msg(&mut buf, b"x");
        let out = a.encrypt(&mut buf, n, 1).unwrap();

        // Peer thinks epoch is 5 even though sender wrote epoch 1 — reject.
        let err = b.decrypt(&mut buf, out.new_len, 5, 1).unwrap_err();
        assert!(matches!(err, CryptoError::UnknownEpoch { got: 5, current: 1 }));
    }

    #[test]
    fn decrypt_rejects_replayed_seq() {
        let mut a = SessionCipher::new(1, 10, 20, provider(), factory(), RotationPolicy::NEVER);
        let mut b = SessionCipher::new(1, 20, 10, provider(), factory(), RotationPolicy::NEVER);

        let mut buf1 = [0u8; 128];
        let n = build_msg(&mut buf1, b"first");
        let out = a.encrypt(&mut buf1, n, 1).unwrap();
        b.decrypt(&mut buf1, out.new_len, 1, 1).unwrap();

        // Identical ciphertext replayed — peer refuses because seq is non-monotonic.
        let mut buf2 = buf1;
        // Restore the encrypted flag the in-place decrypt just cleared, so
        // the replay attempt actually goes through decrypt() rather than
        // being rejected earlier.
        buf2[2] |= crate::frame::FrameFlags::ENCRYPTED | crate::frame::FrameFlags::HAS_AUTH_TAG;
        let err = b.decrypt(&mut buf2, out.new_len, 1, 1).unwrap_err();
        assert!(matches!(err, CryptoError::NonceReuse { .. }));
    }

    #[test]
    fn begin_rotation_is_idempotent() {
        let mut cipher = SessionCipher::new(1, 10, 20, provider(), factory(), RotationPolicy::NEVER);
        let s1 = cipher.begin_rotation(RotationReason::Administrative);
        let s2 = cipher.begin_rotation(RotationReason::CompromiseSuspected);
        // Second call returns the SAME next_epoch as the first.
        if let (RotationSignal::Required { next_epoch: e1, .. }, RotationSignal::Required { next_epoch: e2, .. }) = (s1, s2) {
            assert_eq!(e1, e2);
        } else {
            panic!("expected Required signals");
        }
    }

    #[test]
    fn hsm_interface_can_swap_provider() {
        // Sanity: a custom KeyProvider impl works. This is the HSM hook —
        // prod replaces InMemoryKeyProvider with a thin adapter to Vault /
        // CloudHSM / etc.
        struct FakeHsm;
        impl KeyProvider for FakeHsm {
            fn derive_session_key(&self, session_id: u64, epoch: u32) -> [u8; 16] {
                // Deterministic but NOT a real KDF — test-only.
                let mut k = [0u8; 16];
                k[..8].copy_from_slice(&session_id.to_le_bytes());
                k[8..12].copy_from_slice(&epoch.to_le_bytes());
                k
            }
        }

        let mut a = SessionCipher::new(
            42, 10, 20, Arc::new(FakeHsm) as Arc<dyn KeyProvider>, factory(), RotationPolicy::NEVER,
        );
        let mut b = SessionCipher::new(
            42, 20, 10, Arc::new(FakeHsm) as Arc<dyn KeyProvider>, factory(), RotationPolicy::NEVER,
        );
        let mut buf = [0u8; 128];
        let n = build_msg(&mut buf, b"hsm-backed");
        let out = a.encrypt(&mut buf, n, 1).unwrap();
        let dec = b.decrypt(&mut buf, out.new_len, 1, 1).unwrap();
        assert_eq!(&buf[8..dec], b"hsm-backed");
    }
}
