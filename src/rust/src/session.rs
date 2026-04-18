//! MGEP Session Layer
//!
//! Lightweight session management: negotiate, establish, heartbeat, terminate.
//! Sequence tracking, gap detection, and retransmission for reliable messaging.
//!
//! State machine (client):
//!   Disconnected → [build_negotiate] → Negotiating
//!   Negotiating  → [handle_negotiate_response(accepted)] → Negotiated
//!   Negotiated   → [build_establish] → Establishing
//!   Establishing → [handle_establish_ack] → Active
//!   Active       → [build_terminate / handle_terminate] → Terminating
//!
//! State machine (server):
//!   Disconnected → [handle_negotiate + build_negotiate_response] → WaitEstablish
//!   WaitEstablish → [handle_establish + build_establish_ack] → Active
//!   Active       → [build_terminate / handle_terminate] → Terminating

use crate::frame::FrameFlags;
use crate::types::Timestamp;

/// Session layer schema ID
pub const SESSION_SCHEMA_ID: u16 = 0x0000;

/// Session message types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum SessionMsgType {
    Negotiate = 0x01,
    NegotiateResponse = 0x02,
    Establish = 0x03,
    EstablishAck = 0x04,
    Heartbeat = 0x05,
    RetransmitRequest = 0x06,
    Retransmission = 0x07,
    Terminate = 0x08,
    Sequence = 0x09,
    SessionStatus = 0x0A,
    SequenceReset = 0x0B,
    NotApplied = 0x0C,
    TestRequest = 0x0D,
    ClockStatus = 0x0E,
    /// `KeyRotationRequest` — sender announces the next epoch and asks the
    /// peer to switch on ack. See `crypto_session::SessionCipher`.
    KeyRotationRequest = 0x0F,
    /// `KeyRotationAck` — peer confirms it has prepared the new epoch;
    /// sender then calls `commit_rotation()` to activate.
    KeyRotationAck = 0x10,
}

/// Security level negotiated during session setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityLevel {
    /// No authentication, no encryption (trusted network / IPC)
    None = 0,
    /// HMAC-SHA256 authentication, no encryption
    Authenticated = 1,
    /// AES-128-GCM AEAD (encrypt + authenticate)
    Encrypted = 2,
}

impl SecurityLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Authenticated),
            2 => Some(Self::Encrypted),
            _ => None,
        }
    }
}

// ============================================================================
// Session error type
// ============================================================================

/// Errors from session operations.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    /// Operation not allowed in current state.
    InvalidState {
        current: SessionState,
        operation: &'static str,
    },
    /// Peer rejected negotiation.
    NegotiateRejected { reason: u8 },
    /// Session ID mismatch.
    SessionIdMismatch { expected: u64, received: u64 },
    /// Peer timed out.
    PeerTimeout,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState { current, operation } => {
                write!(f, "cannot {} in state {:?}", operation, current)
            }
            Self::NegotiateRejected { reason } => {
                write!(f, "negotiate rejected (reason={})", reason)
            }
            Self::SessionIdMismatch { expected, received } => {
                write!(f, "session_id mismatch: expected 0x{:X}, got 0x{:X}", expected, received)
            }
            Self::PeerTimeout => write!(f, "peer timed out"),
        }
    }
}

impl std::error::Error for SessionError {}

// ============================================================================
// Core block structs
// ============================================================================

/// Session flags negotiated during Negotiate.
pub struct SessionFlags;
impl SessionFlags {
    /// Cancel all open orders when session disconnects.
    pub const CANCEL_ON_DISCONNECT: u8 = 0x01;
    /// Enable CRC32 checksums on all messages.
    pub const ENABLE_CRC: u8 = 0x02;
    /// Enable message compression when beneficial.
    pub const ENABLE_COMPRESSION: u8 = 0x04;
}

/// Negotiate message core block — client proposes session parameters.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NegotiateCore {
    pub session_id: u64,
    pub keepalive_ms: u32,
    pub security_level: u8,
    pub session_flags: u8,        // SessionFlags bitmap
    pub max_message_size: u16,
    pub public_key: [u8; 32],
}

impl NegotiateCore {
    pub const SIZE: usize = 48;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::Negotiate as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// NegotiateResponse core block — server confirms or rejects.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NegotiateResponseCore {
    pub session_id: u64,
    pub keepalive_ms: u32,
    pub security_level: u8,
    pub session_flags: u8,        // Accepted SessionFlags (may differ from requested)
    pub max_message_size: u16,
    pub status: u8,        // 0 = accepted, 1 = rejected
    pub reject_reason: u8, // 0=none, 1=bad_credentials, 2=unsupported_version, 3=rate_limit
    pub _pad: u16,
    pub public_key: [u8; 32],
}

impl NegotiateResponseCore {
    pub const SIZE: usize = 56;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::NegotiateResponse as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }

    pub fn is_accepted(&self) -> bool {
        self.status == 0
    }
}

/// Establish message — start sequenced messaging.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EstablishCore {
    pub session_id: u64,
    pub next_seq_num: u64,
    pub _pad: u32,
    pub credentials: [u8; 32],
}

impl EstablishCore {
    pub const SIZE: usize = 56;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::Establish as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// EstablishAck — server confirms session established.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EstablishAckCore {
    pub session_id: u64,
    /// Server's next outbound seq. Client expects the next inbound message
    /// on this session to carry this sequence number.
    pub next_seq_num: u64,
    /// Lowest seq still retrievable from the server's replay journal. If
    /// the client's `next_expected_seq < journal_low_seq_num`, a
    /// RetransmitRequest cannot cover the gap and the client must initiate
    /// snapshot recovery (BookSnapshotRequest for market data). `0` means
    /// the server has not produced any messages yet.
    pub journal_low_seq_num: u64,
}

impl EstablishAckCore {
    pub const SIZE: usize = 24;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::EstablishAck as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// Heartbeat — keepalive with implicit sequence ack.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HeartbeatCore {
    pub next_seq_num: u64,
    pub _pad: u32,
}

impl HeartbeatCore {
    pub const SIZE: usize = 16;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::Heartbeat as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// RetransmitRequest — request replay of missed messages.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RetransmitRequestCore {
    pub from_seq_num: u32,
    pub count: u32,
}

impl RetransmitRequestCore {
    pub const SIZE: usize = 8;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::RetransmitRequest as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// Retransmission header — precedes replayed messages.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RetransmissionCore {
    pub next_seq_num: u64, // Server's next sequence after retransmission
    pub count: u32,        // Number of messages being retransmitted
}

impl RetransmissionCore {
    pub const SIZE: usize = 16;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::Retransmission as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// Terminate — graceful session end.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TerminateCore {
    pub reason: u8, // 0=normal, 1=error, 2=timeout, 3=auth_failure
    pub _pad: [u8; 7],
}

impl TerminateCore {
    pub const SIZE: usize = 8;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::Terminate as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe zero-copy decode. Returns `None` if buffer is too short.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// TestRequest — solicited heartbeat for RTT measurement.
/// Peer must respond with a Heartbeat echoing the `test_request_id`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TestRequestCore {
    pub test_request_id: u64,
}

impl TestRequestCore {
    pub const SIZE: usize = 8;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::TestRequest as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// NotApplied — iLink3-style: "received your msgs but didn't apply them due to gap".
/// Client must decide: retransmit, re-sequence, or cancel.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NotAppliedCore {
    pub from_seq_num: u32,   // first non-applied sequence
    pub count: u32,          // number of messages not applied
}

impl NotAppliedCore {
    pub const SIZE: usize = 8;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::NotApplied as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// SequenceReset — reset sequence numbers (admin or slow consumer).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SequenceResetCore {
    pub new_seq_num: u32,
    pub reason: u8, // 0=admin, 1=slow_consumer, 2=reconnect, 3=journal_exhausted
    pub _pad: [u8; 3],
}

/// KeyRotationRequest — sender announces the next crypto epoch and
/// requests that the peer switch its inbound cipher to the new key.
///
/// The rotation handshake is two-phase: after sending, the initiator
/// keeps encrypting under the CURRENT epoch until `KeyRotationAck`
/// arrives, then calls `SessionCipher::commit_rotation()` to activate
/// the new key for outbound. This prevents dropped messages across
/// the transition.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct KeyRotationRequestCore {
    pub session_id: u64,
    /// Epoch number the sender is rotating to (current + 1, unless
    /// multiple rotations are batched).
    pub next_epoch: u32,
    /// [`crypto_session::RotationReason`] as `u8`.
    pub reason: u8,
    pub _pad: [u8; 3],
}

impl KeyRotationRequestCore {
    pub const SIZE: usize = 16;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::KeyRotationRequest as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// KeyRotationAck — peer confirms it has derived and loaded the new
/// epoch key. On receipt, the initiator calls
/// `SessionCipher::commit_rotation()` and starts encrypting under the new
/// epoch.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct KeyRotationAckCore {
    pub session_id: u64,
    pub epoch: u32,
    /// 0 = accepted, 1 = rejected (peer refuses rotation — initiator
    /// should abort via `abort_rotation()`).
    pub status: u8,
    pub _pad: [u8; 3],
}

impl KeyRotationAckCore {
    pub const SIZE: usize = 16;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::KeyRotationAck as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

impl SequenceResetCore {
    pub const SIZE: usize = 8;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::SequenceReset as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

/// SessionStatus — query/report session state.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SessionStatusCore {
    pub session_id: u64,
    pub state: u8,
    pub _pad: [u8; 3],
    pub next_inbound_seq: u32,
    pub next_outbound_seq: u64,
    pub uptime_secs: u32,
}

impl SessionStatusCore {
    pub const SIZE: usize = 24;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::SessionStatus as u16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

// ============================================================================
// Session State Machine
// ============================================================================

/// Session states following a strict state machine.
/// Every transition is validated — calling a method in the wrong state returns an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, no connection.
    Disconnected,
    /// Client: Negotiate sent, waiting for NegotiateResponse.
    Negotiating,
    /// Client: NegotiateResponse received (accepted), ready to Establish.
    /// Server: NegotiateResponse sent, waiting for Establish.
    Negotiated,
    /// Client: Establish sent, waiting for EstablishAck.
    Establishing,
    /// Session active, sequenced messages can flow.
    Active,
    /// Retransmission in progress — application messages paused.
    Retransmitting,
    /// Terminate sent or received, draining.
    Terminating,
}

/// Maximum number of messages kept in the replay journal.
pub const DEFAULT_REPLAY_CAPACITY: usize = 4096;

/// Tracks session state and sequence numbers.
pub struct Session {
    state: SessionState,
    session_id: u64,
    security_level: SecurityLevel,
    keepalive_ms: u32,

    // Outbound sequence tracking
    next_outbound_seq: u64,

    // Inbound sequence tracking
    next_expected_seq: u64,

    // Timing
    last_sent: Timestamp,
    last_received: Timestamp,

    // Session flags negotiated during handshake (SessionFlags bitmap).
    // Populated on a successful Negotiate/NegotiateResponse exchange; used
    // post-connect to drive behaviors like cancel-on-disconnect.
    negotiated_flags: u8,

    // Security (used when encryption is negotiated)
    #[allow(dead_code)]
    shared_secret: Option<[u8; 32]>,

    // Replay journal: stores outbound messages for retransmission.
    // Ring buffer: journal[seq % capacity] = (seq, message_bytes).
    replay_journal: Vec<Option<(u64, Vec<u8>)>>,
    // Lowest seq still recoverable from the journal. Once the ring wraps,
    // earlier entries get overwritten and `journal_low_water` advances. A
    // retransmit request below this watermark cannot be satisfied and the
    // server must tell the client explicitly rather than silently return
    // `None` (which the old code did and clients treated as "message never
    // existed"). 0 means "journal is empty" — same meaning as high < low.
    journal_low_water: u64,
    // Highest seq ever journaled. Together with `journal_low_water` this
    // gives the client an honest picture of what can be replayed.
    journal_high_water: u64,

    // Optional persistent WAL
    wal: Option<crate::wal::WalWriter>,
}

/// Client-side post-reconnect decision derived from `EstablishAck`.
///
/// After a reconnect, the client needs to know whether the server can
/// replay the gap via RetransmitRequest (fast path), or whether the gap is
/// bigger than the journal and the client must fall back to a snapshot.
/// Silently assuming retransmit works — the old behavior — leads to lost
/// messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAssessment {
    /// Client is caught up; no action needed.
    InSync,
    /// Gap is within the journal; issue `RetransmitRequest(from_seq, count)`.
    CanRetransmit { from_seq: u64, count: u32 },
    /// Gap extends below the server's journal low-water mark. A retransmit
    /// cannot cover this gap — the client must perform snapshot recovery
    /// (e.g. `BookSnapshotRequest` for market data). `earliest_available`
    /// is the lowest seq the journal still holds.
    MustSnapshot { missing_from: u64, earliest_available: u64 },
}

/// Reasons for emitting `SequenceReset`. Keep in sync with the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SequenceResetReason {
    Admin = 0,
    SlowConsumer = 1,
    Reconnect = 2,
    /// Client requested retransmit below the journal low-water — cannot be
    /// satisfied. Client must perform snapshot recovery.
    JournalExhausted = 3,
}

impl SequenceResetReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Admin),
            1 => Some(Self::SlowConsumer),
            2 => Some(Self::Reconnect),
            3 => Some(Self::JournalExhausted),
            _ => None,
        }
    }
}

/// Result of the server's attempt to satisfy a RetransmitRequest. Surfaced
/// to the server's dispatch loop so it can either send the replay or
/// emit a `SequenceReset(JournalExhausted)`.
#[derive(Debug)]
pub enum RetransmitResponse {
    /// Journal covered the request. Caller sends `header` followed by
    /// `messages` in order.
    Replay { header: RetransmissionCore, messages: Vec<Vec<u8>> },
    /// The client asked for seqs below the journal low-water. Server must
    /// reply with `SequenceReset(JournalExhausted)` and direct the client
    /// to snapshot recovery. `low` is the lowest seq the journal still holds.
    JournalExhausted { requested_from: u64, low: u64 },
}

/// Outcome of looking up a sequence in the replay journal.
///
/// Splits the old `Option<&[u8]>` into cases that tell the caller *why* a
/// message is unavailable — crucial for deciding whether to retransmit or
/// fall back to snapshot-based recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalLookup<'a> {
    /// Message bytes found; safe to replay.
    Found(&'a [u8]),
    /// Below the low-water mark — the entry existed but has been overwritten
    /// by a newer message. The caller should NOT retransmit; it should issue
    /// a `SequenceReset` with reason `journal_exhausted` and direct the peer
    /// to snapshot recovery. `low` is the lowest still-available seq.
    BelowWatermark { low: u64 },
    /// Above the high-water mark — this seq has not been produced yet.
    /// Normally a programming error (client asking for future messages).
    AboveWatermark { high: u64 },
    /// Journal is empty: nothing has been produced yet.
    Empty,
}

impl Session {
    pub fn new(session_id: u64) -> Self {
        Self::with_journal_capacity(session_id, DEFAULT_REPLAY_CAPACITY)
    }

    /// Create a session with a custom replay-journal size.
    ///
    /// Memory cost: `capacity × avg_msg_size`. For a 4096-slot journal at
    /// ~64 B/msg this is ~256 KiB per session — acceptable for dozens of
    /// sessions, tight for 10K+ colocated sessions. Tune per deployment.
    ///
    /// Panics if `capacity == 0`.
    pub fn with_journal_capacity(session_id: u64, capacity: usize) -> Self {
        assert!(capacity > 0, "journal capacity must be > 0");
        let mut journal = Vec::with_capacity(capacity);
        journal.resize_with(capacity, || None);
        Self {
            state: SessionState::Disconnected,
            session_id,
            security_level: SecurityLevel::None,
            keepalive_ms: 1000,
            next_outbound_seq: 1,
            next_expected_seq: 1,
            last_sent: Timestamp::NULL,
            last_received: Timestamp::NULL,
            negotiated_flags: 0,
            shared_secret: None,
            replay_journal: journal,
            journal_low_water: 0,
            journal_high_water: 0,
            wal: None,
        }
    }

    // ── Getters ──────────────────────────────────────────────

    pub fn state(&self) -> SessionState { self.state }
    pub fn session_id(&self) -> u64 { self.session_id }
    pub fn security_level(&self) -> SecurityLevel { self.security_level }
    pub fn keepalive_ms(&self) -> u32 { self.keepalive_ms }
    pub fn next_outbound_seq(&self) -> u64 { self.next_outbound_seq }
    pub fn next_expected_seq(&self) -> u64 { self.next_expected_seq }
    pub fn last_sent(&self) -> Timestamp { self.last_sent }
    pub fn last_received(&self) -> Timestamp { self.last_received }
    pub fn negotiated_flags(&self) -> u8 { self.negotiated_flags }

    /// True iff the `CANCEL_ON_DISCONNECT` flag was accepted in the handshake.
    /// When true, the server must cancel all open orders belonging to this
    /// session if the transport drops and the session is not re-established
    /// within the configured grace period.
    pub fn cancel_on_disconnect(&self) -> bool {
        self.negotiated_flags & SessionFlags::CANCEL_ON_DISCONNECT != 0
    }

    // ── Setters (for initial configuration before handshake) ─

    pub fn set_security_level(&mut self, level: SecurityLevel) {
        self.security_level = level;
    }

    pub fn set_keepalive_ms(&mut self, ms: u32) {
        self.keepalive_ms = ms;
    }

    /// Client: request that the server honor the given `SessionFlags` bitmap
    /// on the next `build_negotiate`. Server filtering is authoritative —
    /// whatever the server returns in `NegotiateResponse` becomes the
    /// committed value.
    pub fn request_flags(&mut self, flags: u8) {
        self.negotiated_flags = flags;
    }

    /// Server: explicitly set the accepted flags before `build_negotiate_response`.
    /// Use this to filter out any flag the server will not honor (e.g. reject
    /// `CANCEL_ON_DISCONNECT` if no `CancelOnDisconnectManager` is wired in).
    pub fn set_accepted_flags(&mut self, flags: u8) {
        self.negotiated_flags = flags;
    }

    // ── Sequence tracking ────────────────────────────────────

    /// Allocate next outbound sequence number.
    #[inline(always)]
    pub fn next_seq(&mut self) -> u64 {
        let seq = self.next_outbound_seq;
        self.next_outbound_seq = seq.wrapping_add(1);
        seq
    }

    /// Check if an inbound sequence number is expected (no gap).
    #[inline(always)]
    pub fn check_seq(&self, seq: u64) -> SeqCheck {
        match seq.cmp(&self.next_expected_seq) {
            core::cmp::Ordering::Equal => SeqCheck::Expected,
            core::cmp::Ordering::Greater => SeqCheck::Gap {
                expected: self.next_expected_seq,
                received: seq,
            },
            core::cmp::Ordering::Less => SeqCheck::Duplicate,
        }
    }

    /// Accept an inbound sequence number and update tracking.
    #[inline(always)]
    pub fn accept_seq(&mut self, seq: u64) {
        if seq >= self.next_expected_seq {
            self.next_expected_seq = seq.wrapping_add(1);
        }
        self.last_received = Timestamp::now();
    }

    // ── Replay journal ───────────────────────────────────────

    /// Record an outbound message for potential retransmission.
    /// Also writes to WAL if attached.
    ///
    /// Maintains the journal's low/high watermarks so retransmit requests
    /// outside the recoverable range can be rejected honestly rather than
    /// silently returning "not found".
    pub fn journal_outbound(&mut self, seq: u64, msg: &[u8]) {
        let capacity = self.replay_journal.len() as u64;
        let idx = seq as usize % self.replay_journal.len();
        self.replay_journal[idx] = Some((seq, msg.to_vec()));

        if self.journal_high_water == 0 && self.journal_low_water == 0 {
            // First entry ever.
            self.journal_low_water = seq;
            self.journal_high_water = seq;
        } else {
            if seq > self.journal_high_water {
                self.journal_high_water = seq;
            }
            // If the high-water has advanced past the ring window, the
            // low-water is the oldest slot the ring still holds.
            let oldest_retained = self.journal_high_water.saturating_sub(capacity - 1);
            if oldest_retained > self.journal_low_water {
                self.journal_low_water = oldest_retained;
            }
        }

        // Write to persistent WAL if attached
        if let Some(wal) = &mut self.wal {
            let _ = wal.append(msg); // best-effort, don't block on IO error
        }
    }

    /// Look up a journaled message by sequence number.
    ///
    /// Prefer [`lookup_journaled`](Self::lookup_journaled) in new code — it
    /// tells the caller *why* a message is unavailable. This wrapper is kept
    /// for back-compat; it returns `Some` only when `Found`.
    pub fn get_journaled(&self, seq: u64) -> Option<&[u8]> {
        match self.lookup_journaled(seq) {
            JournalLookup::Found(data) => Some(data),
            _ => None,
        }
    }

    /// Rich lookup: returns the bytes when found, otherwise reports whether
    /// the miss is because the entry was overwritten, never produced, or
    /// the journal is empty. See [`JournalLookup`] for semantics.
    pub fn lookup_journaled(&self, seq: u64) -> JournalLookup<'_> {
        if self.journal_high_water == 0 && self.journal_low_water == 0 {
            return JournalLookup::Empty;
        }
        if seq < self.journal_low_water {
            return JournalLookup::BelowWatermark { low: self.journal_low_water };
        }
        if seq > self.journal_high_water {
            return JournalLookup::AboveWatermark { high: self.journal_high_water };
        }
        let idx = seq as usize % self.replay_journal.len();
        match &self.replay_journal[idx] {
            Some((stored_seq, data)) if *stored_seq == seq => JournalLookup::Found(data),
            // In-range but slot mismatch shouldn't happen; treat as below
            // watermark to be safe.
            _ => JournalLookup::BelowWatermark { low: self.journal_low_water },
        }
    }

    /// Inclusive range of seq numbers still recoverable from the journal,
    /// or `None` if nothing has been journaled yet.
    pub fn journal_range(&self) -> Option<(u64, u64)> {
        if self.journal_high_water == 0 && self.journal_low_water == 0 {
            None
        } else {
            Some((self.journal_low_water, self.journal_high_water))
        }
    }

    /// Lowest seq still recoverable. Reported to the client in `EstablishAck`
    /// so reconnecting clients know up front whether they must do snapshot
    /// recovery instead of retransmit.
    pub fn journal_low_water(&self) -> u64 {
        self.journal_low_water
    }

    /// Highest seq ever journaled. Useful for metrics and debugging.
    pub fn journal_high_water(&self) -> u64 {
        self.journal_high_water
    }

    /// Configured journal capacity.
    pub fn journal_capacity(&self) -> usize {
        self.replay_journal.len()
    }

    /// Attach a WAL for persistent journaling.
    /// After this, every `journal_outbound` also writes to disk.
    pub fn attach_wal(&mut self, wal: crate::wal::WalWriter) {
        self.wal = Some(wal);
    }

    /// Recover journal from WAL file. Call after `reset_to_disconnected()`.
    pub fn recover_from_wal(path: &std::path::Path) -> std::io::Result<Vec<Vec<u8>>> {
        let reader = crate::wal::WalReader::open(path)?;
        Ok(reader.collect())
    }

    // ── Timing ───────────────────────────────────────────────

    /// Check if heartbeat is needed.
    pub fn needs_heartbeat(&self, now: Timestamp) -> bool {
        if self.state != SessionState::Active || self.last_sent.is_null() {
            return false;
        }
        let elapsed_ns = now.as_nanos().saturating_sub(self.last_sent.as_nanos());
        let interval_ns = self.keepalive_ms as u64 * 1_000_000;
        elapsed_ns >= interval_ns
    }

    /// Check if peer has timed out (no message received within 3x keepalive).
    pub fn peer_timed_out(&self, now: Timestamp) -> bool {
        if self.state != SessionState::Active || self.last_received.is_null() {
            return false;
        }
        let elapsed_ns = now.as_nanos().saturating_sub(self.last_received.as_nanos());
        let timeout_ns = self.keepalive_ms as u64 * 3 * 1_000_000;
        elapsed_ns >= timeout_ns
    }

    // ── Client-side handshake ────────────────────────────────

    /// Client: send Negotiate.
    /// Requires: Disconnected.
    /// Transitions to: Negotiating.
    pub fn build_negotiate(
        &mut self,
        buf: &mut [u8],
        public_key: [u8; 32],
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Disconnected, "build_negotiate")?;

        let core = NegotiateCore {
            session_id: self.session_id,
            keepalive_ms: self.keepalive_ms,
            security_level: self.security_level as u8,
            session_flags: self.negotiated_flags,
            max_message_size: 4096,
            public_key,
        };

        let total = crate::header::FullHeader::SIZE + NegotiateCore::SIZE;
        write_session_message(buf, SessionMsgType::Negotiate as u16, 0, 0, core.as_bytes(), total);

        self.state = SessionState::Negotiating;
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Client: process NegotiateResponse.
    /// Requires: Negotiating.
    /// Transitions to: Negotiated (if accepted) or Disconnected (if rejected).
    pub fn handle_negotiate_response(
        &mut self,
        core: &NegotiateResponseCore,
    ) -> Result<(), SessionError> {
        self.require_state(SessionState::Negotiating, "handle_negotiate_response")?;

        if !core.is_accepted() {
            self.state = SessionState::Disconnected;
            self.negotiated_flags = 0;
            return Err(SessionError::NegotiateRejected {
                reason: core.reject_reason,
            });
        }

        self.keepalive_ms = core.keepalive_ms;
        self.security_level =
            SecurityLevel::from_u8(core.security_level).unwrap_or(SecurityLevel::None);
        // Server may have filtered out some requested flags.
        self.negotiated_flags = core.session_flags;
        self.state = SessionState::Negotiated;
        self.last_received = Timestamp::now();
        Ok(())
    }

    /// Client: send Establish.
    /// Requires: Negotiated.
    /// Transitions to: Establishing.
    pub fn build_establish(
        &mut self,
        buf: &mut [u8],
        credentials: [u8; 32],
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Negotiated, "build_establish")?;

        let core = EstablishCore {
            session_id: self.session_id,
            next_seq_num: self.next_outbound_seq,
            _pad: 0,
            credentials,
        };

        let total = crate::header::FullHeader::SIZE + EstablishCore::SIZE;
        write_session_message(buf, SessionMsgType::Establish as u16, 0, 0, core.as_bytes(), total);

        self.state = SessionState::Establishing;
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Client: process EstablishAck.
    /// Requires: Establishing.
    /// Transitions to: Active.
    pub fn handle_establish_ack(
        &mut self,
        core: &EstablishAckCore,
    ) -> Result<(), SessionError> {
        self.require_state(SessionState::Establishing, "handle_establish_ack")?;

        if core.session_id != self.session_id {
            return Err(SessionError::SessionIdMismatch {
                expected: self.session_id,
                received: core.session_id,
            });
        }

        self.next_expected_seq = core.next_seq_num;
        self.state = SessionState::Active;
        self.last_received = Timestamp::now();
        Ok(())
    }

    /// After `handle_establish_ack`, call this to find out whether the
    /// client's position within the server's journal is recoverable via
    /// retransmit (`CanRetransmit`) or requires falling back to snapshot
    /// recovery (`MustSnapshot`). `expected_before_reconnect` is the seq
    /// number the client had last consumed before the disconnect — i.e. the
    /// value of `next_expected_seq` before calling `handle_establish_ack`.
    pub fn assess_recovery(
        expected_before_reconnect: u64,
        ack: &EstablishAckCore,
    ) -> RecoveryAssessment {
        // ack.next_seq_num is the server's next outbound. If we already have
        // everything up to that point, there is no gap.
        if expected_before_reconnect >= ack.next_seq_num {
            return RecoveryAssessment::InSync;
        }
        let gap_start = expected_before_reconnect;
        // `journal_low_seq_num == 0` means the server has nothing journaled
        // yet; no gap to fill.
        if ack.journal_low_seq_num == 0 {
            return RecoveryAssessment::InSync;
        }
        if gap_start < ack.journal_low_seq_num {
            RecoveryAssessment::MustSnapshot {
                missing_from: gap_start,
                earliest_available: ack.journal_low_seq_num,
            }
        } else {
            RecoveryAssessment::CanRetransmit {
                from_seq: gap_start,
                count: (ack.next_seq_num - gap_start).min(u32::MAX as u64) as u32,
            }
        }
    }

    // ── Server-side handshake ────────────────────────────────

    /// Server: process Negotiate and configure session.
    /// Requires: Disconnected.
    /// Transitions to: Negotiating (internal — waiting to send response).
    pub fn handle_negotiate(
        &mut self,
        core: &NegotiateCore,
    ) -> Result<(), SessionError> {
        self.require_state(SessionState::Disconnected, "handle_negotiate")?;

        self.session_id = core.session_id;
        self.keepalive_ms = core.keepalive_ms;
        self.security_level =
            SecurityLevel::from_u8(core.security_level).unwrap_or(SecurityLevel::None);
        // Capture requested flags; final accepted flags are committed in
        // `build_negotiate_response` (server may filter out flags it will not
        // honor, e.g. if the server has no order-tracker configured).
        self.negotiated_flags = core.session_flags;
        self.state = SessionState::Negotiating;
        self.last_received = Timestamp::now();
        Ok(())
    }

    /// Server: send NegotiateResponse.
    /// Requires: Negotiating.
    /// Transitions to: Negotiated (if accepted) or Disconnected (if rejected).
    pub fn build_negotiate_response(
        &mut self,
        buf: &mut [u8],
        accepted: bool,
        reject_reason: u8,
        public_key: [u8; 32],
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Negotiating, "build_negotiate_response")?;

        // If the server rejects the handshake, drop any requested flags so a
        // rejected session never looks like it has cancel-on-disconnect.
        if !accepted {
            self.negotiated_flags = 0;
        }

        let core = NegotiateResponseCore {
            session_id: self.session_id,
            keepalive_ms: self.keepalive_ms,
            security_level: self.security_level as u8,
            session_flags: self.negotiated_flags,
            max_message_size: 4096,
            status: if accepted { 0 } else { 1 },
            reject_reason,
            _pad: 0,
            public_key,
        };

        let total = crate::header::FullHeader::SIZE + NegotiateResponseCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::NegotiateResponse as u16,
            0,
            0,
            core.as_bytes(),
            total,
        );

        self.state = if accepted {
            SessionState::Negotiated
        } else {
            SessionState::Disconnected
        };
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Server: process Establish from client.
    /// Requires: Negotiated.
    /// Transitions to: Establishing (internal — waiting to send ack).
    pub fn handle_establish(
        &mut self,
        core: &EstablishCore,
    ) -> Result<(), SessionError> {
        self.require_state(SessionState::Negotiated, "handle_establish")?;

        if core.session_id != self.session_id {
            return Err(SessionError::SessionIdMismatch {
                expected: self.session_id,
                received: core.session_id,
            });
        }

        self.next_expected_seq = core.next_seq_num;
        self.state = SessionState::Establishing;
        self.last_received = Timestamp::now();
        Ok(())
    }

    /// Server: send EstablishAck.
    /// Requires: Establishing.
    /// Transitions to: Active.
    pub fn build_establish_ack(
        &mut self,
        buf: &mut [u8],
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Establishing, "build_establish_ack")?;

        let core = EstablishAckCore {
            session_id: self.session_id,
            next_seq_num: self.next_outbound_seq,
            journal_low_seq_num: self.journal_low_water,
        };

        let total = crate::header::FullHeader::SIZE + EstablishAckCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::EstablishAck as u16,
            0,
            0,
            core.as_bytes(),
            total,
        );

        self.state = SessionState::Active;
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    // ── Active session operations ────────────────────────────

    /// Send Heartbeat. Requires: Active.
    pub fn build_heartbeat(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_heartbeat")?;

        let core = HeartbeatCore {
            next_seq_num: self.next_expected_seq,
            _pad: 0,
        };

        let seq = self.next_seq();
        let total = crate::header::FullHeader::SIZE + HeartbeatCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::Heartbeat as u16,
            seq,
            0,
            core.as_bytes(),
            total,
        );

        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Send RetransmitRequest when a gap is detected.
    /// Requires: Active.
    /// Transitions to: Retransmitting.
    pub fn build_retransmit_request(
        &mut self,
        buf: &mut [u8],
        from_seq: u32,
        count: u32,
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_retransmit_request")?;

        let core = RetransmitRequestCore {
            from_seq_num: from_seq,
            count,
        };

        let seq = self.next_seq();
        let total = crate::header::FullHeader::SIZE + RetransmitRequestCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::RetransmitRequest as u16,
            seq,
            0,
            core.as_bytes(),
            total,
        );

        self.state = SessionState::Retransmitting;
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Handle RetransmitRequest from peer — build Retransmission header + replay.
    /// Requires: Active.
    /// Returns the header bytes and a list of journaled messages to send.
    ///
    /// **Deprecated**: returns `None`-collapsed `Vec` that can't distinguish
    /// between "message not yet produced" and "journal already wrapped past
    /// this seq". Prefer [`handle_retransmit_request_v2`](Self::handle_retransmit_request_v2)
    /// which surfaces the exhausted-journal case explicitly.
    pub fn handle_retransmit_request(
        &self,
        core: &RetransmitRequestCore,
    ) -> Result<(RetransmissionCore, Vec<Vec<u8>>), SessionError> {
        self.require_state(SessionState::Active, "handle_retransmit_request")?;

        let mut messages = Vec::new();
        let mut replayed = 0u32;
        for i in 0..core.count {
            let seq = core.from_seq_num.wrapping_add(i);
            if let Some(data) = self.get_journaled(seq as u64) {
                messages.push(data.to_vec());
                replayed += 1;
            }
        }

        let header = RetransmissionCore {
            next_seq_num: self.next_outbound_seq,
            count: replayed,
        };

        Ok((header, messages))
    }

    /// Honest version of retransmit handling. Instead of silently skipping
    /// overwritten entries, detects when the client has fallen below the
    /// journal's low-water mark and returns `JournalExhausted` so the
    /// server can reply with a `SequenceReset(JournalExhausted)` and
    /// redirect the client to snapshot recovery.
    pub fn handle_retransmit_request_v2(
        &self,
        core: &RetransmitRequestCore,
    ) -> Result<RetransmitResponse, SessionError> {
        self.require_state(SessionState::Active, "handle_retransmit_request_v2")?;

        let from_seq = core.from_seq_num as u64;

        // Below low-water? This is the case the old code silently ignored.
        // The client cannot know by looking at our reply — their gap stays
        // open forever. Fail loudly.
        if let Some((low, _high)) = self.journal_range()
            && from_seq < low {
                return Ok(RetransmitResponse::JournalExhausted {
                    requested_from: from_seq,
                    low,
                });
            }

        let mut messages = Vec::with_capacity(core.count as usize);
        for i in 0..core.count {
            let seq = core.from_seq_num.wrapping_add(i) as u64;
            match self.lookup_journaled(seq) {
                JournalLookup::Found(data) => messages.push(data.to_vec()),
                JournalLookup::BelowWatermark { low } => {
                    // Partial-range straddling the watermark. Treat as
                    // exhausted — the client can re-request the available
                    // tail via snapshot.
                    return Ok(RetransmitResponse::JournalExhausted {
                        requested_from: from_seq,
                        low,
                    });
                }
                JournalLookup::AboveWatermark { .. } | JournalLookup::Empty => {
                    // Stop early — we can't replay messages not yet produced.
                    break;
                }
            }
        }

        let header = RetransmissionCore {
            next_seq_num: self.next_outbound_seq,
            count: messages.len() as u32,
        };
        Ok(RetransmitResponse::Replay { header, messages })
    }

    /// Build Retransmission header message into buffer.
    pub fn build_retransmission(
        &mut self,
        buf: &mut [u8],
        next_seq: u32,
        count: u32,
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_retransmission")?;

        let core = RetransmissionCore {
            next_seq_num: next_seq as u64,
            count,
        };

        let total = crate::header::FullHeader::SIZE + RetransmissionCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::Retransmission as u16,
            0,
            0,
            core.as_bytes(),
            total,
        );

        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Handle Retransmission header from peer — we can resume normal flow.
    /// Requires: Retransmitting.
    /// Transitions to: Active.
    pub fn handle_retransmission_complete(&mut self) -> Result<(), SessionError> {
        self.require_state(SessionState::Retransmitting, "handle_retransmission_complete")?;
        self.state = SessionState::Active;
        self.last_received = Timestamp::now();
        Ok(())
    }

    // ── Terminate ────────────────────────────────────────────

    /// Send Terminate. Requires: Active or Retransmitting.
    pub fn build_terminate(
        &mut self,
        buf: &mut [u8],
        reason: u8,
    ) -> Result<usize, SessionError> {
        if self.state != SessionState::Active && self.state != SessionState::Retransmitting {
            return Err(SessionError::InvalidState {
                current: self.state,
                operation: "build_terminate",
            });
        }

        let core = TerminateCore {
            reason,
            _pad: [0; 7],
        };

        let seq = self.next_seq();
        let total = crate::header::FullHeader::SIZE + TerminateCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::Terminate as u16,
            seq,
            0,
            core.as_bytes(),
            total,
        );

        self.state = SessionState::Terminating;
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Handle Terminate from peer. Allowed in any state except Disconnected.
    pub fn handle_terminate(&mut self) {
        self.state = SessionState::Terminating;
        self.last_received = Timestamp::now();
    }

    // ── Reconnect support ────────────────────────────────────

    /// Reset session to Disconnected, preserving session_id, sequences, and replay journal.
    /// Used for reconnection: re-Negotiate/Establish with the same session_id,
    /// then detect gaps via next_seq_num in Establish/EstablishAck.
    pub fn reset_to_disconnected(&mut self) {
        self.state = SessionState::Disconnected;
        self.last_sent = Timestamp::NULL;
        self.last_received = Timestamp::NULL;
        // Deliberately keep: session_id, next_outbound_seq, next_expected_seq,
        // security_level, keepalive_ms, shared_secret, replay_journal.
    }

    // ── Admin messages ───────────────────────────────────────

    /// Send SequenceReset. Requires: Active.
    pub fn build_sequence_reset(
        &mut self,
        buf: &mut [u8],
        new_seq: u32,
        reason: u8,
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_sequence_reset")?;

        let core = SequenceResetCore {
            new_seq_num: new_seq,
            reason,
            _pad: [0; 3],
        };

        let total = crate::header::FullHeader::SIZE + SequenceResetCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::SequenceReset as u16,
            self.next_seq(),
            0,
            core.as_bytes(),
            total,
        );

        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Handle SequenceReset from peer. Resets expected inbound sequence.
    pub fn handle_sequence_reset(&mut self, core: &SequenceResetCore) {
        self.next_expected_seq = core.new_seq_num as u64;
        self.last_received = Timestamp::now();
    }

    // ── Key rotation handshake ───────────────────────────────

    /// Build a `KeyRotationRequest` announcing `next_epoch` to the peer.
    /// Caller owns the `SessionCipher` state (from `crypto_session`); this
    /// method only generates the wire message. After sending, caller
    /// should wait for `KeyRotationAck` and then invoke
    /// `SessionCipher::commit_rotation()`.
    pub fn build_key_rotation_request(
        &mut self,
        buf: &mut [u8],
        next_epoch: u32,
        reason: u8,
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_key_rotation_request")?;

        let core = KeyRotationRequestCore {
            session_id: self.session_id,
            next_epoch,
            reason,
            _pad: [0; 3],
        };
        let total = crate::header::FullHeader::SIZE + KeyRotationRequestCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::KeyRotationRequest as u16,
            self.next_seq(),
            0,
            core.as_bytes(),
            total,
        );
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Build a `KeyRotationAck` in response to a peer's request.
    /// `status = 0` accepts, `status = 1` rejects (peer must then abort
    /// its pending rotation).
    pub fn build_key_rotation_ack(
        &mut self,
        buf: &mut [u8],
        epoch: u32,
        status: u8,
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_key_rotation_ack")?;

        let core = KeyRotationAckCore {
            session_id: self.session_id,
            epoch,
            status,
            _pad: [0; 3],
        };
        let total = crate::header::FullHeader::SIZE + KeyRotationAckCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::KeyRotationAck as u16,
            self.next_seq(),
            0,
            core.as_bytes(),
            total,
        );
        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Build SessionStatus report.
    pub fn build_session_status(
        &self,
        buf: &mut [u8],
        uptime_secs: u32,
    ) -> usize {
        let core = SessionStatusCore {
            session_id: self.session_id,
            state: self.state as u8,
            _pad: [0; 3],
            next_inbound_seq: self.next_expected_seq as u32,
            next_outbound_seq: self.next_outbound_seq,
            uptime_secs,
        };

        let total = crate::header::FullHeader::SIZE + SessionStatusCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::SessionStatus as u16,
            0,
            0,
            core.as_bytes(),
            total,
        );

        total
    }

    /// Send TestRequest — solicited heartbeat for RTT measurement.
    /// Peer must respond with Heartbeat. Compare timestamps to compute RTT.
    pub fn build_test_request(
        &mut self,
        buf: &mut [u8],
        test_request_id: u64,
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_test_request")?;

        let core = TestRequestCore { test_request_id };

        let total = crate::header::FullHeader::SIZE + TestRequestCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::TestRequest as u16,
            self.next_seq(),
            0,
            core.as_bytes(),
            total,
        );

        self.last_sent = Timestamp::now();
        Ok(total)
    }

    /// Send NotApplied — tell client their messages were received but not applied.
    /// Used when server detects a gap in inbound sequence from client.
    pub fn build_not_applied(
        &mut self,
        buf: &mut [u8],
        from_seq: u32,
        count: u32,
    ) -> Result<usize, SessionError> {
        self.require_state(SessionState::Active, "build_not_applied")?;

        let core = NotAppliedCore {
            from_seq_num: from_seq,
            count,
        };

        let total = crate::header::FullHeader::SIZE + NotAppliedCore::SIZE;
        write_session_message(
            buf,
            SessionMsgType::NotApplied as u16,
            self.next_seq(),
            0,
            core.as_bytes(),
            total,
        );

        self.last_sent = Timestamp::now();
        Ok(total)
    }

    // ── Internal helpers ─────────────────────────────────────

    fn require_state(
        &self,
        expected: SessionState,
        operation: &'static str,
    ) -> Result<(), SessionError> {
        if self.state != expected {
            Err(SessionError::InvalidState {
                current: self.state,
                operation,
            })
        } else {
            Ok(())
        }
    }
}

/// Result of checking an inbound sequence number.
#[derive(Debug, PartialEq, Eq)]
pub enum SeqCheck {
    Expected,
    Gap { expected: u64, received: u64 },
    Duplicate,
}

/// Helper: write a session-layer message into a buffer.
fn write_session_message(
    buf: &mut [u8],
    message_type: u16,
    sequence_num: u64,
    sender_comp_id: u32,
    core_bytes: &[u8],
    total_size: usize,
) {
    let header = crate::header::FullHeader::new(
        SESSION_SCHEMA_ID,
        message_type,
        sender_comp_id,
        sequence_num,
        0, // correlation_id
        total_size as u32,
        FrameFlags::NONE,
    );

    header.write_to(buf);
    let offset = crate::header::FullHeader::SIZE;
    buf[offset..offset + core_bytes.len()].copy_from_slice(core_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_core_size() {
        assert_eq!(core::mem::size_of::<NegotiateCore>(), NegotiateCore::SIZE);
    }

    #[test]
    fn negotiate_response_core_size() {
        assert_eq!(
            core::mem::size_of::<NegotiateResponseCore>(),
            NegotiateResponseCore::SIZE
        );
    }

    #[test]
    fn establish_core_size() {
        assert_eq!(core::mem::size_of::<EstablishCore>(), EstablishCore::SIZE);
    }

    #[test]
    fn heartbeat_core_size() {
        assert_eq!(core::mem::size_of::<HeartbeatCore>(), HeartbeatCore::SIZE);
    }

    #[test]
    fn retransmission_core_size() {
        assert_eq!(
            core::mem::size_of::<RetransmissionCore>(),
            RetransmissionCore::SIZE
        );
    }

    #[test]
    fn session_sequence_tracking() {
        let mut session = Session::new(1);
        assert_eq!(session.next_seq(), 1);
        assert_eq!(session.next_seq(), 2);
        assert_eq!(session.next_seq(), 3);
    }

    #[test]
    fn session_gap_detection() {
        let mut session = Session::new(1);
        session.next_expected_seq = 5;

        assert_eq!(session.check_seq(5), SeqCheck::Expected);
        assert_eq!(
            session.check_seq(8),
            SeqCheck::Gap {
                expected: 5,
                received: 8,
            }
        );
        assert_eq!(session.check_seq(3), SeqCheck::Duplicate);
    }

    // ── Full client handshake test ───────────────────────────

    #[test]
    fn client_full_handshake() {
        let mut client = Session::new(42);
        client.set_security_level(SecurityLevel::Authenticated);
        client.set_keepalive_ms(500);

        let mut buf = [0u8; 256];

        // Step 1: Negotiate
        let len = client.build_negotiate(&mut buf, [0u8; 32]).unwrap();
        assert_eq!(len, 32 + NegotiateCore::SIZE);
        assert_eq!(client.state(), SessionState::Negotiating);

        // Verify frame
        let header = crate::header::FullHeader::from_bytes(&buf);
        assert_eq!(header.message.schema_id, SESSION_SCHEMA_ID);
        assert_eq!(header.message.message_type, SessionMsgType::Negotiate as u16);

        let core = NegotiateCore::from_bytes(&buf[32..]);
        assert_eq!(core.session_id, 42);
        assert_eq!(core.keepalive_ms, 500);

        // Cannot negotiate again
        assert!(client.build_negotiate(&mut buf, [0u8; 32]).is_err());

        // Step 2: Receive NegotiateResponse (accepted)
        let resp = NegotiateResponseCore {
            session_id: 42,
            keepalive_ms: 500,
            security_level: SecurityLevel::Authenticated as u8,
            session_flags: 0,
            max_message_size: 4096,
            status: 0, // accepted
            reject_reason: 0,
            _pad: 0,
            public_key: [0u8; 32],
        };
        client.handle_negotiate_response(&resp).unwrap();
        assert_eq!(client.state(), SessionState::Negotiated);

        // Step 3: Establish
        let len = client.build_establish(&mut buf, [0u8; 32]).unwrap();
        assert_eq!(len, 32 + EstablishCore::SIZE);
        assert_eq!(client.state(), SessionState::Establishing);

        // Cannot establish again
        assert!(client.build_establish(&mut buf, [0u8; 32]).is_err());

        // Step 4: EstablishAck
        let ack = EstablishAckCore {
            session_id: 42,
            next_seq_num: 1,
            journal_low_seq_num: 0,
        };
        client.handle_establish_ack(&ack).unwrap();
        assert_eq!(client.state(), SessionState::Active);

        // Now heartbeat and terminate work
        client.build_heartbeat(&mut buf).unwrap();
        client.build_terminate(&mut buf, 0).unwrap();
        assert_eq!(client.state(), SessionState::Terminating);
    }

    // ── Full server handshake test ───────────────────────────

    #[test]
    fn server_full_handshake() {
        let mut server = Session::new(0);
        let mut buf = [0u8; 256];

        // Step 1: Receive Negotiate
        let negotiate = NegotiateCore {
            session_id: 42,
            keepalive_ms: 500,
            security_level: SecurityLevel::None as u8,
            session_flags: 0,
            max_message_size: 4096,
            public_key: [0u8; 32],
        };
        server.handle_negotiate(&negotiate).unwrap();
        assert_eq!(server.state(), SessionState::Negotiating);
        assert_eq!(server.session_id(), 42);

        // Step 2: Send NegotiateResponse
        server
            .build_negotiate_response(&mut buf, true, 0, [0u8; 32])
            .unwrap();
        assert_eq!(server.state(), SessionState::Negotiated);

        // Step 3: Receive Establish
        let establish = EstablishCore {
            session_id: 42,
            next_seq_num: 1,
            _pad: 0,
            credentials: [0u8; 32],
        };
        server.handle_establish(&establish).unwrap();
        assert_eq!(server.state(), SessionState::Establishing);

        // Step 4: Send EstablishAck
        server.build_establish_ack(&mut buf).unwrap();
        assert_eq!(server.state(), SessionState::Active);
    }

    // ── State enforcement tests ──────────────────────────────

    #[test]
    fn cannot_heartbeat_before_active() {
        let mut session = Session::new(1);
        let mut buf = [0u8; 256];
        let err = session.build_heartbeat(&mut buf).unwrap_err();
        assert_eq!(
            err,
            SessionError::InvalidState {
                current: SessionState::Disconnected,
                operation: "build_heartbeat",
            }
        );
    }

    #[test]
    fn cannot_establish_before_negotiate() {
        let mut session = Session::new(1);
        let mut buf = [0u8; 256];
        assert!(session.build_establish(&mut buf, [0u8; 32]).is_err());
    }

    #[test]
    fn cannot_terminate_before_active() {
        let mut session = Session::new(1);
        let mut buf = [0u8; 256];
        assert!(session.build_terminate(&mut buf, 0).is_err());
    }

    #[test]
    fn negotiate_rejected() {
        let mut client = Session::new(1);
        let mut buf = [0u8; 256];
        client.build_negotiate(&mut buf, [0u8; 32]).unwrap();

        let resp = NegotiateResponseCore {
            session_id: 1,
            keepalive_ms: 1000,
            security_level: 0,
            session_flags: 0,
            max_message_size: 4096,
            status: 1, // rejected
            reject_reason: 2,
            _pad: 0,
            public_key: [0u8; 32],
        };
        let err = client.handle_negotiate_response(&resp).unwrap_err();
        assert_eq!(err, SessionError::NegotiateRejected { reason: 2 });
        assert_eq!(client.state(), SessionState::Disconnected);
    }

    #[test]
    fn establish_ack_session_id_mismatch() {
        let mut client = Session::new(42);
        let mut buf = [0u8; 256];
        client.build_negotiate(&mut buf, [0u8; 32]).unwrap();

        let resp = NegotiateResponseCore {
            session_id: 42,
            keepalive_ms: 1000,
            security_level: 0,
            session_flags: 0,
            max_message_size: 4096,
            status: 0,
            reject_reason: 0,
            _pad: 0,
            public_key: [0u8; 32],
        };
        client.handle_negotiate_response(&resp).unwrap();
        client.build_establish(&mut buf, [0u8; 32]).unwrap();

        let ack = EstablishAckCore {
            session_id: 999, // wrong ID
            next_seq_num: 1,
            journal_low_seq_num: 0,
        };
        let err = client.handle_establish_ack(&ack).unwrap_err();
        assert!(matches!(err, SessionError::SessionIdMismatch { .. }));
    }

    // ── Replay journal tests ─────────────────────────────────

    #[test]
    fn replay_journal_roundtrip() {
        let mut session = Session::new(1);
        let msg = vec![1u8, 2, 3, 4, 5];
        session.journal_outbound(1, &msg);
        session.journal_outbound(2, &[10, 20, 30]);

        assert_eq!(session.get_journaled(1), Some(&[1u8, 2, 3, 4, 5][..]));
        assert_eq!(session.get_journaled(2), Some(&[10u8, 20, 30][..]));
        assert_eq!(session.get_journaled(3), None);
    }

    #[test]
    fn replay_journal_wraps() {
        let mut session = Session::new(1);
        let cap = session.replay_journal.len() as u64;

        session.journal_outbound(1, &[1]);
        session.journal_outbound(cap + 1, &[2]); // overwrites slot 1

        // Old message gone
        assert_eq!(session.get_journaled(1), None);
        assert_eq!(session.get_journaled(cap + 1), Some(&[2u8][..]));
    }

    // ── Journal watermark tests (Task #4) ────────────────────

    #[test]
    fn journal_empty_reports_empty_lookup() {
        let session = Session::with_journal_capacity(1, 64);
        assert_eq!(session.journal_range(), None);
        assert!(matches!(session.lookup_journaled(5), JournalLookup::Empty));
    }

    #[test]
    fn watermark_advances_on_wrap() {
        let mut session = Session::with_journal_capacity(1, 4);
        // Fill journal: seqs 1..=4. low=1, high=4.
        for s in 1..=4u64 {
            session.journal_outbound(s, &[s as u8]);
        }
        assert_eq!(session.journal_range(), Some((1, 4)));

        // Seq 5 overwrites slot 1. low must advance to 2.
        session.journal_outbound(5, &[5]);
        assert_eq!(session.journal_low_water(), 2);
        assert_eq!(session.journal_high_water(), 5);

        // Seq 7 (non-contiguous gap) — high jumps to 7, low to 4.
        session.journal_outbound(7, &[7]);
        assert_eq!(session.journal_high_water(), 7);
        assert_eq!(session.journal_low_water(), 4);
    }

    #[test]
    fn lookup_distinguishes_below_from_above_watermark() {
        let mut session = Session::with_journal_capacity(1, 4);
        for s in 1..=5u64 {
            session.journal_outbound(s, &[s as u8]);
        }
        // seq 1 overwritten by seq 5.
        match session.lookup_journaled(1) {
            JournalLookup::BelowWatermark { low } => assert_eq!(low, 2),
            other => panic!("expected BelowWatermark, got {:?}", other),
        }
        // seq 3 still present.
        assert!(matches!(session.lookup_journaled(3), JournalLookup::Found(_)));
        // seq 99 in the future.
        match session.lookup_journaled(99) {
            JournalLookup::AboveWatermark { high } => assert_eq!(high, 5),
            other => panic!("expected AboveWatermark, got {:?}", other),
        }
    }

    #[test]
    fn establish_ack_carries_low_watermark() {
        // Drive a server past a wrap and verify its EstablishAck reports
        // the correct low-water.
        let mut server = Session::with_journal_capacity(1, 4);
        let mut buf = [0u8; 256];

        // Force to Negotiated → Establishing → Active path, then journal
        // enough to wrap the ring.
        let neg = NegotiateCore {
            session_id: 1, keepalive_ms: 1000, security_level: 0,
            session_flags: 0, max_message_size: 4096, public_key: [0; 32],
        };
        server.handle_negotiate(&neg).unwrap();
        server.build_negotiate_response(&mut buf, true, 0, [0; 32]).unwrap();
        let est = EstablishCore {
            session_id: 1, next_seq_num: 1, _pad: 0, credentials: [0; 32],
        };
        server.handle_establish(&est).unwrap();

        // Inject journal entries *before* building the ack.
        for s in 1..=7u64 {
            server.journal_outbound(s, &[s as u8]);
        }
        assert_eq!(server.journal_low_water(), 4); // capacity=4, high=7 ⇒ low=4

        server.build_establish_ack(&mut buf).unwrap();
        let hdr = crate::header::FullHeader::SIZE;
        let ack = EstablishAckCore::from_bytes(&buf[hdr..]);
        assert_eq!(ack.journal_low_seq_num, 4);
    }

    #[test]
    fn assess_recovery_decides_snapshot_vs_retransmit() {
        // Fresh session, no gap.
        let ack_empty = EstablishAckCore {
            session_id: 1, next_seq_num: 1, journal_low_seq_num: 0,
        };
        assert_eq!(
            Session::assess_recovery(1, &ack_empty),
            RecoveryAssessment::InSync
        );

        // Small gap within journal.
        let ack = EstablishAckCore {
            session_id: 1, next_seq_num: 100, journal_low_seq_num: 50,
        };
        assert_eq!(
            Session::assess_recovery(80, &ack),
            RecoveryAssessment::CanRetransmit { from_seq: 80, count: 20 }
        );

        // Gap extends below the journal — must snapshot.
        match Session::assess_recovery(30, &ack) {
            RecoveryAssessment::MustSnapshot { missing_from, earliest_available } => {
                assert_eq!(missing_from, 30);
                assert_eq!(earliest_available, 50);
            }
            other => panic!("expected MustSnapshot, got {:?}", other),
        }

        // Already caught up.
        assert_eq!(
            Session::assess_recovery(100, &ack),
            RecoveryAssessment::InSync
        );
        assert_eq!(
            Session::assess_recovery(150, &ack),
            RecoveryAssessment::InSync
        );
    }

    #[test]
    fn retransmit_v2_rejects_exhausted_request() {
        let mut server = Session::with_journal_capacity(1, 4);
        // Fast-forward to Active.
        let mut buf = [0u8; 256];
        let neg = NegotiateCore {
            session_id: 1, keepalive_ms: 1000, security_level: 0,
            session_flags: 0, max_message_size: 4096, public_key: [0; 32],
        };
        server.handle_negotiate(&neg).unwrap();
        server.build_negotiate_response(&mut buf, true, 0, [0; 32]).unwrap();
        let est = EstablishCore {
            session_id: 1, next_seq_num: 1, _pad: 0, credentials: [0; 32],
        };
        server.handle_establish(&est).unwrap();
        server.build_establish_ack(&mut buf).unwrap();

        // Produce seqs 1..=10; journal (cap=4) only retains 7..=10.
        for s in 1..=10u64 {
            server.journal_outbound(s, &[s as u8]);
        }
        assert_eq!(server.journal_range(), Some((7, 10)));

        // Client asks for seq 3..=6 — entirely below the watermark.
        let req = RetransmitRequestCore { from_seq_num: 3, count: 4 };
        let resp = server.handle_retransmit_request_v2(&req).unwrap();
        match resp {
            RetransmitResponse::JournalExhausted { requested_from, low } => {
                assert_eq!(requested_from, 3);
                assert_eq!(low, 7);
            }
            other => panic!("expected JournalExhausted, got {:?}", other),
        }

        // Request straddling watermark (5..=9): must also exhaust honestly.
        let req = RetransmitRequestCore { from_seq_num: 5, count: 5 };
        match server.handle_retransmit_request_v2(&req).unwrap() {
            RetransmitResponse::JournalExhausted { requested_from: 5, low: 7 } => {}
            other => panic!("expected straddle → JournalExhausted, got {:?}", other),
        }

        // Request fully in range: must replay.
        let req = RetransmitRequestCore { from_seq_num: 8, count: 3 };
        match server.handle_retransmit_request_v2(&req).unwrap() {
            RetransmitResponse::Replay { header, messages } => {
                assert_eq!(messages.len(), 3);
                assert_eq!(header.count, 3);
                assert_eq!(messages[0], vec![8]);
                assert_eq!(messages[2], vec![10]);
            }
            other => panic!("expected Replay, got {:?}", other),
        }
    }

    #[test]
    fn sequence_reset_reason_codes() {
        assert_eq!(SequenceResetReason::from_u8(3), Some(SequenceResetReason::JournalExhausted));
        assert_eq!(SequenceResetReason::from_u8(99), None);
    }

    // ── Key rotation wire handshake (Task #18) ───────────────

    /// End-to-end proof that the session-layer wire messages drive a
    /// real `SessionCipher` rotation: both peers transition from
    /// epoch=1 → epoch=2 and can encrypt/decrypt across the boundary.
    #[test]
    fn key_rotation_handshake_advances_epoch_on_both_sides() {
        use crate::crypto::{Aes128Gcm, AeadCipher};
        use crate::crypto_session::{
            CipherFactory, InMemoryKeyProvider, KeyProvider, RotationPolicy, RotationReason,
            SessionCipher,
        };
        use std::sync::Arc;

        // Fast-forward two Session peers to Active.
        let session_id = 0xCAFE;
        let mut client_sess = Session::new(session_id);
        let mut server_sess = Session::new(session_id);
        client_sess.state = SessionState::Active;
        server_sess.state = SessionState::Active;

        // Matching SessionCiphers on both sides (same master key).
        let provider: Arc<dyn KeyProvider> =
            Arc::new(InMemoryKeyProvider::new(b"shared-master-key-for-test!!".to_vec()));
        let factory: CipherFactory = Arc::new(|key: &[u8; 16]| {
            Box::new(Aes128Gcm::new(key)) as Box<dyn AeadCipher + Send + Sync>
        });
        let mut client_cipher = SessionCipher::new(
            session_id, 1, 2, provider.clone(), factory.clone(), RotationPolicy::NEVER,
        );
        let mut server_cipher = SessionCipher::new(
            session_id, 2, 1, provider, factory, RotationPolicy::NEVER,
        );

        // Client initiates rotation.
        let signal = client_cipher.begin_rotation(RotationReason::Administrative);
        assert!(matches!(
            signal,
            crate::crypto_session::RotationSignal::Required { next_epoch: 2, .. }
        ));

        // Client writes KeyRotationRequest on the wire.
        let mut wire = [0u8; 256];
        let req_len = client_sess
            .build_key_rotation_request(&mut wire, 2, RotationReason::Administrative as u8)
            .unwrap();
        let next_epoch = {
            let req_body = &wire[crate::header::FullHeader::SIZE..req_len];
            KeyRotationRequestCore::from_bytes(req_body).next_epoch
        };
        assert_eq!(next_epoch, 2);

        // Server receives, prepares its rotation, sends Ack.
        let _ = server_cipher.begin_rotation(RotationReason::Administrative);
        let ack_len = server_sess
            .build_key_rotation_ack(&mut wire, next_epoch, 0)
            .unwrap();
        let ack = KeyRotationAckCore::from_bytes(
            &wire[crate::header::FullHeader::SIZE..ack_len],
        );
        assert_eq!(ack.epoch, 2);
        assert_eq!(ack.status, 0);

        // Both sides commit; epochs advance in lockstep.
        server_cipher.commit_rotation().unwrap();
        client_cipher.commit_rotation().unwrap();
        assert_eq!(client_cipher.current_epoch(), 2);
        assert_eq!(server_cipher.current_epoch(), 2);

        // Proof of functional rotation: encrypt under epoch=2, decrypt.
        let mut buf = [0u8; 128];
        buf[0..2].copy_from_slice(&0x474Du16.to_le_bytes()); // magic
        buf[2] = 0;
        buf[3] = 1;
        buf[4..8].copy_from_slice(&24u32.to_le_bytes());
        buf[8..24].copy_from_slice(b"post-rotation!!!");
        let out = client_cipher.encrypt(&mut buf, 24, 1).unwrap();
        let n = server_cipher.decrypt(&mut buf, out.new_len, 2, 1).unwrap();
        assert_eq!(&buf[8..n], b"post-rotation!!!");
    }

    #[test]
    fn key_rotation_messages_sizes_are_stable() {
        assert_eq!(KeyRotationRequestCore::SIZE, 16);
        assert_eq!(KeyRotationAckCore::SIZE, 16);
        assert_eq!(
            KeyRotationRequestCore::MESSAGE_TYPE,
            SessionMsgType::KeyRotationRequest as u16
        );
        assert_eq!(
            KeyRotationAckCore::MESSAGE_TYPE,
            SessionMsgType::KeyRotationAck as u16
        );
    }

    // ── Retransmission test ──────────────────────────────────

    #[test]
    fn retransmit_request_and_response() {
        let mut client = Session::new(1);
        let mut server = Session::new(1);
        let mut buf = [0u8; 256];

        // Fast-forward both to Active
        client.state = SessionState::Active;
        server.state = SessionState::Active;

        // Server journals some messages
        server.journal_outbound(1, &[0xAA; 10]);
        server.journal_outbound(2, &[0xBB; 20]);
        server.journal_outbound(3, &[0xCC; 30]);

        // Client detects gap, requests retransmit of seq 2..3
        client
            .build_retransmit_request(&mut buf, 2, 2)
            .unwrap();
        assert_eq!(client.state(), SessionState::Retransmitting);

        // Server handles request
        let req = RetransmitRequestCore {
            from_seq_num: 2,
            count: 2,
        };
        let (header, messages) = server.handle_retransmit_request(&req).unwrap();
        assert_eq!(header.count, 2);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], vec![0xBB; 20]);
        assert_eq!(messages[1], vec![0xCC; 30]);

        // Client processes retransmission
        client.handle_retransmission_complete().unwrap();
        assert_eq!(client.state(), SessionState::Active);
    }

    #[test]
    fn session_build_heartbeat() {
        let mut session = Session::new(1);
        session.state = SessionState::Active;
        session.next_expected_seq = 10;

        let mut buf = [0u8; 256];
        let len = session.build_heartbeat(&mut buf).unwrap();

        assert_eq!(len, 32 + HeartbeatCore::SIZE);

        let core = HeartbeatCore::from_bytes(&buf[32..]);
        assert_eq!(core.next_seq_num, 10);
    }
}
