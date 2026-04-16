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
    pub next_seq_num: u64,
    pub _pad: u32,
}

impl EstablishAckCore {
    pub const SIZE: usize = 16;
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
    pub reason: u8, // 0=admin, 1=slow_consumer, 2=reconnect
    pub _pad: [u8; 3],
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

    // Security (used when encryption is negotiated)
    #[allow(dead_code)]
    shared_secret: Option<[u8; 32]>,

    // Replay journal: stores outbound messages for retransmission.
    // Ring buffer: journal[seq % capacity] = (seq, message_bytes).
    replay_journal: Vec<Option<(u64, Vec<u8>)>>,

    // Optional persistent WAL
    wal: Option<crate::wal::WalWriter>,
}

impl Session {
    pub fn new(session_id: u64) -> Self {
        let mut journal = Vec::with_capacity(DEFAULT_REPLAY_CAPACITY);
        journal.resize_with(DEFAULT_REPLAY_CAPACITY, || None);
        Self {
            state: SessionState::Disconnected,
            session_id,
            security_level: SecurityLevel::None,
            keepalive_ms: 1000,
            next_outbound_seq: 1,
            next_expected_seq: 1,
            last_sent: Timestamp::NULL,
            last_received: Timestamp::NULL,
            shared_secret: None,
            replay_journal: journal,
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

    // ── Setters (for initial configuration before handshake) ─

    pub fn set_security_level(&mut self, level: SecurityLevel) {
        self.security_level = level;
    }

    pub fn set_keepalive_ms(&mut self, ms: u32) {
        self.keepalive_ms = ms;
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
    pub fn journal_outbound(&mut self, seq: u64, msg: &[u8]) {
        let idx = seq as usize % self.replay_journal.len();
        self.replay_journal[idx] = Some((seq, msg.to_vec()));

        // Write to persistent WAL if attached
        if let Some(wal) = &mut self.wal {
            let _ = wal.append(msg); // best-effort, don't block on IO error
        }
    }

    /// Look up a journaled message by sequence number.
    pub fn get_journaled(&self, seq: u64) -> Option<&[u8]> {
        let idx = seq as usize % self.replay_journal.len();
        match &self.replay_journal[idx] {
            Some((stored_seq, data)) if *stored_seq == seq => Some(data),
            _ => None,
        }
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
            session_flags: 0,
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
            return Err(SessionError::NegotiateRejected {
                reason: core.reject_reason,
            });
        }

        self.keepalive_ms = core.keepalive_ms;
        self.security_level =
            SecurityLevel::from_u8(core.security_level).unwrap_or(SecurityLevel::None);
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

        let core = NegotiateResponseCore {
            session_id: self.session_id,
            keepalive_ms: self.keepalive_ms,
            security_level: self.security_level as u8,
            session_flags: 0,
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
            _pad: 0,
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
            _pad: 0,
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
            _pad: 0,
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
