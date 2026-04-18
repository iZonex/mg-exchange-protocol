//! Regulatory audit trail.
//!
//! # Why this exists
//!
//! MiFID II (RTS 24), SEC Reg SCI, CAT reporting, and equivalent regimes
//! oblige trading venues to retain an immutable, timestamped record of
//! every material event — submissions, cancellations, fills, halts,
//! compliance actions. A venue that cannot produce that record on request
//! loses its authorization.
//!
//! Before this module, MGEP had no audit-record schema and no gate between
//! "we can emit a regulatory event" and "our wall clock is disciplined".
//! Both are fixed here:
//!
//! * [`AuditRecord`] captures the mandatory fields in a single zero-copy
//!   struct. `actor_id`, `action`, `reason_code`, `timestamp`, and the
//!   full [`ClockQuality`] at the moment of the event are all recorded —
//!   so regulators can verify not just *what* happened but *whether the
//!   clock was trustworthy* at that moment.
//! * [`AuditLogger`] is a trait. Production deployments implement it on
//!   top of whatever append-only store is authoritative for them —
//!   Kafka + S3, WORM-mode filesystem, managed database. We ship
//!   [`InMemoryAuditLogger`] for tests and for servers that can afford to
//!   buffer records until a durable sink is healthy.
//! * The emission path goes through [`AuditGate`] which consults
//!   [`ClockMonitor::regulatory_ok`] and refuses to record if the clock
//!   isn't disciplined. The refusal is itself audit-worthy and surfaces
//!   as an error the server must raise to ops.

use std::sync::{Arc, Mutex};

use crate::clock_discipline::{ClockMonitor, ClockQuality};
use crate::types::Timestamp;

// ─── Actions & reasons ───────────────────────────────────────

/// What kind of event is being audited. Stable `u8` for the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditAction {
    OrderSubmit = 1,
    OrderAck = 2,
    OrderReject = 3,
    OrderCancel = 4,
    OrderReplace = 5,
    Fill = 6,
    PartialFill = 7,
    Expire = 8,
    MassCancel = 9,
    SessionLost = 10,
    KillSwitchHalt = 11,
    KillSwitchResume = 12,
    ComplianceOverride = 13,
    RiskBreach = 14,
}

impl AuditAction {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::OrderSubmit),
            2 => Some(Self::OrderAck),
            3 => Some(Self::OrderReject),
            4 => Some(Self::OrderCancel),
            5 => Some(Self::OrderReplace),
            6 => Some(Self::Fill),
            7 => Some(Self::PartialFill),
            8 => Some(Self::Expire),
            9 => Some(Self::MassCancel),
            10 => Some(Self::SessionLost),
            11 => Some(Self::KillSwitchHalt),
            12 => Some(Self::KillSwitchResume),
            13 => Some(Self::ComplianceOverride),
            14 => Some(Self::RiskBreach),
            _ => None,
        }
    }

    /// Actions whose emission must be gated on `ClockQuality::RegulatoryGrade`.
    /// Operational events (e.g. `SessionLost`) are still recorded when the
    /// clock is best-effort so ops can diagnose — but matching-engine events
    /// (`Fill`, `PartialFill`, `OrderAck`) are regulator-grade only.
    pub fn requires_regulatory_clock(&self) -> bool {
        matches!(
            self,
            Self::OrderSubmit
                | Self::OrderAck
                | Self::OrderReject
                | Self::OrderCancel
                | Self::OrderReplace
                | Self::Fill
                | Self::PartialFill
                | Self::Expire
                | Self::MassCancel
                | Self::KillSwitchHalt
                | Self::KillSwitchResume
        )
    }
}

/// Reason code accompanying an audit record. Avoids free-form strings in
/// the hot-path emission and gives regulators a stable vocabulary.
///
/// The `u16` wire size leaves room for per-venue extensions above 0x8000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuditReason {
    Normal = 0,
    /// Regulatory cancel: risk, compliance, or admin-initiated.
    RegulatoryCancel = 1,
    /// `CANCEL_ON_DISCONNECT` flag triggered.
    SessionCancelOnDisconnect = 2,
    RateLimited = 3,
    DuplicateClOrdID = 4,
    /// Order rejected because the book/market is halted.
    MarketHalted = 5,
    /// Order violated a pre-trade risk check.
    RiskCheckFailed = 6,
    /// Self-trade prevention matched.
    SelfTradePrevented = 7,
    /// Client's clock was detected as ahead of ours by more than the
    /// protocol tolerance — we rejected to avoid ambiguous ordering.
    ClockSkew = 8,
    /// Session terminated — no heartbeat within grace.
    PeerTimeout = 9,
    /// Kill-switch tripped.
    KillSwitchTripped = 10,
    /// Venue-specific reason (documented out-of-band).
    VenueDefined = 0x8000,
}

impl AuditReason {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

// ─── Record ──────────────────────────────────────────────────

/// A single audit-log entry.
///
/// 80 bytes, `#[repr(C)]` so it can be mmapped / DMA'd straight into a WORM
/// storage layer without a serializer. Consider `AuditRecord` + an
/// append-only file as the minimum compliant storage shape; richer sinks
/// (Kafka, database) can derive a row per record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct AuditRecord {
    /// Monotonic sequence number within this audit stream. Regulators ask
    /// for "record N through M"; this makes that query trivial.
    pub audit_seq: u64,
    /// Wall-clock timestamp of the event. MUST be disciplined per spec §6
    /// (see `docs/spec/06-clock-discipline.md`).
    pub timestamp: Timestamp,
    /// Who performed / triggered the action. For customer-originated events
    /// this is the session/account id; for administrative actions it's the
    /// operator id.
    pub actor_id: u64,
    /// Order / trade / cancel identifier tied to this event (0 if N/A).
    pub subject_id: u64,
    /// Instrument this event relates to (0 for venue-wide actions).
    pub instrument_id: u32,
    pub action: u8,
    pub actor_role: u8,
    /// [`ClockQuality`] at the moment of emission. Preserves the ability
    /// to audit the audit: if quality wasn't Regulatory, the record will
    /// say so and regulators can filter accordingly.
    pub clock_quality: u8,
    pub _pad: u8,
    pub reason: u16,
    pub _pad2: u16,
    /// Content-addressable hash of the full event payload (e.g. SHA-256
    /// truncated to the first 16 bytes). Enables later tamper detection
    /// when paired with an append-only storage layer.
    pub payload_digest: [u8; 16],
    /// Hash chain: digest of the previous record. Forms a linked log so a
    /// regulator can independently verify ordering and detect deletions.
    pub prev_digest: [u8; 16],
}

impl AuditRecord {
    pub const SIZE: usize = 80;

    /// Parse the `action` byte as an enum (returns `None` on unknown codes
    /// so forward-compat readers don't crash on new record types).
    pub fn action(&self) -> Option<AuditAction> {
        AuditAction::from_u8(self.action)
    }

    pub fn clock_quality(&self) -> Option<ClockQuality> {
        ClockQuality::from_u8(self.clock_quality)
    }
}

/// Role of the actor on whose behalf an audit record is written. Used to
/// authorize privileged operations (kill-switch, compliance override) and
/// to filter the audit stream by principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActorRole {
    Trader = 1,
    MarketMaker = 2,
    RiskOfficer = 3,
    ComplianceOfficer = 4,
    SystemOperator = 5,
    /// The exchange itself (housekeeping events: session cleanup, scheduled
    /// halts, etc.).
    Venue = 6,
}

impl ActorRole {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Trader),
            2 => Some(Self::MarketMaker),
            3 => Some(Self::RiskOfficer),
            4 => Some(Self::ComplianceOfficer),
            5 => Some(Self::SystemOperator),
            6 => Some(Self::Venue),
            _ => None,
        }
    }

    /// Roles authorized to trip the kill-switch. Traders and market makers
    /// are not.
    pub fn can_halt_market(&self) -> bool {
        matches!(
            self,
            Self::RiskOfficer | Self::ComplianceOfficer | Self::SystemOperator | Self::Venue
        )
    }
}

// ─── Logger ──────────────────────────────────────────────────

/// Where audit records land. Implementations MUST be append-only — once a
/// record is handed off, it must never be mutated or deleted short of
/// end-of-retention purge.
pub trait AuditLogger: Send + Sync {
    /// Persist one record. Errors bubble out to the caller: a failed audit
    /// append is a failed business action.
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// Clock is not in a state where a regulatory record can be emitted.
    /// The business action that triggered this MUST be rejected upstream.
    ClockNotRegulatory { quality: ClockQuality },
    /// Storage layer rejected the write (full, network, permission).
    StorageRejected(String),
    /// Role-based authorization failed.
    Unauthorized { actor_role: ActorRole, required: &'static str },
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClockNotRegulatory { quality } => {
                write!(f, "clock quality {:?} insufficient for regulatory audit", quality)
            }
            Self::StorageRejected(s) => write!(f, "audit storage rejected: {}", s),
            Self::Unauthorized { actor_role, required } => {
                write!(f, "role {:?} cannot perform {}", actor_role, required)
            }
        }
    }
}

impl std::error::Error for AuditError {}

/// Append-only in-memory logger. Primarily for tests and dev; production
/// wraps a durable sink.
pub struct InMemoryAuditLogger {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl InMemoryAuditLogger {
    pub fn new() -> Self {
        Self { records: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.lock().unwrap().is_empty()
    }
}

impl Default for InMemoryAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger for InMemoryAuditLogger {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.records.lock().unwrap().push(*record);
        Ok(())
    }
}

/// Fail-by-default logger: useful as a placeholder while integrating, so a
/// missing configuration doesn't silently drop audit records.
pub struct FailingAuditLogger;

impl AuditLogger for FailingAuditLogger {
    fn append(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::StorageRejected(
            "no audit sink configured".into(),
        ))
    }
}

// ─── Gate + emitter ──────────────────────────────────────────

/// Serializes audit records: maintains `audit_seq`, chains `prev_digest`,
/// consults [`ClockMonitor`] before emitting regulatory-gated events, and
/// delegates storage to a [`AuditLogger`].
///
/// One `AuditGate` instance per audit stream (typically one per venue; a
/// sharded venue may run one per shard and merge post-hoc).
pub struct AuditGate {
    next_seq: u64,
    prev_digest: [u8; 16],
    clock: Arc<ClockMonitor>,
    sink: Arc<dyn AuditLogger>,
}

impl AuditGate {
    pub fn new(clock: Arc<ClockMonitor>, sink: Arc<dyn AuditLogger>) -> Self {
        Self {
            next_seq: 1,
            prev_digest: [0; 16],
            clock,
            sink,
        }
    }

    /// Emit a record. The gate:
    /// 1. Checks the action's regulatory requirement against current clock
    ///    quality. Refuses if insufficient.
    /// 2. Enforces role-based authz on privileged actions (kill-switch
    ///    family).
    /// 3. Fills in `audit_seq` and `prev_digest`.
    /// 4. Hands off to the sink.
    pub fn emit(&mut self, mut record: AuditRecord) -> Result<AuditRecord, AuditError> {
        let action = record.action().ok_or(AuditError::StorageRejected(
            format!("unknown action code 0x{:02x}", record.action),
        ))?;

        // Regulatory clock gate.
        let quality = self
            .clock
            .last_quality()
            .unwrap_or(ClockQuality::Unreliable);
        if action.requires_regulatory_clock() && quality != ClockQuality::RegulatoryGrade {
            return Err(AuditError::ClockNotRegulatory { quality });
        }

        // Role authz: kill-switch family requires a privileged role.
        if matches!(action, AuditAction::KillSwitchHalt | AuditAction::KillSwitchResume | AuditAction::ComplianceOverride) {
            let role = ActorRole::from_u8(record.actor_role).unwrap_or(ActorRole::Trader);
            if !role.can_halt_market() {
                return Err(AuditError::Unauthorized {
                    actor_role: role,
                    required: "kill_switch / compliance",
                });
            }
        }

        record.audit_seq = self.next_seq;
        self.next_seq += 1;
        record.clock_quality = quality as u8;
        record.prev_digest = self.prev_digest;

        self.sink.append(&record)?;
        // Chain: prev_digest of next record = digest of this record's
        // payload, combined with this record's digest. The stored digest
        // itself isn't recomputed from the whole record — that's the
        // sink's job if it wants WORM-grade integrity.
        self.prev_digest = record.payload_digest;
        Ok(record)
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock_discipline::{ClockProbe, ClockSource, ClockSourceProbe};
    use std::time::Duration;

    struct FixedProbe {
        source: ClockSource,
        drift: Duration,
    }

    impl ClockSourceProbe for FixedProbe {
        fn probe(&self) -> ClockProbe {
            ClockProbe {
                source: self.source,
                observed_at: Timestamp::from_nanos(1_700_000_000_000_000_000),
                last_sync: Timestamp::from_nanos(1_700_000_000_000_000_000),
                estimated_drift: self.drift,
                reference_clock_id: 0xCAFE,
            }
        }
    }

    fn monitor(source: ClockSource, drift: Duration) -> Arc<ClockMonitor> {
        let probe = Box::new(FixedProbe { source, drift });
        let mut m = ClockMonitor::new(probe, Duration::from_secs(1));
        // Prime the monitor so last_quality is populated.
        let _ = m.tick();
        Arc::new(m)
    }

    fn mk_record(action: AuditAction, actor_role: ActorRole) -> AuditRecord {
        AuditRecord {
            audit_seq: 0,
            timestamp: Timestamp::from_nanos(1_700_000_000_000_000_000),
            actor_id: 42,
            subject_id: 100,
            instrument_id: 7,
            action: action as u8,
            actor_role: actor_role as u8,
            clock_quality: 0,
            _pad: 0,
            reason: AuditReason::Normal.as_u16(),
            _pad2: 0,
            payload_digest: [0xAA; 16],
            prev_digest: [0; 16],
        }
    }

    #[test]
    fn record_is_80_bytes() {
        assert_eq!(std::mem::size_of::<AuditRecord>(), AuditRecord::SIZE);
    }

    #[test]
    fn regulatory_clock_allows_order_events() {
        let clock = monitor(ClockSource::PtpHardwareTimestamp, Duration::from_micros(50));
        let sink = Arc::new(InMemoryAuditLogger::new());
        let mut gate = AuditGate::new(clock, sink.clone());

        let r = gate.emit(mk_record(AuditAction::OrderSubmit, ActorRole::Trader)).unwrap();
        assert_eq!(r.audit_seq, 1);
        assert_eq!(
            r.clock_quality().unwrap(),
            ClockQuality::RegulatoryGrade
        );
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn unreliable_clock_refuses_regulatory_action() {
        let clock = monitor(ClockSource::Unsynchronized, Duration::from_nanos(0));
        let sink = Arc::new(InMemoryAuditLogger::new());
        let mut gate = AuditGate::new(clock, sink.clone());

        let err = gate
            .emit(mk_record(AuditAction::Fill, ActorRole::Venue))
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::ClockNotRegulatory {
                quality: ClockQuality::Unreliable
            }
        ));
        assert_eq!(sink.len(), 0, "no record must land on refusal");
    }

    #[test]
    fn operational_events_allowed_without_regulatory_clock() {
        // SessionLost isn't a matching-engine event — we still want it
        // recorded for ops even when the clock is best-effort.
        let clock = monitor(ClockSource::Ntp, Duration::from_millis(20));
        let sink = Arc::new(InMemoryAuditLogger::new());
        let mut gate = AuditGate::new(clock, sink.clone());

        gate.emit(mk_record(AuditAction::SessionLost, ActorRole::Venue))
            .unwrap();
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn kill_switch_requires_privileged_role() {
        let clock = monitor(ClockSource::PtpHardwareTimestamp, Duration::from_micros(10));
        let sink = Arc::new(InMemoryAuditLogger::new());
        let mut gate = AuditGate::new(clock, sink.clone());

        // Trader cannot halt.
        let err = gate
            .emit(mk_record(AuditAction::KillSwitchHalt, ActorRole::Trader))
            .unwrap_err();
        assert!(matches!(err, AuditError::Unauthorized { .. }));

        // Risk officer can.
        gate.emit(mk_record(AuditAction::KillSwitchHalt, ActorRole::RiskOfficer))
            .unwrap();
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn audit_seq_monotonic_and_chained() {
        let clock = monitor(ClockSource::PtpHardwareTimestamp, Duration::from_micros(10));
        let sink = Arc::new(InMemoryAuditLogger::new());
        let mut gate = AuditGate::new(clock, sink.clone());

        let r1 = gate.emit(mk_record(AuditAction::OrderSubmit, ActorRole::Trader)).unwrap();
        let r2 = gate.emit(mk_record(AuditAction::OrderAck, ActorRole::Venue)).unwrap();
        let r3 = gate.emit(mk_record(AuditAction::Fill, ActorRole::Venue)).unwrap();

        assert_eq!(r1.audit_seq, 1);
        assert_eq!(r2.audit_seq, 2);
        assert_eq!(r3.audit_seq, 3);

        // Chain: each prev_digest equals the previous record's payload_digest.
        assert_eq!(r1.prev_digest, [0; 16]);
        assert_eq!(r2.prev_digest, r1.payload_digest);
        assert_eq!(r3.prev_digest, r2.payload_digest);
    }

    #[test]
    fn roles_authz() {
        assert!(ActorRole::Venue.can_halt_market());
        assert!(ActorRole::ComplianceOfficer.can_halt_market());
        assert!(ActorRole::RiskOfficer.can_halt_market());
        assert!(ActorRole::SystemOperator.can_halt_market());
        assert!(!ActorRole::Trader.can_halt_market());
        assert!(!ActorRole::MarketMaker.can_halt_market());
    }

    #[test]
    fn failing_logger_surfaces_error() {
        let clock = monitor(ClockSource::PtpHardwareTimestamp, Duration::from_micros(10));
        let sink: Arc<dyn AuditLogger> = Arc::new(FailingAuditLogger);
        let mut gate = AuditGate::new(clock, sink);
        let err = gate
            .emit(mk_record(AuditAction::OrderSubmit, ActorRole::Trader))
            .unwrap_err();
        assert!(matches!(err, AuditError::StorageRejected(_)));
    }

    #[test]
    fn action_regulatory_gates_match_intuition() {
        assert!(AuditAction::Fill.requires_regulatory_clock());
        assert!(AuditAction::OrderAck.requires_regulatory_clock());
        assert!(AuditAction::KillSwitchHalt.requires_regulatory_clock());
        assert!(!AuditAction::SessionLost.requires_regulatory_clock());
        assert!(!AuditAction::RiskBreach.requires_regulatory_clock());
    }
}
