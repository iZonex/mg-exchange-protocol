//! Clock discipline and `ClockStatus` reporting.
//!
//! # Why this exists
//!
//! MGEP timestamps are `u64` nanoseconds from `CLOCK_REALTIME`. Before this
//! module there was no way for a server to declare *how* that clock is
//! disciplined, and no way for a client to know whether the server's
//! timestamps would survive a regulatory audit:
//!
//! * MiFID II (RTS 25) requires trading-venue clocks to be traceable to UTC
//!   and disciplined to ≤ 100 μs for matching-engine events.
//! * SEC Regulation SCI likewise requires documented clock discipline.
//! * If the host clock drifts 50 ms and nobody knows, every audit record
//!   emitted for that period is invalid — but the wire never signaled a
//!   problem.
//!
//! We solve this in three layers:
//!
//! 1. A [`ClockSource`] probe abstracts where discipline comes from —
//!    PTPv2 hardware-timestamped (the only option that meets MiFID II for
//!    most venues), PTPv2 software, NTP, monotonic-only (colocated demo),
//!    or unsynchronized.
//! 2. A [`ClockMonitor`] polls its probe and tracks the last-known state
//!    plus an estimated drift envelope; it emits a [`ClockStatusCore`] for
//!    the server to broadcast over the session channel (`SessionMsgType::
//!    ClockStatus = 0x0E`).
//! 3. Callers (session layer, audit log) can inspect
//!    [`ClockStatusCore::quality`] and refuse to emit post-trade /
//!    regulatory records when the clock isn't adequately disciplined.
//!
//! The module does NOT ship a PTP stack — that's an operating-system
//! concern. See `docs/spec/clock-discipline.md` for the Linux
//! `phc2sys` / `ptp4l` setup recommended for production.

use std::fmt;
use std::time::Duration;

use crate::session::SessionMsgType;
use crate::types::Timestamp;

// ─── Timestamp source enum ───────────────────────────────────

/// Where the server's wall-clock discipline comes from. Ordered from
/// strongest to weakest — the wire representation is a stable `u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ClockSource {
    /// Host clock is driven by PTPv2 (IEEE 1588) with a hardware-timestamped
    /// NIC. This is the only configuration that comfortably meets the 100 μs
    /// MiFID II tolerance for matching-engine events. Regulated venues MUST
    /// use this.
    PtpHardwareTimestamp = 1,
    /// PTPv2 with software (kernel) timestamping. ~microsecond precision on
    /// a well-tuned box; acceptable for non-matching timestamps (e.g. trade
    /// capture) but NOT for regulatory records.
    PtpSoftwareTimestamp = 2,
    /// Plain NTP. Millisecond precision typical. Not regulator-acceptable
    /// for timestamping trades, but OK for operational logs.
    Ntp = 3,
    /// Only CLOCK_MONOTONIC + a fixed offset. Safe for colocation
    /// deployments where absolute UTC does not matter, but offers zero
    /// traceability.
    MonotonicOnly = 4,
    /// No discipline at all. Host wall clock may drift arbitrarily. Callers
    /// MUST refuse to emit regulatory-grade timestamps in this state.
    Unsynchronized = 5,
}

impl ClockSource {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PtpHardwareTimestamp),
            2 => Some(Self::PtpSoftwareTimestamp),
            3 => Some(Self::Ntp),
            4 => Some(Self::MonotonicOnly),
            5 => Some(Self::Unsynchronized),
            _ => None,
        }
    }

    /// Whether this source meets the common regulatory bar (≤ 100 μs
    /// estimated drift, traceable to UTC). Callers use this to gate audit
    /// emission.
    pub fn is_regulatory_grade(&self) -> bool {
        matches!(self, Self::PtpHardwareTimestamp)
    }

    /// Whether the source provides a UTC-traceable time, regardless of
    /// precision. `MonotonicOnly` and `Unsynchronized` are not traceable.
    pub fn is_utc_traceable(&self) -> bool {
        matches!(self, Self::PtpHardwareTimestamp | Self::PtpSoftwareTimestamp | Self::Ntp)
    }
}

impl fmt::Display for ClockSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PtpHardwareTimestamp => "ptp-hw",
            Self::PtpSoftwareTimestamp => "ptp-sw",
            Self::Ntp => "ntp",
            Self::MonotonicOnly => "monotonic",
            Self::Unsynchronized => "unsynced",
        };
        f.write_str(s)
    }
}

// ─── Clock Quality ───────────────────────────────────────────

/// A coarse categorization of the effective timestamp quality. Cheaper to
/// check than drift-in-nanos for fast-path gating, and stable across
/// implementations / hardware vendors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ClockQuality {
    /// Regulator-grade: PTP-HW and drift estimate ≤ 100 μs.
    RegulatoryGrade = 1,
    /// Operational-grade: PTP-SW / well-disciplined NTP, drift ≤ 10 ms.
    OperationalGrade = 2,
    /// Best-effort: NTP with larger drift, or PTP in an unhealthy state.
    BestEffort = 3,
    /// No useful discipline. MUST refuse regulatory emission.
    Unreliable = 4,
}

impl ClockQuality {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::RegulatoryGrade),
            2 => Some(Self::OperationalGrade),
            3 => Some(Self::BestEffort),
            4 => Some(Self::Unreliable),
            _ => None,
        }
    }

    /// Derived from `(source, estimated_drift)`. The boundary is the MiFID II
    /// 100 μs tolerance for matching events.
    pub fn from_source_and_drift(source: ClockSource, drift: Duration) -> Self {
        match source {
            ClockSource::PtpHardwareTimestamp if drift <= Duration::from_micros(100) => {
                Self::RegulatoryGrade
            }
            ClockSource::PtpHardwareTimestamp | ClockSource::PtpSoftwareTimestamp
                if drift <= Duration::from_millis(10) =>
            {
                Self::OperationalGrade
            }
            ClockSource::Ntp if drift <= Duration::from_millis(50) => Self::OperationalGrade,
            ClockSource::Ntp => Self::BestEffort,
            ClockSource::PtpHardwareTimestamp | ClockSource::PtpSoftwareTimestamp => {
                Self::BestEffort
            }
            ClockSource::MonotonicOnly | ClockSource::Unsynchronized => Self::Unreliable,
        }
    }
}

// ─── Clock Status wire message ───────────────────────────────

/// Session-layer `ClockStatus` message — server → client, broadcast
/// periodically (e.g. once per second) and on any quality transition.
///
/// Size: 40 bytes. Binary, zero-copy, fits comfortably in a single frame.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ClockStatusCore {
    /// [`ClockSource`] as `u8`.
    pub source: u8,
    /// [`ClockQuality`] as `u8`.
    pub quality: u8,
    pub _pad: [u8; 6],
    /// Wall-clock timestamp at the moment of publication. Clients compare
    /// this to their own clock to sanity-check. Nanoseconds since Unix
    /// epoch (same convention as other MGEP timestamps).
    pub observed_at: Timestamp,
    /// Last time the discipline subsystem was observed in sync — i.e. the
    /// moment of the last successful PTP sync / NTP step-or-slew. Stale
    /// values relative to `observed_at` mean the clock is drifting.
    pub last_sync: Timestamp,
    /// Best-effort upper bound on current drift from UTC, in nanoseconds.
    /// 0 means "unknown" (not "zero drift").
    pub estimated_drift_ns: u64,
    /// Identifier of the reference clock, if applicable. For PTP this is a
    /// truncated GrandMaster Clock Identity; for NTP, a stratum-encoded
    /// identifier. Zero if unknown.
    pub reference_clock_id: u64,
}

impl ClockStatusCore {
    pub const SIZE: usize = 40;
    pub const MESSAGE_TYPE: u16 = SessionMsgType::ClockStatus as u16;

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

    /// Parsed [`ClockSource`]; returns the `Unsynchronized` fallback if the
    /// byte is out of range.
    pub fn source(&self) -> ClockSource {
        ClockSource::from_u8(self.source).unwrap_or(ClockSource::Unsynchronized)
    }

    pub fn quality(&self) -> ClockQuality {
        ClockQuality::from_u8(self.quality).unwrap_or(ClockQuality::Unreliable)
    }
}

// ─── Clock Probe & Monitor ───────────────────────────────────

/// Snapshot of the OS-level clock discipline state.
///
/// Producing this requires operating-system specific probing: on Linux, a
/// combination of `clock_adjtime(CLOCK_REALTIME)` and reading the PTP PHC
/// via ioctl is canonical. We keep it behind a trait so callers inject the
/// right probe for their platform (and so tests can inject a fake).
#[derive(Debug, Clone, Copy)]
pub struct ClockProbe {
    pub source: ClockSource,
    /// When the probe was taken.
    pub observed_at: Timestamp,
    /// Last known good sync.
    pub last_sync: Timestamp,
    /// Upper-bound drift estimate from UTC.
    pub estimated_drift: Duration,
    pub reference_clock_id: u64,
}

/// OS/environment-specific hook for gathering a [`ClockProbe`]. Production
/// deployments implement one per supported platform; tests use
/// `FakeClockSource`.
pub trait ClockSourceProbe: Send + Sync {
    fn probe(&self) -> ClockProbe;
}

/// Tracks clock discipline state and decides when to broadcast a
/// `ClockStatus` update.
pub struct ClockMonitor {
    probe: Box<dyn ClockSourceProbe>,
    last: Option<ClockProbe>,
    last_quality: Option<ClockQuality>,
    /// Minimum interval between scheduled broadcasts. Quality transitions
    /// broadcast immediately regardless.
    broadcast_interval: Duration,
    last_broadcast_at: Option<Timestamp>,
}

/// Reason the monitor decided to emit a ClockStatus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastReason {
    Interval,
    QualityTransition { from: ClockQuality, to: ClockQuality },
    Initial,
}

impl ClockMonitor {
    pub fn new(probe: Box<dyn ClockSourceProbe>, broadcast_interval: Duration) -> Self {
        Self {
            probe,
            last: None,
            last_quality: None,
            broadcast_interval,
            last_broadcast_at: None,
        }
    }

    /// Poll the probe and decide whether to broadcast. Returns `Some(core)`
    /// when the caller should emit a `ClockStatus` message.
    pub fn tick(&mut self) -> Option<(ClockStatusCore, BroadcastReason)> {
        let probe = self.probe.probe();
        let quality = ClockQuality::from_source_and_drift(probe.source, probe.estimated_drift);

        let reason = match self.last_quality {
            None => BroadcastReason::Initial,
            Some(last_q) if last_q != quality => {
                BroadcastReason::QualityTransition { from: last_q, to: quality }
            }
            _ => {
                let interval_elapsed = match self.last_broadcast_at {
                    Some(last) => elapsed(last, probe.observed_at) >= self.broadcast_interval,
                    None => true,
                };
                if interval_elapsed {
                    BroadcastReason::Interval
                } else {
                    self.last = Some(probe);
                    return None;
                }
            }
        };

        self.last = Some(probe);
        self.last_quality = Some(quality);
        self.last_broadcast_at = Some(probe.observed_at);

        let core = ClockStatusCore {
            source: probe.source as u8,
            quality: quality as u8,
            _pad: [0; 6],
            observed_at: probe.observed_at,
            last_sync: probe.last_sync,
            estimated_drift_ns: probe.estimated_drift.as_nanos().min(u64::MAX as u128) as u64,
            reference_clock_id: probe.reference_clock_id,
        };
        Some((core, reason))
    }

    /// Most recent probe observed (may be older than the most recent broadcast).
    pub fn last_probe(&self) -> Option<ClockProbe> {
        self.last
    }

    pub fn last_quality(&self) -> Option<ClockQuality> {
        self.last_quality
    }

    /// Decide whether the server is currently allowed to emit a
    /// regulatory-grade timestamp (e.g. a MiFID II transaction report).
    pub fn regulatory_ok(&self) -> bool {
        matches!(self.last_quality, Some(ClockQuality::RegulatoryGrade))
    }
}

fn elapsed(earlier: Timestamp, later: Timestamp) -> Duration {
    let ns = later.as_nanos().saturating_sub(earlier.as_nanos());
    Duration::from_nanos(ns)
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct FakeProbe {
        state: Arc<Mutex<ClockProbe>>,
    }

    impl FakeProbe {
        fn new(initial: ClockProbe) -> (Self, Arc<Mutex<ClockProbe>>) {
            let state = Arc::new(Mutex::new(initial));
            (Self { state: state.clone() }, state)
        }
    }

    impl ClockSourceProbe for FakeProbe {
        fn probe(&self) -> ClockProbe {
            *self.state.lock().unwrap()
        }
    }

    fn ts(nanos: u64) -> Timestamp {
        Timestamp::from_nanos(nanos)
    }

    fn baseline(source: ClockSource, drift_ns: u64, at: u64) -> ClockProbe {
        ClockProbe {
            source,
            observed_at: ts(at),
            last_sync: ts(at),
            estimated_drift: Duration::from_nanos(drift_ns),
            reference_clock_id: 0xAB,
        }
    }

    #[test]
    fn quality_gates_on_source_and_drift() {
        // PTP-HW with tiny drift → RegulatoryGrade.
        assert_eq!(
            ClockQuality::from_source_and_drift(
                ClockSource::PtpHardwareTimestamp,
                Duration::from_micros(50)
            ),
            ClockQuality::RegulatoryGrade
        );
        // PTP-HW but drift blew past 100 μs → drops to OperationalGrade.
        assert_eq!(
            ClockQuality::from_source_and_drift(
                ClockSource::PtpHardwareTimestamp,
                Duration::from_millis(1)
            ),
            ClockQuality::OperationalGrade
        );
        // NTP at 30 ms → operational.
        assert_eq!(
            ClockQuality::from_source_and_drift(
                ClockSource::Ntp,
                Duration::from_millis(30)
            ),
            ClockQuality::OperationalGrade
        );
        // NTP drifting past 50 ms → best-effort.
        assert_eq!(
            ClockQuality::from_source_and_drift(
                ClockSource::Ntp,
                Duration::from_millis(100)
            ),
            ClockQuality::BestEffort
        );
        // Monotonic-only → unreliable regardless of drift.
        assert_eq!(
            ClockQuality::from_source_and_drift(
                ClockSource::MonotonicOnly,
                Duration::from_nanos(0)
            ),
            ClockQuality::Unreliable
        );
    }

    #[test]
    fn source_traits() {
        assert!(ClockSource::PtpHardwareTimestamp.is_regulatory_grade());
        assert!(!ClockSource::PtpSoftwareTimestamp.is_regulatory_grade());
        assert!(ClockSource::Ntp.is_utc_traceable());
        assert!(!ClockSource::MonotonicOnly.is_utc_traceable());
        assert!(!ClockSource::Unsynchronized.is_utc_traceable());
    }

    #[test]
    fn first_tick_broadcasts() {
        let (probe, _state) = FakeProbe::new(baseline(
            ClockSource::PtpHardwareTimestamp,
            50_000,
            1_000_000_000,
        ));
        let mut mon = ClockMonitor::new(Box::new(probe), Duration::from_secs(1));

        let (core, reason) = mon.tick().expect("initial broadcast expected");
        assert_eq!(reason, BroadcastReason::Initial);
        assert_eq!(core.source(), ClockSource::PtpHardwareTimestamp);
        assert_eq!(core.quality(), ClockQuality::RegulatoryGrade);
        assert_eq!(core.reference_clock_id, 0xAB);
        assert_eq!(core.estimated_drift_ns, 50_000);
    }

    #[test]
    fn subsequent_ticks_respect_interval() {
        let (probe, state) = FakeProbe::new(baseline(
            ClockSource::PtpHardwareTimestamp,
            50_000,
            1_000_000_000,
        ));
        let mut mon = ClockMonitor::new(Box::new(probe), Duration::from_millis(500));

        // Initial.
        assert!(mon.tick().is_some());

        // Advance 100 ms with no quality change — must NOT broadcast.
        state.lock().unwrap().observed_at = ts(1_000_000_000 + 100_000_000);
        assert!(mon.tick().is_none());

        // Advance past the 500 ms interval.
        state.lock().unwrap().observed_at = ts(1_000_000_000 + 600_000_000);
        let (_, reason) = mon.tick().unwrap();
        assert_eq!(reason, BroadcastReason::Interval);
    }

    #[test]
    fn quality_transition_broadcasts_immediately() {
        let (probe, state) = FakeProbe::new(baseline(
            ClockSource::PtpHardwareTimestamp,
            50_000,
            1_000_000_000,
        ));
        let mut mon = ClockMonitor::new(Box::new(probe), Duration::from_secs(60));

        // Initial broadcast at RegulatoryGrade.
        assert!(mon.tick().is_some());
        assert!(mon.regulatory_ok());

        // Drift blows past 100 μs — still within the 60 s interval, but
        // the monitor must broadcast the transition immediately.
        state.lock().unwrap().estimated_drift = Duration::from_millis(5);
        state.lock().unwrap().observed_at = ts(1_000_000_000 + 10_000_000);
        let (core, reason) = mon.tick().expect("transition must broadcast");
        match reason {
            BroadcastReason::QualityTransition {
                from: ClockQuality::RegulatoryGrade,
                to: ClockQuality::OperationalGrade,
            } => {}
            other => panic!("unexpected reason: {:?}", other),
        }
        assert_eq!(core.quality(), ClockQuality::OperationalGrade);
        assert!(!mon.regulatory_ok(), "audit gate must close");
    }

    #[test]
    fn unsynchronized_forbids_regulatory_emission() {
        let (probe, _s) = FakeProbe::new(baseline(
            ClockSource::Unsynchronized,
            0,
            1_000_000_000,
        ));
        let mut mon = ClockMonitor::new(Box::new(probe), Duration::from_secs(1));
        let (core, _) = mon.tick().unwrap();
        assert_eq!(core.quality(), ClockQuality::Unreliable);
        assert!(!mon.regulatory_ok());
    }

    #[test]
    fn clock_status_wire_roundtrip() {
        let core = ClockStatusCore {
            source: ClockSource::PtpHardwareTimestamp as u8,
            quality: ClockQuality::RegulatoryGrade as u8,
            _pad: [0; 6],
            observed_at: ts(1_700_000_000_000_000_000),
            last_sync: ts(1_700_000_000_000_000_000),
            estimated_drift_ns: 42_000,
            reference_clock_id: 0xDEADBEEF,
        };
        let bytes = core.as_bytes();
        assert_eq!(bytes.len(), ClockStatusCore::SIZE);

        let decoded = ClockStatusCore::from_bytes(bytes);
        assert_eq!(decoded.source(), ClockSource::PtpHardwareTimestamp);
        assert_eq!(decoded.quality(), ClockQuality::RegulatoryGrade);
        assert_eq!(decoded.estimated_drift_ns, 42_000);
        assert_eq!(decoded.reference_clock_id, 0xDEADBEEF);
    }

    #[test]
    fn try_from_bytes_short_buffer() {
        let short = [0u8; ClockStatusCore::SIZE - 1];
        assert!(ClockStatusCore::try_from_bytes(&short).is_none());
        let ok = [0u8; ClockStatusCore::SIZE];
        assert!(ClockStatusCore::try_from_bytes(&ok).is_some());
    }

    #[test]
    fn message_type_wired() {
        assert_eq!(
            ClockStatusCore::MESSAGE_TYPE,
            SessionMsgType::ClockStatus as u16
        );
    }
}
