//! `LinuxPtpProbe` — real `ClockSourceProbe` impl for Linux.
//!
//! # What it does
//!
//! * Calls `clock_adjtime(CLOCK_REALTIME)` to retrieve the kernel's own
//!   view of the clock's max-error / est-error in microseconds. This is
//!   the authoritative drift estimate on any Linux box running
//!   `chronyd` / `ntpd` / `ptp4l` + `phc2sys`.
//! * Walks `/sys/class/ptp/` to detect whether a hardware PTP clock is
//!   present. When found, we upgrade the `ClockSource` from
//!   `PtpSoftwareTimestamp` / `Ntp` to `PtpHardwareTimestamp`.
//! * Extracts the PHC `clock_name` — on PTP-capable NICs this is the
//!   grand-master identity prefix (e.g. "eth0 timestamping").
//!
//! # What it deliberately does not do
//!
//! * No ioctl to `/dev/ptp0`. The PHC ioctl dance gives richer data
//!   (PTP_CLOCK_GETCAPS etc.) but requires `CAP_SYS_TIME` and a matching
//!   kernel header. `clock_adjtime` covers the cases we actually need
//!   for the MGEP `ClockQuality` gate.
//! * No non-Linux targets. `cfg(target_os = "linux")`-only. macOS / BSD
//!   deployments supply their own `ClockSourceProbe` — the trait is
//!   OS-agnostic.
//!
//! # Feature flag
//!
//! Gated behind `linux-ptp` so macOS CI builds stay clean without
//! platform-specific syscalls.

#![cfg(all(target_os = "linux", feature = "linux-ptp"))]

use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::clock_discipline::{ClockProbe, ClockSource, ClockSourceProbe};
use crate::types::Timestamp;

/// Linux-native clock discipline probe. Safe to share across threads;
/// `probe()` is stateless beyond a cached PHC path discovered at ctor.
pub struct LinuxPtpProbe {
    phc_name: Option<String>,
    reference_clock_id: u64,
    /// If the `/sys/class/ptp` walk succeeded with at least one device,
    /// we infer hardware timestamping is available.
    has_hardware_ptp: bool,
}

impl LinuxPtpProbe {
    pub fn new() -> Self {
        let (phc_name, has_hardware_ptp, reference_clock_id) = scan_sys_class_ptp();
        Self { phc_name, has_hardware_ptp, reference_clock_id }
    }

    pub fn phc_name(&self) -> Option<&str> {
        self.phc_name.as_deref()
    }
}

impl Default for LinuxPtpProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockSourceProbe for LinuxPtpProbe {
    fn probe(&self) -> ClockProbe {
        let (source, drift, last_sync_unix_ns) = probe_kernel_state(self.has_hardware_ptp);
        ClockProbe {
            source,
            observed_at: Timestamp::now(),
            last_sync: Timestamp::from_nanos(last_sync_unix_ns),
            estimated_drift: drift,
            reference_clock_id: self.reference_clock_id,
        }
    }
}

// ─── /sys/class/ptp discovery ────────────────────────────────

fn scan_sys_class_ptp() -> (Option<String>, bool, u64) {
    let root = Path::new("/sys/class/ptp");
    if !root.exists() {
        return (None, false, 0);
    }
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return (None, false, 0),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name_file = path.join("clock_name");
        if let Ok(name) = fs::read_to_string(&name_file) {
            let name = name.trim().to_string();
            // First 8 bytes of the name hashed → stable u64 identity for
            // `reference_clock_id`. Not cryptographic; just stable.
            let id = hash_name_fnv1a64(&name);
            return (Some(name), true, id);
        }
    }
    (None, false, 0)
}

fn hash_name_fnv1a64(s: &str) -> u64 {
    // FNV-1a 64-bit. Deterministic, trivial.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ─── clock_adjtime syscall ───────────────────────────────────

/// Subset of `struct timex` (Linux `clock_adjtime`). We only read the
/// status + `maxerror` / `esterror` fields so we don't need the full
/// layout. Layout mirrors the ABI exactly.
#[repr(C)]
#[derive(Default)]
struct Timex {
    modes: u32,
    _offset: i64,
    _freq: i64,
    maxerror: i64,
    esterror: i64,
    status: i32,
    _constant: i64,
    _precision: i64,
    _tolerance: i64,
    time_sec: i64,
    time_usec: i64,
    _tick: i64,
    _ppsfreq: i64,
    _jitter: i64,
    _shift: i32,
    _stabil: i64,
    _jitcnt: i64,
    _calcnt: i64,
    _errcnt: i64,
    _stbcnt: i64,
    _tai: i32,
    _pad: [i32; 11],
}

const STA_UNSYNC: i32 = 0x0040;
const STA_CLOCKERR: i32 = 0x1000;
const CLOCK_REALTIME: i32 = 0;

extern "C" {
    // `clock_adjtime` is in glibc >=2.14. Returns `TIME_*` state codes
    // or -1 on error; we just care about the filled `tx` struct.
    fn clock_adjtime(clk_id: i32, tx: *mut Timex) -> i32;
}

fn probe_kernel_state(has_hardware_ptp: bool) -> (ClockSource, Duration, u64) {
    let mut tx = Timex::default();
    // SAFETY: Timex is `#[repr(C)]` matching Linux ABI; the call only
    // writes into `tx`. No lifetime issues.
    let rc = unsafe { clock_adjtime(CLOCK_REALTIME, &mut tx) };

    if rc < 0 {
        // Syscall failed — conservative fallback.
        return (ClockSource::Unsynchronized, Duration::from_secs(86400), 0);
    }

    // `STA_UNSYNC` = kernel believes the clock is not synced.
    let unsynced = tx.status & STA_UNSYNC != 0;
    let clock_error = tx.status & STA_CLOCKERR != 0;

    // `maxerror` is in µs.
    let drift = Duration::from_micros(tx.maxerror.max(0) as u64);

    let source = if unsynced || clock_error {
        ClockSource::Unsynchronized
    } else if has_hardware_ptp && drift <= Duration::from_micros(200) {
        ClockSource::PtpHardwareTimestamp
    } else if has_hardware_ptp {
        // PTP is configured but drift is high — we're between a PTP-HW
        // and PTP-SW grade. Be honest: software-timestamping grade.
        ClockSource::PtpSoftwareTimestamp
    } else if drift <= Duration::from_millis(50) {
        // NTP is the likely source when we see small but nonzero drift.
        ClockSource::Ntp
    } else {
        ClockSource::MonotonicOnly
    };

    let last_sync_unix_ns =
        (tx.time_sec as u64).saturating_mul(1_000_000_000) + tx.time_usec.max(0) as u64 * 1000;

    (source, drift, last_sync_unix_ns)
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        // On any Linux box (CI included) we at least get a non-panicking
        // probe. Content depends on environment.
        let p = LinuxPtpProbe::new().probe();
        // observed_at is always set to "now".
        assert!(p.observed_at.as_nanos() > 0);
    }

    #[test]
    fn fnv1a_is_stable() {
        assert_eq!(hash_name_fnv1a64(""), 0xcbf29ce484222325);
        // Two distinct strings produce distinct hashes; stability is the
        // important property for `reference_clock_id`.
        assert_ne!(
            hash_name_fnv1a64("eth0 timestamping"),
            hash_name_fnv1a64("eth1 timestamping")
        );
    }
}
