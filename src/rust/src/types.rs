/// Fixed-point decimal: i64 with 10^8 scaling factor.
/// Represents values with up to 8 decimal places.
/// Range: +/- 92,233,720,368.54775807
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Decimal(pub i64);

impl Decimal {
    pub const SCALE: i64 = 100_000_000; // 10^8
    pub const NULL: Self = Self(i64::MIN);
    pub const ZERO: Self = Self(0);

    #[inline(always)]
    pub fn from_fixed(value: i64) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn from_f64(value: f64) -> Self {
        Self((value * Self::SCALE as f64) as i64)
    }

    #[inline(always)]
    pub fn to_f64(self) -> f64 {
        self.0 as f64 / Self::SCALE as f64
    }

    #[inline(always)]
    pub fn is_null(self) -> bool {
        self.0 == i64::MIN
    }

    /// Create from integer and fractional parts.
    /// e.g., from_parts(123, 45_000_000) = 123.45
    #[inline]
    pub fn from_parts(integer: i64, frac: u32) -> Self {
        Self(integer * Self::SCALE + frac as i64)
    }
}

impl core::fmt::Debug for Decimal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_null() {
            write!(f, "NULL")
        } else {
            write!(f, "{}", self.to_f64())
        }
    }
}

impl core::fmt::Display for Decimal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_null() {
            write!(f, "NULL")
        } else {
            let abs = self.0.unsigned_abs();
            let integer = abs / Self::SCALE as u64;
            let frac = abs % Self::SCALE as u64;
            let sign = if self.0 < 0 { "-" } else { "" };
            write!(f, "{sign}{integer}.{frac:08}")
        }
    }
}

/// Nanosecond timestamp since Unix epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub const NULL: Self = Self(u64::MAX);

    /// Get current time as nanoseconds since Unix epoch.
    /// Uses clock_gettime(CLOCK_REALTIME) on Unix for production-grade precision.
    /// Falls back to SystemTime on non-Unix.
    #[inline(always)]
    pub fn now() -> Self {
        #[cfg(unix)]
        {
            Self(clock_gettime_realtime_ns())
        }
        #[cfg(not(unix))]
        {
            Self(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64)
        }
    }

    #[inline(always)]
    pub fn is_null(self) -> bool {
        self.0 == u64::MAX
    }

    #[inline(always)]
    pub fn as_nanos(self) -> u64 {
        self.0
    }

    /// Create from raw nanosecond value.
    #[inline(always)]
    pub fn from_nanos(ns: u64) -> Self {
        Self(ns)
    }
}

/// Production clock: clock_gettime(CLOCK_REALTIME) with nanosecond precision.
/// Single syscall, no allocation, no chrono/jiff dependency.
#[cfg(unix)]
#[inline(always)]
fn clock_gettime_realtime_ns() -> u64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    unsafe extern "C" {
        safe fn clock_gettime(clockid: i32, tp: *mut Timespec) -> i32;
    }

    const CLOCK_REALTIME: i32 = 0;
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    clock_gettime(CLOCK_REALTIME, &mut ts);
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Side of an order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum Side {
    Buy = 1,
    Sell = 2,
}

impl Side {
    pub const NULL: u8 = 0xFF;

    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Buy),
            2 => Some(Self::Sell),
            _ => None,
        }
    }
}

/// Order type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum OrderType {
    Market = 1,
    Limit = 2,
    Stop = 3,
    StopLimit = 4,
}

impl OrderType {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Market),
            2 => Some(Self::Limit),
            3 => Some(Self::Stop),
            4 => Some(Self::StopLimit),
            _ => None,
        }
    }
}

/// Time in force.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TimeInForce {
    Day = 1,
    GTC = 2,
    IOC = 3,
    FOK = 4,
    GTD = 5,
}

impl TimeInForce {
    #[inline(always)]
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Day),
            2 => Some(Self::GTC),
            3 => Some(Self::IOC),
            4 => Some(Self::FOK),
            5 => Some(Self::GTD),
            _ => None,
        }
    }
}

/// Execution report type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ExecType {
    New = 0,
    PartialFill = 1,
    Fill = 2,
    Canceled = 4,
    Replaced = 5,
    Rejected = 8,
    Expired = 12,
}

impl ExecType {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::New),
            1 => Some(Self::PartialFill),
            2 => Some(Self::Fill),
            4 => Some(Self::Canceled),
            5 => Some(Self::Replaced),
            8 => Some(Self::Rejected),
            12 => Some(Self::Expired),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_roundtrip() {
        let d = Decimal::from_f64(123.456);
        assert!((d.to_f64() - 123.456).abs() < 1e-6);
    }

    #[test]
    fn decimal_display() {
        let d = Decimal::from_parts(100, 50_000_000);
        assert_eq!(d.to_string(), "100.50000000");
    }

    #[test]
    fn decimal_null() {
        assert!(Decimal::NULL.is_null());
        assert!(!Decimal::ZERO.is_null());
    }

    #[test]
    fn timestamp_not_null() {
        let ts = Timestamp::now();
        assert!(!ts.is_null());
    }
}
