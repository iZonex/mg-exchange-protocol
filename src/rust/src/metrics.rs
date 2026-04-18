//! Built-in Metrics — latency, throughput, and error counters.
//!
//! Lock-free atomic counters. Zero overhead when not read.
//! Aeron-style: counters are always running, you just read them when needed.
//!
//!   let metrics = Metrics::new();
//!   // ... on each message:
//!   metrics.record_send(msg.len());
//!   metrics.record_latency_ns(end - start);
//!   // ... periodic report:
//!   println!("{}", metrics.snapshot());

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic metrics counters — thread-safe, lock-free.
pub struct Metrics {
    // Message counters
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,

    // Error counters
    pub decode_errors: AtomicU64,
    pub auth_errors: AtomicU64,
    pub connection_resets: AtomicU64,
    pub retransmit_requests: AtomicU64,
    pub sequence_gaps: AtomicU64,

    // Latency tracking (nanoseconds)
    pub latency_sum_ns: AtomicU64,
    pub latency_count: AtomicU64,
    pub latency_min_ns: AtomicU64,
    pub latency_max_ns: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            decode_errors: AtomicU64::new(0),
            auth_errors: AtomicU64::new(0),
            connection_resets: AtomicU64::new(0),
            retransmit_requests: AtomicU64::new(0),
            sequence_gaps: AtomicU64::new(0),
            latency_sum_ns: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_min_ns: AtomicU64::new(u64::MAX),
            latency_max_ns: AtomicU64::new(0),
        }
    }

    /// Record a sent message.
    #[inline(always)]
    pub fn record_send(&self, bytes: usize) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a received message.
    #[inline(always)]
    pub fn record_recv(&self, bytes: usize) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a latency measurement in nanoseconds.
    #[inline(always)]
    pub fn record_latency_ns(&self, ns: u64) {
        self.latency_sum_ns.fetch_add(ns, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        // Update min (CAS loop)
        let mut current = self.latency_min_ns.load(Ordering::Relaxed);
        while ns < current {
            match self.latency_min_ns.compare_exchange_weak(current, ns, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        // Update max
        let mut current = self.latency_max_ns.load(Ordering::Relaxed);
        while ns > current {
            match self.latency_max_ns.compare_exchange_weak(current, ns, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    #[inline(always)]
    pub fn record_decode_error(&self) { self.decode_errors.fetch_add(1, Ordering::Relaxed); }
    #[inline(always)]
    pub fn record_auth_error(&self) { self.auth_errors.fetch_add(1, Ordering::Relaxed); }
    #[inline(always)]
    pub fn record_connection_reset(&self) { self.connection_resets.fetch_add(1, Ordering::Relaxed); }
    #[inline(always)]
    pub fn record_retransmit_request(&self) { self.retransmit_requests.fetch_add(1, Ordering::Relaxed); }
    #[inline(always)]
    pub fn record_sequence_gap(&self) { self.sequence_gaps.fetch_add(1, Ordering::Relaxed); }

    /// Take a point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let count = self.latency_count.load(Ordering::Relaxed);
        let sum = self.latency_sum_ns.load(Ordering::Relaxed);
        let min = self.latency_min_ns.load(Ordering::Relaxed);
        let max = self.latency_max_ns.load(Ordering::Relaxed);

        MetricsSnapshot {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            auth_errors: self.auth_errors.load(Ordering::Relaxed),
            connection_resets: self.connection_resets.load(Ordering::Relaxed),
            retransmit_requests: self.retransmit_requests.load(Ordering::Relaxed),
            sequence_gaps: self.sequence_gaps.load(Ordering::Relaxed),
            latency_avg_ns: if count > 0 { sum / count } else { 0 },
            latency_min_ns: if min == u64::MAX { 0 } else { min },
            latency_max_ns: max,
            latency_count: count,
        }
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.messages_sent.store(0, Ordering::Relaxed);
        self.messages_received.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.decode_errors.store(0, Ordering::Relaxed);
        self.auth_errors.store(0, Ordering::Relaxed);
        self.connection_resets.store(0, Ordering::Relaxed);
        self.retransmit_requests.store(0, Ordering::Relaxed);
        self.sequence_gaps.store(0, Ordering::Relaxed);
        self.latency_sum_ns.store(0, Ordering::Relaxed);
        self.latency_count.store(0, Ordering::Relaxed);
        self.latency_min_ns.store(u64::MAX, Ordering::Relaxed);
        self.latency_max_ns.store(0, Ordering::Relaxed);
    }
}

/// Point-in-time snapshot of metrics.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub decode_errors: u64,
    pub auth_errors: u64,
    pub connection_resets: u64,
    pub retransmit_requests: u64,
    pub sequence_gaps: u64,
    pub latency_avg_ns: u64,
    pub latency_min_ns: u64,
    pub latency_max_ns: u64,
    pub latency_count: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "MGEP Metrics:")?;
        writeln!(f, "  Messages: sent={} recv={}", self.messages_sent, self.messages_received)?;
        writeln!(f, "  Bytes:    sent={} recv={}", self.bytes_sent, self.bytes_received)?;
        if self.latency_count > 0 {
            writeln!(f, "  Latency:  avg={}ns min={}ns max={}ns (n={})",
                self.latency_avg_ns, self.latency_min_ns, self.latency_max_ns, self.latency_count)?;
        }
        if self.decode_errors > 0 || self.auth_errors > 0 || self.connection_resets > 0 {
            writeln!(f, "  Errors:   decode={} auth={} resets={} gaps={} retransmit={}",
                self.decode_errors, self.auth_errors, self.connection_resets,
                self.sequence_gaps, self.retransmit_requests)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_basic() {
        let m = Metrics::new();
        m.record_send(64);
        m.record_send(80);
        m.record_recv(64);

        let snap = m.snapshot();
        assert_eq!(snap.messages_sent, 2);
        assert_eq!(snap.bytes_sent, 144);
        assert_eq!(snap.messages_received, 1);
    }

    #[test]
    fn metrics_latency() {
        let m = Metrics::new();
        m.record_latency_ns(100);
        m.record_latency_ns(200);
        m.record_latency_ns(50);

        let snap = m.snapshot();
        assert_eq!(snap.latency_min_ns, 50);
        assert_eq!(snap.latency_max_ns, 200);
        assert_eq!(snap.latency_avg_ns, 116); // (100+200+50)/3 = 116
        assert_eq!(snap.latency_count, 3);
    }

    #[test]
    fn metrics_thread_safe() {
        let m = std::sync::Arc::new(Metrics::new());
        let mut handles = Vec::new();

        for _ in 0..4 {
            let m = m.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    m.record_send(64);
                    m.record_latency_ns(100);
                }
            }));
        }

        for h in handles { h.join().unwrap(); }

        let snap = m.snapshot();
        assert_eq!(snap.messages_sent, 4000);
        assert_eq!(snap.latency_count, 4000);
    }

    #[test]
    fn metrics_reset() {
        let m = Metrics::new();
        m.record_send(64);
        m.record_decode_error();
        m.reset();

        let snap = m.snapshot();
        assert_eq!(snap.messages_sent, 0);
        assert_eq!(snap.decode_errors, 0);
    }

    #[test]
    fn metrics_display() {
        let m = Metrics::new();
        m.record_send(64);
        m.record_recv(80);
        m.record_latency_ns(1500);
        let output = format!("{}", m.snapshot());
        assert!(output.contains("sent=1"));
        assert!(output.contains("recv=1"));
        assert!(output.contains("1500ns"));
    }
}
