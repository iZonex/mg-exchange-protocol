//! Market-data entitlement framework.
//!
//! # Why this exists
//!
//! Exchanges sell data. Different participants pay for different views:
//! top-of-book retail feeds, full-depth pro feeds, conflated delayed
//! feeds, single-symbol feeds, etc. Without an entitlement layer, every
//! subscriber gets everything — which is either a revenue leak (paid
//! data given away) or a regulatory problem (non-pro users seeing
//! non-display feeds they're not authorized for).
//!
//! This module owns the subscription-time authorization:
//!
//! * `EntitlementGrant` — a signed (conceptually) permission from the
//!   billing backend: who, what symbols, what depth, what conflation,
//!   valid until when.
//! * `EntitlementRegistry` — the venue's in-process cache of active
//!   grants. Queried on every subscribe; revoked on billing callback.
//! * `EntitlementGate` — the decision function: `check(account, sub) ->
//!   Result<(), EntitlementError>`.
//!
//! Integration:
//!
//! * `server.rs` consults the gate before accepting `Subscribe` messages.
//! * `snapshot_provider` consults the gate before building a snapshot.
//! * `audit.rs` records every grant / revoke for compliance.
//!
//! This module is pure logic. The billing backend is a separate concern
//! — it feeds grants in via `EntitlementRegistry::insert` and pushes
//! revocations via `remove`.

use std::collections::HashMap;
use std::time::Instant;
#[cfg(test)]
use std::time::Duration;

// ─── Feed descriptors ────────────────────────────────────────

/// Levels of depth a subscription can be authorized for. Ordered —
/// `FullDepth` implies `TopOfBook`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
/// Tier of market-depth access. Ordered: `FullDepth` implies
/// `Depth10` implies `TopOfBook`.
pub enum DepthTier {
    /// Best bid + best ask only (retail, non-pro).
    TopOfBook = 1,
    /// First 10 price levels each side (semi-pro).
    Depth10 = 2,
    /// Full book (pro, institutional).
    FullDepth = 3,
}

impl DepthTier {
    /// Parse a stable u8 encoding back to the enum.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::TopOfBook),
            2 => Some(Self::Depth10),
            3 => Some(Self::FullDepth),
            _ => None,
        }
    }
}

/// Real-time / conflated / delayed. Lower numeric value = stricter
/// latency requirement (RealTime < Conflated < Delayed). A grant for a
/// delayed feed does not cover a real-time request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FeedLatencyTier {
    /// Unrestricted, submillisecond.
    RealTime = 1,
    /// Aggregated over a fixed interval (e.g. 100 ms snapshots).
    Conflated = 2,
    /// 15-minute delayed (retail free tier).
    Delayed = 3,
}

/// What exactly a grant covers.
#[derive(Debug, Clone)]
pub struct EntitlementFeed {
    /// `None` = all instruments (used for broad pro grants).
    pub instruments: Option<Vec<u32>>,
    pub depth: DepthTier,
    pub latency: FeedLatencyTier,
    /// Trades-only visibility; no depth updates.
    pub trades_only: bool,
}

// ─── Grant ───────────────────────────────────────────────────

/// A single authorization. Equivalent to a short-lived JWT:
/// `expires_at` is checked on every subscribe.
#[derive(Debug, Clone)]
pub struct EntitlementGrant {
    pub grant_id: u64,
    pub account_id: u64,
    pub feed: EntitlementFeed,
    pub expires_at: Instant,
    /// Monotonic counter. On revoke, the version bumps so
    /// already-subscribed sessions can be paged off.
    pub version: u32,
}

/// Why a subscription request was denied. Each variant maps 1:1 to a
/// `SubscribeResponse.reject_reason` text so the client knows which
/// knob to ask billing to turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementError {
    NoGrantForAccount { account_id: u64 },
    InstrumentNotCovered { instrument_id: u32 },
    DepthExceedsGrant { requested: DepthTier, granted: DepthTier },
    LatencyExceedsGrant { requested: FeedLatencyTier, granted: FeedLatencyTier },
    GrantExpired { grant_id: u64 },
    TradesOnlyGrant { asked_for_depth: bool },
}

impl EntitlementError {
    /// Stable machine-readable code suitable for placing in a
    /// `BusinessReject` flex text field. Clients pivot UI on these.
    pub fn as_code(&self) -> String {
        match self {
            Self::NoGrantForAccount { .. } => "entitlement:no_grant".into(),
            Self::InstrumentNotCovered { instrument_id } => {
                format!("entitlement:instrument_not_covered:{}", instrument_id)
            }
            Self::DepthExceedsGrant { .. } => "entitlement:depth_exceeds".into(),
            Self::LatencyExceedsGrant { .. } => "entitlement:latency_exceeds".into(),
            Self::GrantExpired { grant_id } => format!("entitlement:expired:{}", grant_id),
            Self::TradesOnlyGrant { .. } => "entitlement:trades_only".into(),
        }
    }
}

// ─── Request descriptor ──────────────────────────────────────

/// The subscription request an inbound client is trying to make.
/// Evaluated against the account's active grants by
/// [`EntitlementRegistry::check`].
#[derive(Debug, Clone, Copy)]
pub struct SubscribeRequest {
    pub instrument_id: u32,
    pub depth: DepthTier,
    pub latency: FeedLatencyTier,
    pub wants_depth_updates: bool,
}

// ─── Registry ────────────────────────────────────────────────

/// In-process registry of active entitlement grants. Populated by the
/// billing/auth system at session creation and on lifecycle events
/// (grant issued / revoked). Every `Subscribe` request consults this.
pub struct EntitlementRegistry {
    /// Primary: grants keyed by `grant_id`.
    grants: HashMap<u64, EntitlementGrant>,
    /// Secondary: which grants belong to which account (multi-grant
    /// accounts are common — pro on equities + delayed on options).
    by_account: HashMap<u64, Vec<u64>>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl EntitlementRegistry {
    /// Construct an empty registry using `Instant::now` as the clock.
    pub fn new() -> Self {
        Self {
            grants: HashMap::new(),
            by_account: HashMap::new(),
            now: Box::new(Instant::now),
        }
    }

    /// Replace the clock source — intended for deterministic tests.
    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> Instant + Send + Sync + 'static,
    {
        self.now = Box::new(clock);
        self
    }

    /// Install or replace a grant. Billing pushes grants here after
    /// payment clears; idempotent on `grant_id`.
    pub fn insert(&mut self, grant: EntitlementGrant) {
        let account = grant.account_id;
        let gid = grant.grant_id;
        self.grants.insert(gid, grant);
        let list = self.by_account.entry(account).or_default();
        if !list.contains(&gid) {
            list.push(gid);
        }
    }

    /// Remove a grant (billing callback on cancel / chargeback).
    /// Sessions already subscribed should be paged off by the caller.
    pub fn remove(&mut self, grant_id: u64) -> Option<EntitlementGrant> {
        let g = self.grants.remove(&grant_id)?;
        if let Some(list) = self.by_account.get_mut(&g.account_id) {
            list.retain(|&id| id != grant_id);
        }
        Some(g)
    }

    /// Check whether `account_id` is authorized for `req`. Returns the
    /// matching grant on success (caller stashes it on the subscription
    /// for re-auth on every delivered message).
    pub fn check(
        &self,
        account_id: u64,
        req: &SubscribeRequest,
    ) -> Result<&EntitlementGrant, EntitlementError> {
        let grant_ids = self
            .by_account
            .get(&account_id)
            .ok_or(EntitlementError::NoGrantForAccount { account_id })?;

        if grant_ids.is_empty() {
            return Err(EntitlementError::NoGrantForAccount { account_id });
        }

        let now = (self.now)();

        // Walk the account's grants and return the first one that
        // covers the request. Grants are additive — a pro grant on
        // equities plus a delayed grant on options is normal.
        let mut last_err = EntitlementError::NoGrantForAccount { account_id };
        for gid in grant_ids {
            let grant = match self.grants.get(gid) {
                Some(g) => g,
                None => continue,
            };

            if grant.expires_at <= now {
                last_err = EntitlementError::GrantExpired { grant_id: grant.grant_id };
                continue;
            }

            if let Some(ref list) = grant.feed.instruments
                && !list.contains(&req.instrument_id) {
                    last_err = EntitlementError::InstrumentNotCovered {
                        instrument_id: req.instrument_id,
                    };
                    continue;
                }

            if grant.feed.trades_only && req.wants_depth_updates {
                last_err = EntitlementError::TradesOnlyGrant {
                    asked_for_depth: true,
                };
                continue;
            }

            if req.depth > grant.feed.depth {
                last_err = EntitlementError::DepthExceedsGrant {
                    requested: req.depth,
                    granted: grant.feed.depth,
                };
                continue;
            }

            // Latency: lower-numbered = stricter (RealTime < Conflated < Delayed).
            // A grant for Delayed does NOT cover a RealTime request.
            if (req.latency as u8) < (grant.feed.latency as u8) {
                last_err = EntitlementError::LatencyExceedsGrant {
                    requested: req.latency,
                    granted: grant.feed.latency,
                };
                continue;
            }

            return Ok(grant);
        }

        Err(last_err)
    }

    /// Evict expired grants. Return their ids for audit logging.
    pub fn evict_expired(&mut self) -> Vec<u64> {
        let now = (self.now)();
        let expired: Vec<u64> = self
            .grants
            .iter()
            .filter_map(|(id, g)| if g.expires_at <= now { Some(*id) } else { None })
            .collect();
        for id in &expired {
            self.remove(*id);
        }
        expired
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }
}

impl Default for EntitlementRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn mock_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync + 'static) {
        let anchor = Arc::new(Mutex::new(Instant::now()));
        let c = anchor.clone();
        (anchor, move || *c.lock().unwrap())
    }

    fn grant(id: u64, account: u64, depth: DepthTier, latency: FeedLatencyTier, instruments: Option<Vec<u32>>) -> EntitlementGrant {
        EntitlementGrant {
            grant_id: id,
            account_id: account,
            feed: EntitlementFeed {
                instruments,
                depth,
                latency,
                trades_only: false,
            },
            expires_at: Instant::now() + Duration::from_secs(3600),
            version: 1,
        }
    }

    fn req(instrument: u32, depth: DepthTier, latency: FeedLatencyTier, want_depth: bool) -> SubscribeRequest {
        SubscribeRequest {
            instrument_id: instrument,
            depth,
            latency,
            wants_depth_updates: want_depth,
        }
    }

    #[test]
    fn no_grant_rejects() {
        let reg = EntitlementRegistry::new();
        let err = reg.check(42, &req(1, DepthTier::TopOfBook, FeedLatencyTier::RealTime, true)).unwrap_err();
        assert!(matches!(err, EntitlementError::NoGrantForAccount { account_id: 42 }));
    }

    #[test]
    fn top_of_book_grant_blocks_full_depth_request() {
        let mut reg = EntitlementRegistry::new();
        reg.insert(grant(1, 10, DepthTier::TopOfBook, FeedLatencyTier::RealTime, None));
        let err = reg.check(10, &req(1, DepthTier::FullDepth, FeedLatencyTier::RealTime, true)).unwrap_err();
        assert!(matches!(err, EntitlementError::DepthExceedsGrant { requested: DepthTier::FullDepth, granted: DepthTier::TopOfBook }));
    }

    #[test]
    fn instrument_filter_is_authoritative() {
        let mut reg = EntitlementRegistry::new();
        reg.insert(grant(1, 10, DepthTier::FullDepth, FeedLatencyTier::RealTime, Some(vec![42, 99])));
        assert!(reg.check(10, &req(42, DepthTier::FullDepth, FeedLatencyTier::RealTime, true)).is_ok());
        let err = reg.check(10, &req(1, DepthTier::FullDepth, FeedLatencyTier::RealTime, true)).unwrap_err();
        assert!(matches!(err, EntitlementError::InstrumentNotCovered { instrument_id: 1 }));
    }

    #[test]
    fn delayed_grant_cannot_access_realtime() {
        let mut reg = EntitlementRegistry::new();
        reg.insert(grant(1, 10, DepthTier::TopOfBook, FeedLatencyTier::Delayed, None));
        let err = reg.check(10, &req(1, DepthTier::TopOfBook, FeedLatencyTier::RealTime, false)).unwrap_err();
        assert!(matches!(err, EntitlementError::LatencyExceedsGrant { .. }));
        // A delayed request is fine though.
        assert!(reg.check(10, &req(1, DepthTier::TopOfBook, FeedLatencyTier::Delayed, false)).is_ok());
    }

    #[test]
    fn trades_only_blocks_depth_updates() {
        let mut g = grant(1, 10, DepthTier::FullDepth, FeedLatencyTier::RealTime, None);
        g.feed.trades_only = true;
        let mut reg = EntitlementRegistry::new();
        reg.insert(g);
        let err = reg.check(10, &req(1, DepthTier::TopOfBook, FeedLatencyTier::RealTime, true)).unwrap_err();
        assert!(matches!(err, EntitlementError::TradesOnlyGrant { .. }));
        // Trades only — no depth — is fine.
        assert!(reg.check(10, &req(1, DepthTier::TopOfBook, FeedLatencyTier::RealTime, false)).is_ok());
    }

    #[test]
    fn expired_grant_rejects_and_next_valid_grant_is_used() {
        let (clock, now_fn) = mock_clock();
        let mut reg = EntitlementRegistry::new().with_clock(now_fn);

        let mut expired = grant(1, 10, DepthTier::FullDepth, FeedLatencyTier::RealTime, None);
        let valid = grant(2, 10, DepthTier::TopOfBook, FeedLatencyTier::RealTime, None);
        expired.expires_at = *clock.lock().unwrap() + Duration::from_secs(1);
        reg.insert(expired);
        reg.insert(valid);

        // Advance past the first grant's expiry.
        *clock.lock().unwrap() += Duration::from_secs(10);

        // TopOfBook request still works via the second grant.
        assert!(reg.check(10, &req(1, DepthTier::TopOfBook, FeedLatencyTier::RealTime, false)).is_ok());
        // FullDepth request fails because the only matching grant is expired.
        let err = reg.check(10, &req(1, DepthTier::FullDepth, FeedLatencyTier::RealTime, false)).unwrap_err();
        // Either GrantExpired or DepthExceedsGrant is acceptable (depends on iteration order).
        assert!(matches!(
            err,
            EntitlementError::GrantExpired { .. } | EntitlementError::DepthExceedsGrant { .. }
        ));
    }

    #[test]
    fn revoke_removes_grant_and_breaks_account_link() {
        let mut reg = EntitlementRegistry::new();
        reg.insert(grant(1, 10, DepthTier::FullDepth, FeedLatencyTier::RealTime, None));
        assert_eq!(reg.grant_count(), 1);
        assert!(reg.check(10, &req(1, DepthTier::FullDepth, FeedLatencyTier::RealTime, false)).is_ok());

        reg.remove(1);
        assert_eq!(reg.grant_count(), 0);
        let err = reg.check(10, &req(1, DepthTier::FullDepth, FeedLatencyTier::RealTime, false)).unwrap_err();
        assert!(matches!(err, EntitlementError::NoGrantForAccount { .. }));
    }

    #[test]
    fn multiple_grants_combine() {
        let mut reg = EntitlementRegistry::new();
        // Grant 1: FullDepth RT on instrument 42.
        reg.insert(grant(1, 10, DepthTier::FullDepth, FeedLatencyTier::RealTime, Some(vec![42])));
        // Grant 2: TopOfBook Delayed on instruments 99, 100.
        reg.insert(grant(2, 10, DepthTier::TopOfBook, FeedLatencyTier::Delayed, Some(vec![99, 100])));

        assert!(reg.check(10, &req(42, DepthTier::FullDepth, FeedLatencyTier::RealTime, true)).is_ok());
        assert!(reg.check(10, &req(99, DepthTier::TopOfBook, FeedLatencyTier::Delayed, false)).is_ok());

        // instrument 99 at FullDepth RT is NOT covered.
        assert!(reg.check(10, &req(99, DepthTier::FullDepth, FeedLatencyTier::RealTime, true)).is_err());
    }

    #[test]
    fn evict_expired_returns_evicted_ids() {
        let (clock, now_fn) = mock_clock();
        let mut reg = EntitlementRegistry::new().with_clock(now_fn);

        let mut short = grant(1, 10, DepthTier::TopOfBook, FeedLatencyTier::RealTime, None);
        short.expires_at = *clock.lock().unwrap() + Duration::from_millis(10);
        reg.insert(short);
        reg.insert(grant(2, 10, DepthTier::TopOfBook, FeedLatencyTier::RealTime, None));

        *clock.lock().unwrap() += Duration::from_secs(1);
        let evicted = reg.evict_expired();
        assert_eq!(evicted, vec![1]);
        assert_eq!(reg.grant_count(), 1);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            EntitlementError::NoGrantForAccount { account_id: 1 }.as_code(),
            "entitlement:no_grant"
        );
        assert_eq!(
            EntitlementError::InstrumentNotCovered { instrument_id: 42 }.as_code(),
            "entitlement:instrument_not_covered:42"
        );
    }
}
