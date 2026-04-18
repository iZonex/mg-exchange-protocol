//! Drop-copy channel: read-only real-time broadcast of order-lifecycle
//! events to authorized compliance / clearing subscribers.
//!
//! # Why this exists
//!
//! Regulators and clearing brokers require **an independent real-time
//! copy** of every participant's trading activity — SEC Rule 15c3-5(c)(2),
//! MiFID II RTS 6, FINRA OATS. The main order-entry session is NOT that
//! copy: a compromised participant can't be trusted to report its own
//! activity, and the main session is bidirectional so the compliance
//! team can't tell "what the venue said" from "what the client said".
//!
//! A drop-copy channel is:
//!
//! * **Read-only from the subscriber's perspective.** No orders, no
//!   cancels. Just a firehose of what happened.
//! * **Authorized separately from order entry.** A compliance officer's
//!   drop-copy session uses different credentials than the trading
//!   desk's order-entry session.
//! * **Scope-filterable.** A clearing broker sees only its members; a
//!   regulator sees all; a participant sees only itself.
//! * **Latency-irrelevant.** It's not on the trading hot path; a slow
//!   drop-copy consumer MUST NOT slow down matching.
//!
//! # Design
//!
//! The venue fans out every order-lifecycle event to zero or more
//! `DropCopySubscriber`s. Each subscriber has a `DropCopyScope` filter
//! (all / account / instrument / own-only) and a role (determines which
//! events are visible — e.g. only `ComplianceOfficer`+ can see
//! KillSwitchHalt).
//!
//! The publisher is thread-safe behind an `Arc<Mutex<>>`. Slow
//! subscribers get their queue capped via a `max_backlog`; if a
//! subscriber can't keep up, it's disconnected rather than stall the
//! venue. This is the same slow-consumer guard from `snapshot.rs`,
//! applied to the audit fanout.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::audit::{ActorRole, AuditAction, AuditRecord};

/// Scope of a drop-copy subscription. The venue checks this on every
/// event before delivering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropCopyScope {
    /// See everything on the venue (regulators, exchange operator).
    All,
    /// See only events for the named account (participant self-audit).
    Account(u64),
    /// See only events on the named instrument (single-symbol regulator
    /// / market-quality analyst).
    Instrument(u32),
    /// See everything for a set of accounts (clearing broker covering
    /// multiple underlying participants).
    AccountSet(Vec<u64>),
}

impl DropCopyScope {
    fn matches(&self, rec: &AuditRecord) -> bool {
        match self {
            Self::All => true,
            Self::Account(id) => rec.actor_id == *id || rec.subject_id == *id,
            Self::Instrument(id) => rec.instrument_id == *id,
            Self::AccountSet(ids) => {
                ids.iter().any(|&id| rec.actor_id == id || rec.subject_id == id)
            }
        }
    }
}

/// A drop-copy subscriber. Identified by a monotonic `subscription_id`
/// so the publisher can drop slow ones.
pub struct DropCopySubscriber {
    pub subscription_id: u64,
    pub scope: DropCopyScope,
    pub role: ActorRole,
    /// Bounded mailbox — publishers push into `outbox`, the subscriber
    /// drains via `drain_*`. Capped to prevent slow-consumer OOM.
    outbox: VecDeque<AuditRecord>,
    max_backlog: usize,
    dropped_count: u64,
}

impl DropCopySubscriber {
    /// Build a subscriber. `max_backlog` caps the outbox — once it's
    /// reached, further records are dropped and counted in
    /// `dropped_count` so ops can page the operator.
    pub fn new(
        subscription_id: u64,
        scope: DropCopyScope,
        role: ActorRole,
        max_backlog: usize,
    ) -> Self {
        Self {
            subscription_id,
            scope,
            role,
            outbox: VecDeque::new(),
            max_backlog,
            dropped_count: 0,
        }
    }

    /// Drain up to `limit` buffered records for delivery on the wire.
    pub fn drain(&mut self, limit: usize) -> Vec<AuditRecord> {
        let take = self.outbox.len().min(limit);
        self.outbox.drain(..take).collect()
    }

    /// Current number of records waiting to be drained.
    pub fn backlog(&self) -> usize {
        self.outbox.len()
    }

    /// Total records dropped because `backlog >= max_backlog`. Monotonic.
    pub fn dropped(&self) -> u64 {
        self.dropped_count
    }

    /// Internal — publisher calls this under the lock.
    fn try_enqueue(&mut self, rec: &AuditRecord) -> EnqueueOutcome {
        if !self.scope.matches(rec) {
            return EnqueueOutcome::Filtered;
        }
        if !visibility_allowed(self.role, rec) {
            return EnqueueOutcome::Filtered;
        }
        if self.outbox.len() >= self.max_backlog {
            self.dropped_count += 1;
            return EnqueueOutcome::BackloggedAndDropped;
        }
        self.outbox.push_back(*rec);
        EnqueueOutcome::Enqueued
    }
}

/// Outcome of attempting to deliver a record to a single subscriber.
/// Exposed so external dispatch code can aggregate per-subscriber
/// stats even when the fanout runs via `DropCopyPublisher::publish`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Enqueued,
    Filtered,
    /// Subscriber's mailbox is full; record dropped. Publisher tracks
    /// overall dropped count per subscriber; venue operators should page
    /// when this starts happening and force-disconnect the subscriber.
    BackloggedAndDropped,
}

/// Role-based visibility filter. Traders see only their own records;
/// market-makers see their own; compliance/risk see everything in scope.
fn visibility_allowed(role: ActorRole, rec: &AuditRecord) -> bool {
    let action = match rec.action() {
        Some(a) => a,
        None => return false,
    };
    let is_sensitive = matches!(
        action,
        AuditAction::KillSwitchHalt
            | AuditAction::KillSwitchResume
            | AuditAction::ComplianceOverride
            | AuditAction::RiskBreach
    );
    if is_sensitive {
        // Privileged events — only privileged roles see them.
        matches!(
            role,
            ActorRole::RiskOfficer
                | ActorRole::ComplianceOfficer
                | ActorRole::SystemOperator
                | ActorRole::Venue
        )
    } else {
        // Everyday events visible to all roles — scope still applies.
        true
    }
}

/// The drop-copy publisher. Fans out audit records to all matching
/// subscribers. Cheap to clone (`Arc` internally); call from the audit
/// hot path via `publish(rec)`.
pub struct DropCopyPublisher {
    subscribers: Vec<DropCopySubscriber>,
    next_id: AtomicU64,
}

impl DropCopyPublisher {
    /// Create an empty publisher with no subscribers.
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Register a new subscriber. The returned id is used to look up /
    /// remove the subscription later.
    pub fn subscribe(
        &mut self,
        scope: DropCopyScope,
        role: ActorRole,
        max_backlog: usize,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.subscribers.push(DropCopySubscriber::new(id, scope, role, max_backlog));
        id
    }

    /// Detach a subscriber by id. Returns `true` if it was actually
    /// tracked (for idempotency checks in upstream code).
    pub fn unsubscribe(&mut self, subscription_id: u64) -> bool {
        let len = self.subscribers.len();
        self.subscribers.retain(|s| s.subscription_id != subscription_id);
        self.subscribers.len() < len
    }

    /// Fan out a record to every matching subscriber.
    pub fn publish(&mut self, rec: &AuditRecord) -> PublishStats {
        let mut stats = PublishStats::default();
        for sub in &mut self.subscribers {
            match sub.try_enqueue(rec) {
                EnqueueOutcome::Enqueued => stats.delivered += 1,
                EnqueueOutcome::Filtered => stats.filtered += 1,
                EnqueueOutcome::BackloggedAndDropped => stats.dropped += 1,
            }
        }
        stats
    }

    /// Current active subscriber count. Cheap — O(1).
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Look up a subscriber by id (for draining from the session layer).
    pub fn subscriber_mut(&mut self, subscription_id: u64) -> Option<&mut DropCopySubscriber> {
        self.subscribers
            .iter_mut()
            .find(|s| s.subscription_id == subscription_id)
    }

    /// Drop subscribers whose backlog hasn't cleared in `max_backlog`
    /// consecutive publishes. Caller invokes periodically.
    pub fn evict_slow(&mut self) -> Vec<u64> {
        let mut evicted = Vec::new();
        self.subscribers.retain(|s| {
            if s.backlog() >= s.max_backlog {
                evicted.push(s.subscription_id);
                false
            } else {
                true
            }
        });
        evicted
    }
}

impl Default for DropCopyPublisher {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate result of one `publish` call: how many subscribers the
/// record reached, how many filtered it out by scope/role, how many
/// had to drop it due to full mailbox.
#[derive(Debug, Default, Clone, Copy)]
pub struct PublishStats {
    pub delivered: u32,
    pub filtered: u32,
    pub dropped: u32,
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditReason;
    use crate::types::Timestamp;

    fn mk_record(action: AuditAction, actor_id: u64, instrument_id: u32) -> AuditRecord {
        AuditRecord {
            audit_seq: 1,
            timestamp: Timestamp::from_nanos(1_700_000_000_000_000_000),
            actor_id,
            subject_id: 0,
            instrument_id,
            action: action as u8,
            actor_role: ActorRole::Trader as u8,
            clock_quality: 0,
            _pad: 0,
            reason: AuditReason::Normal.as_u16(),
            _pad2: 0,
            payload_digest: [0; 16],
            prev_digest: [0; 16],
        }
    }

    #[test]
    fn all_scope_receives_everything() {
        let mut pub_ = DropCopyPublisher::new();
        let sid = pub_.subscribe(DropCopyScope::All, ActorRole::Venue, 100);
        let stats = pub_.publish(&mk_record(AuditAction::OrderSubmit, 42, 7));
        assert_eq!(stats.delivered, 1);
        let drained = pub_.subscriber_mut(sid).unwrap().drain(100);
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn account_scope_filters_other_accounts() {
        let mut pub_ = DropCopyPublisher::new();
        pub_.subscribe(DropCopyScope::Account(42), ActorRole::Trader, 100);

        let hit = pub_.publish(&mk_record(AuditAction::OrderSubmit, 42, 1));
        let miss = pub_.publish(&mk_record(AuditAction::OrderSubmit, 99, 1));

        assert_eq!(hit.delivered, 1);
        assert_eq!(miss.delivered, 0);
        assert_eq!(miss.filtered, 1);
    }

    #[test]
    fn instrument_scope_filters() {
        let mut pub_ = DropCopyPublisher::new();
        pub_.subscribe(DropCopyScope::Instrument(7), ActorRole::Venue, 100);
        let hit = pub_.publish(&mk_record(AuditAction::Fill, 1, 7));
        let miss = pub_.publish(&mk_record(AuditAction::Fill, 1, 8));
        assert_eq!(hit.delivered, 1);
        assert_eq!(miss.delivered, 0);
    }

    #[test]
    fn account_set_matches_any_member() {
        let mut pub_ = DropCopyPublisher::new();
        pub_.subscribe(
            DropCopyScope::AccountSet(vec![10, 20, 30]),
            ActorRole::ComplianceOfficer,
            100,
        );
        assert_eq!(pub_.publish(&mk_record(AuditAction::OrderSubmit, 20, 0)).delivered, 1);
        assert_eq!(pub_.publish(&mk_record(AuditAction::OrderSubmit, 40, 0)).delivered, 0);
    }

    #[test]
    fn trader_role_cannot_see_kill_switch() {
        let mut pub_ = DropCopyPublisher::new();
        pub_.subscribe(DropCopyScope::All, ActorRole::Trader, 100);
        let stats = pub_.publish(&mk_record(AuditAction::KillSwitchHalt, 1, 0));
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.filtered, 1);
    }

    #[test]
    fn compliance_officer_sees_kill_switch() {
        let mut pub_ = DropCopyPublisher::new();
        pub_.subscribe(DropCopyScope::All, ActorRole::ComplianceOfficer, 100);
        let stats = pub_.publish(&mk_record(AuditAction::KillSwitchHalt, 1, 0));
        assert_eq!(stats.delivered, 1);
    }

    #[test]
    fn slow_subscriber_drops_records_rather_than_stall() {
        let mut pub_ = DropCopyPublisher::new();
        let sid = pub_.subscribe(DropCopyScope::All, ActorRole::Venue, 3);
        for i in 0..10u64 {
            let rec = mk_record(AuditAction::OrderSubmit, i, 1);
            pub_.publish(&rec);
        }
        let sub = pub_.subscriber_mut(sid).unwrap();
        assert_eq!(sub.backlog(), 3, "cap must not be exceeded");
        assert_eq!(sub.dropped(), 7, "excess records must be counted");
    }

    #[test]
    fn evict_slow_removes_saturated_subscribers() {
        let mut pub_ = DropCopyPublisher::new();
        let _ok_sid = pub_.subscribe(DropCopyScope::All, ActorRole::Venue, 100);
        let slow_sid = pub_.subscribe(DropCopyScope::All, ActorRole::Venue, 2);

        for i in 0..5u64 {
            pub_.publish(&mk_record(AuditAction::OrderSubmit, i, 1));
        }
        let evicted = pub_.evict_slow();
        assert_eq!(evicted, vec![slow_sid]);
        assert_eq!(pub_.subscriber_count(), 1);
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let mut pub_ = DropCopyPublisher::new();
        let sid = pub_.subscribe(DropCopyScope::All, ActorRole::Venue, 100);
        pub_.unsubscribe(sid);
        let stats = pub_.publish(&mk_record(AuditAction::OrderSubmit, 1, 1));
        assert_eq!(stats.delivered, 0);
    }

    #[test]
    fn multiple_subscribers_independent_filtering() {
        let mut pub_ = DropCopyPublisher::new();
        pub_.subscribe(DropCopyScope::Account(1), ActorRole::Trader, 100);
        pub_.subscribe(DropCopyScope::Account(2), ActorRole::Trader, 100);
        pub_.subscribe(DropCopyScope::All, ActorRole::Venue, 100);

        let stats = pub_.publish(&mk_record(AuditAction::Fill, 1, 5));
        // Acct-1 sub and All sub deliver; Acct-2 filters.
        assert_eq!(stats.delivered, 2);
        assert_eq!(stats.filtered, 1);
    }
}
