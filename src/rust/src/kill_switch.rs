//! Kill-switch: halt market / instrument / account with an auditable trail.
//!
//! # Why this exists
//!
//! Every real exchange has a red button. MGEP needed three:
//!
//! * **Market-wide halt** — stop ALL new orders and cancels across the venue
//!   (e.g. circuit-breaker tripped, infrastructure incident).
//! * **Instrument halt** — halt a single symbol (pending-news, LULD).
//! * **Account halt** — suspend a single participant (risk breach,
//!   compliance lock).
//! * **Session halt** — cut a single session loose without halting the
//!   account as a whole (operational — e.g. an algo went wild).
//!
//! Before this module there was no way to express halts on the wire, no
//! authz gate around who could trip them, and no audit tie-in. All three
//! are addressed here.
//!
//! Integration: the matching engine consults [`KillSwitchState::gate_order`]
//! before accepting any submission / cancel / replace; the session layer
//! emits a `MarketHaltNotification` broadcast; every halt/resume goes
//! through the [`crate::audit::AuditGate`] so regulators can reconstruct
//! the timeline.

use std::collections::HashMap;

use crate::audit::{ActorRole, AuditError};

// ─── Scopes ──────────────────────────────────────────────────

/// What a halt applies to. Halts compose additively: a halt at any level
/// blocks the affected order, strictest-first for clarity in audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillSwitchScope {
    MarketWide,
    Instrument(u32),
    Account(u64),
    Session(u64),
}

impl KillSwitchScope {
    /// Tight stable code suitable for a `BusinessReject.business_reason`
    /// field — helps the client back off with the right granularity.
    pub fn as_reject_code(&self) -> String {
        match self {
            Self::MarketWide => "halt:market".into(),
            Self::Instrument(id) => format!("halt:instrument:{}", id),
            Self::Account(id) => format!("halt:account:{}", id),
            Self::Session(id) => format!("halt:session:{}", id),
        }
    }
}

/// Why the halt was tripped. Distinct from [`crate::audit::AuditReason`]
/// because halts have their own vocabulary (regulators categorize these).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HaltReason {
    /// Venue-initiated circuit breaker (price move, volume spike).
    CircuitBreaker = 1,
    /// Regulator-requested halt (news-pending, investigation).
    RegulatoryHalt = 2,
    /// Operational incident (infra issue, matching-engine anomaly).
    OperationalIncident = 3,
    /// Risk-officer action (participant risk breach).
    RiskAction = 4,
    /// Scheduled halt (auction, market close).
    Scheduled = 5,
    /// Test / drill (should never appear in production logs).
    Drill = 6,
    VenueDefined = 255,
}

impl HaltReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::CircuitBreaker),
            2 => Some(Self::RegulatoryHalt),
            3 => Some(Self::OperationalIncident),
            4 => Some(Self::RiskAction),
            5 => Some(Self::Scheduled),
            6 => Some(Self::Drill),
            255 => Some(Self::VenueDefined),
            _ => None,
        }
    }
}

// ─── State ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // `actor_id` / `epoch` surfaced via broadcast (#15 wiring).
struct HaltEntry {
    reason: HaltReason,
    actor_id: u64,
    actor_role: ActorRole,
    /// Monotonic counter — lets audit records pair halts with resumes even
    /// when the same scope is halted + resumed + halted again.
    epoch: u64,
}

/// Why an order was blocked. Returned by [`KillSwitchState::gate_order`].
/// The most specific match wins (Session before Account before Instrument
/// before Market).
#[derive(Debug, Clone, Copy)]
pub struct HaltedBy {
    pub scope: KillSwitchScope,
    pub reason: HaltReason,
    pub actor_role: ActorRole,
}

/// The kill-switch registry. Owns the set of active halts; pure state, no
/// I/O. The server pairs this with `AuditGate` to record transitions.
pub struct KillSwitchState {
    halts: HashMap<KillSwitchScope, HaltEntry>,
    next_epoch: u64,
}

impl KillSwitchState {
    pub fn new() -> Self {
        Self { halts: HashMap::new(), next_epoch: 1 }
    }

    /// Install a halt. Returns the assigned epoch.
    ///
    /// Authz: non-privileged roles get an `Unauthorized` error up front so
    /// callers can't even attempt to halt on behalf of a trader. The
    /// `AuditGate` will apply the same check again at record time — double
    /// gate on purpose; defense in depth.
    pub fn halt(
        &mut self,
        scope: KillSwitchScope,
        reason: HaltReason,
        actor_id: u64,
        actor_role: ActorRole,
    ) -> Result<u64, AuditError> {
        if !actor_role.can_halt_market() {
            return Err(AuditError::Unauthorized {
                actor_role,
                required: "kill_switch_halt",
            });
        }
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.halts.insert(
            scope,
            HaltEntry { reason, actor_id, actor_role, epoch },
        );
        Ok(epoch)
    }

    /// Resume a halted scope. Returns `true` if a halt was actually lifted.
    pub fn resume(
        &mut self,
        scope: KillSwitchScope,
        actor_role: ActorRole,
    ) -> Result<bool, AuditError> {
        if !actor_role.can_halt_market() {
            return Err(AuditError::Unauthorized {
                actor_role,
                required: "kill_switch_resume",
            });
        }
        Ok(self.halts.remove(&scope).is_some())
    }

    pub fn is_halted(&self, scope: KillSwitchScope) -> bool {
        self.halts.contains_key(&scope)
    }

    /// Check whether an order for `(account_id, instrument_id, session_id)`
    /// can be accepted. Checks scopes in order of specificity so audit
    /// records attribute rejection to the tightest applicable halt.
    pub fn gate_order(
        &self,
        session_id: u64,
        account_id: u64,
        instrument_id: u32,
    ) -> Option<HaltedBy> {
        let scopes = [
            KillSwitchScope::Session(session_id),
            KillSwitchScope::Account(account_id),
            KillSwitchScope::Instrument(instrument_id),
            KillSwitchScope::MarketWide,
        ];
        for scope in scopes {
            if let Some(entry) = self.halts.get(&scope) {
                return Some(HaltedBy {
                    scope,
                    reason: entry.reason,
                    actor_role: entry.actor_role,
                });
            }
        }
        None
    }

    /// All active halts — used for periodic broadcast of
    /// `MarketHaltNotification` so late-joining clients see current state.
    pub fn active(&self) -> impl Iterator<Item = (&KillSwitchScope, HaltReason)> + '_ {
        self.halts.iter().map(|(s, e)| (s, e.reason))
    }

    pub fn active_count(&self) -> usize {
        self.halts.len()
    }
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halt_and_resume_roundtrip() {
        let mut ks = KillSwitchState::new();
        let epoch = ks
            .halt(
                KillSwitchScope::MarketWide,
                HaltReason::CircuitBreaker,
                1,
                ActorRole::RiskOfficer,
            )
            .unwrap();
        assert_eq!(epoch, 1);
        assert!(ks.is_halted(KillSwitchScope::MarketWide));

        let resumed = ks.resume(KillSwitchScope::MarketWide, ActorRole::RiskOfficer).unwrap();
        assert!(resumed);
        assert!(!ks.is_halted(KillSwitchScope::MarketWide));

        // Resuming again — no-op, returns false.
        let again = ks.resume(KillSwitchScope::MarketWide, ActorRole::RiskOfficer).unwrap();
        assert!(!again);
    }

    #[test]
    fn trader_cannot_halt() {
        let mut ks = KillSwitchState::new();
        let err = ks
            .halt(
                KillSwitchScope::MarketWide,
                HaltReason::CircuitBreaker,
                7,
                ActorRole::Trader,
            )
            .unwrap_err();
        assert!(matches!(err, AuditError::Unauthorized { .. }));
    }

    #[test]
    fn gate_order_picks_most_specific_scope() {
        let mut ks = KillSwitchState::new();
        ks.halt(
            KillSwitchScope::MarketWide,
            HaltReason::OperationalIncident,
            1,
            ActorRole::Venue,
        )
        .unwrap();
        ks.halt(
            KillSwitchScope::Instrument(42),
            HaltReason::CircuitBreaker,
            1,
            ActorRole::Venue,
        )
        .unwrap();
        ks.halt(
            KillSwitchScope::Account(100),
            HaltReason::RiskAction,
            1,
            ActorRole::RiskOfficer,
        )
        .unwrap();

        // Order for account=100 on instrument=42 — three halts apply; the
        // most specific (Account) should be attributed.
        let halted = ks.gate_order(999, 100, 42).unwrap();
        match halted.scope {
            KillSwitchScope::Account(100) => {}
            other => panic!("expected Account, got {:?}", other),
        }
        assert_eq!(halted.reason, HaltReason::RiskAction);

        // Different account — Instrument halt still applies.
        let halted = ks.gate_order(999, 200, 42).unwrap();
        assert!(matches!(halted.scope, KillSwitchScope::Instrument(42)));

        // Different account + instrument — falls through to MarketWide.
        let halted = ks.gate_order(999, 200, 7).unwrap();
        assert_eq!(halted.scope, KillSwitchScope::MarketWide);
    }

    #[test]
    fn session_halt_beats_account_halt() {
        let mut ks = KillSwitchState::new();
        ks.halt(
            KillSwitchScope::Account(100),
            HaltReason::RiskAction,
            1,
            ActorRole::RiskOfficer,
        )
        .unwrap();
        ks.halt(
            KillSwitchScope::Session(555),
            HaltReason::OperationalIncident,
            1,
            ActorRole::SystemOperator,
        )
        .unwrap();

        // Session=555, Account=100: Session wins.
        let halted = ks.gate_order(555, 100, 42).unwrap();
        assert_eq!(halted.scope, KillSwitchScope::Session(555));
    }

    #[test]
    fn gate_order_unhalted_returns_none() {
        let ks = KillSwitchState::new();
        assert!(ks.gate_order(1, 2, 3).is_none());
    }

    #[test]
    fn reject_codes_are_stable() {
        assert_eq!(
            KillSwitchScope::MarketWide.as_reject_code(),
            "halt:market"
        );
        assert_eq!(
            KillSwitchScope::Instrument(42).as_reject_code(),
            "halt:instrument:42"
        );
        assert_eq!(
            KillSwitchScope::Account(100).as_reject_code(),
            "halt:account:100"
        );
        assert_eq!(
            KillSwitchScope::Session(555).as_reject_code(),
            "halt:session:555"
        );
    }

    #[test]
    fn active_enumerates_all() {
        let mut ks = KillSwitchState::new();
        ks.halt(KillSwitchScope::MarketWide, HaltReason::CircuitBreaker, 1, ActorRole::Venue).unwrap();
        ks.halt(KillSwitchScope::Instrument(7), HaltReason::Scheduled, 1, ActorRole::Venue).unwrap();
        assert_eq!(ks.active_count(), 2);

        let scopes: Vec<_> = ks.active().map(|(s, _)| *s).collect();
        assert!(scopes.contains(&KillSwitchScope::MarketWide));
        assert!(scopes.contains(&KillSwitchScope::Instrument(7)));
    }

    #[test]
    fn halt_reason_roundtrip() {
        for reason in [
            HaltReason::CircuitBreaker,
            HaltReason::RegulatoryHalt,
            HaltReason::OperationalIncident,
            HaltReason::RiskAction,
            HaltReason::Scheduled,
            HaltReason::Drill,
            HaltReason::VenueDefined,
        ] {
            let byte = reason as u8;
            assert_eq!(HaltReason::from_u8(byte), Some(reason));
        }
        assert_eq!(HaltReason::from_u8(99), None);
    }
}
