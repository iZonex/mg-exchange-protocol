//! Rich, typed client-side errors over the wire reject stream.
//!
//! # Why this exists
//!
//! Every server-side reject eventually becomes a `BusinessReject` or
//! `OrderCancelReject` on the wire. The fields are stable but not
//! convenient — `business_reason: u8` plus a free-form `text` flex
//! field. Terminal vendors that pipe these into UI need typed errors
//! they can pattern-match:
//!
//! * Is this a retryable error (rate limit, transient network)?
//! * Should I show "Order rejected: market halted" with a pretty icon?
//! * Should I retry after a specific delay?
//!
//! This module parses the wire reject into a typed `ClientError`
//! enum that UI code can exhaustively match. It's decoupled from the
//! `Connection` — pass the raw BusinessReject bytes, get a `ClientError`.

use std::time::Duration;

use crate::flex::FlexReader;
use crate::header::CORE_BLOCK_OFFSET;
use crate::messages::{BusinessRejectCore, OrderCancelRejectCore};

/// Pretty, typed view of a server-side reject. UI code pattern-matches
/// on this instead of parsing reason codes and flex strings directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Rate limiter rejected the submission. UI should back off and
    /// retry — the dimension tells you how aggressively.
    RateLimited {
        dimension: RateLimitDim,
        /// Hint for retry backoff. Usually 1s for msgs, longer for bytes.
        suggested_retry: Duration,
    },
    /// Scope of the venue is halted; new orders blocked until resume.
    MarketHalted {
        scope: HaltScope,
    },
    /// Pre-trade risk rejected the order. Show the specific reason to
    /// the trader — they need to adjust size / price / position.
    RiskRejected {
        reason: RiskReason,
    },
    /// Client reused a `client_order_id`. Not a retryable error — the
    /// UI should treat this as "we already acked this, show the
    /// original ExecutionReport".
    DuplicateClOrdID,
    /// `client_order_id = 0` is reserved; the UI forgot to allocate.
    InvalidClientOrderId,
    /// Cancel request refused (unknown order / too-late / dup).
    CancelRejected {
        reason: CancelRejectCause,
    },
    /// Unrecognized reject; show the raw text to the user.
    Other {
        reason_code: u8,
        text: Option<String>,
    },
}

impl ClientError {
    /// Can the UI automatically retry this, or does it need user action?
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited { .. })
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::RateLimited { dimension, suggested_retry } => format!(
                "Rate limited ({}). Retry in ~{} ms.",
                dimension.label(),
                suggested_retry.as_millis()
            ),
            Self::MarketHalted { scope } => format!("Halted: {}", scope.label()),
            Self::RiskRejected { reason } => format!("Risk check failed: {}", reason.label()),
            Self::DuplicateClOrdID => "Order ID already in use".into(),
            Self::InvalidClientOrderId => "Client order ID 0 is reserved".into(),
            Self::CancelRejected { reason } => format!("Cancel refused: {}", reason.label()),
            Self::Other { text: Some(t), .. } => t.clone(),
            Self::Other { reason_code, .. } => format!("Reject code {}", reason_code),
        }
    }
}

/// Sub-category for rate-limit rejections. Maps to
/// `rate_limit::RateLimitDimension` on the server side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDim {
    SessionMsgs,
    SessionBytes,
    AccountMsgs,
    AccountBytes,
    Unknown,
}

impl RateLimitDim {
    fn label(&self) -> &'static str {
        match self {
            Self::SessionMsgs => "session msgs/sec",
            Self::SessionBytes => "session bytes/sec",
            Self::AccountMsgs => "account msgs/sec",
            Self::AccountBytes => "account bytes/sec",
            Self::Unknown => "rate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltScope {
    Market,
    Instrument(u32),
    Account(u64),
    Session(u64),
    Unknown,
}

impl HaltScope {
    fn label(&self) -> String {
        match self {
            Self::Market => "market-wide".into(),
            Self::Instrument(id) => format!("instrument {}", id),
            Self::Account(id) => format!("account {}", id),
            Self::Session(id) => format!("session {}", id),
            Self::Unknown => "halted".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskReason {
    NotionalExceeded,
    QuantityExceeded,
    PositionExceeded,
    PriceCollar,
    NoReferencePrice,
    SubmissionThrottle,
    SelfTrade,
    Unknown,
}

impl RiskReason {
    fn label(&self) -> &'static str {
        match self {
            Self::NotionalExceeded => "order notional exceeds limit",
            Self::QuantityExceeded => "order quantity exceeds limit",
            Self::PositionExceeded => "position would exceed limit",
            Self::PriceCollar => "price outside collar",
            Self::NoReferencePrice => "no reference price available",
            Self::SubmissionThrottle => "submission rate exceeded",
            Self::SelfTrade => "would self-trade",
            Self::Unknown => "risk check failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelRejectCause {
    UnknownOrder,
    TooLateToCancel,
    OrderAlreadyPending,
    DuplicateRequest,
    InvalidInstrument,
    NotAuthorized,
    Unknown,
}

impl CancelRejectCause {
    fn label(&self) -> &'static str {
        match self {
            Self::UnknownOrder => "unknown order",
            Self::TooLateToCancel => "too late to cancel",
            Self::OrderAlreadyPending => "cancel/replace already in progress",
            Self::DuplicateRequest => "duplicate cancel request",
            Self::InvalidInstrument => "instrument mismatch",
            Self::NotAuthorized => "not authorized",
            Self::Unknown => "cancel rejected",
        }
    }
}

// ─── Parsers ─────────────────────────────────────────────────

/// Parse a `BusinessReject` (core + optional flex) into a typed
/// `ClientError`. The dispatch is on `business_reason` and then
/// refined by the flex `text` field which encodes the specific
/// dimension (e.g. `"rate_limited:session_msgs"`).
pub fn parse_business_reject(full_msg: &[u8]) -> ClientError {
    if full_msg.len() < CORE_BLOCK_OFFSET + BusinessRejectCore::SIZE {
        return ClientError::Other { reason_code: 0, text: None };
    }
    let core = BusinessRejectCore::from_bytes(&full_msg[CORE_BLOCK_OFFSET..]);
    let flex_start = CORE_BLOCK_OFFSET + BusinessRejectCore::SIZE;
    let text = if full_msg.len() > flex_start {
        FlexReader::new(&full_msg[flex_start..])
            .get_string(1)
            .map(|s| s.to_string())
    } else {
        None
    };

    match core.business_reason {
        1 => {
            // Rate limit — dimension encoded in flex text.
            let (dim, hint) = match text.as_deref() {
                Some("rate_limited:session_msgs") => {
                    (RateLimitDim::SessionMsgs, Duration::from_millis(100))
                }
                Some("rate_limited:session_bytes") => {
                    (RateLimitDim::SessionBytes, Duration::from_millis(200))
                }
                Some("rate_limited:account_msgs") => {
                    (RateLimitDim::AccountMsgs, Duration::from_millis(500))
                }
                Some("rate_limited:account_bytes") => {
                    (RateLimitDim::AccountBytes, Duration::from_millis(1000))
                }
                _ => (RateLimitDim::Unknown, Duration::from_millis(100)),
            };
            ClientError::RateLimited { dimension: dim, suggested_retry: hint }
        }
        2 => {
            // Invalid ClOrdID (0) OR duplicate — distinguished by text.
            match text.as_deref() {
                Some(s) if s.contains("zero_reserved") => ClientError::InvalidClientOrderId,
                _ => ClientError::DuplicateClOrdID,
            }
        }
        3 => {
            let scope = parse_halt_scope(text.as_deref());
            ClientError::MarketHalted { scope }
        }
        4 => {
            let reason = parse_risk_reason(text.as_deref());
            ClientError::RiskRejected { reason }
        }
        _ => ClientError::Other { reason_code: core.business_reason, text },
    }
}

fn parse_halt_scope(text: Option<&str>) -> HaltScope {
    match text {
        Some("halt:market") => HaltScope::Market,
        Some(s) if s.starts_with("halt:instrument:") => s
            .strip_prefix("halt:instrument:")
            .and_then(|n| n.parse::<u32>().ok())
            .map(HaltScope::Instrument)
            .unwrap_or(HaltScope::Unknown),
        Some(s) if s.starts_with("halt:account:") => s
            .strip_prefix("halt:account:")
            .and_then(|n| n.parse::<u64>().ok())
            .map(HaltScope::Account)
            .unwrap_or(HaltScope::Unknown),
        Some(s) if s.starts_with("halt:session:") => s
            .strip_prefix("halt:session:")
            .and_then(|n| n.parse::<u64>().ok())
            .map(HaltScope::Session)
            .unwrap_or(HaltScope::Unknown),
        _ => HaltScope::Unknown,
    }
}

fn parse_risk_reason(text: Option<&str>) -> RiskReason {
    match text {
        Some("risk:notional_exceeded") => RiskReason::NotionalExceeded,
        Some("risk:quantity_exceeded") => RiskReason::QuantityExceeded,
        Some("risk:position_exceeded") => RiskReason::PositionExceeded,
        Some("risk:price_collar") => RiskReason::PriceCollar,
        Some("risk:no_reference_price") => RiskReason::NoReferencePrice,
        Some("risk:submission_throttle") => RiskReason::SubmissionThrottle,
        Some("risk:self_trade") => RiskReason::SelfTrade,
        _ => RiskReason::Unknown,
    }
}

/// Parse an `OrderCancelReject` into a typed error.
pub fn parse_cancel_reject(full_msg: &[u8]) -> ClientError {
    if full_msg.len() < CORE_BLOCK_OFFSET + OrderCancelRejectCore::SIZE {
        return ClientError::Other { reason_code: 0, text: None };
    }
    let core = OrderCancelRejectCore::from_bytes(&full_msg[CORE_BLOCK_OFFSET..]);
    let reason = match core.reason {
        1 => CancelRejectCause::UnknownOrder,
        2 => CancelRejectCause::TooLateToCancel,
        3 => CancelRejectCause::OrderAlreadyPending,
        4 => CancelRejectCause::DuplicateRequest,
        5 => CancelRejectCause::InvalidInstrument,
        6 => CancelRejectCause::NotAuthorized,
        _ => CancelRejectCause::Unknown,
    };
    ClientError::CancelRejected { reason }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageBuffer;
    use crate::flex::FlexWriter;
    use crate::messages::BusinessRejectCore;

    fn mk_reject(reason: u8, text: Option<&str>) -> Vec<u8> {
        let core = BusinessRejectCore {
            ref_seq_num: 42,
            ref_msg_type: 0x01,
            business_reason: reason,
            order_id: 7,
        };
        let mut buf = MessageBuffer::with_capacity(256);
        let flex_bytes = if let Some(t) = text {
            let mut fw = FlexWriter::new();
            let _ = fw.try_put_string(1, t);
            Some(fw.build())
        } else {
            None
        };
        buf.encode(0, 1, &core, flex_bytes.as_deref());
        buf.as_slice().to_vec()
    }

    #[test]
    fn rate_limit_session_msgs_parses() {
        let bytes = mk_reject(1, Some("rate_limited:session_msgs"));
        let err = parse_business_reject(&bytes);
        match err {
            ClientError::RateLimited { dimension: RateLimitDim::SessionMsgs, .. } => {}
            other => panic!("got {:?}", other),
        }
        assert!(parse_business_reject(&bytes).is_retryable());
    }

    #[test]
    fn halt_scope_roundtrip() {
        let bytes = mk_reject(3, Some("halt:instrument:42"));
        match parse_business_reject(&bytes) {
            ClientError::MarketHalted { scope: HaltScope::Instrument(42) } => {}
            other => panic!("got {:?}", other),
        }
        let bytes2 = mk_reject(3, Some("halt:market"));
        match parse_business_reject(&bytes2) {
            ClientError::MarketHalted { scope: HaltScope::Market } => {}
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn risk_reason_parsing() {
        let bytes = mk_reject(4, Some("risk:price_collar"));
        match parse_business_reject(&bytes) {
            ClientError::RiskRejected { reason: RiskReason::PriceCollar } => {}
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn clordid_distinctions() {
        let invalid = mk_reject(2, Some("invalid_client_order_id:zero_reserved"));
        match parse_business_reject(&invalid) {
            ClientError::InvalidClientOrderId => {}
            other => panic!("got {:?}", other),
        }
        let dup = mk_reject(2, None);
        match parse_business_reject(&dup) {
            ClientError::DuplicateClOrdID => {}
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn unknown_reason_falls_through() {
        let bytes = mk_reject(99, Some("something exotic"));
        match parse_business_reject(&bytes) {
            ClientError::Other { reason_code: 99, text: Some(s) } => {
                assert_eq!(s, "something exotic");
            }
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn user_messages_are_sensible() {
        let e = ClientError::RateLimited {
            dimension: RateLimitDim::SessionMsgs,
            suggested_retry: Duration::from_millis(100),
        };
        assert!(e.user_message().contains("session"));

        let e = ClientError::MarketHalted { scope: HaltScope::Instrument(42) };
        assert!(e.user_message().contains("42"));

        let e = ClientError::RiskRejected { reason: RiskReason::SelfTrade };
        assert!(e.user_message().contains("self-trade"));
    }

    #[test]
    fn short_buffer_produces_other() {
        let err = parse_business_reject(&[0; 10]);
        assert!(matches!(err, ClientError::Other { .. }));
    }
}
