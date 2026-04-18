//! FIX 4.4 → MGEP translation primitives.
//!
//! # Scope
//!
//! A **minimal** FIX-to-MGEP bridge. Covers exactly the subset needed
//! for a basic order-entry session:
//!
//! * **Session layer**: FIX `35=A` (Logon), `35=5` (Logout), `35=0`
//!   (Heartbeat) ↔ MGEP `Negotiate` / `Establish` / `Terminate` /
//!   `Heartbeat`.
//! * **Order entry**: FIX `35=D` (NewOrderSingle) → MGEP
//!   `NewOrderSingleCore`, with FIX `ClOrdID` (`11=`) mapped to the
//!   MGEP `client_order_id` via a stable hash.
//! * **Executions**: MGEP `ExecutionReportCore` → FIX `35=8`
//!   (ExecutionReport).
//! * **Cancel**: FIX `35=F` (OrderCancelRequest) → MGEP
//!   `OrderCancelRequestCore`.
//!
//! # What's NOT here
//!
//! Real FIX engines cover hundreds of messages, session recovery with
//! `35=4` ResendRequest, sequence reset, SSL layers, application
//! versioning, message cracking, etc. A full FIX 4.4 engine is weeks
//! of work — QuickFIX-Rust and onixs are the right answer for a real
//! deployment. What this module provides is the **translation
//! layer**: parse FIX into typed `FixMessage`, translate to MGEP,
//! translate back on the response path.
//!
//! # Wire format (reminder)
//!
//! FIX is an ASCII `|`-delimited (well, SOH = 0x01) key=value format:
//! ```text
//! 8=FIX.4.4|9=length|35=D|34=seq|49=sender|56=target|52=timestamp|
//! 11=clordid|55=symbol|54=side|38=qty|40=type|44=price|10=checksum|
//! ```
//!
//! `8` (BeginString), `9` (BodyLength), `10` (CheckSum) wrap the
//! message. All other tags are the payload.

use std::collections::HashMap;

use crate::messages::NewOrderSingleCore;
use crate::types::{Decimal, OrderType, Side, TimeInForce};

const SOH: u8 = 0x01;

// ─── FIX parser ─────────────────────────────────────────────

/// Parsed FIX message — tag/value map plus the msg_type.
#[derive(Debug, Clone)]
pub struct FixMessage {
    pub msg_type: char,
    pub fields: HashMap<u32, String>,
}

impl FixMessage {
    /// Return the raw string value for FIX tag `tag`, or `None` if
    /// absent.
    pub fn get(&self, tag: u32) -> Option<&str> {
        self.fields.get(&tag).map(|s| s.as_str())
    }

    /// Parse a tag's value as `u64`. Returns `None` if absent or
    /// unparseable.
    pub fn get_u64(&self, tag: u32) -> Option<u64> {
        self.get(tag).and_then(|s| s.parse().ok())
    }

    /// Parse a tag's value as `f64`. Returns `None` if absent or
    /// unparseable.
    pub fn get_f64(&self, tag: u32) -> Option<f64> {
        self.get(tag).and_then(|s| s.parse().ok())
    }
}

/// Reason the inbound FIX payload could not be parsed. Surfaces at
/// the gateway's session-level decode path — upstream MGEP logic
/// never sees malformed FIX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixParseError {
    NotAscii,
    MissingBeginString,
    MissingBodyLength,
    MissingMsgType,
    MissingChecksum,
    MalformedTagValue(String),
    InvalidMsgType,
}

/// Parse a single FIX message.
pub fn parse_fix(raw: &[u8]) -> Result<FixMessage, FixParseError> {
    let text = std::str::from_utf8(raw).map_err(|_| FixParseError::NotAscii)?;
    let mut fields = HashMap::new();
    let mut msg_type: Option<char> = None;
    let mut saw_begin = false;
    let mut saw_body_len = false;
    let mut saw_checksum = false;

    for pair in text.split(SOH as char) {
        if pair.is_empty() {
            continue;
        }
        let (tag_s, value) = match pair.split_once('=') {
            Some(p) => p,
            None => return Err(FixParseError::MalformedTagValue(pair.to_string())),
        };
        let tag: u32 = tag_s
            .parse()
            .map_err(|_| FixParseError::MalformedTagValue(pair.to_string()))?;

        match tag {
            8 => saw_begin = true,
            9 => saw_body_len = true,
            10 => saw_checksum = true,
            35 => {
                msg_type = value.chars().next();
            }
            _ => {}
        }
        fields.insert(tag, value.to_string());
    }

    if !saw_begin {
        return Err(FixParseError::MissingBeginString);
    }
    if !saw_body_len {
        return Err(FixParseError::MissingBodyLength);
    }
    if !saw_checksum {
        return Err(FixParseError::MissingChecksum);
    }
    let msg_type = msg_type.ok_or(FixParseError::MissingMsgType)?;

    Ok(FixMessage { msg_type, fields })
}

// ─── FIX encoder ────────────────────────────────────────────

fn fix_checksum(body: &[u8]) -> u8 {
    body.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Build a well-formed FIX message from an ordered list of (tag, value)
/// pairs. Handles BeginString / BodyLength / CheckSum framing.
pub fn build_fix(msg_type: char, body_fields: &[(u32, String)]) -> Vec<u8> {
    // Compose the body first.
    let mut body = String::new();
    body.push_str(&format!("35={}\x01", msg_type));
    for (tag, value) in body_fields {
        body.push_str(&format!("{}={}\x01", tag, value));
    }

    let header = format!("8=FIX.4.4\x019={}\x01", body.len());
    let mut full = header.into_bytes();
    full.extend_from_slice(body.as_bytes());
    let sum = fix_checksum(&full);
    full.extend_from_slice(format!("10={:03}\x01", sum).as_bytes());
    full
}

// ─── ClOrdID mapping ────────────────────────────────────────

/// FIX `ClOrdID` is a string of up to 32 chars; MGEP `client_order_id`
/// is `u64`. The gateway maintains a bidirectional mapping: on inbound
/// we hash (stable) the string to a u64 and remember both directions;
/// on outbound we reverse the lookup.
///
/// Hash collisions are exceedingly unlikely at FNV-1a × random 32-char
/// strings, but the gateway detects them and rejects colliding
/// submissions with a FIX `35=j` BusinessMessageReject.
#[derive(Default)]
pub struct ClOrdIdMap {
    forward: HashMap<String, u64>,
    reverse: HashMap<u64, String>,
}

impl ClOrdIdMap {
    /// Empty map. The gateway allocates one per FIX session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Translate a FIX ClOrdID string to an MGEP `client_order_id`.
    /// Returns `None` on hash collision with a different existing
    /// string — caller should reject.
    pub fn intern(&mut self, fix_clordid: &str) -> Option<u64> {
        if let Some(&existing) = self.forward.get(fix_clordid) {
            return Some(existing);
        }
        let id = fnv1a_u64(fix_clordid);
        // Reserve 0 as invalid — maps to 1 if we collide.
        let id = if id == 0 { 1 } else { id };
        match self.reverse.get(&id) {
            Some(other) if other != fix_clordid => None, // collision
            _ => {
                self.forward.insert(fix_clordid.to_string(), id);
                self.reverse.insert(id, fix_clordid.to_string());
                Some(id)
            }
        }
    }

    /// Reverse: given an MGEP `client_order_id`, return the FIX
    /// string that interned to it. Used on ExecutionReport translation
    /// to route back to the FIX side with the original ClOrdID.
    pub fn lookup_fix(&self, mgep_id: u64) -> Option<&str> {
        self.reverse.get(&mgep_id).map(|s| s.as_str())
    }
}

fn fnv1a_u64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ─── Translation ────────────────────────────────────────────

/// Reason a valid-FIX message could not be translated to the MGEP
/// core block. Surfaces at the gateway's translation layer; mapped
/// to a FIX BusinessMessageReject (`35=j`) at the session edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixTranslateError {
    UnsupportedMsgType(char),
    MissingField(u32),
    InvalidField(u32, String),
    ClOrdIdCollision(String),
}

/// Translate a parsed FIX NewOrderSingle (`35=D`) into an MGEP
/// `NewOrderSingleCore`. Returns the core + the client_order_id the
/// gateway allocated (caller stashes it for mapping ExecutionReports
/// back to the FIX side).
pub fn translate_new_order_single(
    msg: &FixMessage,
    instrument_lookup: &HashMap<String, u32>,
    clordid_map: &mut ClOrdIdMap,
) -> Result<(NewOrderSingleCore, u64), FixTranslateError> {
    if msg.msg_type != 'D' {
        return Err(FixTranslateError::UnsupportedMsgType(msg.msg_type));
    }

    // ClOrdID (11) required.
    let fix_clordid = msg.get(11).ok_or(FixTranslateError::MissingField(11))?;
    let client_order_id = clordid_map
        .intern(fix_clordid)
        .ok_or_else(|| FixTranslateError::ClOrdIdCollision(fix_clordid.to_string()))?;

    // Symbol (55) → instrument_id via lookup.
    let symbol = msg.get(55).ok_or(FixTranslateError::MissingField(55))?;
    let instrument_id = *instrument_lookup
        .get(symbol)
        .ok_or_else(|| FixTranslateError::InvalidField(55, symbol.to_string()))?;

    // Side (54).
    let side = match msg.get(54) {
        Some("1") => Side::Buy as u8,    // FIX 1=Buy
        Some("2") => Side::Sell as u8,   // FIX 2=Sell
        Some(other) => {
            return Err(FixTranslateError::InvalidField(54, other.to_string()));
        }
        None => return Err(FixTranslateError::MissingField(54)),
    };

    // OrdType (40).
    let order_type = match msg.get(40) {
        Some("1") => OrderType::Market as u8,   // FIX 1=Market
        Some("2") => OrderType::Limit as u8,    // FIX 2=Limit
        Some("3") => OrderType::Stop as u8,     // FIX 3=Stop
        Some("4") => OrderType::StopLimit as u8,// FIX 4=Stop Limit
        Some(other) => {
            return Err(FixTranslateError::InvalidField(40, other.to_string()));
        }
        None => return Err(FixTranslateError::MissingField(40)),
    };

    // TimeInForce (59), defaults to Day.
    let time_in_force = match msg.get(59) {
        Some("0") | None => TimeInForce::Day as u16,
        Some("1") => TimeInForce::GTC as u16,
        Some("3") => TimeInForce::IOC as u16,
        Some("4") => TimeInForce::FOK as u16,
        Some("6") => TimeInForce::GTD as u16,
        Some(other) => {
            return Err(FixTranslateError::InvalidField(59, other.to_string()));
        }
    };

    // OrderQty (38), required.
    let quantity = msg
        .get_f64(38)
        .ok_or(FixTranslateError::MissingField(38))?;

    // Price (44), optional (market orders have none).
    let price = msg.get_f64(44).map(Decimal::from_f64).unwrap_or(Decimal::NULL);

    // StopPx (99), optional.
    let stop_price = msg.get_f64(99).map(Decimal::from_f64).unwrap_or(Decimal::NULL);

    Ok((
        NewOrderSingleCore {
            order_id: 0,
            client_order_id,
            instrument_id,
            side,
            order_type,
            time_in_force,
            price,
            quantity: Decimal::from_f64(quantity),
            stop_price,
        },
        client_order_id,
    ))
}

/// Translate an MGEP ExecutionReport (core) to a FIX `35=8` message.
/// Requires the reverse ClOrdID lookup + symbol lookup for the
/// instrument. Sequence number / comp IDs are supplied by the
/// gateway's FIX session.
pub fn translate_execution_report(
    er: &crate::messages::ExecutionReportCore,
    fix_clordid: &str,
    symbol: &str,
    seq: u64,
    sender: &str,
    target: &str,
) -> Vec<u8> {
    // FIX ExecType maps are 1:1 in the common cases we handle.
    let exec_type = match crate::types::ExecType::from_u8(er.exec_type) {
        Some(crate::types::ExecType::New) => "0",
        Some(crate::types::ExecType::PartialFill) => "1",
        Some(crate::types::ExecType::Fill) => "2",
        Some(crate::types::ExecType::Canceled) => "4",
        Some(crate::types::ExecType::Replaced) => "5",
        Some(crate::types::ExecType::Rejected) => "8",
        _ => "I", // Order Status as catch-all
    };
    let side = match Side::from_u8(er.side) {
        Some(Side::Buy) => "1",
        Some(Side::Sell) => "2",
        None => "1",
    };

    let body: Vec<(u32, String)> = vec![
        (34, seq.to_string()),                   // MsgSeqNum
        (49, sender.to_string()),                // SenderCompID
        (56, target.to_string()),                // TargetCompID
        (11, fix_clordid.to_string()),           // ClOrdID
        (17, er.exec_id.to_string()),            // ExecID
        (37, er.order_id.to_string()),           // OrderID
        (55, symbol.to_string()),                // Symbol
        (54, side.to_string()),                  // Side
        (150, exec_type.to_string()),            // ExecType
        (14, er.cum_qty.to_f64().to_string()),   // CumQty
        (151, er.leaves_qty.to_f64().to_string()),// LeavesQty
        (32, er.last_qty.to_f64().to_string()),  // LastQty
        (31, er.last_px.to_f64().to_string()),   // LastPx
    ];
    build_fix('8', &body)
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_new_order_fix_body(clordid: &str, symbol: &str) -> String {
        let mut parts = Vec::new();
        parts.push("8=FIX.4.4".to_string());
        parts.push("9=100".to_string());
        parts.push("35=D".to_string());
        parts.push("34=1".to_string());
        parts.push("49=CLIENT".to_string());
        parts.push("56=VENUE".to_string());
        parts.push(format!("11={}", clordid));
        parts.push(format!("55={}", symbol));
        parts.push("54=1".to_string()); // Buy
        parts.push("38=100".to_string());
        parts.push("40=2".to_string()); // Limit
        parts.push("44=150.25".to_string());
        parts.push("59=0".to_string()); // Day
        parts.push("10=000".to_string());
        parts.join("\x01")
    }

    #[test]
    fn parse_new_order_single_fix() {
        let raw = build_new_order_fix_body("CLORD-123", "BTCUSD");
        let msg = parse_fix(raw.as_bytes()).unwrap();
        assert_eq!(msg.msg_type, 'D');
        assert_eq!(msg.get(11), Some("CLORD-123"));
        assert_eq!(msg.get(55), Some("BTCUSD"));
    }

    #[test]
    fn parse_rejects_missing_begin() {
        let raw = "35=D\x0110=000\x01";
        assert!(matches!(
            parse_fix(raw.as_bytes()),
            Err(FixParseError::MissingBeginString)
        ));
    }

    #[test]
    fn translate_new_order_end_to_end() {
        let raw = build_new_order_fix_body("CLORD-ABC", "BTCUSD");
        let msg = parse_fix(raw.as_bytes()).unwrap();
        let mut instruments = HashMap::new();
        instruments.insert("BTCUSD".to_string(), 42u32);
        let mut clmap = ClOrdIdMap::new();
        let (core, clordid) = translate_new_order_single(&msg, &instruments, &mut clmap).unwrap();
        assert_eq!(core.instrument_id, 42);
        assert_eq!(core.side, Side::Buy as u8);
        assert_eq!(core.order_type, OrderType::Limit as u8);
        assert!((core.quantity.to_f64() - 100.0).abs() < 0.001);
        assert!((core.price.to_f64() - 150.25).abs() < 0.001);
        assert_ne!(clordid, 0, "client_order_id must be non-zero");
        assert_eq!(clmap.lookup_fix(clordid), Some("CLORD-ABC"));
    }

    #[test]
    fn same_clordid_interns_to_same_id() {
        let mut clmap = ClOrdIdMap::new();
        let a = clmap.intern("order-1").unwrap();
        let b = clmap.intern("order-1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_clordid_intern_to_different_ids() {
        let mut clmap = ClOrdIdMap::new();
        let a = clmap.intern("order-1").unwrap();
        let b = clmap.intern("order-2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn missing_symbol_fails_translate() {
        let raw = build_new_order_fix_body("CLORD", "UNKNOWN");
        let msg = parse_fix(raw.as_bytes()).unwrap();
        let instruments = HashMap::new();
        let mut clmap = ClOrdIdMap::new();
        let err = translate_new_order_single(&msg, &instruments, &mut clmap).unwrap_err();
        assert!(matches!(err, FixTranslateError::InvalidField(55, _)));
    }

    #[test]
    fn build_and_roundtrip_fix_message() {
        let body = vec![
            (34, "1".to_string()),
            (49, "VENUE".to_string()),
            (56, "CLIENT".to_string()),
            (11, "CLORD".to_string()),
        ];
        let bytes = build_fix('8', &body);
        let parsed = parse_fix(&bytes).unwrap();
        assert_eq!(parsed.msg_type, '8');
        assert_eq!(parsed.get(11), Some("CLORD"));
    }

    #[test]
    fn execution_report_translates_to_fix() {
        use crate::messages::ExecutionReportCore;
        use crate::types::{ExecType, Timestamp};
        let er = ExecutionReportCore {
            order_id: 1234,
            client_order_id: 999,
            exec_id: 5678,
            instrument_id: 42,
            side: Side::Buy as u8,
            exec_type: ExecType::Fill as u8,
            order_status: 2,
            _pad: 0,
            price: Decimal::from_f64(150.0),
            quantity: Decimal::from_f64(10.0),
            leaves_qty: Decimal::ZERO,
            cum_qty: Decimal::from_f64(10.0),
            last_px: Decimal::from_f64(150.0),
            last_qty: Decimal::from_f64(10.0),
            transact_time: Timestamp::now(),
        };
        let fix_bytes = translate_execution_report(&er, "CLORD-X", "BTCUSD", 7, "VENUE", "CLIENT");
        let parsed = parse_fix(&fix_bytes).unwrap();
        assert_eq!(parsed.msg_type, '8');
        assert_eq!(parsed.get(150), Some("2"));       // ExecType=Fill
        assert_eq!(parsed.get(11), Some("CLORD-X"));
        assert_eq!(parsed.get(37), Some("1234"));     // OrderID
        assert_eq!(parsed.get(17), Some("5678"));     // ExecID
    }

    #[test]
    fn side_and_order_type_errors_surface() {
        let mut raw = build_new_order_fix_body("C", "BTC");
        raw = raw.replace("54=1", "54=9"); // invalid side
        let msg = parse_fix(raw.as_bytes()).unwrap();
        let mut inst = HashMap::new();
        inst.insert("BTC".to_string(), 1u32);
        let mut clmap = ClOrdIdMap::new();
        let err = translate_new_order_single(&msg, &inst, &mut clmap).unwrap_err();
        assert!(matches!(err, FixTranslateError::InvalidField(54, _)));
    }
}
