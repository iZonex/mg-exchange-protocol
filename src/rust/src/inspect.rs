//! Protocol Inspector — human-readable dump of MGEP messages.
//!
//! Essential for debugging: see what's on the wire without a hex editor.
//!
//!   let msg = transport.recv()?;
//!   println!("{}", mgep::inspect::format_message(msg));
//!
//! Output:
//!   [NewOrderSingle] schema=0x0001 type=0x01 seq=42 size=106B
//!     order_id=1000 instrument=42 side=Buy type=Limit tif=Day
//!     price=150.25000000 qty=100.00000000 stop=NULL
//!     flex: account="ACC001" client_tag="strat-1"

use crate::codec::dispatch_message;
use crate::codec::MessageKind;
use crate::flex::FlexReader;
use crate::frame::FrameHeader;
use crate::header::{FullHeader, CORE_BLOCK_OFFSET};
use crate::messages::*;
use std::fmt::Write;

/// Format an MGEP message as a human-readable string.
pub fn format_message(buf: &[u8]) -> String {
    let mut out = String::with_capacity(256);

    if buf.len() < CORE_BLOCK_OFFSET {
        write!(out, "[TRUNCATED] {} bytes", buf.len()).unwrap();
        return out;
    }

    let header = FullHeader::from_bytes(buf);
    let schema = header.message.schema_id;
    let msg_type = header.message.message_type;
    let seq = header.message.sequence_num;
    let size = header.frame.message_size;

    let flags = &mut Vec::new();
    if header.frame.flags.has_auth_tag() { flags.push("AUTH"); }
    if header.frame.flags.is_encrypted() { flags.push("ENC"); }
    if header.frame.flags.is_compressed() { flags.push("COMP"); }
    if header.frame.flags.has_flex() { flags.push("FLEX"); }
    let flags_str = if flags.is_empty() { String::new() } else { format!(" [{}]", flags.join("|")) };

    match dispatch_message(buf) {
        MessageKind::NewOrder(o) => {
            writeln!(out, "[NewOrderSingle] schema=0x{:04X} type=0x{:02X} seq={} size={}B{}",
                schema, msg_type, seq, size, flags_str).unwrap();
            writeln!(out, "  order_id={} instrument={} side={} type={} tif={}",
                o.order_id, o.instrument_id,
                side_str(o.side), order_type_str(o.order_type), tif_str(o.time_in_force)).unwrap();
            write!(out, "  price={} qty={} stop={}", o.price, o.quantity, o.stop_price).unwrap();
            append_flex(&mut out, buf, NewOrderSingleCore::SIZE, &[(1, "account"), (2, "client_tag")]);
        }
        MessageKind::ExecutionReport(r) => {
            writeln!(out, "[ExecutionReport] schema=0x{:04X} type=0x{:02X} seq={} size={}B{}",
                schema, msg_type, seq, size, flags_str).unwrap();
            writeln!(out, "  order_id={} exec_id={} instrument={} side={}",
                r.order_id, r.exec_id, r.instrument_id, side_str(r.side)).unwrap();
            writeln!(out, "  exec_type={} price={} qty={} leaves={} cum={}",
                exec_type_str(r.exec_type), r.price, r.quantity, r.leaves_qty, r.cum_qty).unwrap();
            write!(out, "  last_px={} last_qty={}", r.last_px, r.last_qty).unwrap();
            append_flex(&mut out, buf, ExecutionReportCore::SIZE, &[(1, "text"), (4, "fee_currency")]);
        }
        MessageKind::CancelRequest(c) => {
            write!(out, "[OrderCancelRequest] seq={} size={}B{}\n  order_id={} cancel_id={} instrument={}",
                seq, size, flags_str, c.order_id, c.cancel_id, c.instrument_id).unwrap();
        }
        MessageKind::Reject(r) => {
            write!(out, "[Reject] seq={} size={}B{}\n  ref_seq={} ref_type=0x{:02X} reason={}",
                seq, size, flags_str, r.ref_seq_num, r.ref_msg_type, r.reject_reason).unwrap();
            append_flex(&mut out, buf, RejectCore::SIZE, &[(1, "text"), (2, "ref_field")]);
        }
        MessageKind::BusinessReject(b) => {
            write!(out, "[BusinessReject] seq={} size={}B{}\n  ref_seq={} reason={} order_id={}",
                seq, size, flags_str, b.ref_seq_num, b.business_reason, b.order_id).unwrap();
        }
        MessageKind::Quote(q) => {
            write!(out, "[Quote] seq={} size={}B{}\n  quote_id={} instrument={}\n  bid={}@{} ask={}@{}",
                seq, size, flags_str, q.quote_id, q.instrument_id,
                q.bid_price, q.bid_quantity, q.ask_price, q.ask_quantity).unwrap();
        }
        MessageKind::PositionReport(p) => {
            write!(out, "[PositionReport] seq={} size={}B{}\n  account={} instrument={}\n  long={} short={} net={} avg_entry={}\n  unrealized_pnl={} realized_pnl={}",
                seq, size, flags_str, p.account_id, p.instrument_id,
                p.long_quantity, p.short_quantity, p.net_quantity, p.avg_entry_price,
                p.unrealized_pnl, p.realized_pnl).unwrap();
        }
        MessageKind::MarketStatistics(s) => {
            write!(out, "[MarketStatistics] seq={} size={}B{}\n  instrument={}\n  O={} H={} L={} C={}\n  VWAP={} volume={} turnover={} OI={}",
                seq, size, flags_str, s.instrument_id,
                s.open_price, s.high_price, s.low_price, s.close_price,
                s.vwap, s.total_volume, s.total_turnover, s.open_interest).unwrap();
        }
        MessageKind::MarginCall(m) => {
            write!(out, "[MarginCall] seq={} size={}B{}\n  account={} action={} deficit={}",
                seq, size, flags_str, m.account_id, m.action, m.margin_deficit).unwrap();
        }
        MessageKind::Malformed => {
            write!(out, "[MALFORMED] {} bytes", buf.len()).unwrap();
        }
        MessageKind::Unknown { schema_id, msg_type } => {
            write!(out, "[Unknown] schema=0x{:04X} type=0x{:02X} seq={} size={}B{}",
                schema_id, msg_type, seq, size, flags_str).unwrap();
        }
        // Catch-all for types without specific formatting
        _ => {
            let name = schema_name(schema);
            write!(out, "[{}/0x{:02X}] seq={} size={}B{}", name, msg_type, seq, size, flags_str).unwrap();
        }
    }

    out
}

/// Format a hex dump of raw bytes (for debugging).
pub fn hex_dump(buf: &[u8], max_bytes: usize) -> String {
    let mut out = String::with_capacity(max_bytes * 3 + 20);
    let limit = buf.len().min(max_bytes);
    for (i, &b) in buf[..limit].iter().enumerate() {
        if i > 0 && i % 16 == 0 { out.push('\n'); }
        else if i > 0 { out.push(' '); }
        write!(out, "{:02X}", b).unwrap();
    }
    if buf.len() > limit {
        write!(out, " ... ({} more bytes)", buf.len() - limit).unwrap();
    }
    out
}

// ── Helpers ──────────────────────────────────────────────

fn side_str(side: u8) -> &'static str {
    match side { 1 => "Buy", 2 => "Sell", _ => "?" }
}

fn order_type_str(ot: u8) -> &'static str {
    match ot { 1 => "Market", 2 => "Limit", 3 => "Stop", 4 => "StopLimit", _ => "?" }
}

fn tif_str(tif: u16) -> &'static str {
    match tif { 1 => "Day", 2 => "GTC", 3 => "IOC", 4 => "FOK", 5 => "GTD", _ => "?" }
}

fn exec_type_str(et: u8) -> &'static str {
    match et { 0 => "New", 1 => "PartialFill", 2 => "Fill", 4 => "Canceled", 5 => "Replaced", 8 => "Rejected", 12 => "Expired", _ => "?" }
}

fn schema_name(id: u16) -> &'static str {
    match id {
        0x0000 => "session",
        0x0001 => "trading",
        0x0002 => "market_data",
        0x0003 => "quotes",
        0x0004 => "post_trade",
        0x0005 => "risk",
        0xFFFF => "batch",
        _ => "unknown",
    }
}

fn append_flex(out: &mut String, buf: &[u8], core_size: usize, fields: &[(u16, &str)]) {
    let flex_offset = CORE_BLOCK_OFFSET + core_size;
    if flex_offset >= buf.len() { return; }
    let frame = FrameHeader::from_bytes(buf);
    if !frame.flags.has_flex() { return; }

    let reader = FlexReader::new(&buf[flex_offset..]);
    if reader.count() == 0 { return; }

    write!(out, "\n  flex:").unwrap();
    for &(id, name) in fields {
        if let Some(s) = reader.get_string(id) {
            write!(out, " {}=\"{}\"", name, s).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageBuffer;
    use crate::types::*;

    #[test]
    fn format_new_order() {
        let mut enc = MessageBuffer::with_capacity(256);
        let order = NewOrderSingleCore {
            order_id: 1000, instrument_id: 42, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: Decimal::from_f64(150.25),
            quantity: Decimal::from_f64(100.0), stop_price: Decimal::NULL,
        };
        enc.encode(1, 5, &order, None);

        let output = format_message(enc.as_slice());
        assert!(output.contains("[NewOrderSingle]"));
        assert!(output.contains("seq=5"));
        assert!(output.contains("order_id=1000"));
        assert!(output.contains("side=Buy"));
        assert!(output.contains("type=Limit"));
        assert!(output.contains("150.25"));
    }

    #[test]
    fn format_with_flex() {
        let mut flex = crate::flex::FlexWriter::new();
        flex.put_string(1, "ACC001");
        flex.put_string(2, "strat-1");
        let flex_data = flex.build();

        let mut enc = MessageBuffer::with_capacity(512);
        let order = NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 3, price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(10.0), stop_price: Decimal::NULL,
        };
        enc.encode(1, 1, &order, Some(&flex_data));

        let output = format_message(enc.as_slice());
        assert!(output.contains("[FLEX]"));
        assert!(output.contains("account=\"ACC001\""));
        assert!(output.contains("client_tag=\"strat-1\""));
    }

    #[test]
    fn hex_dump_basic() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let output = hex_dump(&data, 100);
        assert_eq!(output, "DE AD BE EF");
    }

    #[test]
    fn hex_dump_truncated() {
        let data = vec![0u8; 100];
        let output = hex_dump(&data, 8);
        assert!(output.contains("... (92 more bytes)"));
    }
}
