use crate::frame::{FrameFlags, FrameHeader};
use crate::header::{FullHeader, CORE_BLOCK_OFFSET};
use crate::messages::*;
#[allow(unused_imports)]
use crate::types::*;

/// Trait for any MGEP core block that can be encoded/decoded.
pub trait CoreBlock: Copy {
    const SIZE: usize;
    const MESSAGE_TYPE: u16;
    const SCHEMA_ID: u16;

    fn as_bytes(&self) -> &[u8];
    fn from_bytes(buf: &[u8]) -> &Self;
}

// Implement CoreBlock for all message types
macro_rules! impl_core_block {
    ($ty:ty) => {
        impl CoreBlock for $ty {
            const SIZE: usize = <$ty>::SIZE;
            const MESSAGE_TYPE: u16 = <$ty>::MESSAGE_TYPE;
            const SCHEMA_ID: u16 = <$ty>::SCHEMA_ID;

            #[inline(always)]
            fn as_bytes(&self) -> &[u8] {
                <$ty>::as_bytes(self)
            }

            #[inline(always)]
            fn from_bytes(buf: &[u8]) -> &Self {
                <$ty>::from_bytes(buf)
            }
        }
    };
}

// Trading (0x0001)
impl_core_block!(NewOrderSingleCore);
impl_core_block!(OrderCancelRequestCore);
impl_core_block!(OrderCancelReplaceRequestCore);
impl_core_block!(OrderMassCancelRequestCore);
impl_core_block!(ExecutionReportCore);
impl_core_block!(OrderCancelRejectCore);
impl_core_block!(OrderStatusRequestCore);
impl_core_block!(OrderMassCancelReportCore);
impl_core_block!(NewOrderCrossCore);
impl_core_block!(OrderMassStatusRequestCore);
impl_core_block!(CrossOrderCancelRequestCore);
impl_core_block!(RejectCore);
impl_core_block!(BusinessRejectCore);
// Market Data (0x0002)
impl_core_block!(OrderAddCore);
impl_core_block!(OrderModifyCore);
impl_core_block!(OrderDeleteCore);
impl_core_block!(OrderExecutedCore);
impl_core_block!(TradeCore);
impl_core_block!(TradingStatusCore);
impl_core_block!(SubscribeCore);
impl_core_block!(UnsubscribeCore);
impl_core_block!(SubscribeResponseCore);
impl_core_block!(MarketStatisticsCore);
impl_core_block!(SecurityListRequestCore);
impl_core_block!(SecurityListResponseCore);
// Quotes (0x0003)
impl_core_block!(QuoteRequestCore);
impl_core_block!(QuoteCore);
impl_core_block!(QuoteCancelCore);
impl_core_block!(MassQuoteCore);
impl_core_block!(MassQuoteAckCore);
impl_core_block!(QuoteStatusRequestCore);
impl_core_block!(IOICore);
// Post-Trade (0x0004)
impl_core_block!(TradeCaptureReportCore);
impl_core_block!(TradeCaptureReportRequestCore);
impl_core_block!(AllocationInstructionCore);
impl_core_block!(AllocationReportCore);
impl_core_block!(ConfirmationCore);
impl_core_block!(ConfirmationAckCore);
impl_core_block!(SettlementInstructionCore);
impl_core_block!(SettlementStatusCore);
// Risk (0x0005)
impl_core_block!(RequestForPositionsCore);
impl_core_block!(PositionReportCore);
impl_core_block!(CollateralInquiryCore);
impl_core_block!(CollateralReportCore);
impl_core_block!(CollateralRequestCore);
impl_core_block!(CollateralRequestAckCore);
impl_core_block!(MarginRequirementInquiryCore);
impl_core_block!(MarginRequirementReportCore);
impl_core_block!(MarginCallCore);

/// Pre-allocated message buffer for zero-allocation encoding.
/// In production, these would be pooled and reused.
pub struct MessageBuffer {
    buf: Vec<u8>,
    len: usize,
}

impl MessageBuffer {
    /// Create a new buffer with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity],
            len: 0,
        }
    }

    /// Access the written portion of the buffer.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Reset buffer for reuse (no deallocation).
    #[inline(always)]
    pub fn reset(&mut self) {
        self.len = 0;
    }

    /// Encode any MGEP message (core block + optional flex).
    /// This is the universal encoder — works for all message types.
    #[inline]
    pub fn encode<T: CoreBlock>(
        &mut self,
        sender_comp_id: u32,
        sequence_num: u64,
        core: &T,
        flex_data: Option<&[u8]>,
    ) -> usize {
        self.encode_with_correlation(sender_comp_id, sequence_num, 0, core, flex_data)
    }

    /// Encode with explicit correlation ID.
    #[inline]
    pub fn encode_with_correlation<T: CoreBlock>(
        &mut self,
        sender_comp_id: u32,
        sequence_num: u64,
        correlation_id: u64,
        core: &T,
        flex_data: Option<&[u8]>,
    ) -> usize {
        let has_flex = flex_data.is_some();
        let flex_len = flex_data.map_or(0, |d| d.len());
        let total_size = CORE_BLOCK_OFFSET + T::SIZE + flex_len;

        let mut flags = FrameFlags::new();
        if has_flex {
            flags = flags.with_flex();
        }

        let header = FullHeader::new(
            T::SCHEMA_ID,
            T::MESSAGE_TYPE,
            sender_comp_id,
            sequence_num,
            correlation_id,
            total_size as u32,
            flags,
        );
        header.write_to(&mut self.buf);

        self.buf[CORE_BLOCK_OFFSET..CORE_BLOCK_OFFSET + T::SIZE]
            .copy_from_slice(core.as_bytes());

        if let Some(flex) = flex_data {
            let flex_offset = CORE_BLOCK_OFFSET + T::SIZE;
            self.buf[flex_offset..flex_offset + flex_len].copy_from_slice(flex);
        }

        self.len = total_size;
        total_size
    }

    /// Legacy alias.
    #[inline]
    pub fn encode_new_order(
        &mut self,
        sender_comp_id: u32,
        sequence_num: u64,
        order: &NewOrderSingleCore,
        flex_data: Option<&[u8]>,
    ) -> usize {
        self.encode(sender_comp_id, sequence_num, order, flex_data)
    }

    // ── Static decoders ──────────────────────────────────────

    /// Decode the frame header from a buffer.
    #[inline(always)]
    pub fn decode_frame_header(buf: &[u8]) -> &FrameHeader {
        FrameHeader::from_bytes(buf)
    }

    /// Decode the full header from a buffer.
    #[inline(always)]
    pub fn decode_full_header(buf: &[u8]) -> &FullHeader {
        FullHeader::from_bytes(buf)
    }

    /// Decode any core block from a message buffer.
    #[inline(always)]
    pub fn decode<T: CoreBlock>(buf: &[u8]) -> &T {
        T::from_bytes(&buf[CORE_BLOCK_OFFSET..])
    }

    /// Decode a NewOrderSingle core block from a message buffer.
    #[inline(always)]
    pub fn decode_new_order(buf: &[u8]) -> &NewOrderSingleCore {
        Self::decode(buf)
    }

    /// Decode an ExecutionReport core block from a message buffer.
    #[inline(always)]
    pub fn decode_execution_report(buf: &[u8]) -> &ExecutionReportCore {
        Self::decode(buf)
    }

    /// Decode the flex block from a message buffer, given core block size.
    #[inline]
    pub fn decode_flex(buf: &[u8], core_size: usize) -> Option<crate::flex::FlexReader<'_>> {
        let header = FrameHeader::from_bytes(buf);
        if !header.flags.has_flex() {
            return None;
        }
        let flex_offset = CORE_BLOCK_OFFSET + core_size;
        if flex_offset < buf.len() {
            Some(crate::flex::FlexReader::new(&buf[flex_offset..]))
        } else {
            None
        }
    }
}

/// Internal macro: try safe decode, return Malformed on short buffer.
macro_rules! try_decode {
    ($buf:expr, $ty:ty, $variant:ident) => {
        match <$ty>::try_from_bytes($buf) {
            Some(v) => MessageKind::$variant(v),
            None => MessageKind::Malformed,
        }
    };
}

/// Dispatch a message to the appropriate handler based on schema_id + message_type.
///
/// This is the hot-path message dispatch. Two integer comparisons, no string parsing.
/// Returns `Malformed` for truncated buffers that can't contain the declared core block.
#[inline]
pub fn dispatch_message(buf: &[u8]) -> MessageKind<'_> {
    let Some(header) = FullHeader::try_from_bytes(buf) else {
        return MessageKind::Malformed;
    };
    let schema_id = header.message.schema_id;
    let msg_type = header.message.message_type;
    let core_buf = &buf[CORE_BLOCK_OFFSET..];

    match (schema_id, msg_type) {
        // Trading (0x0001)
        (0x0001, 0x01) => try_decode!(core_buf, NewOrderSingleCore, NewOrder),
        (0x0001, 0x02) => try_decode!(core_buf, OrderCancelRequestCore, CancelRequest),
        (0x0001, 0x03) => try_decode!(core_buf, OrderCancelReplaceRequestCore, ReplaceRequest),
        (0x0001, 0x04) => try_decode!(core_buf, OrderMassCancelRequestCore, MassCancelRequest),
        (0x0001, 0x05) => try_decode!(core_buf, ExecutionReportCore, ExecutionReport),
        (0x0001, 0x06) => try_decode!(core_buf, OrderCancelRejectCore, CancelReject),
        (0x0001, 0x07) => try_decode!(core_buf, OrderStatusRequestCore, OrderStatusRequest),
        (0x0001, 0x08) => try_decode!(core_buf, OrderMassCancelReportCore, MassCancelReport),
        (0x0001, 0x09) => try_decode!(core_buf, NewOrderCrossCore, NewOrderCross),
        (0x0001, 0x0A) => try_decode!(core_buf, OrderMassStatusRequestCore, OrderMassStatusRequest),
        (0x0001, 0x0B) => try_decode!(core_buf, CrossOrderCancelRequestCore, CrossOrderCancelRequest),
        (0x0001, 0x10) => try_decode!(core_buf, RejectCore, Reject),
        (0x0001, 0x11) => try_decode!(core_buf, BusinessRejectCore, BusinessReject),

        // Market Data (0x0002)
        (0x0002, 0x01) => try_decode!(core_buf, OrderAddCore, OrderAdd),
        (0x0002, 0x02) => try_decode!(core_buf, OrderModifyCore, OrderModify),
        (0x0002, 0x03) => try_decode!(core_buf, OrderDeleteCore, OrderDelete),
        (0x0002, 0x04) => try_decode!(core_buf, OrderExecutedCore, OrderExecuted),
        (0x0002, 0x05) => try_decode!(core_buf, TradeCore, Trade),
        (0x0002, 0x08) => try_decode!(core_buf, TradingStatusCore, TradingStatus),
        (0x0002, 0x10) => try_decode!(core_buf, SubscribeCore, Subscribe),
        (0x0002, 0x11) => try_decode!(core_buf, UnsubscribeCore, Unsubscribe),
        (0x0002, 0x12) => try_decode!(core_buf, SubscribeResponseCore, SubscribeResponse),
        (0x0002, 0x20) => try_decode!(core_buf, MarketStatisticsCore, MarketStatistics),
        (0x0002, 0x21) => try_decode!(core_buf, SecurityListRequestCore, SecurityListRequest),
        (0x0002, 0x22) => try_decode!(core_buf, SecurityListResponseCore, SecurityListResponse),

        // Quotes (0x0003)
        (0x0003, 0x01) => try_decode!(core_buf, QuoteRequestCore, QuoteRequest),
        (0x0003, 0x02) => try_decode!(core_buf, QuoteCore, Quote),
        (0x0003, 0x03) => try_decode!(core_buf, QuoteCancelCore, QuoteCancel),
        (0x0003, 0x04) => try_decode!(core_buf, MassQuoteCore, MassQuote),
        (0x0003, 0x05) => try_decode!(core_buf, MassQuoteAckCore, MassQuoteAck),
        (0x0003, 0x06) => try_decode!(core_buf, QuoteStatusRequestCore, QuoteStatusRequest),
        (0x0003, 0x10) => try_decode!(core_buf, IOICore, IOI),

        // Post-Trade (0x0004)
        (0x0004, 0x01) => try_decode!(core_buf, TradeCaptureReportCore, TradeCaptureReport),
        (0x0004, 0x02) => try_decode!(core_buf, TradeCaptureReportRequestCore, TradeCaptureReportRequest),
        (0x0004, 0x10) => try_decode!(core_buf, AllocationInstructionCore, AllocationInstruction),
        (0x0004, 0x11) => try_decode!(core_buf, AllocationReportCore, AllocationReport),
        (0x0004, 0x20) => try_decode!(core_buf, ConfirmationCore, Confirmation),
        (0x0004, 0x21) => try_decode!(core_buf, ConfirmationAckCore, ConfirmationAck),
        (0x0004, 0x30) => try_decode!(core_buf, SettlementInstructionCore, SettlementInstruction),
        (0x0004, 0x31) => try_decode!(core_buf, SettlementStatusCore, SettlementStatus),

        // Risk (0x0005)
        (0x0005, 0x01) => try_decode!(core_buf, RequestForPositionsCore, RequestForPositions),
        (0x0005, 0x02) => try_decode!(core_buf, PositionReportCore, PositionReport),
        (0x0005, 0x10) => try_decode!(core_buf, CollateralInquiryCore, CollateralInquiry),
        (0x0005, 0x11) => try_decode!(core_buf, CollateralReportCore, CollateralReport),
        (0x0005, 0x12) => try_decode!(core_buf, CollateralRequestCore, CollateralRequest),
        (0x0005, 0x13) => try_decode!(core_buf, CollateralRequestAckCore, CollateralRequestAck),
        (0x0005, 0x20) => try_decode!(core_buf, MarginRequirementInquiryCore, MarginRequirementInquiry),
        (0x0005, 0x21) => try_decode!(core_buf, MarginRequirementReportCore, MarginRequirementReport),
        (0x0005, 0x22) => try_decode!(core_buf, MarginCallCore, MarginCall),

        _ => MessageKind::Unknown { schema_id, msg_type },
    }
}

/// Typed message variants for dispatch — covers full exchange lifecycle.
pub enum MessageKind<'a> {
    // ── Trading (0x0001) ──────────────────────────────────
    NewOrder(&'a NewOrderSingleCore),
    CancelRequest(&'a OrderCancelRequestCore),
    ReplaceRequest(&'a OrderCancelReplaceRequestCore),
    MassCancelRequest(&'a OrderMassCancelRequestCore),
    ExecutionReport(&'a ExecutionReportCore),
    CancelReject(&'a OrderCancelRejectCore),
    OrderStatusRequest(&'a OrderStatusRequestCore),
    MassCancelReport(&'a OrderMassCancelReportCore),
    NewOrderCross(&'a NewOrderCrossCore),
    OrderMassStatusRequest(&'a OrderMassStatusRequestCore),
    CrossOrderCancelRequest(&'a CrossOrderCancelRequestCore),
    Reject(&'a RejectCore),
    BusinessReject(&'a BusinessRejectCore),

    // ── Market Data (0x0002) ──────────────────────────────
    OrderAdd(&'a OrderAddCore),
    OrderModify(&'a OrderModifyCore),
    OrderDelete(&'a OrderDeleteCore),
    OrderExecuted(&'a OrderExecutedCore),
    Trade(&'a TradeCore),
    TradingStatus(&'a TradingStatusCore),
    Subscribe(&'a SubscribeCore),
    Unsubscribe(&'a UnsubscribeCore),
    SubscribeResponse(&'a SubscribeResponseCore),
    MarketStatistics(&'a MarketStatisticsCore),
    SecurityListRequest(&'a SecurityListRequestCore),
    SecurityListResponse(&'a SecurityListResponseCore),

    // ── Quotes (0x0003) ───────────────────────────────────
    QuoteRequest(&'a QuoteRequestCore),
    Quote(&'a QuoteCore),
    QuoteCancel(&'a QuoteCancelCore),
    MassQuote(&'a MassQuoteCore),
    MassQuoteAck(&'a MassQuoteAckCore),
    QuoteStatusRequest(&'a QuoteStatusRequestCore),
    IOI(&'a IOICore),

    // ── Post-Trade (0x0004) ───────────────────────────────
    TradeCaptureReport(&'a TradeCaptureReportCore),
    TradeCaptureReportRequest(&'a TradeCaptureReportRequestCore),
    AllocationInstruction(&'a AllocationInstructionCore),
    AllocationReport(&'a AllocationReportCore),
    Confirmation(&'a ConfirmationCore),
    ConfirmationAck(&'a ConfirmationAckCore),
    SettlementInstruction(&'a SettlementInstructionCore),
    SettlementStatus(&'a SettlementStatusCore),

    // ── Risk (0x0005) ─────────────────────────────────────
    RequestForPositions(&'a RequestForPositionsCore),
    PositionReport(&'a PositionReportCore),
    CollateralInquiry(&'a CollateralInquiryCore),
    CollateralReport(&'a CollateralReportCore),
    CollateralRequest(&'a CollateralRequestCore),
    CollateralRequestAck(&'a CollateralRequestAckCore),
    MarginRequirementInquiry(&'a MarginRequirementInquiryCore),
    MarginRequirementReport(&'a MarginRequirementReportCore),
    MarginCall(&'a MarginCallCore),

    Unknown { schema_id: u16, msg_type: u16 },
    /// Buffer too short to decode the message.
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_new_order() {
        let order = NewOrderSingleCore {
            order_id: 999,
            instrument_id: 42,
            side: Side::Buy as u8,
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::GTC as u16,
            price: Decimal::from_f64(100.50),
            quantity: Decimal::from_f64(10.0),
            stop_price: Decimal::NULL,
        };

        let mut buffer = MessageBuffer::with_capacity(256);
        let written = buffer.encode(1, 1, &order, None);

        // 32 header + 40 core = 72 bytes
        assert_eq!(written, 72);

        let msg = buffer.as_slice();

        // Verify headers
        let full = MessageBuffer::decode_full_header(msg);
        assert!(full.frame.is_valid());
        assert_eq!(full.frame.message_size, 72); // 32 header + 40 core
        assert_eq!(full.message.schema_id, 0x0001);
        assert!(!full.frame.flags.has_flex());
        assert_eq!(full.message.message_type, 0x01);
        assert_eq!(full.message.sender_comp_id, 1);
        assert_eq!(full.message.sequence_num, 1);

        // Verify core block
        let decoded: &NewOrderSingleCore = MessageBuffer::decode(msg);
        assert_eq!(decoded.order_id, 999);
        assert_eq!(decoded.instrument_id, 42);
        assert_eq!(decoded.side(), Some(Side::Buy));
        assert_eq!(decoded.order_type(), Some(OrderType::Limit));
        assert!((decoded.price.to_f64() - 100.50).abs() < 1e-6);
        assert!((decoded.quantity.to_f64() - 10.0).abs() < 1e-6);
        assert!(decoded.stop_price.is_null());
    }

    #[test]
    fn encode_with_flex() {
        let order = NewOrderSingleCore {
            order_id: 1,
            instrument_id: 1,
            side: Side::Sell as u8,
            order_type: OrderType::Market as u8,
            time_in_force: TimeInForce::IOC as u16,
            price: Decimal::NULL,
            quantity: Decimal::from_f64(50.0),
            stop_price: Decimal::NULL,
        };

        let mut flex_writer = crate::flex::FlexWriter::new();
        flex_writer.put_string(1, "ACC001");
        flex_writer.put_string(2, "my-tag");
        let flex_data = flex_writer.build();

        let mut buffer = MessageBuffer::with_capacity(256);
        let written = buffer.encode(1, 1, &order, Some(&flex_data));

        let msg = buffer.as_slice();
        assert_eq!(written, msg.len());

        let frame = MessageBuffer::decode_frame_header(msg);
        assert!(frame.flags.has_flex());

        let flex = MessageBuffer::decode_flex(msg, NewOrderSingleCore::SIZE).unwrap();
        assert_eq!(flex.get_string(1), Some("ACC001"));
        assert_eq!(flex.get_string(2), Some("my-tag"));
    }

    #[test]
    fn generic_encode_execution_report() {
        let report = ExecutionReportCore {
            order_id: 42,
            exec_id: 100,
            instrument_id: 7,
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

        let mut buffer = MessageBuffer::with_capacity(256);
        let written = buffer.encode(0, 1, &report, None);
        assert_eq!(written, CORE_BLOCK_OFFSET + ExecutionReportCore::SIZE);

        let msg = buffer.as_slice();
        let header = MessageBuffer::decode_full_header(msg);
        assert_eq!(header.message.schema_id, 0x0001);
        assert_eq!(header.message.message_type, 0x05);

        let decoded: &ExecutionReportCore = MessageBuffer::decode(msg);
        assert_eq!(decoded.order_id, 42);
        assert_eq!(decoded.exec_type(), Some(ExecType::Fill));
    }

    #[test]
    fn generic_encode_reject() {
        let reject = RejectCore {
            ref_seq_num: 5,
            ref_msg_type: 0x01,
            reject_reason: 3,
            _pad: 0,
        };

        let mut flex_writer = crate::flex::FlexWriter::new();
        flex_writer.put_string(1, "Unknown instrument");
        let flex_data = flex_writer.build();

        let mut buffer = MessageBuffer::with_capacity(256);
        buffer.encode(0, 1, &reject, Some(&flex_data));

        let msg = buffer.as_slice();
        let header = MessageBuffer::decode_full_header(msg);
        assert_eq!(header.message.schema_id, 0x0001);
        assert_eq!(header.message.message_type, 0x10);

        let decoded: &RejectCore = MessageBuffer::decode(msg);
        assert_eq!(decoded.ref_seq_num, 5);
        assert_eq!(decoded.reject_reason, 3);

        let flex = MessageBuffer::decode_flex(msg, RejectCore::SIZE).unwrap();
        assert_eq!(flex.get_string(1), Some("Unknown instrument"));
    }

    #[test]
    fn generic_encode_subscribe() {
        let sub = SubscribeCore {
            request_id: 1,
            instrument_id: 42,
            sub_type: 1,
            depth: 10,
            _pad: [0; 2],
            _pad2: 0,
        };

        let mut buffer = MessageBuffer::with_capacity(256);
        buffer.encode(0, 1, &sub, None);

        let msg = buffer.as_slice();
        let header = MessageBuffer::decode_full_header(msg);
        assert_eq!(header.message.schema_id, 0x0002);
        assert_eq!(header.message.message_type, 0x10);

        let decoded: &SubscribeCore = MessageBuffer::decode(msg);
        assert_eq!(decoded.instrument_id, 42);
        assert_eq!(decoded.depth, 10);
    }

    #[test]
    fn dispatch_all_trading_messages() {
        // NewOrder
        let order = NewOrderSingleCore {
            order_id: 42,
            instrument_id: 1,
            side: Side::Buy as u8,
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(10.0),
            stop_price: Decimal::NULL,
        };
        let mut buf = MessageBuffer::with_capacity(256);
        buf.encode(1, 1, &order, None);
        assert!(matches!(dispatch_message(buf.as_slice()), MessageKind::NewOrder(o) if o.order_id == 42));

        // Reject
        let reject = RejectCore {
            ref_seq_num: 1,
            ref_msg_type: 0x01,
            reject_reason: 1,
            _pad: 0,
        };
        buf.reset();
        buf.encode(0, 1, &reject, None);
        assert!(matches!(dispatch_message(buf.as_slice()), MessageKind::Reject(r) if r.reject_reason == 1));

        // BusinessReject
        let biz = BusinessRejectCore {
            ref_seq_num: 2,
            ref_msg_type: 0x01,
            business_reason: 5,
            order_id: 100,
        };
        buf.reset();
        buf.encode(0, 1, &biz, None);
        assert!(matches!(dispatch_message(buf.as_slice()), MessageKind::BusinessReject(b) if b.business_reason == 5));
    }

    #[test]
    fn dispatch_market_data_subscribe() {
        let sub = SubscribeCore {
            request_id: 1,
            instrument_id: 42,
            sub_type: 1,
            depth: 0,
            _pad: [0; 2],
            _pad2: 0,
        };
        let mut buf = MessageBuffer::with_capacity(256);
        buf.encode(0, 1, &sub, None);
        assert!(matches!(dispatch_message(buf.as_slice()), MessageKind::Subscribe(s) if s.instrument_id == 42));
    }

    // ── Safety tests ──────────────────────────────────────────

    #[test]
    fn dispatch_empty_buffer_returns_malformed() {
        assert!(matches!(dispatch_message(&[]), MessageKind::Malformed));
    }

    #[test]
    fn dispatch_short_buffer_returns_malformed() {
        // 23 bytes = too short for FullHeader (24)
        assert!(matches!(dispatch_message(&[0u8; 23]), MessageKind::Malformed));
    }

    #[test]
    fn dispatch_header_only_returns_malformed() {
        // Valid header but no core block data
        let order = NewOrderSingleCore {
            order_id: 1, instrument_id: 1, side: 1, order_type: 1,
            time_in_force: 1, price: Decimal::ZERO, quantity: Decimal::ZERO,
            stop_price: Decimal::NULL,
        };
        let mut buf = MessageBuffer::with_capacity(256);
        buf.encode(1, 1, &order, None);
        // Truncate to just the header
        let header_only = &buf.as_slice()[..CORE_BLOCK_OFFSET];
        assert!(matches!(dispatch_message(header_only), MessageKind::Malformed));
    }

    #[test]
    fn try_from_bytes_none_on_short_buffer() {
        use crate::frame::FrameHeader;
        use crate::header::FullHeader;

        // Use Vec (heap-allocated, 8-byte aligned) — matches real transport buffers.
        assert!(FrameHeader::try_from_bytes(&[]).is_none());
        assert!(FrameHeader::try_from_bytes(&vec![0u8; 7]).is_none());
        // FrameHeader::try_from_bytes checks magic bytes
        {
            let mut valid = vec![0u8; 8];
            valid[0..2].copy_from_slice(&crate::frame::MAGIC.to_le_bytes());
            assert!(FrameHeader::try_from_bytes(&valid).is_some());
        }

        assert!(FullHeader::try_from_bytes(&[]).is_none());
        assert!(FullHeader::try_from_bytes(&vec![0u8; 31]).is_none());
        // FullHeader::try_from_bytes also checks magic
        {
            let mut valid = vec![0u8; 32];
            valid[0..2].copy_from_slice(&crate::frame::MAGIC.to_le_bytes());
            assert!(FullHeader::try_from_bytes(&valid).is_some());
        }

        assert!(NewOrderSingleCore::try_from_bytes(&[]).is_none());
        assert!(NewOrderSingleCore::try_from_bytes(&vec![0u8; 39]).is_none());
        assert!(NewOrderSingleCore::try_from_bytes(&vec![0u8; 40]).is_some());

        assert!(ExecutionReportCore::try_from_bytes(&[]).is_none());
        assert!(ExecutionReportCore::try_from_bytes(&vec![0u8; 79]).is_none());
        assert!(ExecutionReportCore::try_from_bytes(&vec![0u8; 80]).is_some());

        assert!(RejectCore::try_from_bytes(&[]).is_none());
        assert!(RejectCore::try_from_bytes(&vec![0u8; 7]).is_none());
        assert!(RejectCore::try_from_bytes(&vec![0u8; 8]).is_some());
    }

    #[test]
    fn flex_reader_handles_lying_count() {
        // Declare 100 fields but only provide 10 bytes total
        let mut buf = vec![0u8; 10];
        buf[0] = 100; // count = 100
        buf[1] = 0;
        let reader = crate::flex::FlexReader::new(&buf);
        // Should clamp count, not panic
        assert!(reader.count() < 100);
        assert_eq!(reader.get_string(1), None);
        assert_eq!(reader.get_u64(1), None);
    }

    #[test]
    fn legacy_encode_new_order_still_works() {
        let order = NewOrderSingleCore {
            order_id: 1,
            instrument_id: 1,
            side: Side::Buy as u8,
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(10.0),
            stop_price: Decimal::NULL,
        };
        let mut buf = MessageBuffer::with_capacity(256);
        let len = buf.encode_new_order(1, 1, &order, None);
        assert_eq!(len, 72);
    }
}
