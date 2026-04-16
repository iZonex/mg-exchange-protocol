//! MGEP message definitions — core block structs + optional field accessors.
//!
//! Each struct is generated via `define_core!` (from core_macro.rs) and provides
//! zero-copy `from_bytes` / `as_bytes` plus SIZE, MESSAGE_TYPE, SCHEMA_ID consts.

use crate::types::*;

// ── Enums not in types.rs ──────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OrderStatus {
    New = 1,
    PartiallyFilled = 2,
    Filled = 3,
    Canceled = 4,
    Rejected = 5,
    Expired = 6,
}

impl OrderStatus {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::New),
            2 => Some(Self::PartiallyFilled),
            3 => Some(Self::Filled),
            4 => Some(Self::Canceled),
            5 => Some(Self::Rejected),
            6 => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TradingPhase {
    PreOpen = 1,
    Opening = 2,
    Continuous = 3,
    Closing = 4,
    PostClose = 5,
    Halt = 6,
}

impl TradingPhase {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PreOpen),
            2 => Some(Self::Opening),
            3 => Some(Self::Continuous),
            4 => Some(Self::Closing),
            5 => Some(Self::PostClose),
            6 => Some(Self::Halt),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SubscriptionType {
    /// Full depth order-by-order feed
    OrderByOrder = 1,
    /// Best bid/ask only
    TopOfBook = 2,
    /// Trade reports only
    Trades = 3,
    /// Statistics updates only
    Stats = 4,
}

impl SubscriptionType {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::OrderByOrder),
            2 => Some(Self::TopOfBook),
            3 => Some(Self::Trades),
            4 => Some(Self::Stats),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TradeReportType {
    Submit = 1,
    Alleged = 2,
    Accept = 3,
    Decline = 4,
    Cancel = 5,
    Replace = 6,
}

impl TradeReportType {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Submit),
            2 => Some(Self::Alleged),
            3 => Some(Self::Accept),
            4 => Some(Self::Decline),
            5 => Some(Self::Cancel),
            6 => Some(Self::Replace),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AllocStatus {
    Accepted = 1,
    Rejected = 2,
    Partial = 3,
    Pending = 4,
}

impl AllocStatus {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Accepted),
            2 => Some(Self::Rejected),
            3 => Some(Self::Partial),
            4 => Some(Self::Pending),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SettlementStatusEnum {
    Pending = 1,
    Settled = 2,
    Failed = 3,
    Canceled = 4,
}

impl SettlementStatusEnum {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Pending),
            2 => Some(Self::Settled),
            3 => Some(Self::Failed),
            4 => Some(Self::Canceled),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QuoteRejectReason {
    UnknownInstrument = 1,
    InvalidPrice = 2,
    InvalidQuantity = 3,
    StaleQuote = 4,
    NotEntitled = 5,
    RateLimit = 6,
}

impl QuoteRejectReason {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::UnknownInstrument),
            2 => Some(Self::InvalidPrice),
            3 => Some(Self::InvalidQuantity),
            4 => Some(Self::StaleQuote),
            5 => Some(Self::NotEntitled),
            6 => Some(Self::RateLimit),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IOIType {
    New = 1,
    Cancel = 2,
    Replace = 3,
}

impl IOIType {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::New),
            2 => Some(Self::Cancel),
            3 => Some(Self::Replace),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CollateralAction {
    Deposit = 1,
    Withdraw = 2,
    Transfer = 3,
}

impl CollateralAction {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Deposit),
            2 => Some(Self::Withdraw),
            3 => Some(Self::Transfer),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MarginCallAction {
    /// Margin utilization report
    Info = 1,
    /// Approaching threshold
    Warning = 2,
    /// Must deposit or reduce position
    Call = 3,
    /// Forced liquidation in progress
    Liquidation = 4,
}

impl MarginCallAction {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Info),
            2 => Some(Self::Warning),
            3 => Some(Self::Call),
            4 => Some(Self::Liquidation),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CancelRejectReason {
    /// Order not found
    UnknownOrder = 1,
    /// Order already filled or expired
    TooLateToCancel = 2,
    /// Cancel/replace already in progress
    OrderAlreadyPending = 3,
    /// This cancel_id already used
    DuplicateRequest = 4,
    /// Instrument mismatch
    InvalidInstrument = 5,
    /// Not authorized to cancel this order
    NotAuthorized = 6,
}

impl CancelRejectReason {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::UnknownOrder),
            2 => Some(Self::TooLateToCancel),
            3 => Some(Self::OrderAlreadyPending),
            4 => Some(Self::DuplicateRequest),
            5 => Some(Self::InvalidInstrument),
            6 => Some(Self::NotAuthorized),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════
// trading (schema_id = 0x0001)
// ═══════════════════════════════════════════════

define_core!(
    /// Submit a new order to the exchange. — 40 bytes.
    NewOrderSingleCore, schema=0x0001, msg_type=0x01, size=40,
    {
        /// Exchange-assigned order ID
        pub order_id: u64,
        /// Target instrument
        pub instrument_id: u32,
        pub side: u8,
        pub order_type: u8,
        pub time_in_force: u16,
        /// Required for limit orders, null for market
        pub price: Decimal,
        /// Order quantity, must be > 0
        pub quantity: Decimal,
        /// Trigger price for stop orders
        pub stop_price: Decimal,
    }
);

impl NewOrderSingleCore {
    /// Parse the `side` field as a `Side` enum.
    #[inline(always)]
    pub fn side(&self) -> Option<Side> {
        Side::from_u8(self.side)
    }

    /// Parse the `order_type` field as an `OrderType` enum.
    #[inline(always)]
    pub fn order_type(&self) -> Option<OrderType> {
        OrderType::from_u8(self.order_type)
    }

    /// Parse the `time_in_force` field as a `TimeInForce` enum.
    #[inline(always)]
    pub fn time_in_force(&self) -> Option<TimeInForce> {
        TimeInForce::from_u16(self.time_in_force)
    }
}

/// Optional field accessor for `NewOrderSingle`.
pub struct NewOrderSingleOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> NewOrderSingleOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Trading account
    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// Client-assigned unique order ID
    pub fn client_order_id(&self) -> Option<&'a str> { self.reader.get_string(2) }

    /// Free-form client tag
    pub fn client_tag(&self) -> Option<&'a str> { self.reader.get_string(3) }

    /// Iceberg: visible quantity
    pub fn max_show(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(4) }

    /// GTD: expiration time
    pub fn expire_time(&self) -> Option<u64> { self.reader.get_u64(5) }

    /// STP group ID
    pub fn self_trade_prevention_id(&self) -> Option<u64> { self.reader.get_u64(6) }

    /// Legal Entity Identifier (20 chars)
    pub fn lei(&self) -> Option<&'a str> { self.reader.get_string(7) }

    /// Agency, Principal, RisklessPrincipal
    pub fn order_capacity(&self) -> Option<&'a str> { self.reader.get_string(8) }

    /// true = short sale
    pub fn short_selling(&self) -> Option<u64> { self.reader.get_u64(9) }

    /// Algorithm identifier
    pub fn algo_id(&self) -> Option<&'a str> { self.reader.get_string(10) }

    /// Person/algo making the decision
    pub fn investment_decision_maker(&self) -> Option<&'a str> { self.reader.get_string(11) }
}

define_core!(
    /// Request to cancel an existing order. — 24 bytes.
    OrderCancelRequestCore, schema=0x0001, msg_type=0x02, size=24,
    {
        pub order_id: u64,
        /// Unique cancel request ID
        pub cancel_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub _pad: [u8; 3],
    }
);

define_core!(
    /// Replace an existing order (cancel + new atomically). — 48 bytes.
    OrderCancelReplaceRequestCore, schema=0x0001, msg_type=0x03, size=48,
    {
        /// Order to replace
        pub order_id: u64,
        /// Unique replace request ID
        pub replace_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub order_type: u8,
        pub time_in_force: u16,
        pub price: Decimal,
        pub quantity: Decimal,
        pub stop_price: Decimal,
    }
);

define_core!(
    /// Cancel all orders matching criteria. — 16 bytes.
    OrderMassCancelRequestCore, schema=0x0001, msg_type=0x04, size=16,
    {
        pub cancel_id: u64,
        /// 0 = all instruments
        pub instrument_id: u32,
        /// null = both sides
        pub side: u8,
        pub _pad: [u8; 3],
    }
);

define_core!(
    /// Acknowledges order actions: new, fill, cancel, reject. — 80 bytes.
    ExecutionReportCore, schema=0x0001, msg_type=0x05, size=80,
    {
        pub order_id: u64,
        /// Unique execution ID
        pub exec_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub exec_type: u8,
        pub order_status: u8,
        pub _pad: u8,
        pub price: Decimal,
        pub quantity: Decimal,
        /// Remaining quantity
        pub leaves_qty: Decimal,
        /// Cumulative filled quantity
        pub cum_qty: Decimal,
        /// Last fill price
        pub last_px: Decimal,
        /// Last fill quantity
        pub last_qty: Decimal,
        /// Exchange timestamp of this event
        pub transact_time: Timestamp,
    }
);

impl ExecutionReportCore {
    /// Parse the `exec_type` field as an `ExecType` enum.
    #[inline(always)]
    pub fn exec_type(&self) -> Option<ExecType> {
        ExecType::from_u8(self.exec_type)
    }
}

/// Optional field accessor for `ExecutionReport`.
pub struct ExecutionReportOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> ExecutionReportOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Human-readable message
    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// Trade ID for fills
    pub fn trade_id(&self) -> Option<u64> { self.reader.get_u64(2) }

    /// Transaction fee
    pub fn fee(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(3) }

    /// Fee currency (e.g. USD, BTC)
    pub fn fee_currency(&self) -> Option<&'a str> { self.reader.get_string(4) }

    /// Venue execution ID for regulatory reporting
    pub fn venue_exec_id(&self) -> Option<&'a str> { self.reader.get_string(5) }

    /// Regulatory transaction report ID
    pub fn regulatory_report_id(&self) -> Option<&'a str> { self.reader.get_string(6) }

    /// Regular, LateReport, OutOfSequence
    pub fn trade_condition(&self) -> Option<&'a str> { self.reader.get_string(7) }
}

define_core!(
    /// Cancel or replace was rejected. — 24 bytes.
    OrderCancelRejectCore, schema=0x0001, msg_type=0x06, size=24,
    {
        pub order_id: u64,
        pub cancel_id: u64,
        pub reason: u8,
        pub _pad: [u8; 7],
    }
);

/// Optional field accessor for `OrderCancelReject`.
pub struct OrderCancelRejectOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> OrderCancelRejectOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Human-readable explanation
    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

define_core!(
    /// Query current state of an order. Response = ExecutionReport. — 16 bytes.
    OrderStatusRequestCore, schema=0x0001, msg_type=0x07, size=16,
    {
        pub order_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub _pad: [u8; 3],
    }
);

/// Optional field accessor for `OrderStatusRequest`.
pub struct OrderStatusRequestOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> OrderStatusRequestOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

define_core!(
    /// Response to mass cancel request. — 24 bytes.
    OrderMassCancelReportCore, schema=0x0001, msg_type=0x08, size=24,
    {
        pub cancel_id: u64,
        pub instrument_id: u32,
        pub accepted: u8,
        pub _pad: [u8; 3],
        /// Number of orders canceled
        pub total_affected: u32,
        pub _pad2: [u8; 4],
    }
);

/// Optional field accessor for `OrderMassCancelReport`.
pub struct OrderMassCancelReportOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> OrderMassCancelReportOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn reject_reason(&self) -> Option<&'a str> { self.reader.get_string(2) }
}

define_core!(
    /// Pre-arranged cross trade (two sides matched at one price). — 40 bytes.
    NewOrderCrossCore, schema=0x0001, msg_type=0x09, size=40,
    {
        pub cross_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
        pub price: Decimal,
        pub buy_quantity: Decimal,
        pub sell_quantity: Decimal,
    }
);

/// Optional field accessor for `NewOrderCross`.
pub struct NewOrderCrossOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> NewOrderCrossOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn buy_account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn sell_account(&self) -> Option<&'a str> { self.reader.get_string(2) }
}

define_core!(
    /// Query all open orders.
    OrderMassStatusRequestCore, schema=0x0001, msg_type=0x0A, size=16,
    {
        pub request_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub _pad: [u8; 3],
    }
);

define_core!(
    /// Cancel a cross order.
    CrossOrderCancelRequestCore, schema=0x0001, msg_type=0x0B, size=24,
    {
        pub cross_id: u64,
        pub cancel_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
    }
);

define_core!(
    /// Session-level reject: message was malformed or violated protocol. — 8 bytes.
    RejectCore, schema=0x0001, msg_type=0x10, size=8,
    {
        /// Sequence of rejected message
        pub ref_seq_num: u32,
        pub ref_msg_type: u8,
        pub reject_reason: u8,
        pub _pad: u16,
    }
);

/// Optional field accessor for `Reject`.
pub struct RejectOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> RejectOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// Which field caused the reject
    pub fn ref_field(&self) -> Option<&'a str> { self.reader.get_string(2) }
}

define_core!(
    /// Application-level reject: message was valid but cannot be processed. — 16 bytes.
    BusinessRejectCore, schema=0x0001, msg_type=0x11, size=16,
    {
        pub ref_seq_num: u32,
        pub ref_msg_type: u8,
        pub business_reason: u8,
        /// Related order, if any
        pub order_id: u64,
    }
);

/// Optional field accessor for `BusinessReject`.
pub struct BusinessRejectOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> BusinessRejectOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

// ═══════════════════════════════════════════════
// market_data (schema_id = 0x0002)
// ═══════════════════════════════════════════════

define_core!(
    /// New order added to the order book. — 32 bytes.
    OrderAddCore, schema=0x0002, msg_type=0x01, size=32,
    {
        pub order_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub _pad: [u8; 3],
        pub price: Decimal,
        pub quantity: Decimal,
    }
);

define_core!(
    /// Existing order price or quantity changed. — 24 bytes.
    OrderModifyCore, schema=0x0002, msg_type=0x02, size=24,
    {
        pub order_id: u64,
        pub new_price: Decimal,
        pub new_quantity: Decimal,
    }
);

define_core!(
    /// Order removed from the book. — 8 bytes.
    OrderDeleteCore, schema=0x0002, msg_type=0x03, size=8,
    {
        pub order_id: u64,
    }
);

define_core!(
    /// Order (partially) filled. — 32 bytes.
    OrderExecutedCore, schema=0x0002, msg_type=0x04, size=32,
    {
        pub order_id: u64,
        pub trade_id: u64,
        pub exec_price: Decimal,
        pub exec_quantity: Decimal,
    }
);

define_core!(
    /// Trade report. — 40 bytes.
    TradeCore, schema=0x0002, msg_type=0x05, size=40,
    {
        pub trade_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
        pub price: Decimal,
        pub quantity: Decimal,
        pub aggressor_side: u8,
        pub _pad2: [u8; 7],
    }
);

define_core!(
    /// Trading phase change for an instrument. — 8 bytes.
    TradingStatusCore, schema=0x0002, msg_type=0x08, size=8,
    {
        pub instrument_id: u32,
        pub phase: u8,
        pub _pad: [u8; 3],
    }
);

define_core!(
    /// Request market data for an instrument. — 24 bytes.
    SubscribeCore, schema=0x0002, msg_type=0x10, size=24,
    {
        pub request_id: u64,
        pub instrument_id: u32,
        pub sub_type: u8,
        pub _pad: [u8; 2],
        pub _pad2: u8,
        /// 0 = full book, N = top N levels
        pub depth: u32,
    }
);

define_core!(
    /// Cancel a market data subscription. — 16 bytes.
    UnsubscribeCore, schema=0x0002, msg_type=0x11, size=16,
    {
        pub request_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
    }
);

define_core!(
    /// Response to subscription request. — 16 bytes.
    SubscribeResponseCore, schema=0x0002, msg_type=0x12, size=16,
    {
        pub request_id: u64,
        pub accepted: u8,
        pub _pad: [u8; 7],
    }
);

/// Optional field accessor for `SubscribeResponse`.
pub struct SubscribeResponseOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> SubscribeResponseOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

define_core!(
    /// OHLCV + market statistics for an instrument. — 72 bytes.
    MarketStatisticsCore, schema=0x0002, msg_type=0x20, size=72,
    {
        pub instrument_id: u32,
        pub _pad: [u8; 4],
        pub open_price: Decimal,
        pub high_price: Decimal,
        pub low_price: Decimal,
        pub close_price: Decimal,
        pub vwap: Decimal,
        pub total_volume: Decimal,
        pub total_turnover: Decimal,
        pub open_interest: Decimal,
    }
);

/// Optional field accessor for `MarketStatistics`.
pub struct MarketStatisticsOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> MarketStatisticsOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn num_trades(&self) -> Option<u64> { self.reader.get_u64(1) }

    pub fn prev_close(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(2) }
}

define_core!(
    /// Full instrument reference data. — 40 bytes.
    InstrumentDefinitionCore, schema=0x0002, msg_type=0x0B, size=40,
    {
        pub instrument_id: u32,
        pub _pad: [u8; 4],
        pub tick_size: Decimal,
        pub lot_size: Decimal,
        pub min_price: Decimal,
        pub max_price: Decimal,
    }
);

/// Optional field accessor for `InstrumentDefinition`.
pub struct InstrumentDefinitionOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> InstrumentDefinitionOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Ticker symbol (e.g. BTCUSD)
    pub fn symbol(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// Full instrument name
    pub fn name(&self) -> Option<&'a str> { self.reader.get_string(2) }

    /// Quote currency
    pub fn currency(&self) -> Option<&'a str> { self.reader.get_string(3) }

    /// Exchange code
    pub fn exchange(&self) -> Option<&'a str> { self.reader.get_string(4) }

    /// ISIN code (TradFi)
    pub fn isin(&self) -> Option<&'a str> { self.reader.get_string(5) }
}

define_core!(
    /// Query available instruments. — 8 bytes.
    SecurityListRequestCore, schema=0x0002, msg_type=0x21, size=8,
    {
        pub request_id: u64,
    }
);

/// Optional field accessor for `SecurityListRequest`.
pub struct SecurityListRequestOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> SecurityListRequestOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Wildcard filter (e.g. BTC*)
    pub fn symbol_filter(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn exchange_filter(&self) -> Option<&'a str> { self.reader.get_string(2) }
}

define_core!(
    /// Instruments follow as individual InstrumentDefinition messages. — 16 bytes.
    SecurityListResponseCore, schema=0x0002, msg_type=0x22, size=16,
    {
        pub request_id: u64,
        pub total_instruments: u32,
        pub accepted: u8,
        pub _pad: [u8; 3],
    }
);

/// Optional field accessor for `SecurityListResponse`.
pub struct SecurityListResponseOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> SecurityListResponseOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

// ═══════════════════════════════════════════════
// quotes (schema_id = 0x0003)
// ═══════════════════════════════════════════════

define_core!(
    /// Request for quote — ask a market maker for a price. — 24 bytes.
    QuoteRequestCore, schema=0x0003, msg_type=0x01, size=24,
    {
        pub request_id: u64,
        pub instrument_id: u32,
        /// Buy/Sell/null (both sides)
        pub side: u8,
        pub _pad: [u8; 3],
        pub quantity: Decimal,
    }
);

/// Optional field accessor for `QuoteRequest`.
pub struct QuoteRequestOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> QuoteRequestOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// T+1, T+2, instant
    pub fn settlement_type(&self) -> Option<&'a str> { self.reader.get_string(2) }

    pub fn expire_time(&self) -> Option<u64> { self.reader.get_u64(3) }
}

define_core!(
    /// Single-instrument quote (response to RFQ or unsolicited). — 64 bytes.
    QuoteCore, schema=0x0003, msg_type=0x02, size=64,
    {
        pub quote_id: u64,
        /// 0 if unsolicited
        pub request_id: u64,
        pub instrument_id: u32,
        pub _pad: u32,
        pub bid_price: Decimal,
        pub bid_quantity: Decimal,
        pub ask_price: Decimal,
        pub ask_quantity: Decimal,
        /// Quote expiration
        pub valid_until: Timestamp,
    }
);

/// Optional field accessor for `Quote`.
pub struct QuoteOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> QuoteOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// firm, indicative
    pub fn condition(&self) -> Option<&'a str> { self.reader.get_string(2) }

    pub fn settlement_type(&self) -> Option<&'a str> { self.reader.get_string(3) }
}

define_core!(
    /// Update an existing quote without cancel+requote. — 56 bytes.
    QuoteReplaceCore, schema=0x0003, msg_type=0x03, size=56,
    {
        pub quote_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
        pub bid_price: Decimal,
        pub bid_quantity: Decimal,
        pub ask_price: Decimal,
        pub ask_quantity: Decimal,
        pub valid_until: Timestamp,
    }
);

define_core!(
    /// Cancel one or all quotes. — 16 bytes.
    QuoteCancelCore, schema=0x0003, msg_type=0x04, size=16,
    {
        /// Specific quote, or 0 for mass
        pub quote_id: u64,
        /// 0 if cancel-all
        pub instrument_id: u32,
        /// true = cancel all quotes
        pub cancel_all: u8,
        pub _pad: [u8; 3],
    }
);

define_core!(
    /// Market maker: update quotes for many instruments at once. — 16 bytes.
    MassQuoteCore, schema=0x0003, msg_type=0x05, size=16,
    {
        /// Batch identifier
        pub quote_id: u64,
        /// Number of entries in payload
        pub num_entries: u32,
        pub _pad: [u8; 4],
    }
);

/// Optional field accessor for `MassQuote`.
pub struct MassQuoteOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> MassQuoteOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

define_core!(
    /// Acknowledgment of mass quote. — 24 bytes.
    MassQuoteAckCore, schema=0x0003, msg_type=0x06, size=24,
    {
        pub quote_id: u64,
        pub accepted: u8,
        pub _pad: [u8; 3],
        pub num_accepted: u32,
        pub num_rejected: u32,
        pub _pad2: [u8; 4],
    }
);

/// Optional field accessor for `MassQuoteAck`.
pub struct MassQuoteAckOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> MassQuoteAckOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

define_core!(
    /// Query quote status. — 16 bytes.
    QuoteStatusRequestCore, schema=0x0003, msg_type=0x07, size=16,
    {
        pub quote_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
    }
);

define_core!(
    /// Indication of Interest — signal intent to trade. — 40 bytes.
    IOICore, schema=0x0003, msg_type=0x10, size=40,
    {
        pub ioi_id: u64,
        pub instrument_id: u32,
        pub ioi_type: u8,
        pub side: u8,
        pub _pad: [u8; 2],
        /// null = at market
        pub price: Decimal,
        pub quantity: Decimal,
        pub valid_until: Timestamp,
    }
);

/// Optional field accessor for `IOI`.
pub struct IOIOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> IOIOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(2) }

    /// true = natural order flow
    pub fn natural(&self) -> Option<u64> { self.reader.get_u64(3) }
}

// ═══════════════════════════════════════════════
// post_trade (schema_id = 0x0004)
// ═══════════════════════════════════════════════

define_core!(
    /// Post-trade confirmation for clearing/settlement. — 48 bytes.
    TradeCaptureReportCore, schema=0x0004, msg_type=0x01, size=48,
    {
        pub trade_report_id: u64,
        pub trade_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub report_type: u8,
        pub _pad: [u8; 2],
        pub price: Decimal,
        pub quantity: Decimal,
        pub exec_time: Timestamp,
    }
);

/// Optional field accessor for `TradeCaptureReport`.
pub struct TradeCaptureReportOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> TradeCaptureReportOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Counterparty firm
    pub fn contra_firm(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(2) }

    /// YYYYMMDD
    pub fn settlement_date(&self) -> Option<&'a str> { self.reader.get_string(3) }

    pub fn fee(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(4) }

    pub fn fee_currency(&self) -> Option<&'a str> { self.reader.get_string(5) }

    /// regular, late, OTC
    pub fn trade_condition(&self) -> Option<&'a str> { self.reader.get_string(6) }
}

define_core!(
    /// Query trade history. — 24 bytes.
    TradeCaptureReportRequestCore, schema=0x0004, msg_type=0x02, size=24,
    {
        pub request_id: u64,
        /// 0 = all trades matching filters
        pub trade_id: u64,
        /// 0 = all instruments
        pub instrument_id: u32,
        pub _pad: [u8; 4],
    }
);

/// Optional field accessor for `TradeCaptureReportRequest`.
pub struct TradeCaptureReportRequestOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> TradeCaptureReportRequestOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn start_time(&self) -> Option<u64> { self.reader.get_u64(2) }

    pub fn end_time(&self) -> Option<u64> { self.reader.get_u64(3) }
}

define_core!(
    /// Split fills across sub-accounts (institutional workflow). — 48 bytes.
    AllocationInstructionCore, schema=0x0004, msg_type=0x10, size=48,
    {
        pub alloc_id: u64,
        pub trade_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub _pad: [u8; 3],
        pub total_quantity: Decimal,
        pub avg_price: Decimal,
        pub num_allocs: u32,
        pub _pad2: [u8; 4],
    }
);

/// Optional field accessor for `AllocationInstruction`.
pub struct AllocationInstructionOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> AllocationInstructionOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(2) }

    pub fn settlement_date(&self) -> Option<&'a str> { self.reader.get_string(3) }
}

define_core!(
    /// Response to allocation instruction. — 24 bytes.
    AllocationReportCore, schema=0x0004, msg_type=0x11, size=24,
    {
        pub alloc_id: u64,
        pub alloc_report_id: u64,
        pub status: u8,
        pub _pad: [u8; 7],
    }
);

/// Optional field accessor for `AllocationReport`.
pub struct AllocationReportOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> AllocationReportOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn reject_reason(&self) -> Option<&'a str> { self.reader.get_string(2) }
}

define_core!(
    /// Trade confirmation for a specific allocation. — 64 bytes.
    ConfirmationCore, schema=0x0004, msg_type=0x20, size=64,
    {
        pub confirm_id: u64,
        pub trade_id: u64,
        pub alloc_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub confirmed: u8,
        pub _pad: [u8; 2],
        pub quantity: Decimal,
        pub price: Decimal,
        pub gross_amount: Decimal,
        pub net_amount: Decimal,
    }
);

/// Optional field accessor for `Confirmation`.
pub struct ConfirmationOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> ConfirmationOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn settlement_date(&self) -> Option<&'a str> { self.reader.get_string(2) }

    pub fn commission(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(3) }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(4) }
}

define_core!(
    /// Acknowledge or dispute a confirmation.
    ConfirmationAckCore, schema=0x0004, msg_type=0x21, size=24,
    {
        pub confirm_id: u64,
        pub trade_id: u64,
        pub confirmed: u8,
        pub _pad: [u8; 7],
    }
);

define_core!(
    /// Settlement instruction — works for DVP, FOP, and on-chain. — 48 bytes.
    SettlementInstructionCore, schema=0x0004, msg_type=0x30, size=48,
    {
        pub settl_id: u64,
        pub trade_id: u64,
        pub instrument_id: u32,
        pub side: u8,
        pub _pad: [u8; 3],
        pub quantity: Decimal,
        pub price: Decimal,
        pub settlement_amount: Decimal,
    }
);

/// Optional field accessor for `SettlementInstruction`.
pub struct SettlementInstructionOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> SettlementInstructionOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn account(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn settlement_date(&self) -> Option<&'a str> { self.reader.get_string(2) }

    pub fn currency(&self) -> Option<&'a str> { self.reader.get_string(3) }

    /// DVP, FOP, onchain
    pub fn delivery_method(&self) -> Option<&'a str> { self.reader.get_string(4) }

    /// Crypto: wallet address
    pub fn chain_address(&self) -> Option<&'a str> { self.reader.get_string(5) }

    /// Crypto: chain ID (ETH=1)
    pub fn chain_id(&self) -> Option<u64> { self.reader.get_u64(6) }
}

define_core!(
    /// Settlement status update. — 24 bytes.
    SettlementStatusCore, schema=0x0004, msg_type=0x31, size=24,
    {
        pub settl_id: u64,
        pub trade_id: u64,
        pub status: u8,
        pub _pad: [u8; 7],
    }
);

/// Optional field accessor for `SettlementStatus`.
pub struct SettlementStatusOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> SettlementStatusOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// Crypto: on-chain transaction hash
    pub fn tx_hash(&self) -> Option<&'a str> { self.reader.get_string(2) }

    pub fn settled_time(&self) -> Option<u64> { self.reader.get_u64(3) }
}

// ═══════════════════════════════════════════════
// risk (schema_id = 0x0005)
// ═══════════════════════════════════════════════

define_core!(
    /// Query account positions. — 24 bytes.
    RequestForPositionsCore, schema=0x0005, msg_type=0x01, size=24,
    {
        pub request_id: u64,
        pub account_id: u64,
        /// 0 = all instruments
        pub instrument_id: u32,
        pub _pad: [u8; 4],
    }
);

define_core!(
    /// Account position for an instrument. — 80 bytes.
    PositionReportCore, schema=0x0005, msg_type=0x02, size=80,
    {
        pub report_id: u64,
        /// 0 if push (unsolicited)
        pub request_id: u64,
        pub account_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
        pub long_quantity: Decimal,
        pub short_quantity: Decimal,
        pub net_quantity: Decimal,
        pub avg_entry_price: Decimal,
        pub unrealized_pnl: Decimal,
        pub realized_pnl: Decimal,
    }
);

/// Optional field accessor for `PositionReport`.
pub struct PositionReportOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> PositionReportOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Crypto: forced liquidation price
    pub fn liquidation_price(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(1) }

    /// Margin allocated to this position
    pub fn margin_used(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(2) }

    /// Crypto perps: current funding rate
    pub fn funding_rate(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(3) }

    /// Mark price for P&L calculation
    pub fn mark_price(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(4) }

    pub fn currency(&self) -> Option<&'a str> { self.reader.get_string(5) }
}

define_core!(
    /// Query account balances and collateral. — 16 bytes.
    CollateralInquiryCore, schema=0x0005, msg_type=0x10, size=16,
    {
        pub request_id: u64,
        pub account_id: u64,
    }
);

/// Optional field accessor for `CollateralInquiry`.
pub struct CollateralInquiryOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> CollateralInquiryOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// Filter by currency
    pub fn currency(&self) -> Option<&'a str> { self.reader.get_string(1) }
}

define_core!(
    /// Account collateral and margin summary. — 56 bytes.
    CollateralReportCore, schema=0x0005, msg_type=0x11, size=56,
    {
        pub report_id: u64,
        pub request_id: u64,
        pub account_id: u64,
        /// Total collateral in base currency
        pub total_value: Decimal,
        /// Available after margin
        pub available: Decimal,
        pub margin_used: Decimal,
        /// Utilization: margin / total
        pub margin_ratio: Decimal,
    }
);

/// Optional field accessor for `CollateralReport`.
pub struct CollateralReportOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> CollateralReportOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn currency(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// In open orders
    pub fn locked_balance(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(2) }
}

define_core!(
    /// Deposit, withdraw, or transfer collateral. — 32 bytes.
    CollateralRequestCore, schema=0x0005, msg_type=0x12, size=32,
    {
        pub request_id: u64,
        pub account_id: u64,
        pub action: u8,
        pub _pad: [u8; 7],
        pub amount: Decimal,
    }
);

/// Optional field accessor for `CollateralRequest`.
pub struct CollateralRequestOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> CollateralRequestOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn currency(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// For transfers
    pub fn target_account(&self) -> Option<&'a str> { self.reader.get_string(2) }

    /// Crypto: withdrawal address
    pub fn chain_address(&self) -> Option<&'a str> { self.reader.get_string(3) }

    /// Crypto: chain ID
    pub fn chain_id(&self) -> Option<u64> { self.reader.get_u64(4) }
}

define_core!(
    /// Response to collateral request. — 16 bytes.
    CollateralRequestAckCore, schema=0x0005, msg_type=0x13, size=16,
    {
        pub request_id: u64,
        pub accepted: u8,
        pub _pad: [u8; 7],
    }
);

/// Optional field accessor for `CollateralRequestAck`.
pub struct CollateralRequestAckOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> CollateralRequestAckOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn reject_reason(&self) -> Option<&'a str> { self.reader.get_string(2) }

    /// Crypto: on-chain tx hash
    pub fn tx_hash(&self) -> Option<&'a str> { self.reader.get_string(3) }
}

define_core!(
    /// Query margin requirements. — 24 bytes.
    MarginRequirementInquiryCore, schema=0x0005, msg_type=0x20, size=24,
    {
        pub request_id: u64,
        pub account_id: u64,
        /// 0 = portfolio level
        pub instrument_id: u32,
        pub _pad: [u8; 4],
    }
);

define_core!(
    /// Margin requirement breakdown. — 64 bytes.
    MarginRequirementReportCore, schema=0x0005, msg_type=0x21, size=64,
    {
        pub report_id: u64,
        pub request_id: u64,
        pub account_id: u64,
        pub instrument_id: u32,
        pub _pad: [u8; 4],
        /// To open position
        pub initial_margin: Decimal,
        /// To maintain position
        pub maintenance_margin: Decimal,
        /// Mark-to-market P&L
        pub variation_margin: Decimal,
        pub total_margin: Decimal,
    }
);

/// Optional field accessor for `MarginRequirementReport`.
pub struct MarginRequirementReportOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> MarginRequirementReportOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    /// SPAN, VaR, cross, isolated
    pub fn margin_model(&self) -> Option<&'a str> { self.reader.get_string(1) }

    pub fn currency(&self) -> Option<&'a str> { self.reader.get_string(2) }
}

define_core!(
    /// Margin call notification. — 40 bytes.
    MarginCallCore, schema=0x0005, msg_type=0x22, size=40,
    {
        pub call_id: u64,
        pub account_id: u64,
        pub action: u8,
        pub _pad: [u8; 7],
        /// Amount to deposit
        pub margin_deficit: Decimal,
        /// When liquidation starts
        pub deadline: Timestamp,
    }
);

/// Optional field accessor for `MarginCall`.
pub struct MarginCallOptional<'a> {
    reader: crate::flex::FlexReader<'a>,
}

impl<'a> MarginCallOptional<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { reader: crate::flex::FlexReader::new(buf) }
    }

    pub fn text(&self) -> Option<&'a str> { self.reader.get_string(1) }

    /// % of position to be liquidated
    pub fn liquidation_pct(&self) -> Option<crate::types::Decimal> { self.reader.get_decimal(2) }
}
