//! Ergonomic Message Builders — fluent API for constructing MGEP messages.
//!
//! Instead of:
//!   let order = NewOrderSingleCore { order_id: 42, client_order_id: 0, instrument_id: 7, side: 1, ... };
//!   let mut enc = MessageBuffer::with_capacity(256);
//!   enc.encode(1, seq, &order, Some(&flex));
//!
//! You write:
//!   let msg = OrderBuilder::new(42, 7)
//!       .buy().limit(150.25).quantity(100.0)
//!       .account("ACC001").client_tag("my-tag")
//!       .build(&mut buf);

use crate::codec::MessageBuffer;
use crate::flex::FlexWriter;
use crate::messages::*;
use crate::types::*;

/// Builder for NewOrderSingle messages.
pub struct OrderBuilder {
    core: NewOrderSingleCore,
    flex: FlexWriter,
    sender_comp_id: u32,
}

impl OrderBuilder {
    /// Start building a new order.
    pub fn new(order_id: u64, instrument_id: u32) -> Self {
        Self {
            core: NewOrderSingleCore {
                order_id,
                client_order_id: 0,
                instrument_id,
                side: Side::Buy as u8,
                order_type: OrderType::Limit as u8,
                time_in_force: TimeInForce::Day as u16,
                price: Decimal::NULL,
                quantity: Decimal::ZERO,
                stop_price: Decimal::NULL,
            },
            flex: FlexWriter::new(),
            sender_comp_id: 1,
        }
    }

    pub fn buy(mut self) -> Self { self.core.side = Side::Buy as u8; self }
    pub fn sell(mut self) -> Self { self.core.side = Side::Sell as u8; self }
    pub fn limit(mut self, price: f64) -> Self {
        self.core.order_type = OrderType::Limit as u8;
        self.core.price = Decimal::from_f64(price);
        self
    }
    pub fn market(mut self) -> Self {
        self.core.order_type = OrderType::Market as u8;
        self.core.price = Decimal::NULL;
        self
    }
    pub fn stop(mut self, price: f64) -> Self {
        self.core.order_type = OrderType::Stop as u8;
        self.core.stop_price = Decimal::from_f64(price);
        self
    }
    pub fn quantity(mut self, qty: f64) -> Self {
        self.core.quantity = Decimal::from_f64(qty);
        self
    }
    pub fn tif_day(mut self) -> Self { self.core.time_in_force = TimeInForce::Day as u16; self }
    pub fn tif_gtc(mut self) -> Self { self.core.time_in_force = TimeInForce::GTC as u16; self }
    pub fn tif_ioc(mut self) -> Self { self.core.time_in_force = TimeInForce::IOC as u16; self }
    pub fn tif_fok(mut self) -> Self { self.core.time_in_force = TimeInForce::FOK as u16; self }
    pub fn sender(mut self, id: u32) -> Self { self.sender_comp_id = id; self }
    /// Set the client-assigned order ID. Required for idempotent retry.
    pub fn client_order_id(mut self, id: u64) -> Self { self.core.client_order_id = id; self }

    // Flex fields
    pub fn account(mut self, account: &str) -> Self {
        self.flex.put_string(1, account); self
    }
    pub fn client_tag(mut self, tag: &str) -> Self {
        self.flex.put_string(2, tag); self
    }
    pub fn max_show(mut self, qty: f64) -> Self {
        self.flex.put_decimal(3, Decimal::from_f64(qty)); self
    }

    /// Build into a MessageBuffer. Returns bytes written.
    pub fn build(mut self, encoder: &mut MessageBuffer, seq: u64) -> usize {
        let flex_data = if self.flex.encoded_size() > 2 {
            Some(self.flex.build())
        } else {
            None
        };
        encoder.encode(
            self.sender_comp_id,
            seq,
            &self.core,
            flex_data.as_deref(),
        )
    }

    /// Build into a raw buffer. Returns bytes written.
    pub fn build_into(self, buf: &mut [u8], seq: u64) -> usize {
        let mut encoder = MessageBuffer::with_capacity(buf.len());
        let len = self.build(&mut encoder, seq);
        buf[..len].copy_from_slice(encoder.as_slice());
        len
    }
}

/// Builder for ExecutionReport messages.
pub struct ExecReportBuilder {
    core: ExecutionReportCore,
    flex: FlexWriter,
}

impl ExecReportBuilder {
    pub fn new(order_id: u64, exec_id: u64, instrument_id: u32) -> Self {
        Self {
            core: ExecutionReportCore {
                order_id,
                client_order_id: 0,
                exec_id,
                instrument_id,
                side: Side::Buy as u8,
                exec_type: ExecType::New as u8,
                order_status: 0,
                _pad: 0,
                price: Decimal::NULL,
                quantity: Decimal::ZERO,
                leaves_qty: Decimal::ZERO,
                cum_qty: Decimal::ZERO,
                last_px: Decimal::NULL,
                last_qty: Decimal::ZERO,
                transact_time: Timestamp::now(),
            },
            flex: FlexWriter::new(),
        }
    }

    pub fn buy(mut self) -> Self { self.core.side = Side::Buy as u8; self }
    pub fn sell(mut self) -> Self { self.core.side = Side::Sell as u8; self }
    pub fn new_order(mut self) -> Self { self.core.exec_type = ExecType::New as u8; self.core.order_status = 0; self }
    pub fn fill(mut self, price: f64, qty: f64) -> Self {
        self.core.exec_type = ExecType::Fill as u8;
        self.core.order_status = 2;
        self.core.last_px = Decimal::from_f64(price);
        self.core.last_qty = Decimal::from_f64(qty);
        self
    }
    pub fn partial_fill(mut self, price: f64, qty: f64) -> Self {
        self.core.exec_type = ExecType::PartialFill as u8;
        self.core.order_status = 1;
        self.core.last_px = Decimal::from_f64(price);
        self.core.last_qty = Decimal::from_f64(qty);
        self
    }
    pub fn canceled(mut self) -> Self { self.core.exec_type = ExecType::Canceled as u8; self.core.order_status = 4; self }
    pub fn rejected(mut self) -> Self { self.core.exec_type = ExecType::Rejected as u8; self.core.order_status = 8; self }
    pub fn price(mut self, price: f64) -> Self { self.core.price = Decimal::from_f64(price); self }
    pub fn quantity(mut self, qty: f64) -> Self { self.core.quantity = Decimal::from_f64(qty); self }
    pub fn leaves_qty(mut self, qty: f64) -> Self { self.core.leaves_qty = Decimal::from_f64(qty); self }
    pub fn cum_qty(mut self, qty: f64) -> Self { self.core.cum_qty = Decimal::from_f64(qty); self }

    // Flex fields
    pub fn text(mut self, text: &str) -> Self { self.flex.put_string(1, text); self }
    pub fn trade_id(mut self, id: u64) -> Self { self.flex.put_u64(2, id); self }
    pub fn fee(mut self, amount: f64) -> Self { self.flex.put_decimal(3, Decimal::from_f64(amount)); self }

    pub fn build(mut self, encoder: &mut MessageBuffer, seq: u64) -> usize {
        let flex_data = if self.flex.encoded_size() > 2 {
            Some(self.flex.build())
        } else {
            None
        };
        encoder.encode(0, seq, &self.core, flex_data.as_deref())
    }
}

/// Builder for Quote messages.
pub struct QuoteBuilder {
    core: QuoteCore,
    flex: FlexWriter,
}

impl QuoteBuilder {
    pub fn new(quote_id: u64, instrument_id: u32) -> Self {
        Self {
            core: QuoteCore {
                quote_id,
                request_id: 0,
                instrument_id,
                _pad: 0,
                bid_price: Decimal::NULL,
                bid_quantity: Decimal::ZERO,
                ask_price: Decimal::NULL,
                ask_quantity: Decimal::ZERO,
                valid_until: Timestamp::NULL,
            },
            flex: FlexWriter::new(),
        }
    }

    pub fn in_response_to(mut self, request_id: u64) -> Self { self.core.request_id = request_id; self }
    pub fn bid(mut self, price: f64, qty: f64) -> Self {
        self.core.bid_price = Decimal::from_f64(price);
        self.core.bid_quantity = Decimal::from_f64(qty);
        self
    }
    pub fn ask(mut self, price: f64, qty: f64) -> Self {
        self.core.ask_price = Decimal::from_f64(price);
        self.core.ask_quantity = Decimal::from_f64(qty);
        self
    }
    pub fn valid_until(mut self, ts: Timestamp) -> Self { self.core.valid_until = ts; self }
    pub fn condition(mut self, cond: &str) -> Self { self.flex.put_string(2, cond); self }

    pub fn build(mut self, encoder: &mut MessageBuffer, seq: u64) -> usize {
        let flex_data = if self.flex.encoded_size() > 2 {
            Some(self.flex.build())
        } else {
            None
        };
        encoder.encode(0, seq, &self.core, flex_data.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_builder_basic() {
        let mut enc = MessageBuffer::with_capacity(512);
        let len = OrderBuilder::new(42, 7)
            .buy()
            .limit(150.25)
            .quantity(100.0)
            .tif_ioc()
            .account("ACC001")
            .client_tag("strat-1")
            .build(&mut enc, 1);

        assert!(len > 64); // core + flex
        let decoded = MessageBuffer::decode_new_order(enc.as_slice());
        assert_eq!(decoded.order_id, 42);
        assert_eq!(decoded.instrument_id, 7);
        assert_eq!(decoded.side(), Some(Side::Buy));
        assert_eq!(decoded.order_type(), Some(OrderType::Limit));
        assert!((decoded.price.to_f64() - 150.25).abs() < 1e-6);

        // Check flex
        let flex = MessageBuffer::decode_flex(enc.as_slice(), NewOrderSingleCore::SIZE).unwrap();
        assert_eq!(flex.get_string(1), Some("ACC001"));
        assert_eq!(flex.get_string(2), Some("strat-1"));
    }

    #[test]
    fn order_builder_market() {
        let mut enc = MessageBuffer::with_capacity(256);
        OrderBuilder::new(1, 1)
            .sell()
            .market()
            .quantity(50.0)
            .tif_fok()
            .build(&mut enc, 1);

        let decoded = MessageBuffer::decode_new_order(enc.as_slice());
        assert_eq!(decoded.side(), Some(Side::Sell));
        assert_eq!(decoded.order_type(), Some(OrderType::Market));
        assert!(decoded.price.is_null());
        assert_eq!(decoded.time_in_force(), Some(TimeInForce::FOK));
    }

    #[test]
    fn exec_report_builder() {
        let mut enc = MessageBuffer::with_capacity(512);
        ExecReportBuilder::new(42, 100, 7)
            .buy()
            .fill(150.25, 50.0)
            .price(150.25)
            .quantity(100.0)
            .leaves_qty(50.0)
            .cum_qty(50.0)
            .trade_id(9999)
            .fee(0.50)
            .build(&mut enc, 1);

        let report: &ExecutionReportCore = MessageBuffer::decode(enc.as_slice());
        assert_eq!(report.order_id, 42);
        assert_eq!(report.exec_type(), Some(ExecType::Fill));
        assert!((report.last_px.to_f64() - 150.25).abs() < 1e-6);
        assert!((report.last_qty.to_f64() - 50.0).abs() < 1e-6);
    }

    #[test]
    fn quote_builder() {
        let mut enc = MessageBuffer::with_capacity(512);
        QuoteBuilder::new(1, 42)
            .bid(100.0, 50.0)
            .ask(101.0, 50.0)
            .condition("firm")
            .build(&mut enc, 1);

        let quote: &QuoteCore = MessageBuffer::decode(enc.as_slice());
        assert_eq!(quote.quote_id, 1);
        assert!((quote.bid_price.to_f64() - 100.0).abs() < 1e-6);
        assert!((quote.ask_price.to_f64() - 101.0).abs() < 1e-6);
    }
}
