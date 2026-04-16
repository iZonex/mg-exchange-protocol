//! Stream Multiplexing — multiple logical channels over one connection.
//!
//! Like HTTP/2 streams: one TCP connection carries orders, market data, risk,
//! and admin on separate streams with independent sequence tracking.
//!
//! Design:
//!   - Stream ID is encoded in sender_comp_id (u16) in the MessageHeader.
//!     High 4 bits = stream type, low 12 bits = stream instance.
//!   - Each stream has its own sequence counter for independent retransmission.
//!   - Streams don't block each other (head-of-line blocking avoidance).
//!
//! Predefined stream types:
//!   0x0 = session control (Negotiate, Heartbeat, etc.)
//!   0x1 = order entry (NewOrder, Cancel, Replace)
//!   0x2 = execution (ExecReport, CancelReject)
//!   0x3 = market data (OrderAdd, Trade, etc.)
//!   0x4 = quotes (Quote, MassQuote)
//!   0x5 = risk (PositionReport, MarginCall)
//!   0x6 = post-trade (TradeCaptureReport, Settlement)
//!   0x7-0xF = user-defined

/// Stream types — high 4 bits of stream_id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    Session   = 0x0,
    OrderEntry = 0x1,
    Execution = 0x2,
    MarketData = 0x3,
    Quotes    = 0x4,
    Risk      = 0x5,
    PostTrade = 0x6,
    UserDefined7 = 0x7,
}

/// Stream identifier — encodes type + instance in 16 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(pub u16);

impl StreamId {
    /// Create a stream ID from type and instance.
    /// `stream_type` occupies bits 12-15, `instance` occupies bits 0-11.
    #[inline]
    pub fn new(stream_type: StreamType, instance: u16) -> Self {
        Self(((stream_type as u16) << 12) | (instance & 0x0FFF))
    }

    /// Extract stream type.
    #[inline]
    pub fn stream_type(self) -> u8 { (self.0 >> 12) as u8 }

    /// Extract stream instance.
    #[inline]
    pub fn instance(self) -> u16 { self.0 & 0x0FFF }

    /// Session control stream (always instance 0).
    pub const SESSION: Self = Self(0x0000);
    /// Default order entry stream.
    pub const ORDERS: Self = Self(0x1000);
    /// Default execution stream.
    pub const EXECUTIONS: Self = Self(0x2000);
    /// Default market data stream.
    pub const MARKET_DATA: Self = Self(0x3000);
    /// Default quotes stream.
    pub const QUOTES: Self = Self(0x4000);
    /// Default risk stream.
    pub const RISK: Self = Self(0x5000);
    /// Default post-trade stream.
    pub const POST_TRADE: Self = Self(0x6000);
}

/// Per-stream state: independent sequence tracking.
#[derive(Debug)]
pub struct StreamState {
    pub id: StreamId,
    pub next_outbound_seq: u32,
    pub next_expected_seq: u32,
}

impl StreamState {
    pub fn new(id: StreamId) -> Self {
        Self {
            id,
            next_outbound_seq: 1,
            next_expected_seq: 1,
        }
    }

    #[inline]
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.next_outbound_seq;
        self.next_outbound_seq = seq.wrapping_add(1);
        seq
    }

    #[inline]
    pub fn accept_seq(&mut self, seq: u32) {
        if seq >= self.next_expected_seq {
            self.next_expected_seq = seq.wrapping_add(1);
        }
    }
}

/// Stream multiplexer — manages multiple streams over a single session.
pub struct Multiplexer {
    streams: Vec<StreamState>,
}

impl Multiplexer {
    /// Create a multiplexer with default streams.
    pub fn new() -> Self {
        Self {
            streams: vec![
                StreamState::new(StreamId::SESSION),
                StreamState::new(StreamId::ORDERS),
                StreamState::new(StreamId::EXECUTIONS),
                StreamState::new(StreamId::MARKET_DATA),
                StreamState::new(StreamId::QUOTES),
                StreamState::new(StreamId::RISK),
                StreamState::new(StreamId::POST_TRADE),
            ],
        }
    }

    /// Get stream state by ID. Creates if not exists.
    pub fn stream(&mut self, id: StreamId) -> &mut StreamState {
        if let Some(pos) = self.streams.iter().position(|s| s.id == id) {
            &mut self.streams[pos]
        } else {
            self.streams.push(StreamState::new(id));
            self.streams.last_mut().unwrap()
        }
    }

    /// Get the next sequence number for a stream.
    pub fn next_seq(&mut self, id: StreamId) -> u32 {
        self.stream(id).next_seq()
    }

    /// Accept an inbound sequence for a stream.
    pub fn accept_seq(&mut self, id: StreamId, seq: u32) {
        self.stream(id).accept_seq(seq);
    }

    /// Determine which stream a message belongs to, based on schema_id.
    pub fn route_schema(schema_id: u16) -> StreamId {
        match schema_id {
            0x0000 => StreamId::SESSION,
            0x0001 => StreamId::ORDERS, // could be EXECUTIONS for ExecReport, but sender decides
            0x0002 => StreamId::MARKET_DATA,
            0x0003 => StreamId::QUOTES,
            0x0004 => StreamId::POST_TRADE,
            0x0005 => StreamId::RISK,
            _ => StreamId::SESSION,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_encoding() {
        let id = StreamId::new(StreamType::OrderEntry, 5);
        assert_eq!(id.stream_type(), 1);
        assert_eq!(id.instance(), 5);
        assert_eq!(id.0, 0x1005);
    }

    #[test]
    fn stream_id_constants() {
        assert_eq!(StreamId::SESSION.stream_type(), 0);
        assert_eq!(StreamId::ORDERS.stream_type(), 1);
        assert_eq!(StreamId::MARKET_DATA.stream_type(), 3);
        assert_eq!(StreamId::RISK.stream_type(), 5);
    }

    #[test]
    fn multiplexer_independent_sequences() {
        let mut mux = Multiplexer::new();

        let seq1 = mux.next_seq(StreamId::ORDERS);
        let seq2 = mux.next_seq(StreamId::ORDERS);
        let seq3 = mux.next_seq(StreamId::MARKET_DATA);

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 1); // independent stream
    }

    #[test]
    fn multiplexer_route_schema() {
        assert_eq!(Multiplexer::route_schema(0x0001), StreamId::ORDERS);
        assert_eq!(Multiplexer::route_schema(0x0002), StreamId::MARKET_DATA);
        assert_eq!(Multiplexer::route_schema(0x0003), StreamId::QUOTES);
        assert_eq!(Multiplexer::route_schema(0x0005), StreamId::RISK);
    }

    #[test]
    fn multiplexer_custom_stream() {
        let mut mux = Multiplexer::new();

        // Create a custom order stream for strategy #2
        let custom = StreamId::new(StreamType::OrderEntry, 2);
        let seq = mux.next_seq(custom);
        assert_eq!(seq, 1);

        // Default order stream is independent
        let seq_default = mux.next_seq(StreamId::ORDERS);
        assert_eq!(seq_default, 1);
    }
}
