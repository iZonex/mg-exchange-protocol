//! Message Batching — send multiple MGEP messages in a single frame.
//!
//! Reduces syscall overhead: 50 orders in 1 write() instead of 50 writes.
//! Essential for market data bursts (ITCH sends 50+ events per packet).
//!
//! Wire format:
//!   [FrameHeader: schema_id=0xFFFF, message_type=0x01 (batch)]
//!   [MessageHeader: sequence_num = first seq in batch]
//!   [BatchHeader: count(u16) + _pad(6)]
//!   [Message1: complete MGEP frame (header + core + flex)]
//!   [Message2: complete MGEP frame]
//!   ...
//!
//! Each inner message is a complete, self-contained MGEP frame.
//! The outer batch frame's message_size = sum of all inner frame sizes + 32 (headers).

use crate::frame::{FrameFlags, FrameHeader};
use crate::header::{FullHeader, CORE_BLOCK_OFFSET};


/// Schema ID for batch wrapper messages.
pub const BATCH_SCHEMA_ID: u16 = 0xFFFF;
/// Message type for a batch of messages.
pub const BATCH_MSG_TYPE: u16 = 0x01;

/// Batch header — follows the FullHeader.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BatchHeader {
    pub count: u16,
    pub _pad: [u8; 6],
}

impl BatchHeader {
    pub const SIZE: usize = 8;
}

const BATCH_OVERHEAD: usize = CORE_BLOCK_OFFSET + BatchHeader::SIZE; // 32 bytes

/// Batch writer — accumulates messages and produces a single batch frame.
pub struct BatchWriter {
    buf: Vec<u8>,
    count: u16,
}

impl BatchWriter {
    /// Create a new batch writer with pre-allocated capacity.
    pub fn new(capacity: usize) -> Self {
        let mut buf = Vec::with_capacity(capacity);
        // Reserve space for outer headers (will be filled in build())
        buf.resize(BATCH_OVERHEAD, 0);
        Self { buf, count: 0 }
    }

    /// Add a pre-encoded MGEP message to the batch.
    /// The message must be a complete frame (FrameHeader + MessageHeader + core + flex).
    pub fn push(&mut self, msg: &[u8]) {
        self.buf.extend_from_slice(msg);
        self.count += 1;
    }

    /// Number of messages in the batch.
    pub fn len(&self) -> u16 { self.count }

    /// Is the batch empty?
    pub fn is_empty(&self) -> bool { self.count == 0 }

    /// Total size of the batch frame.
    pub fn size(&self) -> usize { self.buf.len() }

    /// Finalize the batch and return the complete frame.
    /// `first_seq` is the sequence number of the first message in the batch.
    pub fn build(&mut self, sender_comp_id: u32, first_seq: u64) -> &[u8] {
        let total_size = self.buf.len();

        let header = FullHeader::new(
            BATCH_SCHEMA_ID, BATCH_MSG_TYPE,
            sender_comp_id, first_seq, 0,
            total_size as u32, FrameFlags::NONE,
        );
        header.write_to(&mut self.buf);

        self.buf[CORE_BLOCK_OFFSET..CORE_BLOCK_OFFSET + 2]
            .copy_from_slice(&self.count.to_le_bytes());

        &self.buf
    }

    /// Reset for reuse (no deallocation).
    pub fn reset(&mut self) {
        self.buf.truncate(BATCH_OVERHEAD);
        self.buf.iter_mut().for_each(|b| *b = 0);
        self.count = 0;
    }
}

/// Iterator over messages within a batch frame.
pub struct BatchReader<'a> {
    data: &'a [u8],
    offset: usize,
    count: u16,
    index: u16,
}

impl<'a> BatchReader<'a> {
    /// Parse a batch frame. `buf` must start with a valid batch FrameHeader.
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        let header = FullHeader::try_from_bytes(buf)?;
        if header.message.schema_id != BATCH_SCHEMA_ID
            || header.message.message_type != BATCH_MSG_TYPE
        {
            return None;
        }

        if buf.len() < BATCH_OVERHEAD {
            return None;
        }

        let count = u16::from_le_bytes([buf[CORE_BLOCK_OFFSET], buf[CORE_BLOCK_OFFSET + 1]]);

        Some(Self {
            data: buf,
            offset: BATCH_OVERHEAD,
            count,
            index: 0,
        })
    }

    /// Number of messages in this batch.
    pub fn msg_count(&self) -> u16 { self.count }
}

impl<'a> Iterator for BatchReader<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count || self.offset >= self.data.len() {
            return None;
        }

        // Read inner frame's message_size
        let remaining = &self.data[self.offset..];
        let frame = FrameHeader::try_from_bytes(remaining)?;
        let msg_size = frame.message_size as usize;

        if self.offset + msg_size > self.data.len() {
            return None; // truncated
        }

        let msg = &self.data[self.offset..self.offset + msg_size];
        self.offset += msg_size;
        self.index += 1;
        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageBuffer;
    use crate::messages::*;
    use crate::types::*;

    #[test]
    fn batch_write_read_roundtrip() {
        let mut batch = BatchWriter::new(4096);

        // Add 5 NewOrder messages
        for i in 0..5u64 {
            let order = NewOrderSingleCore {
                order_id: 1000 + i, instrument_id: 42,
                side: 1, order_type: 2, time_in_force: 1,
                price: Decimal::from_f64(100.0 + i as f64),
                quantity: Decimal::from_f64(10.0),
                stop_price: Decimal::NULL,
            };
            let mut enc = MessageBuffer::with_capacity(256);
            enc.encode(1, (i + 1) as u64, &order, None);
            batch.push(enc.as_slice());
        }

        assert_eq!(batch.len(), 5);

        let frame = batch.build(1, 1);
        assert!(frame.len() > BATCH_OVERHEAD);

        // Read back
        let reader = BatchReader::new(frame).unwrap();
        assert_eq!(reader.msg_count(), 5);

        let messages: Vec<&[u8]> = reader.collect();
        assert_eq!(messages.len(), 5);

        // Verify each inner message
        for (i, msg) in messages.iter().enumerate() {
            let decoded = MessageBuffer::decode_new_order(msg);
            assert_eq!(decoded.order_id, 1000 + i as u64);
        }
    }

    #[test]
    fn batch_empty() {
        let mut batch = BatchWriter::new(256);
        assert!(batch.is_empty());
        let frame = batch.build(1, 1);

        let reader = BatchReader::new(frame).unwrap();
        assert_eq!(reader.msg_count(), 0);
        assert_eq!(reader.collect::<Vec<_>>().len(), 0);
    }

    #[test]
    fn batch_reset_reuse() {
        let mut batch = BatchWriter::new(4096);

        let order = NewOrderSingleCore {
            order_id: 1, instrument_id: 1, side: 1, order_type: 1,
            time_in_force: 1, price: Decimal::ZERO, quantity: Decimal::ZERO,
            stop_price: Decimal::NULL,
        };
        let mut enc = MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);
        batch.push(enc.as_slice());
        assert_eq!(batch.len(), 1);

        batch.reset();
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());
    }

    #[test]
    fn batch_reader_rejects_non_batch() {
        let order = NewOrderSingleCore {
            order_id: 1, instrument_id: 1, side: 1, order_type: 1,
            time_in_force: 1, price: Decimal::ZERO, quantity: Decimal::ZERO,
            stop_price: Decimal::NULL,
        };
        let mut enc = MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);

        // A regular message should not parse as a batch
        assert!(BatchReader::new(enc.as_slice()).is_none());
    }
}
