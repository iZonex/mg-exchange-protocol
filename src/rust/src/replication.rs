//! Replication Header — makes MGEP messages directly usable as Raft log entries.
//!
//! Optional 16-byte header prepended to any MGEP frame for consensus replication.
//! Eliminates re-serialization when writing to Raft/Paxos logs.
//!
//! Wire format (when replication is enabled):
//!   [ReplicationHeader: 16 bytes]
//!     leader_id  : u32    — ID of the current leader node
//!     term       : u32    — Raft term (or Paxos ballot)
//!     log_index  : u64    — monotonic log position
//!   [Standard MGEP frame: FrameHeader + MessageHeader + core + flex]
//!
//! Detection: the FrameHeader flag bit 4 (0x10) indicates replication header is present.
//! The replication header is NOT part of message_size in the FrameHeader.


/// Bit flag for replication header presence.
pub const HAS_REPLICATION: u8 = 0b0001_0000;

/// Magic bytes identifying a replication header: "RP" (0x5250).
pub const REPLICATION_MAGIC: u16 = 0x5250;

/// Replication header — 16 bytes, prepended to the MGEP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReplicationHeader {
    /// Magic bytes (0x5250 = "RP") for detection.
    pub magic: u16,
    /// ID of the leader node that sequenced this message.
    pub leader_id: u16,
    /// Raft term or Paxos ballot number.
    pub term: u32,
    /// Monotonic log index. Unique across the cluster.
    pub log_index: u64,
}

impl ReplicationHeader {
    pub const SIZE: usize = 16;

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            Some(unsafe { &*(buf.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }

    /// Write the replication header into a buffer.
    #[inline]
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[..Self::SIZE].copy_from_slice(self.as_bytes());
    }
}

/// Wrap an existing MGEP message with a replication header.
/// Writes `repl_header` + `msg` into `buf`. Returns total bytes written.
pub fn wrap_with_replication(
    buf: &mut [u8],
    repl: &ReplicationHeader,
    msg: &[u8],
) -> usize {
    let total = ReplicationHeader::SIZE + msg.len();
    assert!(buf.len() >= total);

    // Write replication header (magic is already set)
    repl.write_to(buf);

    // Copy MGEP message after replication header
    buf[ReplicationHeader::SIZE..total].copy_from_slice(msg);

    total
}

/// Check if a buffer starts with a replication header (by checking magic bytes).
#[inline]
pub fn has_replication_header(buf: &[u8]) -> bool {
    if buf.len() < ReplicationHeader::SIZE {
        return false;
    }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    magic == REPLICATION_MAGIC
}

/// Split a replicated message into (ReplicationHeader, MGEP frame slice).
pub fn split_replication(buf: &[u8]) -> Option<(&ReplicationHeader, &[u8])> {
    if !has_replication_header(buf) {
        return None;
    }
    let repl = ReplicationHeader::try_from_bytes(buf)?;
    let frame = &buf[ReplicationHeader::SIZE..];
    Some((repl, frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageBuffer;
    use crate::messages::*;
    use crate::types::*;

    #[test]
    fn replication_header_size() {
        assert_eq!(core::mem::size_of::<ReplicationHeader>(), ReplicationHeader::SIZE);
    }

    #[test]
    fn wrap_and_split() {
        // Build a normal MGEP message
        let order = NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            time_in_force: 1, price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(10.0), stop_price: Decimal::NULL,
        };
        let mut enc = MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);
        let msg = enc.as_slice();

        // Verify no replication flag initially
        assert!(!has_replication_header(msg));

        // Wrap with replication header
        let repl = ReplicationHeader {
            magic: REPLICATION_MAGIC,
            leader_id: 1,
            term: 5,
            log_index: 12345,
        };
        let mut buf = vec![0u8; 512];
        let total = wrap_with_replication(&mut buf, &repl, msg);
        assert_eq!(total, ReplicationHeader::SIZE + msg.len());

        // Split back
        let (decoded_repl, decoded_frame) = split_replication(&buf[..total]).unwrap();
        assert_eq!(decoded_repl.leader_id, 1);
        assert_eq!(decoded_repl.term, 5);
        assert_eq!(decoded_repl.log_index, 12345);

        // Decode the inner MGEP message
        let decoded_order = MessageBuffer::decode_new_order(decoded_frame);
        assert_eq!(decoded_order.order_id, 42);
    }

    #[test]
    fn no_replication_header_on_plain_message() {
        let order = NewOrderSingleCore {
            order_id: 1, instrument_id: 1, side: 1, order_type: 1,
            time_in_force: 1, price: Decimal::ZERO, quantity: Decimal::ZERO,
            stop_price: Decimal::NULL,
        };
        let mut enc = MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);

        assert!(!has_replication_header(enc.as_slice()));
        assert!(split_replication(enc.as_slice()).is_none());
    }

    #[test]
    fn replication_header_roundtrip() {
        let repl = ReplicationHeader {
            magic: REPLICATION_MAGIC,
            leader_id: 999,
            term: u32::MAX,
            log_index: u64::MAX - 1,
        };
        let bytes = repl.as_bytes();
        let decoded = ReplicationHeader::from_bytes(bytes);
        assert_eq!(decoded, &repl);
    }
}
