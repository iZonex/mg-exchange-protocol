/// Message header — 24 bytes following the frame header.
///
/// Byte layout:
///   [0..2]   schema_id
///   [2..4]   message_type
///   [4..8]   sender_comp_id (u32, was u16)
///   [8..16]  sequence_num   (u64, was u32)
///   [16..24] correlation_id (u64, NEW — request/response linking)
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MessageHeader {
    /// Schema identifier (message type family).
    pub schema_id: u16,
    /// Message type within schema.
    pub message_type: u16,
    /// Sender component ID (u32 — supports >65K clients).
    pub sender_comp_id: u32,
    /// Message sequence number (u64 — no practical wraparound).
    pub sequence_num: u64,
    /// Correlation ID — client sets on request, server echoes on response.
    /// Zero if not applicable.
    pub correlation_id: u64,
}

impl MessageHeader {
    pub const SIZE: usize = 24;
    /// Offset from start of message buffer (after FrameHeader).
    pub const OFFSET: usize = 8;

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
    pub fn from_message(buf: &[u8]) -> &Self {
        Self::from_bytes(&buf[Self::OFFSET..])
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        unsafe { &*(self as *const Self as *const [u8; Self::SIZE]) }
    }

    #[inline(always)]
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[Self::OFFSET..Self::OFFSET + Self::SIZE].copy_from_slice(self.as_bytes());
    }
}

/// Combined frame + message header.
/// Total: 32 bytes — exactly half a cache line.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FullHeader {
    pub frame: crate::frame::FrameHeader,
    pub message: MessageHeader,
}

impl FullHeader {
    pub const SIZE: usize = 32;

    /// Build with magic pre-set.
    pub fn new(
        schema_id: u16,
        message_type: u16,
        sender_comp_id: u32,
        sequence_num: u64,
        correlation_id: u64,
        message_size: u32,
        flags: crate::frame::FrameFlags,
    ) -> Self {
        Self {
            frame: crate::frame::FrameHeader::new(flags, message_size),
            message: MessageHeader {
                schema_id,
                message_type,
                sender_comp_id,
                sequence_num,
                correlation_id,
            },
        }
    }

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            let h = unsafe { &*(buf.as_ptr() as *const Self) };
            if h.frame.is_valid() { Some(h) } else { None }
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        unsafe { &*(self as *const Self as *const [u8; Self::SIZE]) }
    }

    #[inline(always)]
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[..Self::SIZE].copy_from_slice(self.as_bytes());
    }
}

/// Core block starts at this offset from the beginning of the message buffer.
pub const CORE_BLOCK_OFFSET: usize = FullHeader::SIZE; // 32

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameFlags;

    #[test]
    fn message_header_size() {
        assert_eq!(core::mem::size_of::<MessageHeader>(), MessageHeader::SIZE);
        assert_eq!(MessageHeader::SIZE, 24);
    }

    #[test]
    fn full_header_size() {
        assert_eq!(core::mem::size_of::<FullHeader>(), FullHeader::SIZE);
        assert_eq!(FullHeader::SIZE, 32);
    }

    #[test]
    fn full_header_roundtrip() {
        let header = FullHeader::new(
            0x0001, 0x01, 42, 12345, 99999, 64, FrameFlags::NONE,
        );

        let mut buf = vec![0u8; 64];
        header.write_to(&mut buf);

        let decoded = FullHeader::from_bytes(&buf);
        assert!(decoded.frame.is_valid());
        assert_eq!(decoded.message.schema_id, 0x0001);
        assert_eq!(decoded.message.message_type, 0x01);
        assert_eq!(decoded.message.sender_comp_id, 42);
        assert_eq!(decoded.message.sequence_num, 12345);
        assert_eq!(decoded.message.correlation_id, 99999);
    }

    #[test]
    fn try_from_bytes_validates_magic() {
        let buf = vec![0u8; 64]; // bad magic
        assert!(FullHeader::try_from_bytes(&buf).is_none());

        let header = FullHeader::new(0x0001, 0x01, 1, 1, 0, 32, FrameFlags::NONE);
        let mut buf = vec![0u8; 64];
        header.write_to(&mut buf);
        assert!(FullHeader::try_from_bytes(&buf).is_some());
    }

    #[test]
    fn u32_sender_comp_id() {
        let h = FullHeader::new(0x0001, 0x01, 1_000_000, 1, 0, 32, FrameFlags::NONE);
        let mut buf = vec![0u8; 64];
        h.write_to(&mut buf);
        assert_eq!(FullHeader::from_bytes(&buf).message.sender_comp_id, 1_000_000);
    }

    #[test]
    fn u64_sequence_num() {
        let h = FullHeader::new(0x0001, 0x01, 1, u64::MAX - 1, 0, 32, FrameFlags::NONE);
        let mut buf = vec![0u8; 64];
        h.write_to(&mut buf);
        assert_eq!(FullHeader::from_bytes(&buf).message.sequence_num, u64::MAX - 1);
    }

    #[test]
    fn correlation_id_echo() {
        // Request
        let req = FullHeader::new(0x0001, 0x07, 1, 5, 42, 32, FrameFlags::NONE);
        // Response echoes correlation_id
        let resp = FullHeader::new(0x0001, 0x05, 0, 10, 42, 128, FrameFlags::NONE);
        assert_eq!(req.message.correlation_id, resp.message.correlation_id);
    }
}
