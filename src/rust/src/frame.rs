/// Protocol magic bytes: "MG" (0x474D in LE).
pub const MAGIC: u16 = 0x474D;

/// Frame header — first 8 bytes of every MGEP message.
/// Designed for hardware (FPGA/SmartNIC) processing.
///
/// Byte layout:
///   [0..2] magic    = 0x474D ("MG" in LE)
///   [2]    flags    = bitfield
///   [3]    version  = protocol version (currently 1)
///   [4..8] message_size = total message size including this header
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FrameHeader {
    /// Protocol magic (must be 0x474D).
    pub magic: u16,
    /// Bit flags.
    pub flags: FrameFlags,
    /// Protocol version.
    pub version: u8,
    /// Total message size in bytes (including this header, excluding CRC trailer).
    pub message_size: u32,
}

impl FrameHeader {
    pub const SIZE: usize = 8;
    pub const MIN_MESSAGE_SIZE: u32 = crate::header::FullHeader::SIZE as u32;

    /// Create a new frame header with magic pre-set.
    #[inline]
    pub fn new(flags: FrameFlags, message_size: u32) -> Self {
        Self { magic: MAGIC, flags, version: 1, message_size }
    }

    /// Validate magic bytes.
    #[inline(always)]
    pub fn is_valid(&self) -> bool { self.magic == MAGIC }

    #[inline(always)]
    pub fn from_bytes(buf: &[u8]) -> &Self {
        debug_assert!(buf.len() >= Self::SIZE);
        unsafe { &*(buf.as_ptr() as *const Self) }
    }

    /// Safe decode — returns None if too short OR bad magic.
    #[inline(always)]
    pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
        if buf.len() >= Self::SIZE {
            let h = unsafe { &*(buf.as_ptr() as *const Self) };
            if h.is_valid() { Some(h) } else { None }
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

/// Frame flags packed in a single byte.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct FrameFlags(pub u8);

impl FrameFlags {
    pub const NONE: Self = Self(0);
    pub const HAS_AUTH_TAG: u8  = 0b0000_0001;
    pub const ENCRYPTED: u8     = 0b0000_0010;
    pub const COMPRESSED: u8    = 0b0000_0100;
    pub const HAS_FLEX: u8      = 0b0000_1000;
    pub const HAS_CRC: u8       = 0b0001_0000;
    pub const HAS_REPLICATION: u8 = 0b0010_0000;
    pub const BATCH: u8         = 0b0100_0000;
    // bit 7 reserved

    #[inline(always)] pub fn new() -> Self { Self(0) }
    #[inline(always)] pub fn has_auth_tag(self) -> bool { self.0 & Self::HAS_AUTH_TAG != 0 }
    #[inline(always)] pub fn is_encrypted(self) -> bool { self.0 & Self::ENCRYPTED != 0 }
    #[inline(always)] pub fn is_compressed(self) -> bool { self.0 & Self::COMPRESSED != 0 }
    #[inline(always)] pub fn has_flex(self) -> bool { self.0 & Self::HAS_FLEX != 0 }
    #[inline(always)] pub fn has_crc(self) -> bool { self.0 & Self::HAS_CRC != 0 }

    #[inline(always)] pub fn with_auth_tag(self) -> Self { Self(self.0 | Self::HAS_AUTH_TAG) }
    #[inline(always)] pub fn with_encrypted(self) -> Self { Self(self.0 | Self::ENCRYPTED) }
    #[inline(always)] pub fn with_flex(self) -> Self { Self(self.0 | Self::HAS_FLEX) }
    #[inline(always)] pub fn with_crc(self) -> Self { Self(self.0 | Self::HAS_CRC) }
}

impl core::fmt::Debug for FrameFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut parts = Vec::new();
        if self.has_auth_tag() { parts.push("AUTH"); }
        if self.is_encrypted() { parts.push("ENC"); }
        if self.is_compressed() { parts.push("COMP"); }
        if self.has_flex() { parts.push("FLEX"); }
        if self.has_crc() { parts.push("CRC"); }
        write!(f, "Flags({})", if parts.is_empty() { "none".into() } else { parts.join("|") })
    }
}

/// Authentication tag — 16 bytes appended to message when auth is enabled.
pub const AUTH_TAG_SIZE: usize = 16;
pub type AuthTag = [u8; AUTH_TAG_SIZE];

/// CRC32 (ISO 3309 / Ethernet).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 { crc = (crc >> 1) ^ 0xEDB88320; } else { crc >>= 1; }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &b in data { crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize]; }
    crc ^ 0xFFFFFFFF
}

/// Append CRC32 trailer. Sets HAS_CRC flag. Returns new total size.
pub fn append_crc(buf: &mut [u8], msg_size: usize) -> usize {
    buf[2] |= FrameFlags::HAS_CRC;
    let checksum = crc32(&buf[..msg_size]);
    buf[msg_size..msg_size + 4].copy_from_slice(&checksum.to_le_bytes());
    msg_size + 4
}

/// Verify CRC32 trailer.
pub fn verify_crc(buf: &[u8], total_size: usize) -> bool {
    if total_size < 4 { return false; }
    let msg_size = total_size - 4;
    let expected = crc32(&buf[..msg_size]);
    let stored = u32::from_le_bytes([buf[msg_size], buf[msg_size+1], buf[msg_size+2], buf[msg_size+3]]);
    expected == stored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_size() {
        assert_eq!(core::mem::size_of::<FrameHeader>(), FrameHeader::SIZE);
    }

    #[test]
    fn magic_validation() {
        let h = FrameHeader::new(FrameFlags::NONE, 32);
        assert!(h.is_valid());
        assert_eq!(h.magic, MAGIC);

        let bad = FrameHeader { magic: 0xDEAD, flags: FrameFlags::NONE, version: 1, message_size: 32 };
        assert!(!bad.is_valid());
    }

    #[test]
    fn try_from_bytes_rejects_bad_magic() {
        let buf = vec![0u8; 64]; // zeros — bad magic
        assert!(FrameHeader::try_from_bytes(&buf).is_none());

        let mut good = vec![0u8; 64];
        good[0..2].copy_from_slice(&MAGIC.to_le_bytes());
        assert!(FrameHeader::try_from_bytes(&good).is_some());
    }

    #[test]
    fn frame_header_roundtrip() {
        let header = FrameHeader::new(FrameFlags::new().with_auth_tag(), 64);
        let bytes = header.as_bytes();
        let decoded = FrameHeader::from_bytes(bytes);
        assert_eq!(decoded.message_size, 64);
        assert!(decoded.flags.has_auth_tag());
        assert!(!decoded.flags.has_flex());
        assert!(decoded.is_valid());
    }

    #[test]
    fn flags_composition() {
        let flags = FrameFlags::new().with_auth_tag().with_encrypted().with_flex().with_crc();
        assert!(flags.has_auth_tag());
        assert!(flags.is_encrypted());
        assert!(flags.has_flex());
        assert!(flags.has_crc());
        assert!(!flags.is_compressed());
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn crc32_append_verify() {
        let mut buf = vec![0u8; 128];
        let h = FrameHeader::new(FrameFlags::NONE, 64);
        h.write_to(&mut buf);
        for i in 8..64 { buf[i] = (i * 7) as u8; }

        let total = append_crc(&mut buf, 64);
        assert_eq!(total, 68);
        assert!(verify_crc(&buf, total));

        buf[40] ^= 0xFF;
        assert!(!verify_crc(&buf, total));
    }
}
