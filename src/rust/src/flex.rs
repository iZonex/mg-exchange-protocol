/// Flex block — extensible field section for schema evolution.
///
/// Layout:
/// - flex_count: u16 (number of field entries)
/// - field entries: [FieldEntry; flex_count] — sorted by field_id
/// - field data area: raw bytes
///
/// Field lookup is O(1) for small counts (linear scan) or O(log n) for larger counts.

/// A field entry in the flex block index.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FlexFieldEntry {
    /// Field identifier (1-65535, 0 reserved)
    pub field_id: u16,
    /// Byte offset from start of field data area
    pub offset: u16,
}

impl FlexFieldEntry {
    pub const SIZE: usize = 4;
}

/// Type tags for flex field values.
#[repr(u8)]
pub enum FlexType {
    U8 = 0x01,
    U16 = 0x02,
    U32 = 0x03,
    U64 = 0x04,
    I8 = 0x05,
    I16 = 0x06,
    I32 = 0x07,
    I64 = 0x08,
    F64 = 0x09,
    Bool = 0x0A,
    String = 0x0B,
    Bytes = 0x0C,
    Decimal = 0x0D,
    Timestamp = 0x0E,
    Group = 0x0F,
}

/// Reader for a flex block within a message buffer.
pub struct FlexReader<'a> {
    /// Number of fields
    count: u16,
    /// Slice containing field entries
    entries: &'a [u8],
    /// Slice containing field data
    data: &'a [u8],
}

impl<'a> FlexReader<'a> {
    /// Maximum flex block size (64KB).
    pub const MAX_FLEX_SIZE: usize = 65536;

    /// Parse flex block from a buffer starting at the flex block position.
    /// Validates that the declared count is consistent with available data.
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        if buf.len() < 2 || buf.len() > Self::MAX_FLEX_SIZE {
            return Self {
                count: 0,
                entries: &[],
                data: &[],
            };
        }

        let count = u16::from_le_bytes([buf[0], buf[1]]);
        let entries_size = count as usize * FlexFieldEntry::SIZE;
        let entries_start = 2;
        let data_start = entries_start + entries_size;

        // Clamp count if entries would extend past buffer
        if data_start > buf.len() {
            let max_entries = (buf.len() - entries_start) / FlexFieldEntry::SIZE;
            let clamped = max_entries as u16;
            let clamped_data_start = entries_start + clamped as usize * FlexFieldEntry::SIZE;
            return Self {
                count: clamped,
                entries: &buf[entries_start..clamped_data_start],
                data: if clamped_data_start < buf.len() {
                    &buf[clamped_data_start..]
                } else {
                    &[]
                },
            };
        }

        Self {
            count,
            entries: &buf[entries_start..data_start],
            data: if data_start < buf.len() {
                &buf[data_start..]
            } else {
                &[]
            },
        }
    }

    /// Number of flex fields.
    #[inline(always)]
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Find a field by ID. Returns offset into data area if found.
    #[inline]
    pub fn find_field(&self, field_id: u16) -> Option<u16> {
        if self.count <= 8 {
            // Linear scan for small counts — cache friendly
            self.linear_find(field_id)
        } else {
            // Binary search for larger counts
            self.binary_find(field_id)
        }
    }

    #[inline]
    fn linear_find(&self, field_id: u16) -> Option<u16> {
        for i in 0..self.count as usize {
            let base = i * FlexFieldEntry::SIZE;
            let id = u16::from_le_bytes([self.entries[base], self.entries[base + 1]]);
            if id == field_id {
                let offset = u16::from_le_bytes([self.entries[base + 2], self.entries[base + 3]]);
                return Some(offset);
            }
            // Entries are sorted — early exit
            if id > field_id {
                return None;
            }
        }
        None
    }

    fn binary_find(&self, field_id: u16) -> Option<u16> {
        let mut lo = 0u16;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let base = mid as usize * FlexFieldEntry::SIZE;
            let id = u16::from_le_bytes([self.entries[base], self.entries[base + 1]]);
            match id.cmp(&field_id) {
                core::cmp::Ordering::Equal => {
                    let offset =
                        u16::from_le_bytes([self.entries[base + 2], self.entries[base + 3]]);
                    return Some(offset);
                }
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Read a u64 flex field.
    #[inline]
    pub fn get_u64(&self, field_id: u16) -> Option<u64> {
        let offset = self.find_field(field_id)? as usize;
        // Skip type tag (1 byte), read 8 bytes
        if offset + 9 <= self.data.len() && self.data[offset] == FlexType::U64 as u8 {
            Some(u64::from_le_bytes(
                self.data[offset + 1..offset + 9].try_into().unwrap(),
            ))
        } else {
            None
        }
    }

    /// Read a string flex field.
    #[inline]
    pub fn get_string(&self, field_id: u16) -> Option<&'a str> {
        let offset = self.find_field(field_id)? as usize;
        if offset + 3 > self.data.len() || self.data[offset] != FlexType::String as u8 {
            return None;
        }
        let len =
            u16::from_le_bytes([self.data[offset + 1], self.data[offset + 2]]) as usize;
        let str_start = offset + 3;
        if str_start + len <= self.data.len() {
            core::str::from_utf8(&self.data[str_start..str_start + len]).ok()
        } else {
            None
        }
    }

    /// Read a decimal flex field.
    #[inline]
    pub fn get_decimal(&self, field_id: u16) -> Option<crate::types::Decimal> {
        let offset = self.find_field(field_id)? as usize;
        if offset + 9 <= self.data.len() && self.data[offset] == FlexType::Decimal as u8 {
            let val = i64::from_le_bytes(
                self.data[offset + 1..offset + 9].try_into().unwrap(),
            );
            Some(crate::types::Decimal(val))
        } else {
            None
        }
    }
}

/// Writer for building a flex block.
pub struct FlexWriter {
    entries: Vec<(u16, u16)>, // (field_id, offset)
    data: Vec<u8>,
}

impl FlexWriter {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            data: Vec::new(),
        }
    }

    pub fn put_u64(&mut self, field_id: u16, value: u64) {
        let offset = self.data.len() as u16;
        self.data.push(FlexType::U64 as u8);
        self.data.extend_from_slice(&value.to_le_bytes());
        self.entries.push((field_id, offset));
    }

    pub fn put_string(&mut self, field_id: u16, value: &str) {
        let offset = self.data.len() as u16;
        self.data.push(FlexType::String as u8);
        self.data
            .extend_from_slice(&(value.len() as u16).to_le_bytes());
        self.data.extend_from_slice(value.as_bytes());
        self.entries.push((field_id, offset));
    }

    pub fn put_decimal(&mut self, field_id: u16, value: crate::types::Decimal) {
        let offset = self.data.len() as u16;
        self.data.push(FlexType::Decimal as u8);
        self.data.extend_from_slice(&value.0.to_le_bytes());
        self.entries.push((field_id, offset));
    }

    /// Serialize the flex block into a byte vector.
    /// Entries are sorted by field_id for efficient lookup.
    pub fn build(&mut self) -> Vec<u8> {
        self.entries.sort_by_key(|e| e.0);

        let count = self.entries.len() as u16;
        let mut buf = Vec::with_capacity(2 + self.entries.len() * 4 + self.data.len());

        buf.extend_from_slice(&count.to_le_bytes());
        for &(field_id, offset) in &self.entries {
            buf.extend_from_slice(&field_id.to_le_bytes());
            buf.extend_from_slice(&offset.to_le_bytes());
        }
        buf.extend_from_slice(&self.data);

        buf
    }

    /// Zero-allocation: serialize directly into a pre-allocated buffer.
    /// Returns the number of bytes written, or None if buffer too small.
    /// This is the hot-path version — no Vec allocation.
    pub fn build_into(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.entries.sort_by_key(|e| e.0);

        let count = self.entries.len() as u16;
        let needed = 2 + self.entries.len() * 4 + self.data.len();
        if buf.len() < needed {
            return None;
        }

        let mut offset = 0;
        buf[offset..offset + 2].copy_from_slice(&count.to_le_bytes());
        offset += 2;

        for &(field_id, foffset) in &self.entries {
            buf[offset..offset + 2].copy_from_slice(&field_id.to_le_bytes());
            buf[offset + 2..offset + 4].copy_from_slice(&foffset.to_le_bytes());
            offset += 4;
        }

        buf[offset..offset + self.data.len()].copy_from_slice(&self.data);
        offset += self.data.len();

        Some(offset)
    }

    /// Total size the flex block would occupy when built.
    pub fn encoded_size(&self) -> usize {
        2 + self.entries.len() * 4 + self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flex_roundtrip_string() {
        let mut writer = FlexWriter::new();
        writer.put_string(1, "ACCOUNT001");
        writer.put_u64(2, 42);
        writer.put_string(3, "client-tag-abc");

        let data = writer.build();
        let reader = FlexReader::new(&data);

        assert_eq!(reader.count(), 3);
        assert_eq!(reader.get_string(1), Some("ACCOUNT001"));
        assert_eq!(reader.get_u64(2), Some(42));
        assert_eq!(reader.get_string(3), Some("client-tag-abc"));
        assert_eq!(reader.get_string(99), None); // missing field
    }

    #[test]
    fn flex_sorted_entries() {
        let mut writer = FlexWriter::new();
        // Insert out of order
        writer.put_u64(5, 500);
        writer.put_u64(1, 100);
        writer.put_u64(3, 300);

        let data = writer.build();
        let reader = FlexReader::new(&data);

        assert_eq!(reader.get_u64(1), Some(100));
        assert_eq!(reader.get_u64(3), Some(300));
        assert_eq!(reader.get_u64(5), Some(500));
    }

    #[test]
    fn flex_empty() {
        let reader = FlexReader::new(&[0, 0]); // count = 0
        assert_eq!(reader.count(), 0);
        assert_eq!(reader.get_u64(1), None);
    }
}
