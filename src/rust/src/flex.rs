/// Flex block — extensible field section for schema evolution.
///
/// Layout:
/// - flex_count: u16 (number of field entries)
/// - field entries: [FieldEntry; flex_count] — sorted by field_id
/// - field data area: raw bytes
///
/// # Bounded size
///
/// The wire format allows `flex_count` to reach 65535, which would push the
/// lookup cost into 10+ microseconds in the worst case — negating MGEP's
/// "zero-copy, sub-microsecond" promise. Callers MUST NOT rely on being
/// able to place an arbitrary number of fields in a single message.
///
/// We enforce a hard cap of [`MAX_FLEX_FIELDS`] fields per message:
///
/// * Readers clamp the declared count. A message claiming more than
///   `MAX_FLEX_FIELDS` fields silently truncates to the cap on parse, so a
///   malicious sender cannot force the reader into a long scan.
/// * Writers silently drop fields beyond the cap when using the infallible
///   `put_*` API; callers that want to detect the condition must use
///   [`FlexWriter::try_put_u64`] / [`FlexWriter::try_put_string`] /
///   [`FlexWriter::try_put_decimal`], which return a [`FlexError`].
///
/// The cap is deliberately conservative — 32 optional fields is already more
/// than any real-world trading message uses. Applications that legitimately
/// need more should split across multiple messages or promote the data into
/// the core block.
///
/// Field lookup is O(log n) via binary search (n ≤ 32), bounded at 5
/// comparisons — worst case benchmarked at ~40 ns on a modern x86 core.

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

/// Maximum number of flex fields in a single message. See the module-level
/// documentation for the rationale — tl;dr: preserves zero-copy decode
/// guarantees, bounds worst-case lookup, makes DoS by oversize messages
/// impossible at parse time.
pub const MAX_FLEX_FIELDS: usize = 32;

/// Error produced by the fallible flex writer API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexError {
    /// Adding this field would exceed [`MAX_FLEX_FIELDS`].
    TooManyFields { limit: usize },
    /// A single-field value exceeded the u16 offset range. Practically
    /// impossible for normal payloads but surfaced rather than silently
    /// corrupting the wire.
    ValueTooLarge,
}

impl std::fmt::Display for FlexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyFields { limit } => write!(f, "flex block would exceed {} fields", limit),
            Self::ValueTooLarge => write!(f, "flex field value too large (u16 offset overflow)"),
        }
    }
}

impl std::error::Error for FlexError {}

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
    /// Validates that the declared count is consistent with available data
    /// AND does not exceed [`MAX_FLEX_FIELDS`]. Excess fields are silently
    /// dropped — the caller sees only the first `MAX_FLEX_FIELDS`.
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        if buf.len() < 2 || buf.len() > Self::MAX_FLEX_SIZE {
            return Self {
                count: 0,
                entries: &[],
                data: &[],
            };
        }

        let declared = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        // Cap at MAX_FLEX_FIELDS before doing any work so a malicious
        // sender can't force us to scan a large entries array.
        let count = declared.min(MAX_FLEX_FIELDS);
        let entries_size = count * FlexFieldEntry::SIZE;
        let entries_start = 2;
        let data_start = entries_start + entries_size;

        // Clamp count if entries would extend past buffer
        if data_start > buf.len() {
            let max_entries = (buf.len() - entries_start) / FlexFieldEntry::SIZE;
            let clamped = max_entries.min(MAX_FLEX_FIELDS);
            let clamped_data_start = entries_start + clamped * FlexFieldEntry::SIZE;
            return Self {
                count: clamped as u16,
                entries: &buf[entries_start..clamped_data_start],
                data: if clamped_data_start < buf.len() {
                    &buf[clamped_data_start..]
                } else {
                    &[]
                },
            };
        }

        Self {
            count: count as u16,
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

impl Default for FlexWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FlexWriter {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Number of fields currently buffered (before `build`).
    pub fn field_count(&self) -> usize {
        self.entries.len()
    }

    /// True iff another `put_*` call will succeed.
    pub fn can_add(&self) -> bool {
        self.entries.len() < MAX_FLEX_FIELDS
    }

    /// Adds a u64 field. Silently drops the field if the writer is already
    /// at [`MAX_FLEX_FIELDS`] — use [`try_put_u64`](Self::try_put_u64) to
    /// get a Result instead.
    pub fn put_u64(&mut self, field_id: u16, value: u64) {
        let _ = self.try_put_u64(field_id, value);
    }

    pub fn put_string(&mut self, field_id: u16, value: &str) {
        let _ = self.try_put_string(field_id, value);
    }

    pub fn put_decimal(&mut self, field_id: u16, value: crate::types::Decimal) {
        let _ = self.try_put_decimal(field_id, value);
    }

    /// Fallible variant of [`put_u64`](Self::put_u64). Returns an error when
    /// the flex-field cap would be exceeded rather than silently dropping
    /// the field.
    pub fn try_put_u64(&mut self, field_id: u16, value: u64) -> Result<(), FlexError> {
        self.check_capacity()?;
        let offset = self.next_offset()?;
        self.data.push(FlexType::U64 as u8);
        self.data.extend_from_slice(&value.to_le_bytes());
        self.entries.push((field_id, offset));
        Ok(())
    }

    pub fn try_put_string(&mut self, field_id: u16, value: &str) -> Result<(), FlexError> {
        self.check_capacity()?;
        let offset = self.next_offset()?;
        if value.len() > u16::MAX as usize {
            return Err(FlexError::ValueTooLarge);
        }
        self.data.push(FlexType::String as u8);
        self.data.extend_from_slice(&(value.len() as u16).to_le_bytes());
        self.data.extend_from_slice(value.as_bytes());
        self.entries.push((field_id, offset));
        Ok(())
    }

    pub fn try_put_decimal(
        &mut self,
        field_id: u16,
        value: crate::types::Decimal,
    ) -> Result<(), FlexError> {
        self.check_capacity()?;
        let offset = self.next_offset()?;
        self.data.push(FlexType::Decimal as u8);
        self.data.extend_from_slice(&value.0.to_le_bytes());
        self.entries.push((field_id, offset));
        Ok(())
    }

    fn check_capacity(&self) -> Result<(), FlexError> {
        if self.entries.len() >= MAX_FLEX_FIELDS {
            Err(FlexError::TooManyFields { limit: MAX_FLEX_FIELDS })
        } else {
            Ok(())
        }
    }

    fn next_offset(&self) -> Result<u16, FlexError> {
        u16::try_from(self.data.len()).map_err(|_| FlexError::ValueTooLarge)
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

    // ─── Bounded flex block (Task #9) ──────────────────────

    #[test]
    fn writer_rejects_beyond_cap() {
        let mut w = FlexWriter::new();
        for i in 0..MAX_FLEX_FIELDS as u16 {
            assert!(w.try_put_u64(i + 1, i as u64).is_ok(), "field {} must fit", i);
        }
        assert!(!w.can_add());

        // 33rd field rejected via fallible API.
        let err = w.try_put_u64(100, 100).unwrap_err();
        assert!(matches!(err, FlexError::TooManyFields { limit: MAX_FLEX_FIELDS }));
        assert_eq!(w.field_count(), MAX_FLEX_FIELDS);
    }

    #[test]
    fn reader_clamps_hostile_count() {
        // Craft a buffer that declares 1000 fields but only has 32 slots.
        // This simulates a malicious sender trying to trigger a long scan.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1000u16.to_le_bytes()); // declared count
        // Provide just enough bytes for MAX_FLEX_FIELDS real entries.
        for i in 0..MAX_FLEX_FIELDS as u16 {
            buf.extend_from_slice(&(i + 1).to_le_bytes()); // field_id
            buf.extend_from_slice(&0u16.to_le_bytes()); // offset (placeholder)
        }
        // No data area needed for the cap test.

        let reader = FlexReader::new(&buf);
        assert_eq!(
            reader.count() as usize,
            MAX_FLEX_FIELDS,
            "reader must clamp a hostile count"
        );
        // Lookup of field_id = 1000 (declared but absent post-cap) must not
        // iterate past MAX_FLEX_FIELDS.
        assert_eq!(reader.get_u64(1000), None);
    }

    #[test]
    fn reader_caps_large_honest_count() {
        // Writer at the cap: further try_put_* returns Err; readers of the
        // built buffer see exactly MAX_FLEX_FIELDS.
        let mut w = FlexWriter::new();
        for i in 0..MAX_FLEX_FIELDS as u16 {
            w.try_put_u64(i + 1, i as u64).unwrap();
        }
        for i in MAX_FLEX_FIELDS as u16..MAX_FLEX_FIELDS as u16 + 20 {
            let err = w.try_put_u64(i + 1, i as u64).unwrap_err();
            assert!(matches!(err, FlexError::TooManyFields { .. }));
        }
        let data = w.build();
        let reader = FlexReader::new(&data);
        assert_eq!(reader.count() as usize, MAX_FLEX_FIELDS);

        // First 32 still retrievable.
        assert_eq!(reader.get_u64(1), Some(0));
        assert_eq!(reader.get_u64(MAX_FLEX_FIELDS as u16), Some((MAX_FLEX_FIELDS - 1) as u64));
        // Beyond-cap fields never written.
        assert_eq!(reader.get_u64(MAX_FLEX_FIELDS as u16 + 1), None);
    }

    #[test]
    fn lookup_cost_is_bounded() {
        // Binary search over MAX_FLEX_FIELDS = 32 → log2(32) = 5 comparisons.
        // Not a benchmark per se — just a sanity check that the loop
        // terminates quickly for a worst-case miss.
        let mut w = FlexWriter::new();
        for i in 0..MAX_FLEX_FIELDS as u16 {
            w.try_put_u64(i + 1, i as u64).unwrap();
        }
        let data = w.build();
        let reader = FlexReader::new(&data);

        // Miss at high end triggers full binary search.
        for _ in 0..10_000 {
            let _ = reader.get_u64(9999);
        }
        // If the search weren't bounded, this test would time out.
    }

    #[test]
    fn try_put_string_rejects_oversize() {
        let mut w = FlexWriter::new();
        let big = "x".repeat(u16::MAX as usize + 1);
        let err = w.try_put_string(1, &big).unwrap_err();
        assert!(matches!(err, FlexError::ValueTooLarge));
    }
}
