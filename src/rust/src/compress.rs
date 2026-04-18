//! LZ4 Compression for MGEP flex blocks and snapshots.
//!
//! Pure-Rust LZ4 block compression (no framing, just raw block format).
//! Used for BookSnapshot, large flex blocks, and batch messages.
//!
//! Wire integration:
//!   - FrameFlags::COMPRESSED (bit 2) indicates compressed payload
//!   - Compression scope: everything after FrameHeader (same as encryption)
//!   - First 4 bytes of compressed region = original uncompressed size (LE u32)
//!   - Followed by LZ4 compressed data
//!
//! Only compress when payload > MIN_COMPRESS_SIZE (64 bytes).
//! Never compress core blocks on the hot path (NewOrder, ExecReport).

use crate::frame::{FrameFlags, FrameHeader};

/// Minimum payload size to bother compressing (below this, overhead > savings).
pub const MIN_COMPRESS_SIZE: usize = 64;

/// Maximum input size for compression (16MB — LZ4 block limit).
pub const MAX_COMPRESS_INPUT: usize = 16 * 1024 * 1024;

/// Compress a byte slice using LZ4 block format.
/// Returns compressed bytes, or None if compression would make it larger.
pub fn lz4_compress(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() > MAX_COMPRESS_INPUT {
        return None;
    }

    let max_output = lz4_max_compressed_size(input.len());
    let mut output = Vec::with_capacity(max_output);

    let mut ip = 0; // input position
    let mut anchor = 0; // start of current literal run

    // Hash table for match finding (4KB, covers 12-bit hash)
    let mut hash_table = [0u32; 4096];

    while ip + 4 <= input.len() {
        let h = hash4(&input[ip..]) as usize % hash_table.len();
        let ref_pos = hash_table[h] as usize;
        hash_table[h] = ip as u32;

        // Check for match (minimum 4 bytes, within 65535 window)
        if ref_pos > 0
            && ip - ref_pos <= 65535
            && ip + 4 <= input.len()
            && ref_pos + 4 <= input.len()
            && input[ref_pos..ref_pos + 4] == input[ip..ip + 4]
        {
            // Found a match — emit literals then match
            let lit_len = ip - anchor;
            let offset = (ip - ref_pos) as u16;

            // Extend match forward
            let mut match_len = 4;
            while ip + match_len < input.len()
                && ref_pos + match_len < ip
                && input[ref_pos + match_len] == input[ip + match_len]
            {
                match_len += 1;
            }

            // Encode token
            emit_sequence(&mut output, &input[anchor..ip], lit_len, offset, match_len);

            ip += match_len;
            anchor = ip;
        } else {
            ip += 1;
        }
    }

    // Final literals (everything from anchor to end)
    let remaining = input.len() - anchor;
    if remaining > 0 {
        emit_last_literals(&mut output, &input[anchor..]);
    }

    // Only return if actually smaller
    if output.len() < input.len() {
        Some(output)
    } else {
        None
    }
}

/// Decompress LZ4 block format.
pub fn lz4_decompress(input: &[u8], max_output_size: usize) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(max_output_size.min(input.len() * 4));
    let mut ip = 0;

    while ip < input.len() {
        let token = input[ip];
        ip += 1;

        // Literal length
        let mut lit_len = ((token >> 4) & 0x0F) as usize;
        if lit_len == 15 {
            loop {
                if ip >= input.len() { return None; }
                let extra = input[ip] as usize;
                ip += 1;
                lit_len += extra;
                if extra != 255 { break; }
            }
        }

        // Copy literals
        if ip + lit_len > input.len() { return None; }
        if output.len() + lit_len > max_output_size { return None; }
        output.extend_from_slice(&input[ip..ip + lit_len]);
        ip += lit_len;

        // End of block?
        if ip >= input.len() { break; }

        // Match offset (2 bytes, LE)
        if ip + 2 > input.len() { return None; }
        let offset = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
        ip += 2;
        if offset == 0 { return None; } // invalid

        // Match length
        let mut match_len = ((token & 0x0F) as usize) + 4; // min match = 4
        if (token & 0x0F) == 15 {
            loop {
                if ip >= input.len() { return None; }
                let extra = input[ip] as usize;
                ip += 1;
                match_len += extra;
                if extra != 255 { break; }
            }
        }

        // Copy match (may overlap — byte-by-byte for overlapping copies)
        if offset > output.len() { return None; }
        let match_start = output.len() - offset;
        if output.len() + match_len > max_output_size { return None; }
        for i in 0..match_len {
            let b = output[match_start + i];
            output.push(b);
        }
    }

    Some(output)
}

/// Compress an MGEP message payload in-place.
/// Compresses everything after FrameHeader. Prepends original size (4 bytes LE).
/// Returns new total message size, or original size if compression didn't help.
pub fn compress_message(buf: &mut [u8], msg_len: usize) -> usize {
    let payload = &buf[FrameHeader::SIZE..msg_len];
    if payload.len() < MIN_COMPRESS_SIZE {
        return msg_len;
    }

    let Some(compressed) = lz4_compress(payload) else {
        return msg_len; // compression made it larger
    };

    let original_size = payload.len() as u32;
    let new_payload_size = 4 + compressed.len(); // 4 bytes for original size + compressed
    let new_total = FrameHeader::SIZE + new_payload_size;

    if new_total >= msg_len {
        return msg_len; // not worth it
    }

    // Write: [original_size: u32 LE] [compressed data]
    buf[FrameHeader::SIZE..FrameHeader::SIZE + 4].copy_from_slice(&original_size.to_le_bytes());
    buf[FrameHeader::SIZE + 4..new_total].copy_from_slice(&compressed);

    // Update frame header: message_size at bytes [4..8], flags at byte [2]
    buf[4..8].copy_from_slice(&(new_total as u32).to_le_bytes());
    buf[2] |= FrameFlags::COMPRESSED;

    new_total
}

/// Decompress an MGEP message in-place.
/// Returns new total message size after decompression.
pub fn decompress_message(buf: &mut [u8], msg_len: usize) -> Option<usize> {
    let flags = buf[2];
    if flags & FrameFlags::COMPRESSED == 0 {
        return Some(msg_len); // not compressed
    }

    if msg_len < FrameHeader::SIZE + 4 {
        return None;
    }

    let original_size = u32::from_le_bytes(
        buf[FrameHeader::SIZE..FrameHeader::SIZE + 4].try_into().ok()?
    ) as usize;
    let compressed = &buf[FrameHeader::SIZE + 4..msg_len];

    let decompressed = lz4_decompress(compressed, original_size)?;
    if decompressed.len() != original_size {
        return None;
    }

    let new_total = FrameHeader::SIZE + original_size;
    buf[FrameHeader::SIZE..new_total].copy_from_slice(&decompressed);

    // Update frame header: message_size at bytes [4..8], flags at byte [2]
    buf[4..8].copy_from_slice(&(new_total as u32).to_le_bytes());
    buf[2] &= !FrameFlags::COMPRESSED;

    Some(new_total)
}

// ── Internal helpers ─────────────────────────────────────

fn lz4_max_compressed_size(input_len: usize) -> usize {
    input_len + (input_len / 255) + 16
}

fn hash4(data: &[u8]) -> u32 {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    v.wrapping_mul(2654435761) >> 20 // Knuth multiplicative hash
}

fn emit_sequence(output: &mut Vec<u8>, literals: &[u8], lit_len: usize, offset: u16, match_len: usize) {
    let ml = match_len - 4; // min match is 4

    // Token: high nibble = literal length, low nibble = match length - 4
    let lit_tok = lit_len.min(15) as u8;
    let match_tok = ml.min(15) as u8;
    output.push((lit_tok << 4) | match_tok);

    // Extended literal length
    if lit_len >= 15 {
        let mut rem = lit_len - 15;
        while rem >= 255 {
            output.push(255);
            rem -= 255;
        }
        output.push(rem as u8);
    }

    // Literal bytes
    output.extend_from_slice(literals);

    // Match offset (2 bytes LE)
    output.extend_from_slice(&offset.to_le_bytes());

    // Extended match length
    if ml >= 15 {
        let mut rem = ml - 15;
        while rem >= 255 {
            output.push(255);
            rem -= 255;
        }
        output.push(rem as u8);
    }
}

fn emit_last_literals(output: &mut Vec<u8>, literals: &[u8]) {
    let lit_len = literals.len();
    let tok = lit_len.min(15) as u8;
    output.push(tok << 4);

    if lit_len >= 15 {
        let mut rem = lit_len - 15;
        while rem >= 255 {
            output.push(255);
            rem -= 255;
        }
        output.push(rem as u8);
    }

    output.extend_from_slice(literals);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"Hello Hello Hello Hello Hello Hello Hello World World World!";
        let compressed = lz4_compress(data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = lz4_decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn compress_repetitive_data() {
        // Repetitive but varied data (like price levels)
        let mut data = Vec::with_capacity(1000);
        for i in 0..100 {
            // Simulates price level entries with repeating structure
            data.extend_from_slice(&(i as u64).to_le_bytes());
            data.extend_from_slice(&100u64.to_le_bytes()); // repeated qty
        }
        let compressed = lz4_compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        let decompressed = lz4_decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn compress_random_data_may_fail() {
        // Random data doesn't compress well
        let data: Vec<u8> = (0..256u16).map(|i| (i * 37 + 13) as u8).collect();
        // May or may not compress — both outcomes are valid
        if let Some(compressed) = lz4_compress(&data) {
            let decompressed = lz4_decompress(&compressed, data.len()).unwrap();
            assert_eq!(decompressed, data);
        }
    }

    #[test]
    fn message_level_compress_decompress() {
        // Build a large MGEP message with repetitive flex data
        let mut buf = [0u8; 4096];
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };

        // Large flex block (repetitive data compresses well)
        let mut flex = crate::flex::FlexWriter::new();
        flex.put_string(1, &"A".repeat(200));
        flex.put_string(2, &"B".repeat(200));
        let flex_data = flex.build();

        let mut enc = crate::codec::MessageBuffer::with_capacity(1024);
        let msg_len = enc.encode(1, 1, &order, Some(&flex_data));
        buf[..msg_len].copy_from_slice(enc.as_slice());

        let original_len = msg_len;

        // Compress
        let compressed_len = compress_message(&mut buf, msg_len);
        assert!(compressed_len < original_len, "should compress: {} vs {}", compressed_len, original_len);

        // Verify compressed flag
        assert!(buf[2] & FrameFlags::COMPRESSED != 0);

        // Decompress
        let decompressed_len = decompress_message(&mut buf, compressed_len).unwrap();
        assert_eq!(decompressed_len, original_len);

        // Verify flag cleared
        assert!(buf[2] & FrameFlags::COMPRESSED == 0);

        // Verify message integrity
        let decoded = crate::codec::MessageBuffer::decode_new_order(&buf[..decompressed_len]);
        assert_eq!(decoded.order_id, 42);
    }

    #[test]
    fn small_message_not_compressed() {
        // Create a buffer smaller than FrameHeader::SIZE + MIN_COMPRESS_SIZE
        // by using raw bytes with a valid frame header but small payload
        let mut buf = [0u8; 256];
        // Write a valid frame header with small message_size
        // magic at [0..2], flags at [2], version at [3], message_size at [4..8]
        buf[0..2].copy_from_slice(&crate::frame::MAGIC.to_le_bytes());
        buf[2] = 0; // no flags
        buf[3] = 1; // version
        let small_size: u32 = (crate::frame::FrameHeader::SIZE + MIN_COMPRESS_SIZE - 1) as u32;
        buf[4..8].copy_from_slice(&small_size.to_le_bytes());

        // Small message — compression should be skipped (payload < MIN_COMPRESS_SIZE)
        let result = compress_message(&mut buf, small_size as usize);
        assert_eq!(result, small_size as usize);
        assert!(buf[2] & FrameFlags::COMPRESSED == 0);
    }
}
