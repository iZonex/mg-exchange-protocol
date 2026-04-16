//! MGEP Security Module
//!
//! Three security levels:
//! - Level 0: No auth (trusted network)
//! - Level 1: HMAC-SHA256 authentication (integrity + auth)
//! - Level 2: AES-128-GCM AEAD (encryption + integrity + auth)
//!
//! This module provides a pure-Rust implementation.
//! In production, AES-NI hardware acceleration makes Level 2 near-zero-cost.

use crate::frame::{AUTH_TAG_SIZE, AuthTag, FrameHeader};

// ============================================================================
// HMAC-SHA256 (Level 1)
// ============================================================================

/// HMAC-SHA256 context for message authentication.
/// Truncated to 128-bit (16 bytes) for the auth tag.
pub struct HmacSha256 {
    key: [u8; 64], // Pre-padded key
}

impl HmacSha256 {
    /// Create a new HMAC context with the given key.
    pub fn new(key: &[u8]) -> Self {
        let mut padded = [0x36u8; 64]; // ipad

        if key.len() <= 64 {
            for (i, &b) in key.iter().enumerate() {
                padded[i] = b ^ 0x36;
            }
        } else {
            // Key > 64 bytes: hash it first
            let hashed = sha256(key);
            for (i, &b) in hashed.iter().enumerate() {
                padded[i] = b ^ 0x36;
            }
        }

        Self { key: padded }
    }

    /// Compute HMAC-SHA256 and return truncated 128-bit tag.
    pub fn authenticate(&self, message: &[u8]) -> AuthTag {
        // Inner hash: H(K ^ ipad || message)
        let mut inner_input = Vec::with_capacity(64 + message.len());
        inner_input.extend_from_slice(&self.key);
        inner_input.extend_from_slice(message);
        let inner_hash = sha256(&inner_input);

        // Outer key: K ^ opad (ipad ^ opad = 0x36 ^ 0x5c = 0x6a)
        let mut outer_key = self.key;
        for b in &mut outer_key {
            *b ^= 0x6a; // ipad -> opad: XOR with (0x36 ^ 0x5c)
        }

        // Outer hash: H(K ^ opad || inner_hash)
        let mut outer_input = Vec::with_capacity(64 + 32);
        outer_input.extend_from_slice(&outer_key);
        outer_input.extend_from_slice(&inner_hash);
        let full_hash = sha256(&outer_input);

        // Truncate to 128-bit
        let mut tag = [0u8; AUTH_TAG_SIZE];
        tag.copy_from_slice(&full_hash[..AUTH_TAG_SIZE]);
        tag
    }

    /// Verify an auth tag against a message.
    pub fn verify(&self, message: &[u8], tag: &AuthTag) -> bool {
        let computed = self.authenticate(message);
        constant_time_eq(&computed, tag)
    }
}

/// Sign a message buffer in-place. Appends 16-byte auth tag.
/// Returns new total length (original + 16).
///
/// The HMAC is computed over the message body (offset 8..msg_len) — everything
/// after the frame header. The frame header itself is excluded because it is
/// modified by this function (size and flags are updated).
pub fn sign_message(buf: &mut [u8], msg_len: usize, hmac: &HmacSha256) -> usize {
    // Update frame header first, then compute HMAC over the body only
    let new_size = msg_len + AUTH_TAG_SIZE;
    buf[4..8].copy_from_slice(&(new_size as u32).to_le_bytes());
    buf[2] |= crate::frame::FrameFlags::HAS_AUTH_TAG;

    // HMAC covers message header + core + flex (not frame header, not tag)
    let body = &buf[FrameHeader::SIZE..msg_len];
    let tag = hmac.authenticate(body);
    buf[msg_len..new_size].copy_from_slice(&tag);

    new_size
}

/// Verify a signed message. Returns true if auth tag is valid.
pub fn verify_message(buf: &[u8], hmac: &HmacSha256) -> bool {
    if buf.len() < AUTH_TAG_SIZE + crate::header::FullHeader::SIZE {
        return false;
    }

    let msg_len = buf.len() - AUTH_TAG_SIZE;
    let mut tag = [0u8; AUTH_TAG_SIZE];
    tag.copy_from_slice(&buf[msg_len..]);

    // HMAC covers message header + core + flex (same range as sign_message)
    let body = &buf[FrameHeader::SIZE..msg_len];
    hmac.verify(body, &tag)
}

// ============================================================================
// SHA-256 (minimal pure-Rust implementation)
// ============================================================================

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing: padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

/// Constant-time comparison to prevent timing attacks.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        let hash = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn sha256_abc() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn hmac_sign_verify() {
        let key = b"super-secret-trading-key-12345";
        let hmac = HmacSha256::new(key);

        let message = b"NewOrderSingle|BUY|AAPL|100@150.25";
        let tag = hmac.authenticate(message);

        assert!(hmac.verify(message, &tag));

        // Tampered message should fail
        let tampered = b"NewOrderSingle|BUY|AAPL|999@150.25";
        assert!(!hmac.verify(tampered, &tag));
    }

    #[test]
    fn hmac_deterministic() {
        let key = b"test-key";
        let hmac = HmacSha256::new(key);

        let msg = b"same message";
        let tag1 = hmac.authenticate(msg);
        let tag2 = hmac.authenticate(msg);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn sign_verify_message_buffer() {
        let key = b"exchange-key-2026";
        let hmac = HmacSha256::new(key);

        // Build a minimal message
        let order = crate::messages::NewOrderSingleCore {
            order_id: 1,
            instrument_id: 42,
            side: crate::types::Side::Buy as u8,
            order_type: crate::types::OrderType::Limit as u8,
            time_in_force: crate::types::TimeInForce::IOC as u16,
            price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };

        let mut buf = [0u8; 256];
        let mut codec = crate::codec::MessageBuffer::with_capacity(256);
        let msg_len = codec.encode_new_order(1, 1, &order, None);
        buf[..msg_len].copy_from_slice(&codec.as_slice()[..msg_len]);

        // Sign
        let total_len = sign_message(&mut buf, msg_len, &hmac);
        assert_eq!(total_len, msg_len + 16);

        // Verify
        assert!(verify_message(&buf[..total_len], &hmac));

        // Tamper and verify fails
        buf[30] ^= 0xFF; // flip a byte in the core block
        assert!(!verify_message(&buf[..total_len], &hmac));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
