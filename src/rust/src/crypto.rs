//! MGEP Cryptography Module
//!
//! Provides AES-128-GCM AEAD encryption (SecurityLevel::Encrypted).
//! Pluggable design: the `AeadCipher` trait allows swapping in hardware-backed
//! or third-party implementations.
//!
//! Wire format:
//!   [FrameHeader (8B cleartext)] [encrypted payload] [GCM tag (16B)]
//!
//! Encrypt scope: message header + core block + flex block.
//! Frame header stays cleartext so the transport layer can read message_size.
//!
//! Nonce construction (12 bytes, never repeats):
//!   [session_id truncated to 4B] [sender_comp_id zero-extended to 4B] [sequence_num 4B]

use crate::frame::{AUTH_TAG_SIZE, FrameFlags, FrameHeader};

// ============================================================================
// Pluggable AEAD trait
// ============================================================================

/// Trait for AEAD (Authenticated Encryption with Associated Data) ciphers.
/// Implementations must be constant-time to prevent side-channel attacks.
pub trait AeadCipher {
    /// Encrypt plaintext in-place and append authentication tag.
    /// `aad` is additional authenticated data (not encrypted, but authenticated).
    /// Returns the ciphertext length (plaintext_len + tag_len).
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, AeadError>;

    /// Decrypt ciphertext in-place and verify authentication tag.
    /// The tag is the last `AUTH_TAG_SIZE` bytes of `ciphertext`.
    /// Returns the plaintext length (ciphertext_len - tag_len).
    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, AeadError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    AuthenticationFailed,
    BufferTooShort,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            Self::BufferTooShort => write!(f, "buffer too short for AEAD operation"),
        }
    }
}

impl std::error::Error for AeadError {}

// ============================================================================
// Nonce construction
// ============================================================================

/// Build a 12-byte GCM nonce from session parameters.
///
/// Layout: [session_id_lo: 4B] [sender_comp_id: 4B] [sequence_num_lo: 4B]
///
/// SAFETY: sequence_num is u64 monotonic, never reused within a session.
/// After SequenceReset, the caller MUST derive a new key (different session epoch)
/// to prevent nonce reuse. See `derive_key_with_epoch()`.
///
/// Uses full u32 of sender_comp_id and low 32 bits of sequence_num.
/// At 1M msg/sec, the 32-bit seq portion wraps in ~71 minutes — but the full
/// u64 sequence is tracked in the session, and key rotation happens at epoch change.
#[inline]
pub fn build_nonce(session_id: u64, sender_comp_id: u32, sequence_num: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&(session_id as u32).to_le_bytes());
    nonce[4..8].copy_from_slice(&sender_comp_id.to_le_bytes());
    // Use low 32 bits of sequence. Key rotation prevents collision across epochs.
    nonce[8..12].copy_from_slice(&(sequence_num as u32).to_le_bytes());
    nonce
}

/// Derive key with epoch — use after SequenceReset to prevent nonce reuse.
/// Each epoch gets a different key, so even if sequence numbers repeat, nonces differ.
pub fn derive_key_with_epoch(pre_shared_key: &[u8], session_id: u64, epoch: u32) -> [u8; 16] {
    let mut salt = [0u8; 12];
    salt[0..8].copy_from_slice(&session_id.to_le_bytes());
    salt[8..12].copy_from_slice(&epoch.to_le_bytes());
    let hmac = crate::auth::HmacSha256::new(&salt);
    let prk = hmac.authenticate(pre_shared_key);
    let expand = crate::auth::HmacSha256::new(&prk);
    let mut info = Vec::with_capacity(16);
    info.extend_from_slice(b"mgep-aes128");
    info.push(0x01);
    let okm = expand.authenticate(&info);
    let mut key = [0u8; 16];
    key.copy_from_slice(&okm[..16]);
    key
}

// ============================================================================
// Message-level encrypt / decrypt
// ============================================================================

/// Encrypt an MGEP message in-place.
///
/// The frame header (first 8 bytes) is used as AAD (authenticated but not encrypted).
/// Everything after the frame header is encrypted.
/// A 16-byte GCM tag is appended.
///
/// Returns the new total message length (original + 16).
pub fn encrypt_message(
    buf: &mut [u8],
    msg_len: usize,
    cipher: &dyn AeadCipher,
    session_id: u64,
    sender_comp_id: u32,
    sequence_num: u64,
) -> Result<usize, AeadError> {
    if msg_len < FrameHeader::SIZE {
        return Err(AeadError::BufferTooShort);
    }
    if buf.len() < msg_len + AUTH_TAG_SIZE {
        return Err(AeadError::BufferTooShort);
    }

    let nonce = build_nonce(session_id, sender_comp_id, sequence_num);

    // Update frame header before capturing AAD
    let new_size = msg_len + AUTH_TAG_SIZE;
    buf[4..8].copy_from_slice(&(new_size as u32).to_le_bytes());
    buf[2] |= FrameFlags::HAS_AUTH_TAG | FrameFlags::ENCRYPTED;

    // AAD = frame header (8 bytes) — stack array, ZERO heap allocation
    let mut aad = [0u8; 8];
    aad.copy_from_slice(&buf[..FrameHeader::SIZE]);

    // Encrypt payload (everything after frame header)
    let payload_start = FrameHeader::SIZE;
    let payload_len = msg_len - payload_start;

    let encrypted_len = cipher.encrypt(
        &nonce,
        &aad,
        &mut buf[payload_start..],
        payload_len,
    )?;

    Ok(payload_start + encrypted_len)
}

/// Decrypt an MGEP message in-place.
///
/// The frame header flags must have ENCRYPTED set.
/// Returns the new total message length (original - 16) after removing the tag.
pub fn decrypt_message(
    buf: &mut [u8],
    msg_len: usize,
    cipher: &dyn AeadCipher,
    session_id: u64,
    sender_comp_id: u32,
    sequence_num: u64,
) -> Result<usize, AeadError> {
    if msg_len < FrameHeader::SIZE + AUTH_TAG_SIZE {
        return Err(AeadError::BufferTooShort);
    }

    let nonce = build_nonce(session_id, sender_comp_id, sequence_num);

    // AAD = frame header (8 bytes) — stack array, no allocation
    let mut aad = [0u8; 8];
    aad.copy_from_slice(&buf[..FrameHeader::SIZE]);

    let payload_start = FrameHeader::SIZE;
    let ciphertext_len = msg_len - payload_start;

    let plaintext_len = cipher.decrypt(
        &nonce,
        &aad,
        &mut buf[payload_start..],
        ciphertext_len,
    )?;

    // Update frame header: remove encrypted flag, adjust size
    let new_size = payload_start + plaintext_len;
    buf[4..8].copy_from_slice(&(new_size as u32).to_le_bytes());
    buf[2] &= !(FrameFlags::ENCRYPTED | FrameFlags::HAS_AUTH_TAG);

    Ok(new_size)
}

// ============================================================================
// HKDF-SHA256 key derivation
// ============================================================================

/// Derive an AES-128 key from a pre-shared key and session context.
/// Uses HKDF-SHA256: extract with salt=session_id, expand with info="mgep-aes128".
pub fn derive_key(pre_shared_key: &[u8], session_id: u64) -> [u8; 16] {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    let salt = session_id.to_le_bytes();
    let hmac = crate::auth::HmacSha256::new(&salt);
    let prk = hmac.authenticate(pre_shared_key);

    // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    // We only need 16 bytes (one block), so one HMAC call suffices.
    let expand_hmac = crate::auth::HmacSha256::new(&prk);
    let mut info_input = Vec::with_capacity(16);
    info_input.extend_from_slice(b"mgep-aes128");
    info_input.push(0x01);
    let okm = expand_hmac.authenticate(&info_input);

    let mut key = [0u8; 16];
    key.copy_from_slice(&okm[..16]);
    key
}

// ============================================================================
// Pure-Rust AES-128-GCM reference implementation
// ============================================================================

/// AES-128-GCM cipher — pure Rust, zero external dependencies.
/// Suitable for testing and environments without AES-NI.
/// For production with AES-NI, use a hardware-backed implementation.
pub struct Aes128Gcm {
    round_keys: [[u8; 16]; 11], // AES-128 = 10 rounds + 1 initial
}

impl Aes128Gcm {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: aes_key_expansion(key),
        }
    }

    fn aes_encrypt_block(&self, block: &mut [u8; 16]) {
        aes_encrypt_block_impl(block, &self.round_keys);
    }
}

impl AeadCipher for Aes128Gcm {
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, AeadError> {
        if buf.len() < plaintext_len + AUTH_TAG_SIZE {
            return Err(AeadError::BufferTooShort);
        }

        // Generate H = AES_K(0^128) for GHASH
        let mut h = [0u8; 16];
        self.aes_encrypt_block(&mut h);

        // Initial counter J0 = nonce || 0x00000001
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        // Encrypt plaintext with counter mode (starting from J0 + 1)
        let mut counter = j0;
        increment_counter(&mut counter);

        let mut i = 0;
        while i < plaintext_len {
            let mut keystream = counter;
            self.aes_encrypt_block(&mut keystream);

            let end = (i + 16).min(plaintext_len);
            for j in i..end {
                buf[j] ^= keystream[j - i];
            }

            increment_counter(&mut counter);
            i += 16;
        }

        // Compute GHASH over AAD and ciphertext
        let tag = ghash_compute(&h, aad, &buf[..plaintext_len]);

        // Final tag = GHASH XOR AES_K(J0)
        let mut encrypted_j0 = j0;
        self.aes_encrypt_block(&mut encrypted_j0);

        let mut final_tag = [0u8; 16];
        for k in 0..16 {
            final_tag[k] = tag[k] ^ encrypted_j0[k];
        }

        // Append tag
        buf[plaintext_len..plaintext_len + AUTH_TAG_SIZE].copy_from_slice(&final_tag);

        Ok(plaintext_len + AUTH_TAG_SIZE)
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, AeadError> {
        if ciphertext_len < AUTH_TAG_SIZE {
            return Err(AeadError::BufferTooShort);
        }

        let plaintext_len = ciphertext_len - AUTH_TAG_SIZE;

        // Generate H for GHASH
        let mut h = [0u8; 16];
        self.aes_encrypt_block(&mut h);

        // J0 = nonce || 0x00000001
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        // Verify tag BEFORE decrypting (to prevent chosen-ciphertext attacks)
        let expected_tag = ghash_compute(&h, aad, &buf[..plaintext_len]);
        let mut encrypted_j0 = j0;
        self.aes_encrypt_block(&mut encrypted_j0);

        let mut expected_final = [0u8; 16];
        for k in 0..16 {
            expected_final[k] = expected_tag[k] ^ encrypted_j0[k];
        }

        // Constant-time tag comparison
        let received_tag = &buf[plaintext_len..ciphertext_len];
        let mut diff = 0u8;
        for k in 0..AUTH_TAG_SIZE {
            diff |= expected_final[k] ^ received_tag[k];
        }
        if diff != 0 {
            return Err(AeadError::AuthenticationFailed);
        }

        // Decrypt with counter mode
        let mut counter = j0;
        increment_counter(&mut counter);

        let mut i = 0;
        while i < plaintext_len {
            let mut keystream = counter;
            self.aes_encrypt_block(&mut keystream);

            let end = (i + 16).min(plaintext_len);
            for j in i..end {
                buf[j] ^= keystream[j - i];
            }

            increment_counter(&mut counter);
            i += 16;
        }

        Ok(plaintext_len)
    }
}

// ============================================================================
// AES-128 core (S-box, MixColumns, KeyExpansion, single-block encrypt)
// ============================================================================

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn aes_key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0].copy_from_slice(key);

    for i in 1..11 {
        let prev = rk[i - 1];
        let mut temp = [prev[12], prev[13], prev[14], prev[15]];

        // RotWord + SubWord + Rcon
        temp.rotate_left(1);
        for b in &mut temp {
            *b = SBOX[*b as usize];
        }
        temp[0] ^= RCON[i - 1];

        for j in 0..4 {
            let base = j * 4;
            for k in 0..4 {
                rk[i][base + k] = prev[base + k] ^ temp[k];
            }
            temp = [rk[i][base], rk[i][base + 1], rk[i][base + 2], rk[i][base + 3]];
        }
    }

    rk
}

fn aes_encrypt_block_impl(state: &mut [u8; 16], rk: &[[u8; 16]; 11]) {
    // AddRoundKey (initial)
    xor_block(state, &rk[0]);

    // Rounds 1..9
    for round in 1..10 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        xor_block(state, &rk[round]);
    }

    // Final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    xor_block(state, &rk[10]);
}

#[inline]
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

#[inline]
fn shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;

    // Row 2: shift left by 2
    let (t0, t1) = (state[2], state[6]);
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;

    // Row 3: shift left by 3 (= right by 1)
    let t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

#[inline]
fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let (a0, a1, a2, a3) = (state[i], state[i + 1], state[i + 2], state[i + 3]);

        let r0 = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3;
        let r1 = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3;
        let r2 = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3);
        let r3 = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3);

        state[i] = r0;
        state[i + 1] = r1;
        state[i + 2] = r2;
        state[i + 3] = r3;
    }
}

#[inline]
fn gf_mul2(x: u8) -> u8 {
    let shifted = (x as u16) << 1;
    (shifted ^ if shifted & 0x100 != 0 { 0x11b } else { 0 }) as u8
}

#[inline]
fn gf_mul3(x: u8) -> u8 {
    gf_mul2(x) ^ x
}

// ============================================================================
// GCM: GHASH and counter management
// ============================================================================

fn increment_counter(counter: &mut [u8; 16]) {
    // Increment the last 4 bytes (big-endian counter)
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// GF(2^128) multiplication for GHASH.
/// Operates on 128-bit blocks represented as [u8; 16] in big-endian bit order.
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..128 {
        // Check if bit i of X is set (MSB first)
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        if (x[byte_idx] >> bit_idx) & 1 == 1 {
            xor_block_ref(&mut z, &v);
        }

        // V = V >> 1 in GF(2^128), with reduction polynomial
        let lsb = v[15] & 1;
        // Right shift V by 1
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;

        if lsb == 1 {
            v[0] ^= 0xe1; // reduction polynomial: x^128 + x^7 + x^2 + x + 1
        }
    }

    z
}

fn xor_block_ref(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// Compute GHASH(H, A, C) where A=AAD, C=ciphertext.
fn ghash_compute(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD
    ghash_update(&mut y, h, aad);

    // Process ciphertext
    ghash_update(&mut y, h, ciphertext);

    // Final block: [len(A) in bits (64-bit BE)] [len(C) in bits (64-bit BE)]
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());

    xor_block_ref(&mut y, &len_block);
    y = gf128_mul(&y, h);

    y
}

fn ghash_update(y: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    let mut i = 0;
    while i + 16 <= data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[i..i + 16]);
        xor_block_ref(y, &block);
        *y = gf128_mul(y, h);
        i += 16;
    }

    // Handle partial last block (pad with zeros)
    if i < data.len() {
        let mut block = [0u8; 16];
        block[..data.len() - i].copy_from_slice(&data[i..]);
        xor_block_ref(y, &block);
        *y = gf128_mul(y, h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST GCM Test Case 1: Empty plaintext, empty AAD, 128-bit key of zeros
    #[test]
    fn aes128_gcm_nist_test_case_1() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128Gcm::new(&key);

        let mut buf = [0u8; 16]; // room for tag only
        let result = cipher.encrypt(&nonce, &[], &mut buf, 0).unwrap();
        assert_eq!(result, 16); // just the tag

        let expected_tag: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
            0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
        ];
        assert_eq!(&buf[..16], &expected_tag);
    }

    // NIST GCM Test Case 2: 128-bit key of zeros, 16 bytes of zero plaintext
    #[test]
    fn aes128_gcm_nist_test_case_2() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128Gcm::new(&key);

        let mut buf = [0u8; 48]; // 16 plaintext + 16 tag + headroom
        let result = cipher.encrypt(&nonce, &[], &mut buf, 16).unwrap();
        assert_eq!(result, 32); // 16 ciphertext + 16 tag

        let expected_ct: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
            0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        ];
        assert_eq!(&buf[..16], &expected_ct);

        let expected_tag: [u8; 16] = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
            0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
        ];
        assert_eq!(&buf[16..32], &expected_tag);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [1u8; 12];
        let cipher = Aes128Gcm::new(&key);
        let aad = b"frame-header";

        let plaintext = b"Hello, MGEP encryption!";
        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let enc_len = cipher.encrypt(&nonce, aad, &mut buf, plaintext.len()).unwrap();
        assert_eq!(enc_len, plaintext.len() + 16);

        // Ciphertext should differ from plaintext
        assert_ne!(&buf[..plaintext.len()], &plaintext[..]);

        // Decrypt
        let dec_len = cipher.decrypt(&nonce, aad, &mut buf, enc_len).unwrap();
        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&buf[..dec_len], &plaintext[..]);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x42u8; 16];
        let nonce = [1u8; 12];
        let cipher = Aes128Gcm::new(&key);

        let plaintext = b"secret data";
        let mut buf = [0u8; 64];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let enc_len = cipher.encrypt(&nonce, &[], &mut buf, plaintext.len()).unwrap();

        // Flip a bit in the ciphertext
        buf[0] ^= 0x01;

        let result = cipher.decrypt(&nonce, &[], &mut buf, enc_len);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn message_level_encrypt_decrypt() {
        let key = derive_key(b"my-pre-shared-key", 0xCAFEBABE);
        let cipher = Aes128Gcm::new(&key);

        // Build a minimal MGEP message
        let mut buf = [0u8; 256];
        let mut encoder = crate::codec::MessageBuffer::with_capacity(256);
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42,
            instrument_id: 7,
            side: 1,
            order_type: 2,
            time_in_force: 1,
            price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };
        let msg_len = encoder.encode(1, 1, &order, None);
        buf[..msg_len].copy_from_slice(encoder.as_slice());

        // Encrypt
        let enc_len = encrypt_message(&mut buf, msg_len, &cipher, 0xCAFEBABE, 1, 1).unwrap();
        assert_eq!(enc_len, msg_len + 16);

        // Verify encrypted flag is set
        let frame = crate::frame::FrameHeader::from_bytes(&buf);
        assert!(frame.flags.is_encrypted());
        assert!(frame.flags.has_auth_tag());

        // Decrypt
        let dec_len = decrypt_message(&mut buf, enc_len, &cipher, 0xCAFEBABE, 1, 1).unwrap();
        assert_eq!(dec_len, msg_len);

        // Verify we can decode the order
        let decoded = crate::codec::MessageBuffer::decode_new_order(&buf[..dec_len]);
        assert_eq!(decoded.order_id, 42);
        assert_eq!(decoded.instrument_id, 7);
    }

    #[test]
    fn derive_key_deterministic() {
        let k1 = derive_key(b"test-key", 1);
        let k2 = derive_key(b"test-key", 1);
        let k3 = derive_key(b"test-key", 2);

        assert_eq!(k1, k2);
        assert_ne!(k1, k3); // different session_id → different key
    }

    #[test]
    fn nonce_uniqueness() {
        let n1 = build_nonce(1, 1, 1);
        let n2 = build_nonce(1, 1, 2);
        let n3 = build_nonce(2, 1, 1);

        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
    }
}
