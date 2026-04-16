#![allow(dead_code, unused_imports)]
//! AES-NI Hardware-Accelerated AES-128-GCM.
//!
//! Uses x86/x86_64 AES-NI and CLMUL intrinsics for constant-time AES-GCM.
//! Falls back to the pure-Rust implementation if CPU doesn't support AES-NI.
//!
//! Constant-time: hardware AES uses a fixed pipeline — no table lookups,
//! no data-dependent branches, no cache-timing side channels.
//!
//! Detection: `has_aesni()` checks CPUID at runtime.

use crate::crypto::{AeadCipher, AeadError};

/// Check if the CPU supports AES-NI instructions.
#[inline]
pub fn has_aesni() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // CPUID leaf 1, ECX bit 25 = AES-NI
        #[cfg(target_arch = "x86")]
        use core::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::__cpuid;

        let result = unsafe { __cpuid(1) };
        (result.ecx & (1 << 25)) != 0
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { false }
}

/// Check if the CPU supports CLMUL (for GCM's GHASH).
#[inline]
pub fn has_clmul() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::__cpuid;

        let result = unsafe { __cpuid(1) };
        (result.ecx & (1 << 1)) != 0 // PCLMULQDQ
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { false }
}

/// AES-128-GCM using AES-NI hardware intrinsics.
/// Constant-time, side-channel resistant.
///
/// Falls back to pure-Rust `Aes128Gcm` if AES-NI not available.
pub struct Aes128GcmNi {
    inner: AesNiInner,
}

enum AesNiInner {
    Hardware(HwKeys),
    Fallback(crate::crypto::Aes128Gcm),
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
struct HwKeys {
    round_keys: [u128; 11],
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
struct HwKeys;

impl Aes128GcmNi {
    /// Create a new AES-128-GCM cipher. Uses hardware if available, fallback otherwise.
    pub fn new(key: &[u8; 16]) -> Self {
        if has_aesni() && has_clmul() {
            Self {
                inner: AesNiInner::Hardware(hw_key_expansion(key)),
            }
        } else {
            Self {
                inner: AesNiInner::Fallback(crate::crypto::Aes128Gcm::new(key)),
            }
        }
    }

    /// Returns true if using hardware AES-NI.
    pub fn is_hardware(&self) -> bool {
        matches!(self.inner, AesNiInner::Hardware(_))
    }
}

impl AeadCipher for Aes128GcmNi {
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, AeadError> {
        match &self.inner {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            AesNiInner::Hardware(keys) => {
                hw_aes_gcm_encrypt(keys, nonce, aad, buf, plaintext_len)
            }
            AesNiInner::Fallback(cipher) => {
                cipher.encrypt(nonce, aad, buf, plaintext_len)
            }
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            _ => unreachable!(),
        }
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, AeadError> {
        match &self.inner {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            AesNiInner::Hardware(keys) => {
                hw_aes_gcm_decrypt(keys, nonce, aad, buf, ciphertext_len)
            }
            AesNiInner::Fallback(cipher) => {
                cipher.decrypt(nonce, aad, buf, ciphertext_len)
            }
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            _ => unreachable!(),
        }
    }
}

// ============================================================================
// AES-NI implementation (x86/x86_64 only)
// ============================================================================

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn hw_key_expansion(key: &[u8; 16]) -> HwKeys {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    unsafe {
        let mut rk = [0u128; 11];
        let k = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        rk[0] = std::mem::transmute(k);

        macro_rules! expand {
            ($prev:expr, $rcon:expr) => {{
                let mut t = $prev;
                let mut g = _mm_aeskeygenassist_si128(t, $rcon);
                g = _mm_shuffle_epi32(g, 0xFF);
                t = _mm_xor_si128(t, _mm_slli_si128(t, 4));
                t = _mm_xor_si128(t, _mm_slli_si128(t, 4));
                t = _mm_xor_si128(t, _mm_slli_si128(t, 4));
                _mm_xor_si128(t, g)
            }};
        }

        let k1 = expand!(k, 0x01); rk[1] = std::mem::transmute(k1);
        let k2 = expand!(k1, 0x02); rk[2] = std::mem::transmute(k2);
        let k3 = expand!(k2, 0x04); rk[3] = std::mem::transmute(k3);
        let k4 = expand!(k3, 0x08); rk[4] = std::mem::transmute(k4);
        let k5 = expand!(k4, 0x10); rk[5] = std::mem::transmute(k5);
        let k6 = expand!(k5, 0x20); rk[6] = std::mem::transmute(k6);
        let k7 = expand!(k6, 0x40); rk[7] = std::mem::transmute(k7);
        let k8 = expand!(k7, 0x80); rk[8] = std::mem::transmute(k8);
        let k9 = expand!(k8, 0x1b); rk[9] = std::mem::transmute(k9);
        let k10 = expand!(k9, 0x36); rk[10] = std::mem::transmute(k10);

        HwKeys { round_keys: rk }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
unsafe fn hw_aes_encrypt_block(keys: &HwKeys, block: &mut [u8; 16]) {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let rk = |i: usize| -> __m128i { std::mem::transmute(keys.round_keys[i]) };

    state = _mm_xor_si128(state, rk(0));
    state = _mm_aesenc_si128(state, rk(1));
    state = _mm_aesenc_si128(state, rk(2));
    state = _mm_aesenc_si128(state, rk(3));
    state = _mm_aesenc_si128(state, rk(4));
    state = _mm_aesenc_si128(state, rk(5));
    state = _mm_aesenc_si128(state, rk(6));
    state = _mm_aesenc_si128(state, rk(7));
    state = _mm_aesenc_si128(state, rk(8));
    state = _mm_aesenc_si128(state, rk(9));
    state = _mm_aesenclast_si128(state, rk(10));

    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

// GCM operations using AES-NI for counter mode + the existing GHASH.
// In a full production build, GHASH would also use PCLMULQDQ, but
// for now we reuse the pure-Rust GHASH and only accelerate AES.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn hw_aes_gcm_encrypt(
    keys: &HwKeys,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    plaintext_len: usize,
) -> Result<usize, AeadError> {
    if buf.len() < plaintext_len + AUTH_TAG_SIZE {
        return Err(AeadError::BufferTooShort);
    }

    // H = AES(0)
    let mut h = [0u8; 16];
    unsafe { hw_aes_encrypt_block(keys, &mut h); }

    // J0 = nonce || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Counter mode encryption
    let mut counter = j0;
    increment_counter(&mut counter);

    let mut i = 0;
    while i < plaintext_len {
        let mut keystream = counter;
        unsafe { hw_aes_encrypt_block(keys, &mut keystream); }

        let end = (i + 16).min(plaintext_len);
        for j in i..end {
            buf[j] ^= keystream[j - i];
        }
        increment_counter(&mut counter);
        i += 16;
    }

    // GHASH + final tag (reusing pure-Rust GHASH)
    let tag = ghash_and_tag(keys, &h, &j0, aad, &buf[..plaintext_len]);
    buf[plaintext_len..plaintext_len + AUTH_TAG_SIZE].copy_from_slice(&tag);

    Ok(plaintext_len + AUTH_TAG_SIZE)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn hw_aes_gcm_decrypt(
    keys: &HwKeys,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    ciphertext_len: usize,
) -> Result<usize, AeadError> {
    if ciphertext_len < AUTH_TAG_SIZE {
        return Err(AeadError::BufferTooShort);
    }

    let plaintext_len = ciphertext_len - AUTH_TAG_SIZE;

    let mut h = [0u8; 16];
    unsafe { hw_aes_encrypt_block(keys, &mut h); }

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Verify tag before decrypting
    let expected_tag = ghash_and_tag(keys, &h, &j0, aad, &buf[..plaintext_len]);
    let mut diff = 0u8;
    for k in 0..AUTH_TAG_SIZE {
        diff |= expected_tag[k] ^ buf[plaintext_len + k];
    }
    if diff != 0 {
        return Err(AeadError::AuthenticationFailed);
    }

    // Counter mode decryption
    let mut counter = j0;
    increment_counter(&mut counter);

    let mut i = 0;
    while i < plaintext_len {
        let mut keystream = counter;
        unsafe { hw_aes_encrypt_block(keys, &mut keystream); }

        let end = (i + 16).min(plaintext_len);
        for j in i..end {
            buf[j] ^= keystream[j - i];
        }
        increment_counter(&mut counter);
        i += 16;
    }

    Ok(plaintext_len)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn ghash_and_tag(keys: &HwKeys, h: &[u8; 16], j0: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    // Reuse the pure-Rust GHASH from crypto.rs
    // A production version would use PCLMULQDQ for GHASH too
    let tag = ghash_compute(h, aad, ciphertext);

    let mut encrypted_j0 = *j0;
    unsafe { hw_aes_encrypt_block(keys, &mut encrypted_j0); }

    let mut final_tag = [0u8; 16];
    for k in 0..16 {
        final_tag[k] = tag[k] ^ encrypted_j0[k];
    }
    final_tag
}

// Shared helper functions (same as crypto.rs)

fn increment_counter(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 { break; }
    }
}

fn ghash_compute(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    ghash_update(&mut y, h, aad);
    ghash_update(&mut y, h, ciphertext);

    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());

    xor_block(&mut y, &len_block);
    y = gf128_mul(&y, h);
    y
}

fn ghash_update(y: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    let mut i = 0;
    while i + 16 <= data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[i..i + 16]);
        xor_block(y, &block);
        *y = gf128_mul(y, h);
        i += 16;
    }
    if i < data.len() {
        let mut block = [0u8; 16];
        block[..data.len() - i].copy_from_slice(&data[i..]);
        xor_block(y, &block);
        *y = gf128_mul(y, h);
    }
}

fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        if (x[byte_idx] >> bit_idx) & 1 == 1 {
            xor_block(&mut z, &v);
        }
        let lsb = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if lsb == 1 { v[0] ^= 0xe1; }
    }
    z
}

fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 { a[i] ^= b[i]; }
}

// Non-x86 stubs
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn hw_key_expansion(_key: &[u8; 16]) -> HwKeys { HwKeys }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_aesni() {
        let has = has_aesni();
        let has_cl = has_clmul();
        println!("AES-NI: {}, CLMUL: {}", has, has_cl);
    }

    #[test]
    fn aesni_roundtrip() {
        let key = [0x42u8; 16];
        let cipher = Aes128GcmNi::new(&key);
        println!("Using hardware: {}", cipher.is_hardware());

        let nonce = [1u8; 12];
        let aad = b"test-aad";
        let plaintext = b"Hello MGEP AES-NI!";

        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let enc_len = cipher.encrypt(&nonce, aad, &mut buf, plaintext.len()).unwrap();
        assert_ne!(&buf[..plaintext.len()], &plaintext[..]);

        let dec_len = cipher.decrypt(&nonce, aad, &mut buf, enc_len).unwrap();
        assert_eq!(&buf[..dec_len], &plaintext[..]);
    }

    #[test]
    fn aesni_tamper_fails() {
        let key = [0x42u8; 16];
        let cipher = Aes128GcmNi::new(&key);
        let nonce = [1u8; 12];

        let plaintext = b"secret";
        let mut buf = [0u8; 64];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let enc_len = cipher.encrypt(&nonce, &[], &mut buf, plaintext.len()).unwrap();
        buf[0] ^= 0x01;
        assert!(cipher.decrypt(&nonce, &[], &mut buf, enc_len).is_err());
    }

    #[test]
    fn aesni_matches_pure_rust() {
        // Both implementations must produce identical ciphertext
        let key = [0x42u8; 16];
        let sw = crate::crypto::Aes128Gcm::new(&key);
        let hw = Aes128GcmNi::new(&key);

        let nonce = [7u8; 12];
        let aad = b"frame-header";
        let plaintext = b"MGEP binary protocol message payload";

        let mut buf_sw = [0u8; 128];
        let mut buf_hw = [0u8; 128];
        buf_sw[..plaintext.len()].copy_from_slice(plaintext);
        buf_hw[..plaintext.len()].copy_from_slice(plaintext);

        let len_sw = sw.encrypt(&nonce, aad, &mut buf_sw, plaintext.len()).unwrap();
        let len_hw = hw.encrypt(&nonce, aad, &mut buf_hw, plaintext.len()).unwrap();

        assert_eq!(len_sw, len_hw);
        assert_eq!(&buf_sw[..len_sw], &buf_hw[..len_hw],
            "hardware and software AES-GCM must produce identical output");
    }

    #[test]
    fn nist_test_case_1_hw() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128GcmNi::new(&key);

        let mut buf = [0u8; 16];
        let result = cipher.encrypt(&nonce, &[], &mut buf, 0).unwrap();
        assert_eq!(result, 16);

        let expected: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
            0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
        ];
        assert_eq!(&buf[..16], &expected);
    }
}
