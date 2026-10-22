//! HMAC-SHA256 (RFC 2104 with SHA-256, the construction RFC 4231 tests) and a
//! constant-time byte comparison.
//!
//! The tag of a key and a message is the same as the one any other HMAC-SHA256
//! implementation computes (`tests/hmac.rs` checks RFC 4231 test cases 1 to 7
//! and compares with the `hmac` crate), so a value stored earlier by another
//! implementation is reproduced exactly. A key longer than the 64-byte block is
//! hashed first; a shorter one is padded with zeros.
//!
//! [`verify_hmac_sha256`] compares in constant time and accepts the full
//! 32-byte tag or a prefix of at least 16 bytes (a truncated tag, as RFC 4231
//! test case 5 and RFC 2104 section 5 describe).

use sha2::{Digest, Sha256};

/// Length of an HMAC-SHA256 tag in bytes.
pub const HMAC_SHA256_LENGTH: usize = 32;

/// The shortest tag prefix [`verify_hmac_sha256`] accepts (half the output,
/// RFC 2104 section 5).
pub const HMAC_SHA256_MIN_TAG_LENGTH: usize = 16;

const BLOCK: usize = 64;

/// Incremental HMAC-SHA256: [`new`](Self::new), any number of
/// [`update`](Self::update) calls, then [`finalize`](Self::finalize). The tag
/// does not depend on how the message is split between the calls.
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer_key: [u8; BLOCK],
}

impl HmacSha256 {
    /// Starts a tag under `key` (any length).
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0u8; BLOCK];
        if key.len() > BLOCK {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut inner_key = [0u8; BLOCK];
        let mut outer_key = [0u8; BLOCK];
        for i in 0..BLOCK {
            inner_key[i] = block[i] ^ 0x36;
            outer_key[i] = block[i] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(inner_key);
        Self { inner, outer_key }
    }

    /// Appends `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// The 32-byte tag of everything given to [`update`](Self::update).
    #[must_use]
    pub fn finalize(self) -> [u8; HMAC_SHA256_LENGTH] {
        let inner = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.outer_key);
        outer.update(inner);
        outer.finalize().into()
    }
}

impl core::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // the state holds key material
        f.write_str("HmacSha256 { .. }")
    }
}

/// The HMAC-SHA256 tag of `message` under `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_SHA256_LENGTH] {
    let mut mac = HmacSha256::new(key);
    mac.update(message);
    mac.finalize()
}

/// Whether `tag` is the HMAC-SHA256 tag of `message` under `key`, or a prefix
/// of it of [`HMAC_SHA256_MIN_TAG_LENGTH`] to [`HMAC_SHA256_LENGTH`] bytes.
/// The comparison takes the same time wherever the bytes differ.
#[must_use]
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], tag: &[u8]) -> bool {
    if tag.len() < HMAC_SHA256_MIN_TAG_LENGTH || tag.len() > HMAC_SHA256_LENGTH {
        return false;
    }
    ct_eq(&hmac_sha256(key, message)[..tag.len()], tag)
}

/// Whether `a` and `b` hold the same bytes, in time that depends only on the
/// lengths (not on where the bytes differ). Inputs of different lengths are
/// unequal; the lengths themselves are not treated as secret.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}
