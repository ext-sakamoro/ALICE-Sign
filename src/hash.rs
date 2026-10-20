//! SHA-256 hashing.

use alloc::string::String;
use core::fmt;

use crate::error::{decode, encode, HexError};

/// A 256-bit hash value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// All-zero hash.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Create a `Hash` from a raw byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Encode to a lowercase hex string (64 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }

    /// Decode from a 64-character hex string.
    ///
    /// # Errors
    ///
    /// [`HexError`] when the input length is not 64 or contains non-hex
    /// characters.
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        decode::<32>(hex).map(Self)
    }

    /// Return `true` when the first `n` bits are zero.
    ///
    /// A hash has 256 bits, so for `n > 256` this is `false` (it does not
    /// panic: `n` may come from outside, for example a difficulty).
    #[must_use]
    pub fn has_leading_zeros(&self, n: u32) -> bool {
        if n > 256 {
            return false;
        }
        let full_bytes = n / 8;
        let remaining_bits = n % 8;
        for &b in &self.0[..full_bytes as usize] {
            if b != 0 {
                return false;
            }
        }
        if remaining_bits > 0 {
            let mask = 0xFF_u8 << (8 - remaining_bits);
            if self.0[full_bytes as usize] & mask != 0 {
                return false;
            }
        }
        true
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// SHA-256 of `data`.
#[must_use]
pub fn hash_data(data: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Hash(bytes)
}
