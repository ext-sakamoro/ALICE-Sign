//! Errors of the hex decoders.

use alloc::string::{String, ToString};
use core::fmt;

/// A hex string that does not decode to the expected number of bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexError(pub String);

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid hex: {}", self.0)
    }
}

impl core::error::Error for HexError {}

/// Decode exactly `N` bytes from `2 * N` hex characters.
pub(crate) fn decode<const N: usize>(hex: &str) -> Result<[u8; N], HexError> {
    if hex.len() != N * 2 {
        return Err(HexError(alloc::format!(
            "expected {} hex chars, got {}",
            N * 2,
            hex.len()
        )));
    }
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| HexError(e.to_string()))?;
    }
    Ok(bytes)
}

/// Lowercase hex of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
