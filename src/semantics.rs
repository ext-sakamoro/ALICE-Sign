//! Content hash of what this crate computes: [`SIGN_SEMANTICS_ID`] (ALICE-Law G6).
//!
//! [`SIGN_SEMANTICS_PINS`] pins, one SHA-256 each, the outputs of the crate's own entry points
//! on fixed inputs: the Ed25519 public keys and signatures, SHA-256, HMAC-SHA256, the Merkle
//! roots, and the verdicts of `verify` and `verify_strict` (including a small-order key, which
//! only the strict one refuses). [`SIGN_SEMANTICS_ID`] folds them. Two builds with the same
//! identifier return the same bytes and verdicts for every pinned scenario; a change in what the
//! crate computes moves a pin and the identifier. `tests/sign_semantics_id.rs` recomputes every
//! pin from the live code. The crate depends on no other Law-bearing crate, so no upstream
//! identifier is folded. The table and the identifier are constants that no `cfg` gates, so a
//! build with any feature set reports the same identifier; `cred` has an identifier of its own.
//!
//! # Hex form
//!
//! ```text
//! 4bab96c9a3e77917a1b6e2af057da23f50109dd6c846b5b9e3792dc89b59ff11
//! ```
//!
//! # Fold
//!
//! The procedure of `alice-det-math`'s `SEMANTICS_ID` fold ([`fold_semantics_pins`]): sort the
//! entries by name (ascending byte order), reject an empty, repeated or non-ASCII name, then
//! SHA-256 over, for each entry in that order, the name length as 4 bytes big-endian (`u32`),
//! the name bytes and the 32 digest bytes.

use alloc::vec::Vec;

use crate::hash::hash_data;

/// Decodes 64 hex digits into 32 bytes at compile time; anything else is a compile error.
pub(crate) const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lower-case hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "a digest is 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) * 16 + nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Fold a `(name, digest)` pins table the way the ecosystem's Law-bearing types do, so the Law
/// matrix recomputes a crate's id the same way: reject an empty, repeated or non-ASCII name,
/// sort by name, then SHA-256 over `u32-BE(name length) || name || digest` for each entry in
/// sorted order.
///
/// # Panics
///
/// On an empty, repeated or non-ASCII name.
#[must_use]
pub fn fold_semantics_pins(pins: &[(&str, [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<&(&str, [u8; 32])> = pins.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut buf = Vec::new();
    let mut prev: Option<&str> = None;
    for (name, digest) in sorted {
        assert!(!name.is_empty(), "empty pin name");
        assert!(name.is_ascii(), "non-ASCII pin name: {name}");
        assert!(prev != Some(name), "repeated pin name: {name}");
        prev = Some(name);
        buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(digest);
    }
    hash_data(&buf).0
}

/// The behavioural goldens [`SIGN_SEMANTICS_ID`] folds, each the SHA-256 of a fixed scenario's
/// outputs (`tests/sign_semantics_id.rs` writes each scenario out and recomputes it).
pub const SIGN_SEMANTICS_PINS: &[(&str, [u8; 32])] = &[
    (
        "golden ed25519 public keys and signatures",
        hex32("b48c978f19494710d57255ecc4b37daefe988d2089accd804760dbf7468e9f45"),
    ),
    (
        "golden hmac_sha256",
        hex32("bc79fb4a88e7b2aebb6f1cc825c369744fde4cb7f1eb26b0d5fb7c744568cce6"),
    ),
    (
        "golden merkle roots",
        hex32("bf909b92f2c8329720d15df102dda2accbf8010fe8d982f9e9af2024879eb751"),
    ),
    (
        "golden sha256",
        hex32("14aebd67c6575b74b36a33ea8836f2bbf7f18aa5f7ba7fa26f5fe852cb2c66c8"),
    ),
    (
        "golden verify verdicts",
        hex32("111cc91811c2c540ddba3107a21613ed637e356b801b59c0e83fc5793a5a3bcb"),
    ),
];

/// The fold of [`SIGN_SEMANTICS_PINS`] ([`fold_semantics_pins`]), pinned by
/// `tests/sign_semantics_id.rs`.
pub const SIGN_SEMANTICS_ID: [u8; 32] =
    hex32("4bab96c9a3e77917a1b6e2af057da23f50109dd6c846b5b9e3792dc89b59ff11");

/// Earlier values of [`SIGN_SEMANTICS_ID`] whose stamped data this build still reproduces: none
/// (the identifier is new).
pub const PREVIOUS_SIGN_SEMANTICS_IDS: &[[u8; 32]] = &[];
