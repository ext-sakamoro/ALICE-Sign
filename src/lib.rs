//! Ed25519 signatures, SHA-256 hashing and a SHA-256 Merkle tree.
//!
//! Every output has a fixed byte layout, pinned by `tests/golden.rs`: a key
//! seed, a message or a list of leaves gives the same bytes on every machine
//! and in every version of this crate.
//!
//! - [`hash_data`] / [`Hash`](struct@Hash): SHA-256 over the input bytes.
//! - [`KeyPair`] / [`PublicKey`] / [`Signature`]: Ed25519 (RFC 8032) through
//!   `ed25519-dalek`. Signing is deterministic: the same seed and message give
//!   the same signature.
//! - [`hmac_sha256`] / [`HmacSha256`]: HMAC-SHA256 (RFC 2104 / RFC 4231), with
//!   [`verify_hmac_sha256`] and the constant-time comparison [`ct_eq`].
//! - [`MerkleTree`] / [`MerkleProof`]: a binary tree of SHA-256 over the
//!   concatenation of two child hashes. See the module docs of [`merkle`] for
//!   two properties of this layout that a caller must know.
//!
//! - `timestamp` (feature `timestamp`, off by default): a signed statement
//!   that a payload hash was seen at a given time, in the `RFC` 3161 style.
//! - `vc` (feature `vc`, off by default): a W3C Verifiable Credentials 2.0
//!   document over a payload hash, signed with Ed25519.
//!
//! The crate is `no_std` and needs `alloc` (hex strings, tree levels).

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod error;
pub mod hash;
pub mod mac;
pub mod merkle;
pub mod signature;
#[cfg(feature = "timestamp")]
pub mod timestamp;
#[cfg(feature = "vc")]
pub mod vc;

pub use error::HexError;
pub use hash::{hash_data, Hash};
pub use mac::{ct_eq, hmac_sha256, verify_hmac_sha256, HmacSha256, HMAC_SHA256_LENGTH};
pub use merkle::{MerkleProof, MerkleTree};
pub use signature::{KeyPair, PublicKey, Signature, PUBLIC_KEY_LENGTH};
#[cfg(feature = "timestamp")]
pub use timestamp::{TimeStamp, TimeStampToken};
#[cfg(feature = "vc")]
pub use vc::{VerifiableCredential, VerifiableCredentialBuilder};
