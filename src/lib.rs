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
//! - [`MerkleTree`] / [`MerkleProof`]: a binary tree of SHA-256 over the
//!   concatenation of two child hashes. See the module docs of [`merkle`] for
//!   two properties of this layout that a caller must know.
//!
//! The crate is `no_std` and needs `alloc` (hex strings, tree levels).

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod error;
pub mod hash;
pub mod merkle;
pub mod signature;

pub use error::HexError;
pub use hash::{hash_data, Hash};
pub use merkle::{MerkleProof, MerkleTree};
pub use signature::{KeyPair, PublicKey, Signature, PUBLIC_KEY_LENGTH};
