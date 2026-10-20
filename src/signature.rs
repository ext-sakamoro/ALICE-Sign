//! Ed25519 signatures (RFC 8032) through `ed25519-dalek`.
//!
//! Two checks:
//!
//! - [`PublicKey::verify`] (`ed25519-dalek` `verify`) accepts a signature under
//!   a small-order public key (which then verifies for any message), one whose
//!   R is a small-order point, and a small-order key written in a non-canonical
//!   encoding.
//! - [`PublicKey::verify_strict`] (`ed25519-dalek` `verify_strict`) refuses all
//!   three. A protocol where a signature must bind a message to a key holder
//!   uses this one.
//!
//! Both refuse an S that is not reduced modulo the group order and a
//! non-canonical encoding of R (tests/verify_strict.rs).

use alloc::string::String;
use core::fmt;

use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
pub use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

use crate::error::{decode, encode, HexError};

/// An Ed25519 signing key and its public key.
#[derive(Clone)]
pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    /// Generate a key from a caller-supplied CSPRNG (feature `rand`).
    #[cfg(feature = "rand")]
    pub fn generate<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
        let signing = SigningKey::generate(rng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// The key whose RFC 8032 secret is `seed`; the same seed always gives the
    /// same key.
    #[must_use]
    pub fn from_seed(seed: [u8; SECRET_KEY_LENGTH]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// The public key.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        PublicKey(self.verifying.to_bytes())
    }

    /// Sign `message` (deterministic: the same key and message give the same
    /// signature).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig: EdSignature = self.signing.sign(message);
        Signature(sig.to_bytes())
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    /// `true` when `signature` is a valid signature of `message` under this
    /// key (`ed25519-dalek` `verify`, see the module docs). `false` for an
    /// invalid key encoding as well.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let Ok(sig) = EdSignature::try_from(&signature.0[..]) else {
            return false;
        };
        vk.verify(message, &sig).is_ok()
    }

    /// `true` when `signature` is a valid signature of `message` under this
    /// key and neither the key nor R is a small-order point (`ed25519-dalek`
    /// `verify_strict`, see the module docs). `false` for an invalid key
    /// encoding as well.
    #[must_use]
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let Ok(sig) = EdSignature::try_from(&signature.0[..]) else {
            return false;
        };
        vk.verify_strict(message, &sig).is_ok()
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
    /// [`HexError`] when the length is wrong or a character is not hex.
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        decode::<PUBLIC_KEY_LENGTH>(hex).map(Self)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Copy)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// Encode to a lowercase hex string (128 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }

    /// Decode from a 128-character hex string.
    ///
    /// # Errors
    ///
    /// [`HexError`] when the length is wrong or a character is not hex.
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        decode::<SIGNATURE_LENGTH>(hex).map(Self)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for Signature {}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
