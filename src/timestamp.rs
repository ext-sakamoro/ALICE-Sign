//! Time-anchoring primitives for tamper-evident ledgers.
//!
//! Records "when" alongside "what" and "who" using the `RFC` 3161-inspired
//! contract of a `TimeStampToken`: a signed statement that a payload hash was
//! observed at a given wall-clock time. The signer's private key models a
//! Time-Stamp Authority (`TSA`); a deployment can anchor this key to an
//! external trusted time source.

use crate::signature::{KeyPair, PublicKey, Signature};
use crate::{hash_data, Hash};

// ---------------------------------------------------------------------------
// TimeStamp
// ---------------------------------------------------------------------------

/// Unsigned wall-clock statement about a payload hash.
///
/// `unix_seconds` is a `Unix` epoch second counter. Sub-second precision is
/// captured by `nanos`. The pair is combined with the payload hash to form
/// the deterministic bytes over which a `TSA` signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeStamp {
    /// SHA-256 of the payload the statement is about.
    pub payload_hash: Hash,
    /// Whole seconds since the Unix epoch.
    pub unix_seconds: u64,
    /// Nanoseconds within that second.
    pub nanos: u32,
}

impl TimeStamp {
    /// Create a new unsigned timestamp record.
    #[must_use]
    pub const fn new(payload_hash: Hash, unix_seconds: u64, nanos: u32) -> Self {
        Self {
            payload_hash,
            unix_seconds,
            nanos,
        }
    }

    /// Canonical byte layout signed by the `TSA`:
    /// `payload_hash (32) || unix_seconds LE (8) || nanos LE (4)` = 44 bytes.
    #[must_use]
    pub fn signing_bytes(&self) -> [u8; 44] {
        let mut buf = [0u8; 44];
        buf[..32].copy_from_slice(&self.payload_hash.0);
        buf[32..40].copy_from_slice(&self.unix_seconds.to_le_bytes());
        buf[40..44].copy_from_slice(&self.nanos.to_le_bytes());
        buf
    }

    /// Hash of the canonical signing bytes (identifier for this record).
    #[must_use]
    pub fn digest(&self) -> Hash {
        hash_data(&self.signing_bytes())
    }
}

// ---------------------------------------------------------------------------
// TimeStampToken
// ---------------------------------------------------------------------------

/// A `TimeStamp` bound to a `TSA` signature.
///
/// Verification confirms that the payload was observed at (or before) the
/// stated time by the party holding the corresponding secret key.
#[derive(Debug, Clone)]
pub struct TimeStampToken {
    /// The statement that was signed.
    pub stamp: TimeStamp,
    /// The public key of the time-stamp authority that signed it.
    pub tsa_public: PublicKey,
    /// Ed25519 signature over [`TimeStamp::signing_bytes`].
    pub signature: Signature,
}

impl TimeStampToken {
    /// Issue a new token by having `tsa` sign the timestamp.
    #[must_use]
    pub fn issue(tsa: &KeyPair, stamp: TimeStamp) -> Self {
        let bytes = stamp.signing_bytes();
        let signature = tsa.sign(&bytes);
        Self {
            stamp,
            tsa_public: tsa.public(),
            signature,
        }
    }

    /// Verify that the signature is valid for the recorded timestamp under
    /// the recorded `TSA` public key.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.tsa_public
            .verify(&self.stamp.signing_bytes(), &self.signature)
    }

    /// Verify against an expected `TSA` public key.
    ///
    /// Rejects tokens carrying a signature valid under a different `TSA`
    /// than the caller trusts.
    #[must_use]
    pub fn verify_by(&self, expected_tsa: &PublicKey) -> bool {
        &self.tsa_public == expected_tsa && self.verify()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::PUBLIC_KEY_LENGTH;

    #[test]
    fn signing_bytes_layout() {
        let stamp = TimeStamp::new(Hash::from_bytes([0xAB; 32]), 1_700_000_000, 123_456_789);
        let bytes = stamp.signing_bytes();
        assert_eq!(bytes.len(), 44);
        assert_eq!(&bytes[..32], &[0xAB; 32]);
        assert_eq!(&bytes[32..40], &1_700_000_000u64.to_le_bytes());
        assert_eq!(&bytes[40..44], &123_456_789u32.to_le_bytes());
    }

    #[test]
    fn digest_changes_when_time_changes() {
        let payload = Hash::from_bytes([1u8; 32]);
        let a = TimeStamp::new(payload, 100, 0).digest();
        let b = TimeStamp::new(payload, 101, 0).digest();
        assert_ne!(a, b);
    }

    #[test]
    fn issued_token_verifies() {
        let tsa = KeyPair::from_seed([9u8; 32]);
        let stamp = TimeStamp::new(hash_data(b"payload"), 1_720_000_000, 500);
        let token = TimeStampToken::issue(&tsa, stamp);
        assert!(token.verify());
        assert!(token.verify_by(&tsa.public()));
    }

    #[test]
    fn tampered_time_breaks_verification() {
        let tsa = KeyPair::from_seed([1u8; 32]);
        let stamp = TimeStamp::new(hash_data(b"payload"), 1000, 0);
        let mut token = TimeStampToken::issue(&tsa, stamp);
        token.stamp.unix_seconds = 2000;
        assert!(!token.verify());
    }

    #[test]
    fn tampered_payload_breaks_verification() {
        let tsa = KeyPair::from_seed([1u8; 32]);
        let stamp = TimeStamp::new(hash_data(b"original"), 1000, 0);
        let mut token = TimeStampToken::issue(&tsa, stamp);
        token.stamp.payload_hash = hash_data(b"tampered");
        assert!(!token.verify());
    }

    #[test]
    fn wrong_tsa_key_rejected_by_verify_by() {
        let tsa = KeyPair::from_seed([1u8; 32]);
        let stamp = TimeStamp::new(hash_data(b"payload"), 1000, 0);
        let token = TimeStampToken::issue(&tsa, stamp);

        let other_public = PublicKey([0u8; PUBLIC_KEY_LENGTH]);
        assert!(!token.verify_by(&other_public));
    }
}
