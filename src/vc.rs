//! W3C Verifiable Credentials 2.0 export for ledger events.
//!
//! Given a payload hash, a signer, an issuance time and a subject identifier,
//! produce a JSON document that follows the W3C Verifiable Credentials Data
//! Model 2.0 skeleton. The output is deterministic (fields serialise in a
//! fixed order) and re-verifiable: consumers can recompute
//! `SHA-256(canonical_bytes)` and check the embedded `Ed25519` signature.
//!
//! The serialisation is a hand-written JSON writer to keep the crate free of
//! `serde` dependencies. Escaping follows RFC 8259 §7.
//!
//! # Example
//!
//! ```
//! use alice_sign::{hash_data, vc, KeyPair};
//!
//! let signer = KeyPair::from_seed([1u8; 32]);
//! let payload = hash_data(b"event:42@2026-07-01T12:00Z");
//! let vc = vc::VerifiableCredentialBuilder::new(
//!     "https://issuer.example/credentials/42",
//!     "did:example:issuer",
//!     "did:example:subject",
//!     payload,
//!     1_720_000_000,
//! )
//! .build_signed(&signer)
//! .expect("an issuance time inside 1970..=9999");
//! assert!(vc.verify());
//! let json = vc.to_json().expect("in range");
//! assert!(json.contains("VerifiableCredential"));
//! ```

use crate::signature::{KeyPair, PublicKey, Signature};
use crate::Hash;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// The last issuance time a credential can carry: `9999-12-31T23:59:59Z`.
///
/// The issuance time is rendered as an ISO 8601 date with a 4-digit year, so
/// the supported range is `1970-01-01T00:00:00Z..=9999-12-31T23:59:59Z`.
/// Issuing past it is refused, a credential past it does not verify, and
/// rendering one is an error.
pub const MAX_ISSUANCE_UNIX_SECONDS: u64 = 253_402_300_799;

/// Why a credential could not be issued or rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VcError {
    /// The issuance time is past [`MAX_ISSUANCE_UNIX_SECONDS`].
    TimestampOutOfRange {
        /// The issuance time that was refused.
        unix_seconds: u64,
    },
}

impl fmt::Display for VcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimestampOutOfRange { unix_seconds } => write!(
                f,
                "issuance time {unix_seconds} s is outside 1970-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
            ),
        }
    }
}

impl core::error::Error for VcError {}

/// `unix_seconds` as an ISO 8601 UTC date (`YYYY-MM-DDThh:mm:ssZ`), the one
/// date function of the credential modules.
///
/// Closed-form civil-from-days (H. Hinnant), constant time for every input.
///
/// # Errors
///
/// [`VcError::TimestampOutOfRange`] past [`MAX_ISSUANCE_UNIX_SECONDS`].
pub fn iso8601_utc(unix_seconds: u64) -> Result<String, VcError> {
    if unix_seconds > MAX_ISSUANCE_UNIX_SECONDS {
        return Err(VcError::TimestampOutOfRange { unix_seconds });
    }
    let days = unix_seconds / 86_400;
    let sec_of_day = unix_seconds % 86_400;
    // shift so day 0 is 0000-03-01; days >= 0, so every step stays in u64
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    let (hour, min, sec) = (sec_of_day / 3_600, sec_of_day % 3_600 / 60, sec_of_day % 60);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z"
    ))
}

// ---------------------------------------------------------------------------
// VerifiableCredential
// ---------------------------------------------------------------------------

/// A signed, W3C VC 2.0-compatible container around a `Hash` payload.
#[derive(Debug, Clone)]
pub struct VerifiableCredential {
    /// The credential's identifier (`id`).
    pub id: String,
    /// The issuer identifier (`issuer`).
    pub issuer: String,
    /// The subject identifier (`credentialSubject.id`).
    pub subject: String,
    /// SHA-256 of the payload the credential is about.
    pub payload_hash: Hash,
    /// Issuance time in seconds since the Unix epoch (`validFrom`).
    pub issuance_unix_seconds: u64,
    /// The public key that signed the credential.
    pub signer_public: PublicKey,
    /// Ed25519 signature over [`VerifiableCredential::canonical_bytes`].
    pub signature: Signature,
}

impl VerifiableCredential {
    /// Canonical byte layout used both for the signature and for tamper-check.
    ///
    /// `id || issuer || subject || payload_hash || issuance` — each string
    /// length-prefixed.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(
            &self.id,
            &self.issuer,
            &self.subject,
            &self.payload_hash,
            self.issuance_unix_seconds,
        )
    }

    /// Verify the embedded signature against the recorded signer public key.
    /// A credential whose issuance time is past [`MAX_ISSUANCE_UNIX_SECONDS`]
    /// does not verify.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.issuance_unix_seconds <= MAX_ISSUANCE_UNIX_SECONDS
            && self
                .signer_public
                .verify(&self.canonical_bytes(), &self.signature)
    }

    /// Verify that the embedded signature was produced by `expected_signer`.
    #[must_use]
    pub fn verify_by(&self, expected_signer: &PublicKey) -> bool {
        &self.signer_public == expected_signer && self.verify()
    }

    /// Serialise as a W3C VC 2.0-compatible JSON document.
    ///
    /// # Errors
    ///
    /// [`VcError::TimestampOutOfRange`] when the issuance time is past
    /// [`MAX_ISSUANCE_UNIX_SECONDS`].
    pub fn to_json(&self) -> Result<String, VcError> {
        let date = iso8601_utc(self.issuance_unix_seconds)?;
        let mut out = String::with_capacity(512);
        out.push('{');
        push_kv_arr(
            &mut out,
            "@context",
            &["https://www.w3.org/ns/credentials/v2"],
        );
        out.push(',');
        push_kv_arr(&mut out, "type", &["VerifiableCredential"]);
        out.push(',');
        push_kv_string(&mut out, "id", &self.id);
        out.push(',');
        push_kv_string(&mut out, "issuer", &self.issuer);
        out.push(',');
        push_kv_string(&mut out, "validFrom", &date);
        out.push(',');

        // credentialSubject.
        out.push_str("\"credentialSubject\":{");
        push_kv_string(&mut out, "id", &self.subject);
        out.push(',');
        push_kv_hex(&mut out, "payloadHash", &self.payload_hash.0);
        out.push('}');
        out.push(',');

        // proof.
        out.push_str("\"proof\":{");
        push_kv_string(&mut out, "type", "Ed25519Signature2020");
        out.push(',');
        push_kv_string(&mut out, "created", &date);
        out.push(',');
        push_kv_string(&mut out, "verificationMethod", &self.issuer);
        out.push(',');
        push_kv_hex(&mut out, "publicKeyHex", &self.signer_public.0);
        out.push(',');
        push_kv_hex(&mut out, "proofValueHex", &self.signature.0);
        out.push('}');

        out.push('}');
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Ergonomic constructor for [`VerifiableCredential`].
///
/// Holds the un-signed portion of the credential and provides one-shot
/// [`Self::build_signed`] to compute and attach an `Ed25519` signature.
pub struct VerifiableCredentialBuilder {
    id: String,
    issuer: String,
    subject: String,
    payload_hash: Hash,
    issuance_unix_seconds: u64,
}

impl VerifiableCredentialBuilder {
    /// Construct a new builder.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        issuer: impl Into<String>,
        subject: impl Into<String>,
        payload_hash: Hash,
        issuance_unix_seconds: u64,
    ) -> Self {
        Self {
            id: id.into(),
            issuer: issuer.into(),
            subject: subject.into(),
            payload_hash,
            issuance_unix_seconds,
        }
    }

    /// Consume the builder and produce a signed credential.
    ///
    /// # Errors
    ///
    /// [`VcError::TimestampOutOfRange`] when the issuance time is past
    /// [`MAX_ISSUANCE_UNIX_SECONDS`]; nothing is signed.
    pub fn build_signed(self, signer: &KeyPair) -> Result<VerifiableCredential, VcError> {
        if self.issuance_unix_seconds > MAX_ISSUANCE_UNIX_SECONDS {
            return Err(VcError::TimestampOutOfRange {
                unix_seconds: self.issuance_unix_seconds,
            });
        }
        let bytes = canonical_bytes(
            &self.id,
            &self.issuer,
            &self.subject,
            &self.payload_hash,
            self.issuance_unix_seconds,
        );
        let signature = signer.sign(&bytes);
        Ok(VerifiableCredential {
            id: self.id,
            issuer: self.issuer,
            subject: self.subject,
            payload_hash: self.payload_hash,
            issuance_unix_seconds: self.issuance_unix_seconds,
            signer_public: signer.public(),
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn canonical_bytes(
    id: &str,
    issuer: &str,
    subject: &str,
    payload_hash: &Hash,
    issuance_unix_seconds: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(id.len() + issuer.len() + subject.len() + 32 + 8 + 32);
    push_lenprefixed(&mut buf, id.as_bytes());
    push_lenprefixed(&mut buf, issuer.as_bytes());
    push_lenprefixed(&mut buf, subject.as_bytes());
    buf.extend_from_slice(&payload_hash.0);
    buf.extend_from_slice(&issuance_unix_seconds.to_le_bytes());
    buf
}

fn push_lenprefixed(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
    buf.extend_from_slice(s);
}

fn escape_json_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_kv_string(out: &mut String, key: &str, value: &str) {
    escape_json_into(out, key);
    out.push(':');
    escape_json_into(out, value);
}

fn push_kv_hex(out: &mut String, key: &str, bytes: &[u8]) {
    escape_json_into(out, key);
    out.push(':');
    out.push('"');
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out.push('"');
}

fn push_kv_arr(out: &mut String, key: &str, values: &[&str]) {
    escape_json_into(out, key);
    out.push(':');
    out.push('[');
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        escape_json_into(out, v);
    }
    out.push(']');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_data;

    fn signer() -> KeyPair {
        KeyPair::from_seed([7u8; 32])
    }

    fn sample_hash() -> Hash {
        hash_data(b"event:42@2026-07-01T12:00Z")
    }

    #[test]
    fn builder_produces_verifiable_vc() {
        let vc = VerifiableCredentialBuilder::new(
            "urn:example:vc:1",
            "did:example:issuer",
            "did:example:subject",
            sample_hash(),
            1_720_000_000,
        )
        .build_signed(&signer())
        .expect("in range");
        assert!(vc.verify());
    }

    #[test]
    fn tampering_hash_breaks_verification() {
        let mut vc = VerifiableCredentialBuilder::new(
            "urn:example:vc:2",
            "did:example:issuer",
            "did:example:subject",
            sample_hash(),
            1_720_000_000,
        )
        .build_signed(&signer())
        .expect("in range");
        vc.payload_hash = hash_data(b"tampered");
        assert!(!vc.verify());
    }

    #[test]
    fn verify_by_expected_signer_rejects_other_key() {
        let vc = VerifiableCredentialBuilder::new(
            "urn:example:vc:3",
            "did:example:issuer",
            "did:example:subject",
            sample_hash(),
            1_720_000_000,
        )
        .build_signed(&signer())
        .expect("in range");
        let other = KeyPair::from_seed([9u8; 32]);
        assert!(!vc.verify_by(&other.public()));
        assert!(vc.verify_by(&signer().public()));
    }

    #[test]
    fn json_contains_required_fields() {
        let vc = VerifiableCredentialBuilder::new(
            "urn:example:vc:4",
            "did:example:issuer",
            "did:example:subject",
            sample_hash(),
            1_720_000_000,
        )
        .build_signed(&signer())
        .expect("in range");
        let json = vc.to_json().expect("in range");
        assert!(json.contains("VerifiableCredential"));
        assert!(json.contains("Ed25519Signature2020"));
        assert!(json.contains("credentialSubject"));
        assert!(json.contains("payloadHash"));
        assert!(json.contains("2024"));
    }

    #[test]
    fn json_starts_and_ends_with_braces() {
        let vc = VerifiableCredentialBuilder::new(
            "urn:example:vc:5",
            "did:example:issuer",
            "did:example:subject",
            sample_hash(),
            1_720_000_000,
        )
        .build_signed(&signer())
        .expect("in range");
        let json = vc.to_json().expect("in range");
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
    }

    #[test]
    fn escape_handles_quotes_and_control_chars() {
        let mut s = String::new();
        escape_json_into(&mut s, "line1\nquote\"tab\tend");
        assert!(s.contains("\\n"));
        assert!(s.contains("\\\""));
        assert!(s.contains("\\t"));
    }

    #[test]
    fn unix_epoch_is_1970_01_01() {
        assert_eq!(iso8601_utc(0).as_deref(), Ok("1970-01-01T00:00:00Z"));
    }

    #[test]
    fn unix_specific_date_matches_iso() {
        assert_eq!(
            iso8601_utc(1_751_371_200).as_deref(),
            Ok("2025-07-01T12:00:00Z")
        );
    }
}
