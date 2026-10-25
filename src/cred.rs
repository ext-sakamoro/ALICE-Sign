//! A signed credential: a payload hash bound to a validity window, verified at
//! a point in time against an expected signer and a revocation set.
//!
//! [`VerifiableCredential`](crate::vc) answers "is this signature valid?"; a
//! credential answers "is this payload authorised, by this signer, right now,
//! and not revoked?" — the time and revocation checks are part of verifying,
//! not a separate step a caller can forget.
//!
//! Holding a [`SignedCredential`] is not proof of anything: its fields are
//! public so it can be carried over a wire. The only thing that establishes
//! trust is [`SignedCredential::verify_at`], which returns the payload hash
//! only when every check passes.
//!
//! The signed message is domain-separated (a context tag and a version byte),
//! so a credential signature can never be read as any other signed-byte layout
//! in this crate, and every security-relevant field — the key id, the window
//! and the payload — is inside it. The layout is little-endian and pinned by a
//! golden vector, matching the byte order used elsewhere in the crate.
//!
//! ```
//! use alice_sign::cred::{SignedCredential, ValidityWindow, NoRevocations};
//! use alice_sign::{hash_data, KeyPair};
//! let signer = KeyPair::from_seed([7u8; 32]);
//! let payload = hash_data(b"grant:read#42");
//! let cred = SignedCredential::sign(&signer, payload, ValidityWindow::new(1000, 2000));
//! assert_eq!(cred.verify_at(&signer.public(), 1500, &NoRevocations), Ok(&payload));
//! ```

use alloc::vec::Vec;
use core::fmt;

use crate::hash::{hash_data, Hash};
use crate::signature::{KeyPair, PublicKey, Signature};

/// Domain-separation tag for the signed message. Changing it or
/// [`SIGNING_VERSION`] changes every signature, by design.
const SIGNING_CONTEXT: &[u8] = b"ALICE-Sign/cred/SignedCredential";
/// Version of the signed-message layout.
const SIGNING_VERSION: u8 = 1;

/// Length in bytes of a [`KeyId`].
pub const KEY_ID_LENGTH: usize = 16;

/// Why a credential did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredError {
    /// `now` is before the window's `not_before`.
    NotYetValid,
    /// `now` is at or after the window's `not_after` (the window is half-open).
    Expired,
    /// The signature is not valid for the signer's key over the credential.
    BadSignature,
    /// The signer's key is not the one the caller expected.
    WrongSigner,
    /// The stored key id is not the one derived from the signer's key.
    KeyIdMismatch,
    /// The signer's key id is in the revocation set.
    Revoked,
}

impl fmt::Display for CredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotYetValid => "credential is not yet valid",
            Self::Expired => "credential has expired",
            Self::BadSignature => "credential signature is invalid",
            Self::WrongSigner => "credential is signed by an unexpected key",
            Self::KeyIdMismatch => "credential key id does not match its signer key",
            Self::Revoked => "credential signer key is revoked",
        };
        f.write_str(s)
    }
}

impl core::error::Error for CredError {}

/// A short, stable identifier for a signing key: the first [`KEY_ID_LENGTH`]
/// bytes of the SHA-256 of the public key. Used as the revocation handle, and
/// bound into the signed message so it cannot be swapped to dodge revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyId(pub [u8; KEY_ID_LENGTH]);

impl KeyId {
    /// The key id of a public key.
    pub fn of(public: &PublicKey) -> Self {
        let full = hash_data(&public.0);
        let mut id = [0u8; KEY_ID_LENGTH];
        id.copy_from_slice(&full.0[..KEY_ID_LENGTH]);
        Self(id)
    }
}

/// A half-open span of UNIX seconds a credential is valid for: `not_before` is
/// valid, `not_after` is not (`[not_before, not_after)`).
///
/// Half-open is the one window rule across the ecosystem (it matches a JWT
/// `exp` and lets adjacent windows chain with neither gap nor overlap). This is
/// the single owner of validity-window semantics in the crate: a caller checks
/// a time against a window only through [`ValidityWindow::check`], so the rule
/// lives in one place and can be shared with other crates that need a
/// not-before / not-after check. An empty or inverted window
/// (`not_before >= not_after`) accepts no time — [`check`](Self::check) rejects
/// every `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityWindow {
    /// First valid UNIX second (inclusive).
    pub not_before: u64,
    /// First invalid UNIX second (exclusive).
    pub not_after: u64,
}

impl ValidityWindow {
    /// A half-open window `[not_before, not_after)`.
    pub const fn new(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Check `now` against the window.
    ///
    /// # Errors
    ///
    /// [`CredError::NotYetValid`] when `now < not_before`, [`CredError::Expired`]
    /// when `now >= not_after`.
    pub const fn check(&self, now: u64) -> Result<(), CredError> {
        if now < self.not_before {
            return Err(CredError::NotYetValid);
        }
        if now >= self.not_after {
            return Err(CredError::Expired);
        }
        Ok(())
    }

    fn extend_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.not_before.to_le_bytes());
        buf.extend_from_slice(&self.not_after.to_le_bytes());
    }
}

/// A set of revoked key ids. The caller supplies the lookup (a hash set, a
/// CRL, a bloom filter); verifying a credential consults it.
pub trait RevokedSet {
    /// Whether `key_id` has been revoked.
    fn is_revoked(&self, key_id: &KeyId) -> bool;
}

/// A [`RevokedSet`] that revokes nothing, for callers without revocation.
#[derive(Debug, Clone, Copy)]
pub struct NoRevocations;

impl RevokedSet for NoRevocations {
    fn is_revoked(&self, _key_id: &KeyId) -> bool {
        false
    }
}

/// A payload hash bound to a validity window and signed with Ed25519.
///
/// The fields are public so the credential can be serialised and rebuilt; they
/// are not trusted until [`verify_at`](Self::verify_at) returns `Ok`.
#[derive(Debug, Clone)]
pub struct SignedCredential {
    /// The signer's key id (derived from `signer_public`; see [`KeyId`]).
    pub key_id: KeyId,
    /// The authorised payload hash.
    pub payload: Hash,
    /// The window the credential is valid for.
    pub window: ValidityWindow,
    /// The signer's public key.
    pub signer_public: PublicKey,
    /// The Ed25519 signature over the canonical message.
    pub signature: Signature,
}

impl SignedCredential {
    /// Issue a credential: bind `payload` and `window` to `signer` and sign.
    pub fn sign(signer: &KeyPair, payload: Hash, window: ValidityWindow) -> Self {
        let signer_public = signer.public();
        let key_id = KeyId::of(&signer_public);
        let signature = signer.sign(&signing_message(&key_id, &payload, &window));
        Self {
            key_id,
            payload,
            window,
            signer_public,
            signature,
        }
    }

    /// Verify the credential against an expected signer, a point in time and a
    /// revocation set, returning the authorised payload hash on success.
    ///
    /// # Errors
    ///
    /// [`CredError::WrongSigner`] if `expected` is not the signer,
    /// [`CredError::KeyIdMismatch`] if the key id was altered,
    /// [`CredError::BadSignature`] if the signature does not match,
    /// [`CredError::Revoked`] if the key id is revoked, and
    /// [`CredError::NotYetValid`] / [`CredError::Expired`] from the window.
    pub fn verify_at(
        &self,
        expected: &PublicKey,
        now: u64,
        revoked: &impl RevokedSet,
    ) -> Result<&Hash, CredError> {
        if &self.signer_public != expected {
            return Err(CredError::WrongSigner);
        }
        if self.key_id != KeyId::of(&self.signer_public) {
            return Err(CredError::KeyIdMismatch);
        }
        let message = signing_message(&self.key_id, &self.payload, &self.window);
        if !self.signer_public.verify_strict(&message, &self.signature) {
            return Err(CredError::BadSignature);
        }
        if revoked.is_revoked(&self.key_id) {
            return Err(CredError::Revoked);
        }
        self.window.check(now)?;
        Ok(&self.payload)
    }
}

/// The canonical bytes signed for a credential:
/// `len(context) || context || version || key_id || not_before || not_after || payload`,
/// all integers little-endian.
fn signing_message(key_id: &KeyId, payload: &Hash, window: &ValidityWindow) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + SIGNING_CONTEXT.len() + 1 + KEY_ID_LENGTH + 16 + 32);
    buf.extend_from_slice(&(SIGNING_CONTEXT.len() as u64).to_le_bytes());
    buf.extend_from_slice(SIGNING_CONTEXT);
    buf.push(SIGNING_VERSION);
    buf.extend_from_slice(&key_id.0);
    window.extend_canonical(&mut buf);
    buf.extend_from_slice(&payload.0);
    buf
}

fn push_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The descriptor [`SEMANTICS_ID`] hashes: the identifiers of everything that
/// changes how a credential verifies, length-prefixed so two fields cannot be
/// read as one. Adding a field here, bumping [`SIGNING_VERSION`] or changing a
/// primitive moves the id. Public so a consumer or the Law matrix can recompute
/// `SEMANTICS_ID` as `hash_data(&semantics_descriptor())` and check provenance.
pub fn semantics_descriptor() -> Vec<u8> {
    let mut d = Vec::new();
    push_length_prefixed(&mut d, b"ALICE-Sign/cred");
    push_length_prefixed(&mut d, &[SIGNING_VERSION]);
    push_length_prefixed(&mut d, SIGNING_CONTEXT);
    push_length_prefixed(&mut d, b"ed25519-verify_strict");
    push_length_prefixed(&mut d, b"sha-256");
    push_length_prefixed(&mut d, b"key-id=sha256-prefix-16");
    push_length_prefixed(
        &mut d,
        b"message=lp(ctx)|ver|key_id|not_before_le|not_after_le|payload",
    );
    push_length_prefixed(&mut d, b"window=half-open[not_before,not_after)");
    d
}

/// A content id for the cred semantics: the SHA-256 of [`semantics_descriptor`],
/// the signed-message layout, version and primitives. Two builds with the same
/// `SEMANTICS_ID` verify a credential identically. cred is byte/crypto only (no
/// `alice-det-math`), so the id is folded over its own layout — Ed25519
/// `verify_strict`, the SHA-256 key id and the half-open window — not over a
/// det-math generation. Pinned by `golden_semantics_id`, which recomputes it.
pub const SEMANTICS_ID: [u8; 32] = [
    0xc2, 0xa1, 0x86, 0xca, 0xde, 0xdc, 0x70, 0x62, 0x66, 0x85, 0xbe, 0x00, 0x2b, 0xf1, 0x97, 0xc5,
    0xe4, 0xf6, 0xc3, 0x2a, 0xb1, 0x13, 0xd8, 0x9c, 0xc2, 0xa4, 0x0b, 0xa3, 0xe9, 0x98, 0x08, 0x2b,
];

/// Earlier values of [`SEMANTICS_ID`] whose stamped data this build still reads.
pub const PREVIOUS_SEMANTICS_IDS: &[[u8; 32]] = &[];

/// The result of [`check_semantics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticsCheck {
    /// Stamped with the current [`SEMANTICS_ID`].
    Current,
    /// Stamped with a value in [`PREVIOUS_SEMANTICS_IDS`].
    VerifiedPrevious,
    /// Stamped with an unknown id.
    Mismatch,
}

/// Classify a stored semantics id against this build.
pub fn check_semantics(stored: &[u8; 32]) -> SemanticsCheck {
    if *stored == SEMANTICS_ID {
        SemanticsCheck::Current
    } else if PREVIOUS_SEMANTICS_IDS.contains(stored) {
        SemanticsCheck::VerifiedPrevious
    } else {
        SemanticsCheck::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> KeyPair {
        KeyPair::from_seed([0u8; 32])
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), 2 * N);
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
    }

    // oracle: the signed-message layout, built independently of the impl.
    #[test]
    fn signing_message_has_the_pinned_layout() {
        let key_id = KeyId([7u8; KEY_ID_LENGTH]);
        let payload = Hash([9u8; 32]);
        let window = ValidityWindow::new(1000, 2000);

        let mut expect = Vec::new();
        expect.extend_from_slice(&(SIGNING_CONTEXT.len() as u64).to_le_bytes());
        expect.extend_from_slice(SIGNING_CONTEXT);
        expect.push(SIGNING_VERSION);
        expect.extend_from_slice(&key_id.0);
        expect.extend_from_slice(&1000u64.to_le_bytes());
        expect.extend_from_slice(&2000u64.to_le_bytes());
        expect.extend_from_slice(&payload.0);

        assert_eq!(signing_message(&key_id, &payload, &window), expect);
    }

    #[test]
    fn window_is_half_open() {
        let w = ValidityWindow::new(100, 200);
        assert_eq!(w.check(100), Ok(())); // not_before is valid
        assert_eq!(w.check(150), Ok(()));
        assert_eq!(w.check(199), Ok(())); // last valid second
        assert_eq!(w.check(200), Err(CredError::Expired)); // not_after is NOT valid
        assert_eq!(w.check(99), Err(CredError::NotYetValid));
        assert_eq!(w.check(201), Err(CredError::Expired));
    }

    #[test]
    fn empty_or_inverted_window_accepts_no_time() {
        // not_before == not_after is empty under half-open
        let empty = ValidityWindow::new(100, 100);
        assert_eq!(empty.check(100), Err(CredError::Expired));
        assert_eq!(empty.check(99), Err(CredError::NotYetValid));
        let w = ValidityWindow::new(200, 100);
        assert_eq!(w.check(50), Err(CredError::NotYetValid));
        assert_eq!(w.check(150), Err(CredError::NotYetValid));
        assert_eq!(w.check(250), Err(CredError::Expired));
    }

    #[test]
    fn key_id_is_the_hash_prefix_of_the_public_key() {
        let pk = signer().public();
        let full = hash_data(&pk.0);
        assert_eq!(KeyId::of(&pk).0, full.0[..KEY_ID_LENGTH]);
    }

    #[test]
    fn verify_at_round_trips_within_the_window() {
        let kp = signer();
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));

        assert_eq!(cred.verify_at(&pk, 1000, &NoRevocations), Ok(&payload));
        assert_eq!(cred.verify_at(&pk, 1500, &NoRevocations), Ok(&payload));
        assert_eq!(cred.verify_at(&pk, 1999, &NoRevocations), Ok(&payload));
    }

    #[test]
    fn verify_at_enforces_the_window() {
        let kp = signer();
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));

        assert_eq!(
            cred.verify_at(&pk, 999, &NoRevocations),
            Err(CredError::NotYetValid)
        );
        // not_after is the first invalid second (half-open)
        assert_eq!(
            cred.verify_at(&pk, 2000, &NoRevocations),
            Err(CredError::Expired)
        );
        assert_eq!(
            cred.verify_at(&pk, 2001, &NoRevocations),
            Err(CredError::Expired)
        );
    }

    // verify uses strict verification: a small-order public key, which plain
    // `verify` accepts for any message, must be refused. (vectors from
    // tests/verify_strict.rs: the identity point, and R = B / S = 1 under it.)
    #[test]
    fn a_small_order_signer_is_rejected() {
        let pk = PublicKey(hex::<32>(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ));
        let sig = Signature(hex::<64>(
            "58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000",
        ));
        let cred = SignedCredential {
            key_id: KeyId::of(&pk),
            payload: hash_data(b"grant:read#42"),
            window: ValidityWindow::new(1000, 2000),
            signer_public: pk,
            signature: sig,
        };
        // plain `verify` would accept this (small-order key, any message);
        // `verify_strict` refuses it, so the result is BadSignature
        assert_eq!(
            cred.verify_at(&pk, 1500, &NoRevocations),
            Err(CredError::BadSignature)
        );
    }

    #[test]
    fn verify_at_rejects_the_wrong_signer() {
        let kp = signer();
        let payload = hash_data(b"grant:read#42");
        let cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        let other = KeyPair::from_seed([1u8; 32]).public();
        assert_eq!(
            cred.verify_at(&other, 1500, &NoRevocations),
            Err(CredError::WrongSigner)
        );
    }

    #[test]
    fn a_tampered_payload_breaks_the_signature() {
        let kp = signer();
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let mut cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        cred.payload = hash_data(b"grant:write#42");
        assert_eq!(
            cred.verify_at(&pk, 1500, &NoRevocations),
            Err(CredError::BadSignature)
        );
    }

    #[test]
    fn a_widened_window_breaks_the_signature() {
        // the window is inside the signed message, so it cannot be extended
        let kp = signer();
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let mut cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        cred.window = ValidityWindow::new(0, u64::MAX);
        assert_eq!(
            cred.verify_at(&pk, 1500, &NoRevocations),
            Err(CredError::BadSignature)
        );
    }

    #[test]
    fn a_swapped_key_id_is_rejected() {
        let kp = signer();
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let mut cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        cred.key_id = KeyId([0u8; KEY_ID_LENGTH]);
        assert_eq!(
            cred.verify_at(&pk, 1500, &NoRevocations),
            Err(CredError::KeyIdMismatch)
        );
    }

    // golden: the layout is pinned by `signing_message_has_the_pinned_layout`;
    // this pins that Ed25519 over that message is stable across versions and
    // machines (the all-zero seed public key is the RFC 8032 vector).
    #[test]
    fn golden_signature_is_stable() {
        let kp = KeyPair::from_seed([0u8; 32]);
        let payload = hash_data(b"grant:read#42");
        let cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        assert_eq!(cred.key_id, KeyId::of(&kp.public()));
        assert_eq!(
            cred.signature.to_hex(),
            "df7a0c2d93f9e401b43f3f52bcf50b52dfd0f1de5130c6260a91690e307058ca\
             7f854da4cb44f5b0e6b4839ab1169a2385b8e0042ae379901221c71d7fbe3b08"
        );
    }

    #[test]
    fn a_revoked_key_is_rejected() {
        struct RevokeOne(KeyId);
        impl RevokedSet for RevokeOne {
            fn is_revoked(&self, key_id: &KeyId) -> bool {
                *key_id == self.0
            }
        }
        let kp = signer();
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        let revoked = RevokeOne(KeyId::of(&pk));
        assert_eq!(cred.verify_at(&pk, 1500, &revoked), Err(CredError::Revoked));
    }

    // golden: the semantics id is the SHA-256 of the descriptor; this pins it
    // so a layout / version / primitive change forces updating SEMANTICS_ID
    // (and recording the old one in PREVIOUS_SEMANTICS_IDS).
    #[test]
    fn golden_semantics_id() {
        assert_eq!(hash_data(&semantics_descriptor()).0, SEMANTICS_ID);
    }

    #[test]
    fn check_semantics_classifies_current_and_unknown() {
        assert_eq!(check_semantics(&SEMANTICS_ID), SemanticsCheck::Current);
        assert_eq!(check_semantics(&[0u8; 32]), SemanticsCheck::Mismatch);
    }
}
