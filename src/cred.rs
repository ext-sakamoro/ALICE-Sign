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

pub mod claims;

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
    /// The credential was issued under another cred semantics identifier than this build's (and
    /// not one of [`PREVIOUS_SEMANTICS_IDS`]): checked before the signature, so a credential of
    /// another layout or version is reported as such rather than as a bad signature.
    SemanticsMismatch {
        /// The identifier the credential carries.
        stored: [u8; 32],
        /// This build's [`SEMANTICS_ID`].
        expected: [u8; 32],
    },
}

impl fmt::Display for CredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::SemanticsMismatch { stored, expected } = self {
            f.write_str("credential issued under cred semantics ")?;
            for b in stored {
                write!(f, "{b:02x}")?;
            }
            f.write_str(", this build verifies ")?;
            for b in expected {
                write!(f, "{b:02x}")?;
            }
            return Ok(());
        }
        let s = match self {
            Self::NotYetValid => "credential is not yet valid",
            Self::Expired => "credential has expired",
            Self::BadSignature => "credential signature is invalid",
            Self::WrongSigner => "credential is signed by an unexpected key",
            Self::KeyIdMismatch => "credential key id does not match its signer key",
            Self::Revoked => "credential signer key is revoked",
            Self::SemanticsMismatch { .. } => unreachable!("written above"),
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
/// Half-open matches a JWT `exp` and ALICE-Identity's DeviceCert, and lets
/// adjacent windows chain with neither gap nor overlap. This is the single
/// owner of validity-window semantics in the crate: a caller checks a time
/// against a window only through [`ValidityWindow::check`], so the rule lives
/// in one place and can be shared with other crates that need a not-before /
/// not-after check (consolidating every crate onto this owner is tracked
/// separately). An empty or inverted window (`not_before >= not_after`) accepts
/// no time — [`check`](Self::check) rejects every `now`.
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
    /// The cred [`SEMANTICS_ID`] of the build that issued it (ALICE-Law G7): a verifier of
    /// another identifier refuses it with [`CredError::SemanticsMismatch`] before reading the
    /// signature. It is not part of the signed message: changing it can only make the
    /// credential fail to verify, never verify under another layout.
    pub semantics_id: [u8; 32],
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
            semantics_id: SEMANTICS_ID,
        }
    }

    /// Verify the credential against an expected signer, a point in time and a
    /// revocation set, returning the authorised payload hash on success.
    ///
    /// # Errors
    ///
    /// [`CredError::SemanticsMismatch`] if the credential carries another cred semantics
    /// identifier than this build's (or an earlier one this build still verifies),
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
        if matches!(
            check_semantics(&self.semantics_id),
            SemanticsCheck::Mismatch
        ) {
            return Err(CredError::SemanticsMismatch {
                stored: self.semantics_id,
                expected: SEMANTICS_ID,
            });
        }
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

/// The behavioural goldens [`SEMANTICS_ID`] folds: each `(name, digest)` pins a
/// SHA-256 of something the crate actually computes — the signature, the signed
/// message, the window-edge verdicts, the revocation verdict, the refusal of a
/// credential of another cred identifier, the small-order refusal, the [`claims`] committed under a
/// payload (a leaf, a set's payload, the verdicts of a disclosure) — plus the tags. A change in behaviour moves a
/// digest and therefore the id. `golden_semantics_id` recomputes every digest
/// from the live code, never from this copied hex.
pub const CRED_SEMANTICS_PINS: &[(&str, [u8; 32])] = &[
    (
        "golden claims disclosure",
        hex32("9efc2f9f570c9a5b6319f4699823629456ee598c7473cc69e2590b2338604b29"),
    ),
    (
        "golden claims leaf",
        hex32("1b7f71783b4af55d704009c201fddd171e5ded9f3ea69c49b494be06750ef154"),
    ),
    (
        "golden claims payload",
        hex32("9afdea3e01ee903ff0e59785455ace1d77be11f7ccdc4fbb165a0a3723beb63e"),
    ),
    (
        "tag claims",
        hex32("5b3d3dfac4846a29b66922f09c08b6a151e8d511527adfe3483d62bc5c75316b"),
    ),
    (
        "golden signature",
        hex32("4a88229368123eadd9a5bf20800f61d8ca116fb7367c5dfaf1225a79dbd65374"),
    ),
    (
        "golden signing_message_layout",
        hex32("d7c05d5655dc70e61202c87538a1fb465b599b808c5c1f90de45113cd63ece76"),
    ),
    (
        "golden window_edges",
        hex32("b8c177e7f68d7e3bb1af685a154e213b3a35e4ef97c353788306539653026357"),
    ),
    (
        "golden revocation",
        hex32("ceb827ad3d3884fd4d50ae6099d6d50c09a21e72ebd309708e8b69d93df19e55"),
    ),
    (
        "golden semantics_mismatch",
        hex32("2ecd8a6b7d2845546659ad4cf443533cf921b19dc81fa83934e83821b4dfdcb7"),
    ),
    (
        "golden small_order_refusal",
        hex32("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
    ),
    (
        "tag context",
        hex32("5875829ffada1f109133caf6cd59239717384c7b56cd5fbf231a34bca54dbcff"),
    ),
    (
        "tag version",
        hex32("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
    ),
];

pub use crate::semantics::fold_semantics_pins;
use crate::semantics::hex32;

/// A content id for the cred semantics: the fold of [`CRED_SEMANTICS_PINS`] over
/// its behavioural goldens and the context and version tags. Two builds with
/// the same `SEMANTICS_ID` verify a credential identically, and a behaviour
/// change (a window edge, the message layout, the signature, a verdict) moves
/// it. Folded by [`fold_semantics_pins`], the same procedure the other
/// Law-bearing types use. cred has no `alice-det-math` dependency, so there is
/// no det-math row. Pinned by `golden_semantics_id`, which recomputes every pin
/// from the live code.
pub const SEMANTICS_ID: [u8; 32] =
    hex32("e45dc92bc0049da2891408d5b5ee6fc36edd3dc9ed182e811010b195ed21a9e1");

/// Earlier values of [`SEMANTICS_ID`] whose stamped data this build still reads.
///
/// `62fb1287…` is the identifier before [`claims`] was folded in: a credential's signed message,
/// window and verdicts are unchanged by it, so a credential stamped with it verifies the same way.
pub const PREVIOUS_SEMANTICS_IDS: &[[u8; 32]] = &[hex32(
    "62fb12876c3c3c52b9bf31946d01aaa6559406333bf5d31b20cac14a4f93d512",
)];

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
            semantics_id: SEMANTICS_ID,
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

    // a stable byte for each verdict, so a digest over verdicts moves when a
    // verdict moves
    fn ecode(e: CredError) -> u8 {
        match e {
            CredError::NotYetValid => 1,
            CredError::Expired => 2,
            CredError::BadSignature => 3,
            CredError::WrongSigner => 4,
            CredError::KeyIdMismatch => 5,
            CredError::Revoked => 6,
            CredError::SemanticsMismatch { .. } => 7,
        }
    }
    fn codew(r: Result<(), CredError>) -> u8 {
        r.map_or_else(ecode, |()| 0)
    }
    fn code(r: Result<&Hash, CredError>) -> u8 {
        r.map_or_else(ecode, |_| 0)
    }

    struct RevokeOne(KeyId);
    impl RevokedSet for RevokeOne {
        fn is_revoked(&self, key_id: &KeyId) -> bool {
            *key_id == self.0
        }
    }

    // recompute each CRED_SEMANTICS_PINS digest from the LIVE code, so a change
    // in behaviour (signature, layout, a window edge, a verdict) moves a digest
    fn live_semantics_pins() -> [(&'static str, [u8; 32]); 12] {
        let kp = KeyPair::from_seed([0u8; 32]);
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let window = ValidityWindow::new(1000, 2000);
        let cred = SignedCredential::sign(&kp, payload, window);

        let signature = hash_data(&cred.signature.0).0;
        let layout = hash_data(&signing_message(&cred.key_id, &payload, &window)).0;
        let window_edges = hash_data(&[
            codew(window.check(999)),
            codew(window.check(1000)),
            codew(window.check(1999)),
            codew(window.check(2000)),
        ])
        .0;
        let revoked = RevokeOne(KeyId::of(&pk));
        let revocation = hash_data(&[
            code(cred.verify_at(&pk, 1500, &revoked)),
            code(cred.verify_at(&pk, 1500, &NoRevocations)),
        ])
        .0;
        let so_pk = PublicKey(hex::<32>(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ));
        let so_sig = Signature(hex::<64>(
            "58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000",
        ));
        let so_cred = SignedCredential {
            key_id: KeyId::of(&so_pk),
            payload,
            window,
            signer_public: so_pk,
            signature: so_sig,
            semantics_id: SEMANTICS_ID,
        };
        let small_order_refusal =
            hash_data(&[code(so_cred.verify_at(&so_pk, 1500, &NoRevocations))]).0;
        // the carried identifier: this build's verifies; another one, even with a valid
        // signature and window, is refused before the signature is read
        let mut other = cred.clone();
        other.semantics_id = [0u8; 32];
        let semantics_mismatch = hash_data(&[
            code(cred.verify_at(&pk, 1500, &NoRevocations)),
            code(other.verify_at(&pk, 1500, &NoRevocations)),
        ])
        .0;

        // claims under the payload: a leaf, the payload of a 3-claim set (odd level) and the
        // verdicts of a disclosure shown, changed, moved and empty
        let set = claims::ClaimSet::new(alloc::vec![
            claims::Claim::new("age_over_18", "true", [1u8; 32]),
            claims::Claim::new("name", "Alice", [2u8; 32]),
            claims::Claim::new("nationality", "JP", [3u8; 32]),
        ])
        .expect("distinct names");
        let claims_leaf = hash_data(&claims::leaf_message(&set.claims()[0])).0;
        let claims_payload = hash_data(&set.payload().0).0;
        let shown = set.disclose(&["name"]).expect("committed");
        let mut changed = shown.clone();
        changed.items[0].claim.value = alloc::string::String::from("Mallory");
        let mut moved = shown.clone();
        moved.items[0].index = 0;
        let ccode = |r: Result<Vec<&claims::Claim>, claims::ClaimError>| match r {
            Ok(v) => u8::try_from(v.len()).expect("few"),
            Err(claims::ClaimError::DuplicateName(_)) => 0x81,
            Err(claims::ClaimError::UnknownName(_)) => 0x82,
            Err(claims::ClaimError::NotCovered) => 0x83,
            Err(claims::ClaimError::BadIndex) => 0x84,
            Err(claims::ClaimError::BadProof) => 0x85,
        };
        let payload3 = set.payload();
        let claims_disclosure = hash_data(&[
            ccode(shown.verify(&payload3)),
            ccode(changed.verify(&payload3)),
            ccode(moved.verify(&payload3)),
            ccode(set.disclose(&[]).expect("none").verify(&payload3)),
        ])
        .0;
        let tags = [
            claims::LEAF_CONTEXT,
            claims::PAYLOAD_CONTEXT,
            &[claims::CLAIMS_VERSION],
        ]
        .concat();

        [
            ("golden claims disclosure", claims_disclosure),
            ("golden claims leaf", claims_leaf),
            ("golden claims payload", claims_payload),
            ("tag claims", hash_data(&tags).0),
            ("golden signature", signature),
            ("golden signing_message_layout", layout),
            ("golden window_edges", window_edges),
            ("golden revocation", revocation),
            ("golden semantics_mismatch", semantics_mismatch),
            ("golden small_order_refusal", small_order_refusal),
            ("tag context", hash_data(SIGNING_CONTEXT).0),
            ("tag version", hash_data(&[SIGNING_VERSION]).0),
        ]
    }

    // golden: every pin recomputed from the live code equals its pinned digest,
    // and the fold of the pins equals SEMANTICS_ID. A window edge, layout,
    // signature or verdict change moves a live digest -> this fails -> the pin
    // and SEMANTICS_ID must be updated (old id recorded in PREVIOUS_SEMANTICS_IDS).
    #[test]
    fn golden_semantics_id() {
        let live = live_semantics_pins();
        assert_eq!(live.len(), CRED_SEMANTICS_PINS.len());
        for (l, p) in live.iter().zip(CRED_SEMANTICS_PINS) {
            assert_eq!(l.0, p.0, "pin name order");
            assert_eq!(l.1, p.1, "pin digest for {}", p.0);
        }
        assert_eq!(fold_semantics_pins(CRED_SEMANTICS_PINS), SEMANTICS_ID);
    }

    #[test]
    fn check_semantics_classifies_current_and_unknown() {
        assert_eq!(check_semantics(&SEMANTICS_ID), SemanticsCheck::Current);
        assert_eq!(check_semantics(&[0u8; 32]), SemanticsCheck::Mismatch);
    }

    // a credential stamped before claims were folded into the identifier verifies unchanged:
    // its signed message, window and verdicts did not move
    #[test]
    fn a_credential_of_the_previous_identifier_still_verifies() {
        let kp = signer();
        let payload = hash_data(b"grant:read#42");
        let mut cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        cred.semantics_id =
            hex::<32>("62fb12876c3c3c52b9bf31946d01aaa6559406333bf5d31b20cac14a4f93d512");
        assert_eq!(
            check_semantics(&cred.semantics_id),
            SemanticsCheck::VerifiedPrevious
        );
        assert_eq!(
            cred.verify_at(&kp.public(), 1500, &NoRevocations),
            Ok(&payload)
        );
    }

    // ALICE-Law G7: a credential issued under another cred identifier is refused as such,
    // naming both identifiers, before the signature is read (a valid signature and window
    // do not let it through, and a corrupted signature still reports the identifier first)
    #[test]
    fn a_credential_of_another_semantics_id_is_refused_naming_both() {
        let kp = signer();
        let pk = kp.public();
        let payload = hash_data(b"grant:read#42");
        let cred = SignedCredential::sign(&kp, payload, ValidityWindow::new(1000, 2000));
        assert_eq!(cred.semantics_id, SEMANTICS_ID);
        let mut other = cred.clone();
        other.semantics_id = [0xab; 32];
        let want = CredError::SemanticsMismatch {
            stored: [0xab; 32],
            expected: SEMANTICS_ID,
        };
        assert_eq!(other.verify_at(&pk, 1500, &NoRevocations), Err(want));
        other.signature = Signature([0u8; 64]);
        assert_eq!(other.verify_at(&pk, 1500, &NoRevocations), Err(want));
        let text = alloc::format!("{want}");
        assert!(text.contains(&"ab".repeat(32)), "{text}");
        let expected_hex: alloc::string::String = SEMANTICS_ID
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert!(text.contains(&expected_hex), "{text}");
        // the identifier is not signed: putting this build's back makes it verify again
        other.signature = cred.signature;
        other.semantics_id = SEMANTICS_ID;
        assert_eq!(other.verify_at(&pk, 1500, &NoRevocations), Ok(&payload));
    }
}
