//! Claims committed under a credential's payload, and the selective disclosure of some of them.
//!
//! A [`ClaimSet`] commits to a list of named claims: each claim is a leaf (a domain-separated
//! SHA-256 over its salt, name and value), the leaves in name order form a
//! [`MerkleTree`], and the payload is a domain-separated SHA-256 over
//! the number of claims and the tree's root. That payload is what a
//! [`SignedCredential`](super::SignedCredential) signs.
//!
//! A [`Disclosure`] carries some of the claims with their salts, their positions and their
//! inclusion proofs; [`Disclosure::verify`] checks it against a payload a credential verified,
//! so a holder can show some claims and keep the others hidden while the issuer's signature
//! still covers what is shown. A claim that is not shown is present in a disclosure only as a
//! sibling hash in a proof; its salt is what keeps a guessable value (a birth year, a yes / no)
//! from being found by hashing candidates, so every salt must come from a cryptographic random
//! source and never be reused ([`Claim::with_random_salt`] under the `rand` feature).
//!
//! What a disclosure still reveals: the number of claims (`count`) and where each shown claim
//! sorts by name (its index), which says something about the hidden names; and, since the shown
//! leaves and the sibling hashes are the same in every presentation of one credential, that two
//! presentations come from the same credential. A verifier that must not link presentations
//! needs a fresh credential (and fresh salts) per verifier.
//!
//! The merkle tree repeats an odd level's last hash and hashes leaves and inner nodes alike
//! (see [`crate::merkle`]). Both are closed here: the payload commits to the number of claims,
//! and a disclosed claim is accepted only with a proof of exactly the tree's depth whose
//! left / right steps are the ones its index gives, from a leaf the verifier hashes itself.
//!
//! ```
//! use alice_sign::cred::claims::{Claim, ClaimSet};
//! use alice_sign::cred::{NoRevocations, SignedCredential, ValidityWindow};
//! use alice_sign::KeyPair;
//! let issuer = KeyPair::from_seed([7u8; 32]);
//! let set = ClaimSet::new(vec![
//!     Claim::new("age_over_18", "true", [1u8; 32]),
//!     Claim::new("name", "Alice", [2u8; 32]),
//! ])
//! .expect("distinct names");
//! let cred = SignedCredential::sign(&issuer, set.payload(), ValidityWindow::new(1000, 2000));
//! let shown = set.disclose(&["age_over_18"]).expect("a committed name");
//! let payload = cred.verify_at(&issuer.public(), 1500, &NoRevocations).expect("valid");
//! let claims = shown.verify(payload).expect("covered by the signature");
//! assert_eq!(claims[0].value, "true");
//! assert_eq!(claims.len(), 1);
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::hash::{hash_data, Hash};
use crate::merkle::{MerkleProof, MerkleTree};

/// Domain-separation tag of a claim leaf.
pub(super) const LEAF_CONTEXT: &[u8] = b"ALICE-Sign/cred/claims/leaf";
/// Domain-separation tag of the payload over the claims' root.
pub(super) const PAYLOAD_CONTEXT: &[u8] = b"ALICE-Sign/cred/claims/payload";
/// Version of the leaf and payload layouts.
pub(super) const CLAIMS_VERSION: u8 = 1;

/// Length in bytes of a claim's salt.
pub const SALT_LENGTH: usize = 32;

/// Why a claim set could not be built or a disclosure did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimError {
    /// Two claims of a set have the same name.
    DuplicateName(String),
    /// A name asked to be disclosed is not in the set.
    UnknownName(String),
    /// The disclosure does not hash to the payload the credential signed (a claim, salt,
    /// position, proof or the number of claims was changed).
    NotCovered,
    /// A disclosed claim's position is not inside the set, or positions are not strictly
    /// increasing (a claim shown twice).
    BadIndex,
    /// A proof is not of the tree's depth, or its steps do not follow its claim's position.
    BadProof,
    /// No claim is shown of a set that has claims: there is nothing to check against the
    /// payload (only the empty set's disclosure can show nothing).
    NothingShown,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName(n) => write!(f, "claim name {n:?} appears twice"),
            Self::UnknownName(n) => write!(f, "no claim named {n:?} in the set"),
            Self::NotCovered => f.write_str("disclosure is not covered by the signed payload"),
            Self::BadIndex => f.write_str("disclosed claim positions are out of range or repeated"),
            Self::BadProof => f.write_str("inclusion proof does not match its claim's position"),
            Self::NothingShown => f.write_str("disclosure shows no claim of a non-empty set"),
        }
    }
}

impl core::error::Error for ClaimError {}

/// One named claim with the salt that hides it while it is not disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The claim's name, unique within its set.
    pub name: String,
    /// The claim's value.
    pub value: String,
    /// Random bytes from a cryptographic source, one fresh salt per claim.
    pub salt: [u8; SALT_LENGTH],
}

impl Claim {
    /// A claim of `name` and `value` under `salt`.
    pub fn new(name: impl Into<String>, value: impl Into<String>, salt: [u8; SALT_LENGTH]) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            salt,
        }
    }

    /// A claim of `name` and `value` under a fresh salt drawn from `rng` (feature `rand`).
    #[cfg(feature = "rand")]
    pub fn with_random_salt<R: rand_core::CryptoRng + rand_core::RngCore>(
        name: impl Into<String>,
        value: impl Into<String>,
        rng: &mut R,
    ) -> Self {
        let mut salt = [0u8; SALT_LENGTH];
        rng.fill_bytes(&mut salt);
        Self::new(name, value, salt)
    }

    /// The leaf: SHA-256 of
    /// `len(context) || context || version || salt || len(name) || name || len(value) || value`,
    /// lengths as u64 little-endian.
    #[must_use]
    pub fn leaf(&self) -> Hash {
        hash_data(&leaf_message(self))
    }
}

pub(super) fn leaf_message(claim: &Claim) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        8 + LEAF_CONTEXT.len() + 1 + SALT_LENGTH + 16 + claim.name.len() + claim.value.len(),
    );
    push_prefixed(&mut buf, LEAF_CONTEXT);
    buf.push(CLAIMS_VERSION);
    buf.extend_from_slice(&claim.salt);
    push_prefixed(&mut buf, claim.name.as_bytes());
    push_prefixed(&mut buf, claim.value.as_bytes());
    buf
}

/// The payload over a set of `count` claims whose tree has `root`: SHA-256 of
/// `len(context) || context || version || count || root`, integers u64 little-endian.
pub(super) fn payload_of(count: u64, root: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(8 + PAYLOAD_CONTEXT.len() + 1 + 8 + 32);
    push_prefixed(&mut buf, PAYLOAD_CONTEXT);
    buf.push(CLAIMS_VERSION);
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&root.0);
    hash_data(&buf)
}

fn push_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The number of proof steps of a tree of `count` leaves: 0 for 0 or 1 leaf, else
/// ceil(log2(count)).
fn depth(count: u64) -> usize {
    if count <= 1 {
        0
    } else {
        (u64::BITS - (count - 1).leading_zeros()) as usize
    }
}

/// A committed list of claims, in name order.
#[derive(Debug, Clone)]
pub struct ClaimSet {
    claims: Vec<Claim>,
    tree: MerkleTree,
}

impl ClaimSet {
    /// Commit to `claims`; they are put in name order (byte order of the names), so the same
    /// claims give the same payload whatever order they come in. An empty set is allowed and
    /// commits to zero claims.
    ///
    /// # Errors
    ///
    /// [`ClaimError::DuplicateName`] when two claims share a name.
    pub fn new(mut claims: Vec<Claim>) -> Result<Self, ClaimError> {
        claims.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        if let Some(w) = claims.windows(2).find(|w| w[0].name == w[1].name) {
            return Err(ClaimError::DuplicateName(w[0].name.clone()));
        }
        let leaves: Vec<Hash> = claims.iter().map(Claim::leaf).collect();
        let tree = MerkleTree::build(&leaves);
        Ok(Self { claims, tree })
    }

    /// The claims, in name order.
    #[must_use]
    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }

    /// The payload a credential signs for this set.
    #[must_use]
    pub fn payload(&self) -> Hash {
        payload_of(self.claims.len() as u64, &self.tree.root())
    }

    /// A disclosure of the claims named in `names` (each at most once; order does not matter),
    /// keeping every other claim hidden.
    ///
    /// # Errors
    ///
    /// [`ClaimError::UnknownName`] when a name is not in the set.
    pub fn disclose(&self, names: &[&str]) -> Result<Disclosure, ClaimError> {
        let mut indices = Vec::with_capacity(names.len());
        for name in names {
            let i = self
                .claims
                .binary_search_by(|c| c.name.as_bytes().cmp(name.as_bytes()))
                .map_err(|_| ClaimError::UnknownName(String::from(*name)))?;
            indices.push(i);
        }
        indices.sort_unstable();
        indices.dedup();
        let items = indices
            .into_iter()
            .map(|i| DisclosedClaim {
                index: i as u64,
                claim: self.claims[i].clone(),
                proof: self.tree.prove(i).expect("an index of the set"),
            })
            .collect();
        Ok(Disclosure {
            count: self.claims.len() as u64,
            items,
        })
    }
}

/// One disclosed claim: the claim, its position in the set and its inclusion proof.
#[derive(Debug, Clone)]
pub struct DisclosedClaim {
    /// Position of the claim in the set's name order.
    pub index: u64,
    /// The claim, with its salt.
    pub claim: Claim,
    /// Inclusion proof of the claim's leaf under the set's root.
    pub proof: MerkleProof,
}

/// Some claims of a set, shown against the payload a credential signed.
///
/// The fields are public so a disclosure can be carried over a wire; nothing in it is trusted
/// until [`verify`](Self::verify) returns `Ok`.
#[derive(Debug, Clone)]
pub struct Disclosure {
    /// The number of claims in the set (shown and hidden).
    pub count: u64,
    /// The shown claims, in strictly increasing position.
    pub items: Vec<DisclosedClaim>,
}

impl Disclosure {
    /// Check the disclosure against `payload` (the hash a credential's
    /// [`verify_at`](super::SignedCredential::verify_at) returned), returning the shown claims.
    ///
    /// # Errors
    ///
    /// [`ClaimError::BadIndex`] for a position outside the set or not strictly increasing,
    /// [`ClaimError::BadProof`] for a proof of another depth or with steps that do not follow
    /// its position, [`ClaimError::NotCovered`] when the claims, the proofs and the number
    /// of claims do not hash to `payload`, and [`ClaimError::NothingShown`] when no claim is
    /// shown of a non-empty set.
    pub fn verify(&self, payload: &Hash) -> Result<Vec<&Claim>, ClaimError> {
        let want_depth = depth(self.count);
        let mut root: Option<Hash> = None;
        let mut previous: Option<u64> = None;
        for item in &self.items {
            if item.index >= self.count || previous.is_some_and(|p| item.index <= p) {
                return Err(ClaimError::BadIndex);
            }
            previous = Some(item.index);
            if item.proof.hashes.len() != want_depth {
                return Err(ClaimError::BadProof);
            }
            let mut at = item.index;
            for &(_, sibling_on_right) in &item.proof.hashes {
                if sibling_on_right != at.is_multiple_of(2) {
                    return Err(ClaimError::BadProof);
                }
                at /= 2;
            }
            let item_root = fold_proof(item.claim.leaf(), &item.proof);
            match root {
                None => root = Some(item_root),
                Some(r) if r != item_root => return Err(ClaimError::NotCovered),
                Some(_) => {}
            }
        }
        // nothing shown: no claim to recompute the root from; only the empty set (zero root)
        // can be checked against its payload
        let root = match root {
            Some(r) => r,
            None if self.count == 0 => Hash::zero(),
            None => return Err(ClaimError::NothingShown),
        };
        if payload_of(self.count, &root) != *payload {
            return Err(ClaimError::NotCovered);
        }
        Ok(self.items.iter().map(|i| &i.claim).collect())
    }
}

/// The root a proof gives for `leaf` (the merkle module's step rule).
fn fold_proof(leaf: Hash, proof: &MerkleProof) -> Hash {
    let mut current = leaf;
    for &(sibling, is_right) in &proof.hashes {
        let mut combined = [0u8; 64];
        if is_right {
            combined[..32].copy_from_slice(&current.0);
            combined[32..].copy_from_slice(&sibling.0);
        } else {
            combined[..32].copy_from_slice(&sibling.0);
            combined[32..].copy_from_slice(&current.0);
        }
        current = hash_data(&combined);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred::{CredError, NoRevocations, SignedCredential, ValidityWindow};
    use crate::KeyPair;
    use alloc::vec;

    fn hex32(s: &str) -> [u8; 32] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
    }

    // given out of name order: the set sorts them
    fn three() -> ClaimSet {
        ClaimSet::new(vec![
            Claim::new("nationality", "JP", [3u8; 32]),
            Claim::new("age_over_18", "true", [1u8; 32]),
            Claim::new("name", "Alice", [2u8; 32]),
        ])
        .expect("distinct names")
    }

    // oracle: Python hashlib over the layouts written out by hand (leaf, a 3-leaf tree whose odd
    // level repeats its last hash, the payload over count 3), not this module's code
    #[test]
    fn leaf_root_and_payload_match_an_independent_computation() {
        let set = three();
        assert_eq!(
            set.claims()[0].leaf().0,
            hex32("1b7f71783b4af55d704009c201fddd171e5ded9f3ea69c49b494be06750ef154")
        );
        assert_eq!(
            set.tree.root().0,
            hex32("42532dc4df0bf403f4fcc0dad978e7d1cf1a526d8931fb8673296314ad63c177")
        );
        assert_eq!(
            set.payload().0,
            hex32("ab0955161561092504ce80d59a7b888d85ef7484217c48c73c0735dc6c8a4eb2")
        );
        assert_eq!(
            ClaimSet::new(vec![]).expect("empty").payload().0,
            hex32("c8ad18ad66de3aabcdc2e1adca798b9310facedbf91cfbdd5fd5858c6d09d2d3")
        );
    }

    #[test]
    fn the_order_claims_come_in_does_not_change_the_payload() {
        let other = ClaimSet::new(vec![
            Claim::new("name", "Alice", [2u8; 32]),
            Claim::new("age_over_18", "true", [1u8; 32]),
            Claim::new("nationality", "JP", [3u8; 32]),
        ])
        .expect("distinct names");
        assert_eq!(other.payload(), three().payload());
    }

    #[test]
    fn a_name_twice_is_refused() {
        let r = ClaimSet::new(vec![
            Claim::new("name", "Alice", [2u8; 32]),
            Claim::new("name", "Bob", [4u8; 32]),
        ]);
        assert_eq!(r.unwrap_err(), ClaimError::DuplicateName("name".into()));
    }

    #[test]
    fn an_unknown_name_cannot_be_disclosed() {
        assert_eq!(
            three().disclose(&["email"]).unwrap_err(),
            ClaimError::UnknownName("email".into())
        );
    }

    #[test]
    fn every_subset_verifies_and_shows_only_its_claims() {
        let set = three();
        let payload = set.payload();
        let names = ["age_over_18", "name", "nationality"];
        for mask in 0u8..8 {
            let chosen: Vec<&str> = (0..3)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| names[i])
                .collect();
            let d = set.disclose(&chosen).expect("committed names");
            if chosen.is_empty() {
                // nothing to recompute the root from: a non-empty set cannot be checked
                assert_eq!(d.verify(&payload), Err(ClaimError::NothingShown));
                continue;
            }
            let shown: Vec<&str> = d
                .verify(&payload)
                .expect("covered")
                .iter()
                .map(|c| c.name.as_str())
                .collect();
            assert_eq!(shown, chosen, "mask {mask}");
        }
    }

    #[test]
    fn the_empty_set_verifies_with_nothing_shown() {
        let set = ClaimSet::new(vec![]).expect("empty");
        let d = set.disclose(&[]).expect("nothing");
        assert_eq!(d.verify(&set.payload()), Ok(vec![]));
        // the empty disclosure of the empty set is not one of any other set
        assert_eq!(d.verify(&three().payload()), Err(ClaimError::NotCovered));
    }

    #[test]
    fn a_changed_value_salt_name_or_proof_is_not_covered() {
        let set = three();
        let payload = set.payload();
        let base = set.disclose(&["name"]).expect("committed");
        let mut v = base.clone();
        v.items[0].claim.value = "Mallory".into();
        assert_eq!(v.verify(&payload), Err(ClaimError::NotCovered));
        let mut s = base.clone();
        s.items[0].claim.salt[0] ^= 1;
        assert_eq!(s.verify(&payload), Err(ClaimError::NotCovered));
        let mut n = base.clone();
        n.items[0].claim.name = "nick".into();
        assert_eq!(n.verify(&payload), Err(ClaimError::NotCovered));
        let mut p = base;
        p.items[0].proof.hashes[0].0 .0[0] ^= 1;
        assert_eq!(p.verify(&payload), Err(ClaimError::NotCovered));
    }

    // every shown claim is checked, not only the first: a changed second or third one is not
    // covered either
    #[test]
    fn a_changed_claim_after_the_first_is_not_covered() {
        let set = three();
        let payload = set.payload();
        for at in 1..3 {
            let mut d = set
                .disclose(&["age_over_18", "name", "nationality"])
                .expect("committed");
            d.items[at].claim.value = "changed".into();
            assert_eq!(d.verify(&payload), Err(ClaimError::NotCovered), "item {at}");
        }
    }

    // the merkle layout gives [a, b, c] and [a, b, c, c] the same root; the payload commits to
    // the count, so the repeated last claim shown as a 4th one is not covered
    #[test]
    fn the_repeated_last_leaf_is_not_a_fourth_claim() {
        let set = three();
        let payload = set.payload();
        let mut d = set.disclose(&["nationality"]).expect("committed");
        d.count = 4;
        d.items[0].index = 3;
        d.items[0].proof.hashes[0].1 = false;
        assert_eq!(d.verify(&payload), Err(ClaimError::NotCovered));
    }

    #[test]
    fn positions_out_of_range_or_repeated_are_refused() {
        let set = three();
        let payload = set.payload();
        let mut out = set.disclose(&["nationality"]).expect("committed");
        out.items[0].index = 3;
        assert_eq!(out.verify(&payload), Err(ClaimError::BadIndex));
        let mut twice = set.disclose(&["name"]).expect("committed");
        let again = twice.items[0].clone();
        twice.items.insert(1, again);
        assert_eq!(twice.verify(&payload), Err(ClaimError::BadIndex));
        let mut backwards = set.disclose(&["age_over_18", "name"]).expect("committed");
        backwards.items.swap(0, 1);
        assert_eq!(backwards.verify(&payload), Err(ClaimError::BadIndex));
    }

    #[test]
    fn a_proof_of_another_depth_or_off_its_position_is_refused() {
        let set = three();
        let payload = set.payload();
        let mut short = set.disclose(&["name"]).expect("committed");
        short.items[0].proof.hashes.pop();
        assert_eq!(short.verify(&payload), Err(ClaimError::BadProof));
        let mut long = set.disclose(&["name"]).expect("committed");
        long.items[0].proof.hashes.insert(0, (Hash::zero(), true));
        assert_eq!(long.verify(&payload), Err(ClaimError::BadProof));
        // the claim at index 1 shown as if it were at index 0
        let mut moved = set.disclose(&["name"]).expect("committed");
        moved.items[0].index = 0;
        assert_eq!(moved.verify(&payload), Err(ClaimError::BadProof));
    }

    // a counting source stands in for a CSPRNG: each claim takes its own 32 bytes from it
    #[cfg(feature = "rand")]
    #[test]
    fn a_random_salt_is_drawn_fresh_for_each_claim() {
        struct Counting(u8);
        impl rand_core::RngCore for Counting {
            fn next_u32(&mut self) -> u32 {
                rand_core::impls::next_u32_via_fill(self)
            }
            fn next_u64(&mut self) -> u64 {
                rand_core::impls::next_u64_via_fill(self)
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for b in dest {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl rand_core::CryptoRng for Counting {}
        let mut rng = Counting(0);
        let a = Claim::with_random_salt("a", "1", &mut rng);
        let b = Claim::with_random_salt("b", "1", &mut rng);
        assert_eq!(a.salt, core::array::from_fn(|i| i as u8 + 1));
        assert_eq!(b.salt, core::array::from_fn(|i| i as u8 + 33));
        assert_eq!((a.name.as_str(), a.value.as_str()), ("a", "1"));
    }

    #[test]
    fn depth_is_ceil_log2_of_the_count() {
        let got: Vec<usize> = [0u64, 1, 2, 3, 4, 5, 8, 9, u64::MAX]
            .iter()
            .map(|&n| depth(n))
            .collect();
        assert_eq!(got, vec![0, 0, 1, 2, 2, 3, 3, 4, 64]);
    }

    // ALICE-Law G7: the leaf, payload and verdict rules are folded into cred's identifier, which
    // the credential over the set carries; a credential of another identifier is refused before
    // its payload (and so any disclosure) is read
    #[test]
    fn a_disclosure_under_another_cred_identifier_is_refused() {
        let issuer = KeyPair::from_seed([7u8; 32]);
        let set = three();
        let mut cred =
            SignedCredential::sign(&issuer, set.payload(), ValidityWindow::new(1000, 2000));
        cred.semantics_id = [0x5a; 32];
        assert_eq!(
            cred.verify_at(&issuer.public(), 1500, &NoRevocations),
            Err(CredError::SemanticsMismatch {
                stored: [0x5a; 32],
                expected: crate::cred::SEMANTICS_ID,
            })
        );
    }

    // end to end: the issuer signs the payload; a holder shows one claim; the verifier gets it
    // only through the credential's checks (another key, the window's end, a swapped payload
    // all fail before the claims are read)
    #[test]
    fn a_disclosure_is_read_only_through_a_verified_credential() {
        let issuer = KeyPair::from_seed([7u8; 32]);
        let other = KeyPair::from_seed([8u8; 32]);
        let set = three();
        let cred = SignedCredential::sign(&issuer, set.payload(), ValidityWindow::new(1000, 2000));
        let d = set.disclose(&["age_over_18"]).expect("committed");
        let payload = cred
            .verify_at(&issuer.public(), 1999, &NoRevocations)
            .expect("valid");
        assert_eq!(d.verify(payload).expect("covered")[0].value, "true");
        assert_eq!(
            cred.verify_at(&other.public(), 1500, &NoRevocations),
            Err(CredError::WrongSigner)
        );
        assert_eq!(
            cred.verify_at(&issuer.public(), 2000, &NoRevocations),
            Err(CredError::Expired)
        );
        let mut swapped = cred.clone();
        swapped.payload = ClaimSet::new(vec![Claim::new("age_over_18", "true", [9u8; 32])])
            .expect("one")
            .payload();
        assert_eq!(
            swapped.verify_at(&issuer.public(), 1500, &NoRevocations),
            Err(CredError::BadSignature)
        );
    }
}
