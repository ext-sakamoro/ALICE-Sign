//! A binary Merkle tree of SHA-256.
//!
//! A parent is `SHA-256(left ‖ right)` of its two 32-byte children, and a
//! level of odd length is completed by repeating its last hash. The root of
//! an empty list is [`Hash::zero`](crate::Hash::zero), and index 0 of the empty tree has an
//! empty proof of it.
//!
//! Two properties of this layout, kept because existing roots and proofs
//! depend on its exact bytes:
//!
//! - **The last leaf can be repeated without changing the root.** The leaves
//!   `[a, b, c]` and `[a, b, c, c]` give the same root (the shape of
//!   CVE-2012-2459). A root alone therefore does not fix the number of
//!   leaves; a caller that needs it must commit to the count separately.
//! - **Leaves and inner nodes are hashed the same way.** There is no domain
//!   separation between them, so the hash of an inner node, with the part of
//!   a proof above it, verifies as if it were a leaf. A caller that accepts
//!   proofs from others must also check the proof length (the tree depth)
//!   or the leaf index.
//!
//! Both are pinned by `tests/golden.rs`.

use alloc::vec;
use alloc::vec::Vec;

use crate::hash::{hash_data, Hash};

/// A Merkle tree built from a list of leaf hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All levels of the tree. `levels[0]` = leaves, last = root.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf hashes.
    ///
    /// If the list is empty the root is `Hash::zero()`. Odd-length levels are
    /// padded by duplicating the last element.
    ///
    /// # Panics
    ///
    /// This function will not panic; the internal `expect` calls are guarded
    /// by non-empty invariants.
    #[must_use]
    pub fn build(leaves: &[Hash]) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![Hash::zero()]],
            };
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let mut current: Vec<Hash> = leaves.to_vec();

        loop {
            levels.push(current.clone());
            if current.len() == 1 {
                break;
            }
            // Duplicate last if odd.
            if !current.len().is_multiple_of(2) {
                let last = *current.last().expect("non-empty");
                current.push(last);
            }
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.as_chunks::<2>().0 {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&pair[0].0);
                combined[32..].copy_from_slice(&pair[1].0);
                next.push(hash_data(&combined));
            }
            current = next;
        }
        Self { levels }
    }

    /// The root hash.
    #[must_use]
    pub fn root(&self) -> Hash {
        *self
            .levels
            .last()
            .and_then(|l| l.first())
            .unwrap_or(&Hash::zero())
    }

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// Returns `None` if the index is out of range.
    ///
    /// # Panics
    ///
    /// This function will not panic; the internal `expect` calls are guarded
    /// by non-empty invariants.
    #[must_use]
    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }
        let mut hashes: Vec<(Hash, bool)> = Vec::new();
        let mut idx = index;

        for level in &self.levels[..self.levels.len() - 1] {
            let mut current_level = level.clone();
            if !current_level.len().is_multiple_of(2) {
                let last = *current_level.last().expect("non-empty");
                current_level.push(last);
            }
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            // `is_right` = true means the sibling goes on the right.
            let is_right = idx.is_multiple_of(2);
            hashes.push((current_level[sibling_idx], is_right));
            idx /= 2;
        }
        Some(MerkleProof { hashes })
    }
}

/// A Merkle inclusion proof.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Pairs of (sibling hash, sibling-is-on-right).
    pub hashes: Vec<(Hash, bool)>,
}

impl MerkleProof {
    /// Verify that `leaf` is included under `root`.
    #[must_use]
    pub fn verify(&self, leaf: Hash, root: Hash) -> bool {
        let mut current = leaf;
        for &(sibling, is_right) in &self.hashes {
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
        current == root
    }
}
