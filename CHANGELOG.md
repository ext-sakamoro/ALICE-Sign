# Changelog

All notable changes to alice-sign are documented here.

## [Unreleased]

### Added
- `KeyPair` / `PublicKey` / `Signature` (Ed25519 through `ed25519-dalek` 2.1), `hash_data` / `Hash` (SHA-256 through `sha2` 0.10) and `MerkleTree` / `MerkleProof`, with `HexError` for the hex decoders `KeyPair::generate` takes a caller-supplied CSPRNG and is behind the `rand` feature
- `tests/golden.rs`: public keys and signatures for 3 seeds and 3 messages, SHA-256 of 3 inputs, Merkle roots and proofs for 0 to 9 leaves, the empty-tree proof, the repeated-last-leaf root and a 44-byte timestamp layout signature Run in debug and release on ubuntu, macOS and Windows
- CI (ALICE-Law G1 / G10): `clippy.toml` bans the floating-point methods IEEE 754 does not require to be correctly rounded, the wall clock and OS randomness `scripts/clippy_canary.py` plants each entry and fails unless clippy flags it
- CI (ALICE-Law G14): the static and dynamic build-flag checks and the floating-point environment test on ubuntu, macOS and Windows
- CI (ALICE-Law G12): the public text check (`scripts/public_text.sh`, ALICE-Law's checker at the pinned revision)
