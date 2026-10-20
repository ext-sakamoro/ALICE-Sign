# Changelog

All notable changes to alice-sign are documented here.

## [Unreleased]

### Added
- `PublicKey::verify_strict` (`ed25519-dalek` `verify_strict`): refuses a signature under a small-order public key (which `verify` accepts for any message), one whose R is a small-order point, and a small-order key in a non-canonical encoding, all three of which `verify` accepts 試験 `tests/verify_strict.rs` (RFC 8032 section 7.1 TEST 1-3 を両方が受ける、上の 3 通りは `verify` が受け `verify_strict` が拒む、S が群の位数で簡約されていない形と R の非正準な符号化は両方が拒む、同じ署名の 2 通りの byte 列のうち受けるのは 1 つ) CI の Test job で `scripts/run_tests.sh verify_strict=8` として走る `verify_strict` を `verify` に戻す変異と、鍵を読めない時に true を返す変異は失敗する 追加のみなので minor
- module doc の訂正: `verify` が受けて `verify_strict` が拒む非正準な符号化は鍵 (A) の方で、S の非正準な符号化は `verify` も拒む (実測)
- `KeyPair` / `PublicKey` / `Signature` (Ed25519 through `ed25519-dalek` 2.1), `hash_data` / `Hash` (SHA-256 through `sha2` 0.10) and `MerkleTree` / `MerkleProof`, with `HexError` for the hex decoders `KeyPair::generate` takes a caller-supplied CSPRNG and is behind the `rand` feature
- `tests/golden.rs`: public keys and signatures for 3 seeds and 3 messages, SHA-256 of 3 inputs, Merkle roots and proofs for 0 to 9 leaves, the empty-tree proof, the repeated-last-leaf root and a 44-byte timestamp layout signature Run in debug and release on ubuntu, macOS and Windows
- CI (ALICE-Law G1 / G10): `clippy.toml` bans the floating-point methods IEEE 754 does not require to be correctly rounded, the wall clock and OS randomness `scripts/clippy_canary.py` plants each entry and fails unless clippy flags it
- CI (ALICE-Law G14): the static and dynamic build-flag checks and the floating-point environment test on ubuntu, macOS and Windows
- CI (ALICE-Law G12): the public text check (`scripts/public_text.sh`, ALICE-Law's checker at the pinned revision)
