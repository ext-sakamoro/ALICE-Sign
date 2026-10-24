# alice-sign

Ed25519 signatures (RFC 8032, through `ed25519-dalek`), SHA-256 hashing, HMAC-SHA256 (RFC 2104 / RFC 4231, with a constant-time comparison) and a binary SHA-256 Merkle tree with inclusion proofs, as a small `no_std` + `alloc` library whose byte layouts are fixed: a key seed, a message or a list of leaves gives the same bytes on every machine, pinned by golden vectors in `tests/golden.rs`. Signing is deterministic; `PublicKey::verify` uses `ed25519-dalek`'s `verify`, and `PublicKey::verify_strict` its `verify_strict`, which also refuses a small-order key or R (use it where a signature must bind a message to a key holder); and the Merkle tree repeats the last hash of an odd level and does not separate leaves from inner nodes; the module documentation states what a caller must check because of that.

## License

`LicenseRef-Proprietary`. The text is [LICENSE-Proprietary](LICENSE-Proprietary).

Enquiries: https://extoria.co.jp/
