# alice-sign

Ed25519 signatures (RFC 8032, through `ed25519-dalek`), SHA-256 hashing and a binary SHA-256 Merkle tree with inclusion proofs, as a small `no_std` + `alloc` library whose byte layouts are fixed: a key seed, a message or a list of leaves gives the same bytes on every machine, pinned by golden vectors in `tests/golden.rs`. Signing is deterministic, verification uses `ed25519-dalek`'s `verify` (not `verify_strict`), and the Merkle tree repeats the last hash of an odd level and does not separate leaves from inner nodes; the module documentation states what a caller must check because of that.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
