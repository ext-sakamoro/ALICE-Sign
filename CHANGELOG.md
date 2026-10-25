# Changelog

All notable changes to alice-sign are documented here.

## [Unreleased]

### Changed

- Licence: from `MIT OR Apache-2.0` to `LicenseRef-Proprietary` from this version (the source stays published for reading; using it needs a written agreement); published versions keep their licence

### Added
- `mac` module: `hmac_sha256(key, message)` / `HmacSha256` (incremental `new` / `update` / `finalize`) / `verify_hmac_sha256(key, message, tag)` / `ct_eq(a, b)` / `HMAC_SHA256_LENGTH` / `HMAC_SHA256_MIN_TAG_LENGTH` HMAC-SHA256 は RFC 2104 の構成を依存済みの `sha2` で組んだもの (新しい依存なし、`no_std`) block の 64 byte を超える鍵は先に hash する `verify_hmac_sha256` は 32 byte の tag か 16 byte 以上の先頭部分を定数時間で比べる (それより短い tag、長い tag、空の tag は拒む) `ct_eq` は長さだけに依存する時間で byte 列を比べる (長さの違いは不一致) 試験 `tests/hmac.rs`: RFC 4231 section 4 の test case 1 から 7 (5 は 128 bit の切り詰め、6 と 7 は block より長い鍵)、`hmac` crate 0.12 (dev-dependency のみ) と 13 通りの鍵長 × 11 通りの message 長で bit 一致、`<label> NUL <payload>` を 3 回の update で与えた tag の一致、update の分け方に依らないこと、tag の 1 byte の変更・長さ・鍵・message の違いを拒むこと CI の Test job で `scripts/run_tests.sh hmac=6` として走り、`Test (public siblings)` の下限を 42 に上げた 変異 10 通り (ipad / opad の定数、鍵を hash する境界、鍵を hash しない、外側の鍵を外す、tag の最短長、長すぎる tag を受ける、`ct_eq` が常に true / 長さを見ない / OR を AND に) はどれも試験が失敗する 追加のみ

### Fixed
- `Hash::has_leading_zeros(n)` は `n > 256` で panic せず `false` を返す (256 bit の hash に 256 を超える先頭の 0 は無い) 以前は slice の範囲外で panic し、外から渡る difficulty (alice-blockchain の `ProofOfWork::verify` など) で呼び出し側が落ちた 試験 `tests/leading_zeros.rs` (257 / 264 / 1000 / u32::MAX が false で panic しない、0 / 255 / 256、各 bit の境界) CI の Test job で `scripts/run_tests.sh leading_zeros=3` として走る 挙動の修正のみで API は同じ

### Added
- feature `timestamp` (既定は無効): `timestamp::{TimeStamp, TimeStampToken}` payload hash と時刻 (秒 + ナノ秒) の 44 byte に Ed25519 で署名する、RFC 3161 型の時刻印 `no_std` + `alloc`
- feature `vc` (既定は無効): `vc::{VerifiableCredential, VerifiableCredentialBuilder, VcError, MAX_ISSUANCE_UNIX_SECONDS, iso8601_utc}` payload hash を指す W3C Verifiable Credentials 2.0 の文書 (手書きの JSON writer、長さ前置きの canonical bytes の SHA-256 に Ed25519 署名) と、その日付の書式 `iso8601_utc` (公開の関数) `no_std` + `alloc` (`VcError` は `core::error::Error`)
- feature `cred` (既定は無効): `cred::{SignedCredential, ValidityWindow, CredError, KeyId, RevokedSet, NoRevocations, SemanticsCheck, check_semantics, semantics_descriptor, KEY_ID_LENGTH, SEMANTICS_ID, PREVIOUS_SEMANTICS_IDS}` payload hash を validity window に結んで Ed25519 で署名した credential `SignedCredential::verify_at(expected, now, revoked)` が期待する署名者・鍵 id の一致・署名 (`verify_strict`)・失効・時刻窓を順に確かめて payload hash を返す (保持しているだけでは信頼にならない、`verify_at` だけが信頼を与える) 署名対象は domain 分離 (context tag + version byte) した `len(context) || context || version || key_id || not_before || not_after || payload` の little-endian で golden vector で固定 `ValidityWindow` は半開区間 `[not_before, not_after)` (`not_before` は有効、`not_after` は無効、JWT `exp` と同じ規約で隣り合う窓が隙間も重なりもなく繋がる) `ValidityWindow::check(now)` が時刻窓の唯一の持ち主 (空・逆転した窓はどの時刻も拒む) `KeyId` は公開鍵の SHA-256 の先頭 16 byte で署名対象に含むので失効の回避に使えない `SEMANTICS_ID` は layout・version・使う primitive を表す `semantics_descriptor` の SHA-256 で、`check_semantics` が保存済みの id を Current / VerifiedPrevious / Mismatch に分類する (det-math でなく自身の crypto layout に対して畳む) 試験は inline (`--all-features` の CI で走る): 署名対象の layout、半開区間の境界 (`not_after` は Expired)、空・逆転窓、往復、窓の内外、署名者違い、小位数鍵が `verify_strict` で拒まれること、payload 改竄と窓の拡大で署名が壊れること、鍵 id のすり替え、失効、golden 署名、golden `SEMANTICS_ID` 中核 5 箇所 (署名者一致 / 鍵 id 一致 / 署名検証 / 失効 / 窓) の変異はどれも試験が失敗する CI の `Test (public siblings)` の下限 (`MIN_PASSED`) を 58 に上げた `no_std` + `alloc` (`CredError` は `core::error::Error`) 追加のみ
- CI: 全 feature の clippy と doc、bare-metal (`thumbv7em-none-eabihf`) の `timestamp` + `vc` の build と clippy、`Test (public siblings)` job (`cargo test --all-features`、cargo の失敗、失敗した試験、通った試験が 36 件未満のどれでも失敗) `scripts/preflight.sh` に同じ step を足した
- `PublicKey::verify_strict` (`ed25519-dalek` `verify_strict`): refuses a signature under a small-order public key (which `verify` accepts for any message), one whose R is a small-order point, and a small-order key in a non-canonical encoding, all three of which `verify` accepts 試験 `tests/verify_strict.rs` (RFC 8032 section 7.1 TEST 1-3 を両方が受ける、上の 3 通りは `verify` が受け `verify_strict` が拒む、S が群の位数で簡約されていない形と R の非正準な符号化は両方が拒む、同じ署名の 2 通りの byte 列のうち受けるのは 1 つ) CI の Test job で `scripts/run_tests.sh verify_strict=8` として走る `verify_strict` を `verify` に戻す変異と、鍵を読めない時に true を返す変異は失敗する 追加のみなので minor
- module doc の訂正: `verify` が受けて `verify_strict` が拒む非正準な符号化は鍵 (A) の方で、S の非正準な符号化は `verify` も拒む (実測)
- `KeyPair` / `PublicKey` / `Signature` (Ed25519 through `ed25519-dalek` 2.1), `hash_data` / `Hash` (SHA-256 through `sha2` 0.10) and `MerkleTree` / `MerkleProof`, with `HexError` for the hex decoders `KeyPair::generate` takes a caller-supplied CSPRNG and is behind the `rand` feature
- `tests/golden.rs`: public keys and signatures for 3 seeds and 3 messages, SHA-256 of 3 inputs, Merkle roots and proofs for 0 to 9 leaves, the empty-tree proof, the repeated-last-leaf root and a 44-byte timestamp layout signature Run in debug and release on ubuntu, macOS and Windows
- CI (ALICE-Law G1 / G10): `clippy.toml` bans the floating-point methods IEEE 754 does not require to be correctly rounded, the wall clock and OS randomness `scripts/clippy_canary.py` plants each entry and fails unless clippy flags it
- CI (ALICE-Law G14): the static and dynamic build-flag checks and the floating-point environment test on ubuntu, macOS and Windows
- CI (ALICE-Law G12): the public text check (`scripts/public_text.sh`, ALICE-Law's checker at the pinned revision)
