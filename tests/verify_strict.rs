//! `PublicKey::verify_strict` against independent references.
//!
//! - RFC 8032 section 7.1 TEST 1-3: the published key, message and signature are accepted
//!   by both checks.
//! - Vectors built for this file (by a separate program with curve25519-dalek, values
//!   printed and copied here) that the two checks treat differently: a signature under a
//!   small-order public key, one with a small-order R under an ordinary key, and one
//!   under a small-order key written in a non-canonical encoding. `verify` accepts all
//!   three, `verify_strict` refuses all three.
//! - Encodings both checks refuse: S not reduced modulo the group order (S + l of a valid
//!   signature) and a non-canonical encoding of R.

use alice_sign::{KeyPair, PublicKey, Signature};

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N, "{hex}");
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
}

fn message(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// RFC 8032 section 7.1, TEST 1, 2 and 3: (secret key, public key, message, signature)
const RFC8032: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

/// The message of the built vectors ("alice-sign strict")
const MSG: &str = "616c6963652d7369676e20737472696374";

/// The ordinary key of the built vectors: the key of the seed [7; 32]
const KEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

/// A valid signature of MSG under KEY
const GOOD: &str = "6ced1642c551e1d628df7b945c52b2d7ea0837dea0e5a380617f94aaf99df8e7606989c853d91d97fe6a8493ef6ee5a980ca33684d316ca1229cf4eaf539dc0b";

/// Small-order public key (the identity point); R = B, S = 1 verifies for any message
const IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
const UNDER_IDENTITY: &str = "58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000";

/// The identity point written as y = p + 1 (a non-canonical encoding of a small-order key)
const IDENTITY_NON_CANONICAL: &str =
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

/// Under KEY: R = identity, S = k·a (a small-order R)
const SMALL_ORDER_R: &str = "0100000000000000000000000000000000000000000000000000000000000000327b035e297e0853b2a3d6866fbde47f8afcea8bca3fba0e17e6df3c85e84408";

/// GOOD with S replaced by S + l (the same value modulo the group order)
const S_PLUS_L: &str = "6ced1642c551e1d628df7b945c52b2d7ea0837dea0e5a380617f94aaf99df8e74d3d7f256e3c30efd4077c36ce68c4be80ca33684d316ca1229cf4eaf539dc1b";

/// Under KEY: R = identity written as y = p + 1, S = k·a over those R bytes
const R_NON_CANONICAL: &str = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f7d7e3e82cad0bb5a7cf936d4094d855a9ed420d9b7a00e0dc7f53fd3634ae708";

fn both(key: &str, msg: &[u8], sig: &str) -> (bool, bool) {
    let key = PublicKey(bytes::<32>(key));
    let sig = Signature(bytes::<64>(sig));
    (key.verify(msg, &sig), key.verify_strict(msg, &sig))
}

#[test]
fn rfc8032_vectors_are_accepted_by_both() {
    for (secret, public, msg, sig) in RFC8032 {
        let kp = KeyPair::from_seed(bytes::<32>(secret));
        assert_eq!(kp.public(), PublicKey(bytes::<32>(public)), "{public}");
        let msg = message(msg);
        assert_eq!(kp.sign(&msg), Signature(bytes::<64>(sig)), "{sig}");
        assert_eq!(both(public, &msg, sig), (true, true), "{sig}");
    }
}

#[test]
fn a_signature_under_a_small_order_key_is_refused_by_strict_only() {
    let msg = message(MSG);
    assert_eq!(both(IDENTITY, &msg, UNDER_IDENTITY), (true, false));
    // the same signature verifies under the small-order key for any other message
    assert_eq!(
        both(IDENTITY, b"any other message", UNDER_IDENTITY),
        (true, false)
    );
}

#[test]
fn a_small_order_r_is_refused_by_strict_only() {
    assert_eq!(both(KEY, &message(MSG), SMALL_ORDER_R), (true, false));
}

#[test]
fn a_small_order_key_in_a_non_canonical_encoding_is_refused_by_strict_only() {
    assert_eq!(
        both(IDENTITY_NON_CANONICAL, &message(MSG), UNDER_IDENTITY),
        (true, false)
    );
}

#[test]
fn non_canonical_s_and_r_are_refused_by_both() {
    let msg = message(MSG);
    assert_eq!(both(KEY, &msg, S_PLUS_L), (false, false));
    assert_eq!(both(KEY, &msg, R_NON_CANONICAL), (false, false));
}

#[test]
fn of_two_byte_forms_of_one_signature_exactly_one_is_accepted() {
    let msg = message(MSG);
    let accepted: Vec<bool> = [GOOD, S_PLUS_L]
        .iter()
        .map(|s| both(KEY, &msg, s).1)
        .collect();
    assert_eq!(accepted, [true, false]);
}

#[test]
fn a_changed_message_or_key_or_signature_is_refused() {
    let msg = message(MSG);
    assert_eq!(both(KEY, &msg, GOOD), (true, true));
    assert_eq!(both(KEY, b"alice-sign strict!", GOOD), (false, false));
    let mut key = bytes::<32>(KEY);
    key[0] ^= 1;
    let sig = Signature(bytes::<64>(GOOD));
    assert!(!PublicKey(key).verify_strict(&msg, &sig));
    let mut flipped = bytes::<64>(GOOD);
    flipped[10] ^= 1;
    assert!(!PublicKey(bytes::<32>(KEY)).verify_strict(&msg, &Signature(flipped)));
}

#[test]
fn an_invalid_key_encoding_and_any_message_length_are_handled() {
    // y = 2 is not on the curve: the key does not decode, both refuse
    let mut not_on_curve = [0u8; 32];
    not_on_curve[0] = 2;
    let sig = Signature(bytes::<64>(GOOD));
    assert!(!PublicKey(not_on_curve).verify_strict(b"", &sig));
    assert!(!PublicKey(not_on_curve).verify(b"", &sig));
    // the empty message and a long one round-trip
    let kp = KeyPair::from_seed([7u8; 32]);
    for msg in [Vec::new(), vec![0xa5u8; 1 << 20]] {
        assert!(
            kp.public().verify_strict(&msg, &kp.sign(&msg)),
            "{}",
            msg.len()
        );
    }
    // a hex signature of the wrong length is refused before verification
    assert!(Signature::from_hex(&GOOD[..126]).is_err());
    assert!(Signature::from_hex(&format!("{GOOD}00")).is_err());
}
