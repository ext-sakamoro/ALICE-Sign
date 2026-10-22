//! HMAC-SHA256 against independent references.
//!
//! - RFC 4231 section 4, test cases 1 to 7 (case 5 is the 128-bit truncation, cases 6
//!   and 7 a key longer than the 64-byte block, which is hashed first).
//! - The `hmac` crate (0.12, a dev-dependency only) over keys of 0 to 200 bytes and
//!   messages of 0 to 300 bytes from a fixed generator: every tag is bit-identical, so
//!   a value already stored by a caller of that crate is reproduced exactly.
//! - The incremental form gives the same tag however the message is split.
//! - `verify_hmac_sha256`, `verify_hmac_sha256_full` and `ct_eq`: equal inputs pass; a changed byte, a different
//!   length, an empty tag and a tag shorter than 16 bytes are refused.

use alice_sign::mac::{
    ct_eq, hmac_sha256, verify_hmac_sha256, verify_hmac_sha256_full, HmacSha256, HMAC_SHA256_LENGTH,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// RFC 4231 section 4: (key, data, HMAC-SHA-256); case 5 lists the first 128 bits only.
fn rfc4231() -> Vec<(Vec<u8>, Vec<u8>, &'static str)> {
    let key4: Vec<u8> = (1..=25).collect();
    vec![
        (vec![0x0b; 20], b"Hi There".to_vec(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa; 20], vec![0xdd; 50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (key4, vec![0xcd; 50], "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (vec![0x0c; 20], b"Test With Truncation".to_vec(), "a3b6167473100ee06e0c796c2955552b"),
        (
            vec![0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        (
            vec![0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ]
}

#[test]
fn rfc4231_test_cases_1_to_7() {
    let cases = rfc4231();
    assert_eq!(cases.len(), 7);
    for (n, (key, data, expected)) in cases.iter().enumerate() {
        let tag = hmac_sha256(key, data);
        assert_eq!(
            &hex(&tag)[..expected.len()],
            *expected,
            "test case {}",
            n + 1
        );
        assert!(
            verify_hmac_sha256(key, data, &unhex(expected)),
            "test case {} verifies",
            n + 1
        );
    }
}

/// A fixed byte generator (xorshift64), so the inputs are the same on every machine.
fn bytes(seed: &mut u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            (*seed >> 24) as u8
        })
        .collect()
}

fn reference(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[test]
fn same_tags_as_the_hmac_crate() {
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut compared = 0;
    // key lengths around the 64-byte block (63 / 64 / 65) and past it, messages around it
    for key_len in [0, 1, 16, 31, 32, 33, 63, 64, 65, 100, 128, 129, 200] {
        for msg_len in [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 300] {
            let key = bytes(&mut seed, key_len);
            let msg = bytes(&mut seed, msg_len);
            assert_eq!(
                hmac_sha256(&key, &msg),
                reference(&key, &msg),
                "key {key_len} B, message {msg_len} B"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 13 * 11);
}

#[test]
fn a_labelled_message_matches_the_hmac_crate() {
    // a caller that feeds `<label> NUL <payload>` in three updates, and keeps the first 16 bytes
    let key = b"0123456789abcdef0123456789abcdef";
    for (label, payload) in [
        ("kind-a", "1.2.1700000000"),
        ("kind-b", ""),
        ("", "payload"),
    ] {
        let mut ours = HmacSha256::new(key);
        ours.update(label.as_bytes());
        ours.update(&[0]);
        ours.update(payload.as_bytes());
        let ours = ours.finalize();
        let mut theirs = Hmac::<Sha256>::new_from_slice(key).expect("key");
        theirs.update(label.as_bytes());
        theirs.update(&[0]);
        theirs.update(payload.as_bytes());
        let theirs: [u8; 32] = theirs.finalize().into_bytes().into();
        assert_eq!(ours, theirs, "{label:?} {payload:?}");
        assert!(verify_hmac_sha256(
            key,
            format!("{label}\0{payload}").as_bytes(),
            &ours[..16]
        ));
    }
}

#[test]
fn incremental_updates_do_not_depend_on_the_split() {
    let mut seed = 7;
    let key = bytes(&mut seed, 40);
    let msg = bytes(&mut seed, 257);
    let whole = hmac_sha256(&key, &msg);
    for split in [0, 1, 63, 64, 65, 128, 256, 257] {
        let mut mac = HmacSha256::new(&key);
        mac.update(&msg[..split]);
        mac.update(&msg[split..]);
        assert_eq!(mac.finalize(), whole, "split at {split}");
    }
    assert_eq!(whole.len(), HMAC_SHA256_LENGTH);
}

#[test]
fn verification_refuses_changed_short_and_long_tags() {
    let key = b"key";
    let msg = b"message";
    let tag = hmac_sha256(key, msg);
    assert!(verify_hmac_sha256(key, msg, &tag));
    assert!(
        verify_hmac_sha256(key, msg, &tag[..16]),
        "a 128-bit prefix is accepted"
    );
    assert!(
        !verify_hmac_sha256(key, msg, &tag[..15]),
        "shorter than 16 bytes"
    );
    assert!(!verify_hmac_sha256(key, msg, &[]), "empty tag");
    let mut long = tag.to_vec();
    long.push(0);
    assert!(!verify_hmac_sha256(key, msg, &long), "longer than 32 bytes");
    for i in 0..32 {
        let mut bad = tag;
        bad[i] ^= 0x01;
        assert!(!verify_hmac_sha256(key, msg, &bad), "byte {i} changed");
    }
    assert!(!verify_hmac_sha256(b"other key", msg, &tag));
    assert!(!verify_hmac_sha256(key, b"other message", &tag));
}

#[test]
fn ct_eq_compares_bytes_and_lengths() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"bbc"));
    assert!(!ct_eq(b"abc", b"ab"));
    assert!(!ct_eq(b"ab", b"abc"));
    assert!(!ct_eq(b"", b"a"));
}

#[test]
fn full_verification_needs_all_32_bytes() {
    let key = b"key";
    let msg = b"message";
    let tag = hmac_sha256(key, msg);
    assert!(verify_hmac_sha256_full(key, msg, &tag));
    assert!(
        !verify_hmac_sha256_full(key, msg, &tag[..16]),
        "a 16-byte prefix is refused"
    );
    assert!(!verify_hmac_sha256_full(key, msg, &tag[..31]), "31 bytes");
    let mut long = tag.to_vec();
    long.push(0);
    assert!(!verify_hmac_sha256_full(key, msg, &long), "33 bytes");
    for i in [0, 15, 16, 31] {
        let mut bad = tag;
        bad[i] ^= 0x80;
        assert!(!verify_hmac_sha256_full(key, msg, &bad), "byte {i} changed");
    }
    assert!(!verify_hmac_sha256_full(b"other key", msg, &tag));
}
