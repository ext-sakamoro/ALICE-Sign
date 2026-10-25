//! `SIGN_SEMANTICS_ID` (ALICE-Law G6): every pin of `SIGN_SEMANTICS_PINS` recomputed from the live
//! code, and the fold of the pins equal to the identifier. A change in what the crate computes
//! for one of these scenarios moves its pin (and the identifier), so the identifier cannot stay
//! while the bytes or verdicts move.
//!
//! `SIGN_PRINT_PINS=1 cargo test --test sign_semantics_id -- --nocapture` prints the pins after an
//! intended change; update the table first, then the identifier.

use alice_sign::semantics::{
    fold_semantics_pins, PREVIOUS_SIGN_SEMANTICS_IDS, SIGN_SEMANTICS_ID, SIGN_SEMANTICS_PINS,
};
use alice_sign::{hash_data, hmac_sha256, Hash, KeyPair, MerkleTree, PublicKey, Signature};

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7) % 256) as u8)
        .collect()
}

fn sha(parts: &[u8]) -> [u8; 32] {
    hash_data(parts).0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes32(s: &str) -> [u8; 32] {
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
}

/// The scenarios, each written out: its pin is the SHA-256 of the bytes listed here.
fn live_pins() -> Vec<(&'static str, [u8; 32])> {
    let seeds: [[u8; 32]; 3] = [[0u8; 32], [0x42u8; 32], core::array::from_fn(|i| i as u8)];
    let messages: [Vec<u8>; 3] = [Vec::new(), b"abc".to_vec(), pattern(1000)];

    // public key || signature, for every seed and message
    let mut ed = Vec::new();
    for seed in seeds {
        let kp = KeyPair::from_seed(seed);
        for m in &messages {
            ed.extend_from_slice(&kp.public().0);
            ed.extend_from_slice(&kp.sign(m).0);
        }
    }

    // SHA-256 at the lengths around the block boundary
    let mut sha256 = Vec::new();
    for n in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 1000] {
        sha256.extend_from_slice(&hash_data(&pattern(n)).0);
    }

    // HMAC-SHA256: keys shorter than, equal to and longer than the block
    let mut hmac = Vec::new();
    for key in [Vec::new(), b"key".to_vec(), pattern(64), pattern(100)] {
        for m in &messages {
            hmac.extend_from_slice(&hmac_sha256(&key, m));
        }
    }

    // Merkle roots of 0..=9 leaves, and whether every proof verifies (1) or not (0)
    let mut merkle = Vec::new();
    for n in 0..=9u8 {
        let leaves: Vec<Hash> = (0..n).map(|i| hash_data(&[i])).collect();
        let tree = MerkleTree::build(&leaves);
        merkle.extend_from_slice(&tree.root().0);
        for (i, leaf) in leaves.iter().enumerate() {
            let ok = tree.prove(i).is_some_and(|p| p.verify(*leaf, tree.root()));
            merkle.push(u8::from(ok));
        }
    }

    // verdicts of verify / verify_strict: a valid signature, another message, another key, and
    // the identity point as the key with R = B, S = 1 (accepted by verify for any message,
    // refused by verify_strict)
    let kp = KeyPair::from_seed([7u8; 32]);
    let sig = kp.sign(b"abc");
    let other = KeyPair::from_seed([8u8; 32]).public();
    let small = PublicKey(bytes32(
        "0100000000000000000000000000000000000000000000000000000000000000",
    ));
    let mut so_sig = [0u8; 64];
    so_sig[..32].copy_from_slice(&bytes32(
        "5866666666666666666666666666666666666666666666666666666666666666",
    ));
    so_sig[32] = 1;
    let so_sig = Signature(so_sig);
    let mut verdicts = Vec::new();
    for (key, msg, s) in [
        (kp.public(), &b"abc"[..], &sig),
        (kp.public(), &b"abd"[..], &sig),
        (other, &b"abc"[..], &sig),
        (small, &b"any message"[..], &so_sig),
    ] {
        verdicts.push(u8::from(key.verify(msg, s)));
        verdicts.push(u8::from(key.verify_strict(msg, s)));
    }

    vec![
        ("golden ed25519 public keys and signatures", sha(&ed)),
        ("golden hmac_sha256", sha(&hmac)),
        ("golden merkle roots", sha(&merkle)),
        ("golden sha256", sha(&sha256)),
        ("golden verify verdicts", sha(&verdicts)),
    ]
}

#[test]
fn every_pin_is_recomputed_from_the_live_code_and_the_fold_is_the_identifier() {
    let live = live_pins();
    if std::env::var_os("SIGN_PRINT_PINS").is_some() {
        for (n, d) in &live {
            println!("{n} {}", hex(d));
        }
        println!("SIGN_SEMANTICS_ID {}", hex(&fold_semantics_pins(&live)));
    }
    assert_eq!(live.len(), SIGN_SEMANTICS_PINS.len(), "pins compared");
    for (l, p) in live.iter().zip(SIGN_SEMANTICS_PINS) {
        assert_eq!(l.0, p.0, "pin order");
        assert_eq!(hex(&l.1), hex(&p.1), "pin {}", p.0);
    }
    assert_eq!(
        hex(&fold_semantics_pins(SIGN_SEMANTICS_PINS)),
        hex(&SIGN_SEMANTICS_ID)
    );
}

#[test]
fn the_verdict_scenario_separates_verify_from_verify_strict() {
    // the pinned verdicts are 1 1 / 0 0 / 0 0 / 1 0: the small-order key is the only case where
    // the two disagree, so a verify_strict that fell back to verify moves the pin
    let kp = KeyPair::from_seed([7u8; 32]);
    let sig = kp.sign(b"abc");
    assert!(kp.public().verify(b"abc", &sig) && kp.public().verify_strict(b"abc", &sig));
    let small = PublicKey(bytes32(
        "0100000000000000000000000000000000000000000000000000000000000000",
    ));
    let mut so = [0u8; 64];
    so[..32].copy_from_slice(&bytes32(
        "5866666666666666666666666666666666666666666666666666666666666666",
    ));
    so[32] = 1;
    assert!(small.verify(b"any message", &Signature(so)));
    assert!(!small.verify_strict(b"any message", &Signature(so)));
}

#[test]
fn the_documented_value_is_the_constant_and_no_previous_identifier_is_listed() {
    let doc = include_str!("../src/semantics.rs");
    assert!(
        doc.contains(&format!("//! {}\n", hex(&SIGN_SEMANTICS_ID))),
        "the hex form in the module doc"
    );
    assert!(PREVIOUS_SIGN_SEMANTICS_IDS.is_empty());
}

#[test]
fn the_fold_does_not_depend_on_the_order_the_table_is_written_in() {
    // the table is written sorted; the fold sorts it again, so any order folds to the same id
    let mut reversed: Vec<(&str, [u8; 32])> = SIGN_SEMANTICS_PINS.to_vec();
    reversed.reverse();
    assert_eq!(fold_semantics_pins(&reversed), SIGN_SEMANTICS_ID);
}
