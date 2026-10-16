//! Golden vectors: every expected value below was produced by the code this
//! crate was moved from (alice-blockchain 1.5.0, main 4816a6a), before the
//! move, by a separate program that printed its outputs. They pin the byte
//! layouts so that a key, message or leaf list gives the same bytes here.
//!
//! Independent references agree where they exist: SHA-256 of "" and "abc"
//! (FIPS 180-2 test vectors) and the public key of the all-zero seed
//! (3b6a27bc..., RFC 8032 / ed25519-dalek).

use alice_sign::{hash_data, Hash, KeyPair, MerkleTree, PublicKey, Signature};

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7) % 256) as u8)
        .collect()
}

fn seeds() -> [[u8; 32]; 3] {
    [[0u8; 32], [0x42u8; 32], core::array::from_fn(|i| i as u8)]
}

fn messages() -> [Vec<u8>; 3] {
    [Vec::new(), b"abc".to_vec(), pattern(1000)]
}
const PUBLIC: [&str; 3] = [
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
];
const SIGNATURE: [[&str; 3]; 3] = [
    [
        "8f895b3cafe2c9506039d0e2a66382568004674fe8d237785092e40d6aaf483e4fc60168705f31f101596138ce21aa357c0d32a064f423dc3ee4aa3abf53f803",
        "885dfb07cab2796eb960531a2f09b972ad59b97bb125bef5fdda0855d6bebebf24447e705fa11575639df396c201ccf52a1a16b014a7a2f0ce73a7a161757308",
        "2c5d26814ffaebe3a28cdf079015a3a4adf19fee93f66a8beaa3e7280546c4e5ad8434ef24ed8f929160e393c76a8ef438bc866e4ec2b42536e7b13526959c06",
    ],
    [
        "3f9f3147d0dd159f334cb800435ae49a2837adae5e6b2394906edc2cfed829785e3dd186eb2fed1319a0451917cb6617fcbe9382e0d1343eb5ffd4a9a2dd820c",
        "0ec9d99b3bbcf3778267e6e5f92a41f9c8c263dd90fc67e0ca4058f09c6bfd5089160f8fa2f0b07bc51d256715a4175a45a9d892e044af5fe201803cac0d560c",
        "90b5dcdd9973aa22a4bc5bd22f46befbe4ef59c31a6442d59fdf843373e03fc4082d23d230245e38bb655284b3a2c7a2b4ed005896c2d353349a98e1718c9f0c",
    ],
    [
        "9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e5845ef4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102",
        "cc46d62d3754f41754b27b6ea2cb2c272bafa7a5a1f6062bd060f414e50caaeac2da66ad39cef4424a90236ea907b7d8057e3443dc5abfc9986967ee7213a407",
        "241db57647191154fd4a3a0c56b6063b3c4e7516bf9a5f9fb5e06d7c389a5020ccf9ca104e1bd39e2bef06527167a603e244a557c536db7ee7de7f14d5c5b10d",
    ],
];

#[test]
fn public_keys_and_signatures_match_the_moved_code() {
    let mut compared = 0;
    for (s, seed) in seeds().iter().enumerate() {
        let kp = KeyPair::from_seed(*seed);
        assert_eq!(kp.public().to_hex(), PUBLIC[s], "seed {s}");
        for (m, msg) in messages().iter().enumerate() {
            let sig = kp.sign(msg);
            assert_eq!(sig.to_hex(), SIGNATURE[s][m], "seed {s} message {m}");
            assert!(kp.public().verify(msg, &sig));
            compared += 1;
        }
    }
    assert_eq!(compared, 9);
}

#[test]
fn a_signature_does_not_verify_for_another_message_or_key() {
    let kp = KeyPair::from_seed(seeds()[1]);
    let other = KeyPair::from_seed(seeds()[2]);
    let sig = kp.sign(b"abc");
    assert!(!kp.public().verify(b"abd", &sig));
    assert!(!other.public().verify(b"abc", &sig));
}

#[test]
fn hex_round_trips() {
    let pk = PublicKey::from_hex(PUBLIC[1]).expect("valid");
    assert_eq!(pk.to_hex(), PUBLIC[1]);
    let sig = Signature::from_hex(SIGNATURE[1][1]).expect("valid");
    assert!(pk.verify(b"abc", &sig));
    assert!(PublicKey::from_hex("00").is_err());
    assert!(Hash::from_hex(&"zz".repeat(32)).is_err());
}

#[test]
fn sha256_matches_the_moved_code_and_fips_180_2() {
    assert_eq!(
        hash_data(b"").to_hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hash_data(b"abc").to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hash_data(&pattern(1 << 20)).to_hex(),
        "06b7bbfb7824aa03382051691630eb26de85102d1b08a81e907ec0744cd8a286"
    );
}
const MERKLE: [(&str, &str); 10] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "30e1867424e66e8b6d159246db94e3486778136f7e386ff5f001859d6b8484ab",
        "bd97614318b4b5cb352b2f15ed425418653596e4b40d5ffc733809b4d06ff19d",
    ),
    (
        "f2dcdd96791b6bac5d554f2d320e594b834f5da1981812c3707e7772234cb0ad",
        "a0844805367b662732210bba0ca38edf9a135f64f52503e474287b6ed919afee",
    ),
    (
        "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e",
        "c3a70ee587cad0bf4e0a36d7aac8ece3a16d0ea2e47d2b604b24db714e2257e4",
    ),
    (
        "9674600fd139741c0f7dd7a32d984a0e74401cc90e6e8e5d203ed973d27324fe",
        "999b9fd0692afa1c2b8df16e2c0a3e410eae67dc75b8ffd4c69ef2f2cfab3ceb",
    ),
    (
        "adccbd2044ec8710e7970bd22e5c68df20fe3848f267086da2013a3377175b5e",
        "28b1ea8d4e332e4a9b215726786a53a0acda45879fc5b1c1fb4232db05045a73",
    ),
    (
        "e263b77a6d80c1c56f3f67d1e0d803ad8eb2ac9d66c82f78735207c886a1592c",
        "5d3acc95a8e3884f638688d69a612e2b5ee7b7a2a6e2435de74304f03e022985",
    ),
    (
        "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578",
        "6a0edde01b8c8a6f74b7dccba5094733841057e0eb35070643be249eb1091584",
    ),
    (
        "2af28dd3cb79464e9f6fd73729e96b05ad6e63366897c1cefe11c7fb1340f6d6",
        "de5cfa1b881a7140c12d1d84ca5a1d62b66f848616e9114b88d949262de571ea",
    ),
];

#[test]
fn merkle_roots_and_proofs_match_the_moved_code() {
    for (n, (root, proofs_sha256)) in MERKLE.iter().enumerate() {
        let leaves: Vec<Hash> = (0..n).map(|i| hash_data(&[i as u8])).collect();
        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.root().to_hex(), *root, "{n} leaves");
        let mut proofs = Vec::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let p = tree.prove(i).expect("in range");
            assert!(p.verify(*leaf, tree.root()), "{n} leaves, index {i}");
            for (h, right) in &p.hashes {
                proofs.extend_from_slice(&h.0);
                proofs.extend_from_slice(&[u8::from(*right)]);
            }
        }
        assert_eq!(hash_data(&proofs).to_hex(), *proofs_sha256, "{n} leaves");
        // past the last leaf there is no proof, except for the empty tree,
        // whose single level holds Hash::zero (see the next test)
        if n > 0 {
            assert!(tree.prove(n).is_none());
        }
    }
}

/// The moved code's behaviour for an empty list: the root is Hash::zero and
/// index 0 has an empty proof of it (documented in the `merkle` module docs).
#[test]
fn the_empty_tree_proves_the_zero_hash_at_index_0() {
    let tree = MerkleTree::build(&[]);
    assert_eq!(tree.root(), Hash::zero());
    let p = tree.prove(0).expect("the moved code returns Some");
    assert!(p.hashes.is_empty());
    assert!(p.verify(Hash::zero(), tree.root()));
    assert!(tree.prove(1).is_none());
}

/// A documented property of the layout (see the `merkle` module docs), kept
/// because existing roots depend on it.
#[test]
fn repeating_the_last_leaf_keeps_the_root() {
    let (a, b, c) = (hash_data(b"a"), hash_data(b"b"), hash_data(b"c"));
    assert_eq!(
        MerkleTree::build(&[a, b, c]).root(),
        MerkleTree::build(&[a, b, c, c]).root()
    );
}

/// The 44-byte layout a caller (a timestamp: hash, u64 seconds, u32 nanos, all
/// little-endian) signs: the signature over it is unchanged by the move.
#[test]
fn a_timestamp_layout_signature_matches_the_moved_code() {
    let mut bytes = [0u8; 44];
    bytes[..32].copy_from_slice(&hash_data(b"contract").0);
    bytes[32..40].copy_from_slice(&1_700_000_000u64.to_le_bytes());
    bytes[40..44].copy_from_slice(&123_456_789u32.to_le_bytes());
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "cc8321d6375c494d043fdd0260f21bc0ec51dacc9f6abb7f909cdcd3041b78bf00f153650000000015cd5b07"
    );
    assert_eq!(
        hash_data(&bytes).to_hex(),
        "722e986f9f3547ed878dd68b15325d18391cd6e88331463d103ae0b892d85d46"
    );
    assert_eq!(KeyPair::from_seed([7u8; 32]).sign(&bytes).to_hex(), "63ab91b36ce5b43b181d179c4d8369b8f920bf09c64a182b6090ce50484f9e6269ec311d4cd8eaccad70c32b14385135fb8655a14316cce18cfae5abd8813900");
}
