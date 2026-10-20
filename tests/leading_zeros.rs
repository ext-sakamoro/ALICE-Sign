//! `Hash::has_leading_zeros(n)` asks whether the first `n` bits of a 256-bit hash
//! are zero. A hash has no bits past 256, so for `n > 256` the answer is `false`
//! (never a panic): a difficulty or bound supplied from outside cannot crash the
//! caller.

use alice_sign::Hash;

fn with_first_one_bit_at(bit: usize) -> Hash {
    let mut b = [0u8; 32];
    b[bit / 8] = 0x80 >> (bit % 8);
    Hash(b)
}

#[test]
fn past_256_bits_is_false_and_does_not_panic() {
    let zero = Hash::zero();
    for n in [257u32, 264, 1_000, u32::MAX] {
        let r = std::panic::catch_unwind(|| zero.has_leading_zeros(n));
        assert!(!r.expect("no panic"), "{n}");
    }
}

#[test]
fn the_all_zero_hash_has_exactly_256_leading_zeros() {
    let zero = Hash::zero();
    assert!(zero.has_leading_zeros(0));
    assert!(zero.has_leading_zeros(255));
    assert!(zero.has_leading_zeros(256));
}

#[test]
fn every_boundary_bit() {
    for bit in 0..256usize {
        let h = with_first_one_bit_at(bit);
        let n = u32::try_from(bit).expect("small");
        assert!(h.has_leading_zeros(n), "{bit}");
        assert!(!h.has_leading_zeros(n + 1), "{bit}");
    }
}
