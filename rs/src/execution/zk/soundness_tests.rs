//! The soundness numbers `specs/soundness.md` states for ZHMITH01.
use super::{REPETITIONS, views};
use nebu::field::P;

/// Bit length of `base^exp`, by schoolbook big-integer multiplication.
fn bit_length_of_power(base: u64, exp: usize) -> usize {
    let mut limbs: Vec<u64> = vec![1];
    for _ in 0..exp {
        let mut carry = 0u128;
        for limb in &mut limbs {
            let v = (*limb as u128) * (base as u128) + carry;
            *limb = v as u64;
            carry = v >> 64;
        }
        if carry > 0 {
            limbs.push(carry as u64);
        }
    }
    let top = *limbs.last().unwrap();
    64 * (limbs.len() - 1) + (64 - top.leading_zeros() as usize)
}

/// (2/3)^r ≤ 2^-128  ⇔  3^r ≥ 2^(r+128)  ⇔  bitlen(3^r) ≥ r + 129.
fn reaches_128_bits(r: usize) -> bool {
    bit_length_of_power(3, r) > r + 128
}

#[test]
fn repetitions_bound_the_interactive_error_below_two_to_minus_128() {
    assert_eq!(REPETITIONS, 219);
    assert!(reaches_128_bits(REPETITIONS));
    assert!(!reaches_128_bits(REPETITIONS - 1), "219 is the smallest such count");
    // log2(3/2) · 219 = 128.107…: bitlen(3^219) = 348 = 219 + 129
    assert_eq!(bit_length_of_power(3, REPETITIONS), 348);
}

#[test]
fn challenge_trits_come_from_an_exact_rejection_sampler() {
    // p − 1 is divisible by three, so `value % 3` over [0, p − 1) is uniform.
    assert_eq!((P - 1) % 3, 0);
    let mut hash = hemera::Hasher::new();
    hash.update(b"soundness-test");
    let trits = views::challenges(&hash);
    let mut counts = [0usize; 3];
    for t in trits {
        counts[t as usize] += 1;
    }
    assert_eq!(counts.iter().sum::<usize>(), REPETITIONS);
    assert!(counts.iter().all(|&c| c > 0));
}
