//! Challenge fields of the IOP: Goldilocks and its cubic extension.
//!
//! Sumcheck and Spartan are generic over [`ChallengeField`]. The witness and
//! every matrix entry stay in Goldilocks; challenges, round polynomials and
//! evaluation claims live in the challenge field. `Fp3 = F_p[t]/(t³ − t − 1)`
//! (nebu) has `p³ ≈ 2^192` elements, so a Schwartz–Zippel or sumcheck round
//! error `d/|F|` is `d · 2^-191.99` instead of `d · 2^-63.99` over the base
//! field. The irreducibility of `t³ − t − 1` is checked by
//! `tests::fp3_modulus_has_no_root_in_goldilocks`.

use core::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};

use nebu::{Fp3, Goldilocks};

use crate::transcript::Transcript;

/// A field the verifier draws challenges from. The base field embeds into it.
pub trait ChallengeField:
    Copy
    + Debug
    + Default
    + PartialEq
    + Eq
    + Send
    + Sync
    + 'static
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;
    /// Goldilocks limbs per element.
    const LIMBS: usize;
    /// `floor(log2 |F|)` — the field size used by the soundness ledger.
    const LOG2_SIZE: u32;
    fn from_base(value: Goldilocks) -> Self;
    /// Multiplicative inverse; zero maps to zero.
    fn inverse(self) -> Self;
    /// Append the canonical little-endian limbs (8 bytes each).
    fn encode(self, out: &mut Vec<u8>);
    /// Draw one challenge from the transcript.
    fn squeeze(transcript: &mut Transcript) -> Self;
}

impl ChallengeField for Goldilocks {
    const ZERO: Self = Goldilocks::ZERO;
    const ONE: Self = Goldilocks::ONE;
    const LIMBS: usize = 1;
    const LOG2_SIZE: u32 = 63;
    fn from_base(value: Goldilocks) -> Self {
        value
    }
    fn inverse(self) -> Self {
        self.inv()
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.as_u64().to_le_bytes());
    }
    fn squeeze(transcript: &mut Transcript) -> Self {
        transcript.squeeze_challenge()
    }
}

impl ChallengeField for Fp3 {
    const ZERO: Self = Fp3::ZERO;
    const ONE: Self = Fp3::ONE;
    const LIMBS: usize = 3;
    const LOG2_SIZE: u32 = 191;
    fn from_base(value: Goldilocks) -> Self {
        Fp3::from_base(value)
    }
    fn inverse(self) -> Self {
        self.inv()
    }
    fn encode(self, out: &mut Vec<u8>) {
        for limb in [self.c0, self.c1, self.c2] {
            out.extend_from_slice(&limb.as_u64().to_le_bytes());
        }
    }
    fn squeeze(transcript: &mut Transcript) -> Self {
        transcript.squeeze_fp3()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nebu::field::P;

    /// Polynomials over Goldilocks, coefficients ascending.
    fn trim(mut a: Vec<Goldilocks>) -> Vec<Goldilocks> {
        while a.last() == Some(&Goldilocks::ZERO) {
            a.pop();
        }
        a
    }

    fn rem(a: &[Goldilocks], b: &[Goldilocks]) -> Vec<Goldilocks> {
        let mut r = trim(a.to_vec());
        let b = trim(b.to_vec());
        let lead_inv = b.last().unwrap().inv();
        while r.len() >= b.len() {
            let shift = r.len() - b.len();
            let factor = *r.last().unwrap() * lead_inv;
            for (i, &c) in b.iter().enumerate() {
                r[shift + i] -= factor * c;
            }
            r = trim(r);
        }
        r
    }

    fn gcd(a: &[Goldilocks], b: &[Goldilocks]) -> Vec<Goldilocks> {
        let (mut a, mut b) = (trim(a.to_vec()), trim(b.to_vec()));
        while !b.is_empty() {
            let r = rem(&a, &b);
            a = b;
            b = r;
        }
        a
    }

    /// A cubic over F_p is irreducible iff it has no root in F_p, iff
    /// gcd(x^p − x, f) = 1. `t^p` is computed in Fp3 = F_p[t]/(f) itself.
    #[test]
    fn fp3_modulus_has_no_root_in_goldilocks() {
        let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
        let mut power = Fp3::ONE;
        let mut base = t;
        let mut e = P;
        while e > 0 {
            if e & 1 == 1 {
                power *= base;
            }
            base = base * base;
            e >>= 1;
        }
        // x^p − x mod f, as a polynomial of degree ≤ 2
        let h = vec![power.c0, power.c1 - Goldilocks::ONE, power.c2];
        let f = vec![-Goldilocks::ONE, -Goldilocks::ONE, Goldilocks::ZERO, Goldilocks::ONE];
        let g = gcd(&f, &h);
        assert_eq!(g.len(), 1, "gcd(x^p − x, t³ − t − 1) must be a nonzero constant");
    }

    #[test]
    fn fp3_inverse_and_embedding() {
        let a = Fp3::new(Goldilocks::new(3), Goldilocks::new(5), Goldilocks::new(7));
        assert_eq!(a * ChallengeField::inverse(a), Fp3::ONE);
        let b = <Fp3 as ChallengeField>::from_base(Goldilocks::new(9));
        assert_eq!(b * Fp3::from_base(Goldilocks::new(2)), Fp3::from_base(Goldilocks::new(18)));
        let mut bytes = Vec::new();
        a.encode(&mut bytes);
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn declared_field_sizes_bound_the_true_sizes() {
        // floor(log2 p) = 63: 2^63 ≤ p < 2^64.
        let p = u128::from(P);
        assert_eq!(p >> 63, 1);
        // floor(log2 p³) = 191: p³ < 2^192 because p < 2^64, and
        // p³ ≥ (p² >> 65) · 2^65 · p ≥ 2^191 when (p² >> 65) · p ≥ 2^126.
        let high = (p * p) >> 65;
        assert!(high * p >= 1u128 << 126);
        assert_eq!(<Goldilocks as ChallengeField>::LOG2_SIZE, 63);
        assert_eq!(<Fp3 as ChallengeField>::LOG2_SIZE, 191);
    }
}
