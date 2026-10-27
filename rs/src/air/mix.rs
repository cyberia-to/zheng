//! Arithmetic over values that are mostly base-field: [`Mix`] is a
//! Goldilocks element until an operation meets an Fp3 one. The zerocheck's
//! first round evaluates the constraints on lines between two trace rows,
//! whose cells are base-field; only the terms that read a challenge leave
//! the base field, so most products cost one Goldilocks multiplication
//! instead of an Fp3 one. Values are the same as in Fp3.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use lens::rspcs::field::mul_base;
use nebu::{Fp3, Goldilocks};

use super::num::Num;

#[derive(Clone, Copy, Debug)]
pub enum Mix {
    B(Goldilocks),
    E(Fp3),
}

impl Mix {
    pub fn of(x: Fp3) -> Self {
        if x.c1 == Goldilocks::ZERO && x.c2 == Goldilocks::ZERO {
            Mix::B(x.c0)
        } else {
            Mix::E(x)
        }
    }
    pub fn fp3(self) -> Fp3 {
        match self {
            Mix::B(b) => Fp3::from_base(b),
            Mix::E(e) => e,
        }
    }
    /// `m·self` for an Fp3 `m`.
    pub fn scale(self, m: Fp3) -> Fp3 {
        match self {
            Mix::B(b) => mul_base(m, b),
            Mix::E(e) => m * e,
        }
    }
}

impl Add for Mix {
    type Output = Mix;
    #[inline]
    fn add(self, o: Mix) -> Mix {
        match (self, o) {
            (Mix::B(a), Mix::B(b)) => Mix::B(a + b),
            (Mix::B(a), Mix::E(e)) | (Mix::E(e), Mix::B(a)) => {
                Mix::E(Fp3::new(e.c0 + a, e.c1, e.c2))
            }
            (Mix::E(a), Mix::E(b)) => Mix::E(a + b),
        }
    }
}

impl Sub for Mix {
    type Output = Mix;
    #[inline]
    fn sub(self, o: Mix) -> Mix {
        self + (-o)
    }
}

impl Neg for Mix {
    type Output = Mix;
    #[inline]
    fn neg(self) -> Mix {
        match self {
            Mix::B(a) => Mix::B(-a),
            Mix::E(e) => Mix::E(-e),
        }
    }
}

impl Mul for Mix {
    type Output = Mix;
    #[inline]
    fn mul(self, o: Mix) -> Mix {
        match (self, o) {
            (Mix::B(a), Mix::B(b)) => Mix::B(a * b),
            (Mix::B(a), Mix::E(e)) | (Mix::E(e), Mix::B(a)) => Mix::E(mul_base(e, a)),
            (Mix::E(a), Mix::E(b)) => Mix::E(a * b),
        }
    }
}

impl AddAssign for Mix {
    fn add_assign(&mut self, o: Mix) {
        *self = *self + o;
    }
}
impl SubAssign for Mix {
    fn sub_assign(&mut self, o: Mix) {
        *self = *self - o;
    }
}
impl MulAssign for Mix {
    fn mul_assign(&mut self, o: Mix) {
        *self = *self * o;
    }
}

impl Num for Mix {
    const ZERO: Self = Mix::B(Goldilocks::ZERO);
    const ONE: Self = Mix::B(Goldilocks::ONE);
    fn from_fp3(c: Fp3) -> Self {
        Mix::of(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_arithmetic_is_fp3_arithmetic() {
        let vals = [
            Fp3::from_base(Goldilocks::new(7)),
            Fp3::from_base(Goldilocks::new(u64::MAX - 5)),
            Fp3::new(Goldilocks::new(3), Goldilocks::new(9), Goldilocks::new(1)),
            Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO),
        ];
        for &a in &vals {
            for &b in &vals {
                let (x, y) = (Mix::of(a), Mix::of(b));
                assert_eq!((x + y).fp3(), a + b);
                assert_eq!((x - y).fp3(), a - b);
                assert_eq!((x * y).fp3(), a * b);
                assert_eq!((-x).fp3(), -a);
                assert_eq!(x.scale(b), b * a);
            }
        }
    }
}
