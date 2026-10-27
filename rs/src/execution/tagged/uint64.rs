//! Unsigned metadata arithmetic. Bounds saturate; execution budgets do not.
use super::{build::Builder, *};

#[derive(Clone, Copy, Debug)]
pub(super) struct U64 {
    pub lo: Wire,
    pub hi: Wire,
}

impl Builder {
    pub(super) fn range_u64(&mut self, value: U64) -> Result<[Wire; 64], Error> {
        let lo = self.word_bits(value.lo, ONE)?;
        let hi = self.word_bits(value.hi, ONE)?;
        Ok(std::array::from_fn(
            |i| if i < 32 { lo[i] } else { hi[i - 32] },
        ))
    }

    fn split33(&mut self, value: Wire) -> Result<(Wire, Wire), Error> {
        let mut bits = [ZERO; 33];
        let mut equation = vec![(value, -F::ONE)];
        for (i, bit) in bits.iter_mut().enumerate() {
            *bit = self.alloc(Op::Bit(value, i))?;
            self.zero_product(*bit, vec![(ONE, F::ONE), (*bit, -F::ONE)])?;
            equation.push((*bit, F::new(1u64 << i)));
        }
        self.zero_product(ONE, equation)?;
        let lo = self.lin(
            bits[..32]
                .iter()
                .enumerate()
                .map(|(i, &bit)| (bit, F::new(1u64 << i)))
                .collect(),
        )?;
        Ok((lo, bits[32]))
    }

    pub(super) fn saturating_u64_add(&mut self, a: U64, b: U64) -> Result<U64, Error> {
        self.range_u64(a)?;
        self.range_u64(b)?;
        let lo = self.lin(vec![(a.lo, F::ONE), (b.lo, F::ONE)])?;
        let (lo, carry) = self.split33(lo)?;
        let hi = self.lin(vec![(a.hi, F::ONE), (b.hi, F::ONE), (carry, F::ONE)])?;
        let (hi, overflow) = self.split33(hi)?;
        let max = self.constant(u32::MAX as u64)?;
        Ok(U64 {
            lo: self.select(overflow, lo, max)?,
            hi: self.select(overflow, hi, max)?,
        })
    }

    pub(super) fn max_u64(&mut self, a: U64, b: U64) -> Result<U64, Error> {
        let aa = self.range_u64(a)?;
        let bb = self.range_u64(b)?;
        let mut less = ZERO;
        for (a, b) in aa.into_iter().zip(bb) {
            let both = self.mul(a, b)?;
            let equal = self.lin(vec![
                (ONE, F::ONE),
                (a, -F::ONE),
                (b, -F::ONE),
                (both, F::new(2)),
            ])?;
            let inherited = self.mul(equal, less)?;
            less = self.lin(vec![(b, F::ONE), (both, -F::ONE), (inherited, F::ONE)])?;
        }
        Ok(U64 {
            lo: self.select(less, a.lo, b.lo)?,
            hi: self.select(less, a.hi, b.hi)?,
        })
    }
}
