//! Native unsigned ordering and32-bit word operations, with active range checks.
use super::{build::Builder, *};
impl Builder {
    fn word_bits(&mut self, value: Wire, active: Wire) -> Result<[Wire; 32], Error> {
        // Mask before decomposing: inactive words have unique zero bits; active
        // values outside U32 cannot satisfy exact (nonwrapping) recomposition.
        let masked = self.mul(active, value)?;
        let mut bits = [ZERO; 32];
        let mut sum = vec![(masked, -F::ONE)];
        for (k, b) in bits.iter_mut().enumerate() {
            *b = self.alloc(Op::Bit(masked, k))?;
            self.zero_product(*b, vec![(ONE, F::ONE), (*b, -F::ONE)])?;
            sum.push((*b, F::new(1u64 << k)));
        }
        self.zero_product(ONE, sum)?;
        Ok(bits)
    }
    fn pack_word(&mut self, bits: &[Wire]) -> Result<Wire, Error> {
        self.lin(
            bits.iter()
                .enumerate()
                .map(|(k, &b)| (b, F::new(1u64 << k)))
                .collect(),
        )
    }
    pub fn unsigned_less(&mut self, a: Wire, b: Wire) -> Result<Wire, Error> {
        let a = self.canonical_bits(a)?;
        let b = self.canonical_bits(b)?;
        let mut less = ZERO;
        // Process low to high: a differing higher bit supersedes the previous
        // comparison; an equal bit preserves it.
        for (a, b) in a.into_iter().zip(b) {
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
        self.lin(vec![(ONE, F::ONE), (less, -F::ONE)]) // native Bool:0 is true
    }
    pub fn word_not(&mut self, value: Wire, active: Wire) -> Result<Wire, Error> {
        let bits = self.word_bits(value, active)?;
        let value = self.pack_word(&bits)?;
        self.lin(vec![(ONE, F::new(u32::MAX as u64)), (value, -F::ONE)])
    }
    pub fn word_binary(&mut self, tag: u64, a: Wire, b: Wire, active: Wire) -> Result<Wire, Error> {
        let a = self.word_bits(a, active)?;
        let b = self.word_bits(b, active)?;
        let mut out = [ZERO; 32];
        if tag == 14 {
            let mut shifted = a;
            for (k, bit) in b[..5].iter().enumerate() {
                for i in 0..32 {
                    let source = if i >= 1 << k {
                        shifted[i - (1 << k)]
                    } else {
                        ZERO
                    };
                    out[i] = self.select(*bit, shifted[i], source)?;
                }
                shifted = out;
            }
            let high = self.pack_word(&b[5..])?;
            let outside = self.inverse_or_zero(high)?.1;
            let inside = self.lin(vec![(ONE, F::ONE), (outside, -F::ONE)])?;
            for i in 0..32 {
                out[i] = self.mul(inside, shifted[i])?;
            }
        } else {
            for i in 0..32 {
                let both = self.mul(a[i], b[i])?;
                out[i] = if tag == 12 {
                    both
                } else {
                    self.lin(vec![(a[i], F::ONE), (b[i], F::ONE), (both, -F::new(2))])?
                };
            }
        }
        self.pack_word(&out)
    }
}
