use super::*;
impl Builder {
    pub(super) fn bits(&mut self, v: &Value, n: usize) -> Result<Vec<Value>, RelationError> {
        let source = self.linear(v)?;
        let mut bits = vec![];
        let mut sum = vec![];
        for k in 0..n {
            let i = self.wire(Op::Bit(source.clone(), k));
            self.rows
                .push((vec![(i, F::ONE)], vec![(0, F::ONE), (i, -F::ONE)], vec![]));
            sum.push((i, F::new(1u64 << k)));
            bits.push(Value::Wire(i));
        }
        self.rows.push((sum, vec![(0, F::ONE)], source));
        if n == 64 {
            // Goldilocks p = 0xffffffff00000001. A canonical u64 has
            // high32 != MAX, or (high32 == MAX AND low32 == 0).
            let mut all_high = Value::Constant(F::ONE);
            for bit in &bits[32..] {
                all_high = self.product(self.linear(&all_high)?, self.linear(bit)?);
            }
            let low = self.pack(&bits[..32])?;
            self.rows
                .push((self.linear(&all_high)?, self.linear(&low)?, vec![]));
        }
        Ok(bits)
    }
    pub(super) fn pack(&mut self, bits: &[Value]) -> Result<Value, RelationError> {
        let mut l = vec![];
        for (k, b) in bits.iter().enumerate() {
            l.extend(
                self.linear(b)?
                    .into_iter()
                    .map(|(i, c)| (i, c * F::new(1u64 << k))),
            );
        }
        Ok(self.alloc_linear(l))
    }
    pub(super) fn less_than(&mut self, a: &Value, b: &Value) -> Result<Value, RelationError> {
        let ab = self.bits(a, 64)?;
        let bb = self.bits(b, 64)?;
        let one = Value::Constant(F::ONE);
        let mut lt = Value::Constant(F::ZERO);
        for (a, b) in ab.iter().zip(bb.iter()) {
            let both = self.product(self.linear(a)?, self.linear(b)?);
            let equal = self.add(&one, a, true)?;
            let equal = self.add(&equal, b, true)?;
            let twice = self.add(&both, &both, false)?;
            let equal = self.add(&equal, &twice, false)?;
            let lower = self.product(self.linear(&equal)?, self.linear(&lt)?);
            let at_bit = self.add(b, &both, true)?;
            lt = self.add(&at_bit, &lower, false)?;
        }
        self.add(&one, &lt, true) // nox boolean: zero means less than
    }
    pub(super) fn word_binary(
        &mut self,
        tag: u64,
        a: &Value,
        b: &Value,
    ) -> Result<Value, RelationError> {
        let ab = self.bits(a, 32)?;
        let bb = self.bits(b, 32)?;
        let mut out = vec![];
        if tag == 14 {
            // Barrel shifter, constrained at each of the five low shift bits.
            let mut shifted = ab;
            for (k, bit) in bb[..5].iter().enumerate() {
                let mut next = vec![];
                for i in 0..32 {
                    let source = if i >= 1 << k {
                        shifted[i - (1 << k)].clone()
                    } else {
                        Value::Constant(F::ZERO)
                    };
                    next.push(self.mux(bit, &shifted[i], &source)?);
                }
                shifted = next;
            }
            let high = self.pack(&bb[5..])?;
            let too_large = self.nonzero(&high)?;
            let in_range = self.add(&Value::Constant(F::ONE), &too_large, true)?;
            for bit in shifted {
                out.push(self.product(self.linear(&in_range)?, self.linear(&bit)?));
            }
        } else {
            for (a, b) in ab.iter().zip(bb.iter()) {
                let both = self.product(self.linear(a)?, self.linear(b)?);
                out.push(if tag == 12 {
                    both
                } else {
                    let sum = self.add(a, b, false)?;
                    let twice = self.add(&both, &both, false)?;
                    self.add(&sum, &twice, true)?
                });
            }
        }
        self.pack(&out)
    }
}
