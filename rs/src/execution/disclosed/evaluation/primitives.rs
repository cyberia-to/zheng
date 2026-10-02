use super::{
    super::memory::{Particle, Value, VerifiedNode},
    *,
};
use nebu::Goldilocks as F;

impl Evaluations<'_> {
    pub(super) fn noun(&self, id: u32) -> Result<&VerifiedNode, Error> {
        self.memory.get(id).map_err(|_| Error::Noun)
    }
    pub(super) fn pair(&self, id: u32) -> Result<(u32, u32), Error> {
        match self.noun(id)?.value() {
            Value::Pair { left, right } => Ok((left, right)),
            _ => Err(Error::Type),
        }
    }
    pub(super) fn atom(&self, id: u32) -> Result<u64, Error> {
        match self.noun(id)?.value() {
            Value::Atom(value) => Ok(value),
            _ => Err(Error::Type),
        }
    }
    pub(super) fn same(&self, a: u32, b: u32) -> Result<(), Error> {
        if self.noun(a)?.particle() == self.noun(b)?.particle() {
            Ok(())
        } else {
            Err(Error::Result)
        }
    }
    pub(super) fn result_atom(&self, result: u32, value: u64) -> Result<(), Error> {
        if self.atom(result).map_err(|_| Error::Result)? == value {
            Ok(())
        } else {
            Err(Error::Result)
        }
    }
    pub(super) fn hash_data(&self, result: u32, expected: Particle) -> Result<(), Error> {
        let (left, right) = self.pair(result).map_err(|_| Error::Result)?;
        let (h0, h1) = self.pair(left).map_err(|_| Error::Result)?;
        let (h2, h3) = self.pair(right).map_err(|_| Error::Result)?;
        for (id, value) in [h0, h1, h2, h3].into_iter().zip(expected) {
            self.result_atom(id, value)?;
        }
        Ok(())
    }
    pub(super) fn axis(&self, object: u32, address: u32, result: u32) -> Result<(), Error> {
        let address = self.atom(address).map_err(|_| Error::Formula)?;
        if address == 0 {
            return self.hash_data(result, self.noun(object)?.particle());
        }
        let mut current = object;
        let bits = 63 - address.leading_zeros();
        for bit in (0..bits).rev() {
            let (left, right) = self.pair(current)?;
            current = if (address >> bit) & 1 == 0 {
                left
            } else {
                right
            };
        }
        self.same(result, current)
    }
    pub(super) fn unary(&self, tag: u64, child: u32, result: u32) -> Result<(), Error> {
        if tag == 15 {
            let particle = self.noun(child)?.particle();
            let mut rate = [hemera::field::Goldilocks::ZERO; 8];
            for (to, from) in rate.iter_mut().zip(particle) {
                *to = hemera::field::Goldilocks::new(from);
            }
            let mut sponge = hemera::StepSponge::absorb(&rate);
            let mut state = [hemera::field::Goldilocks::ZERO; 16];
            while !sponge.done() {
                state = sponge.step();
            }
            return self.hash_data(result, std::array::from_fn(|i| state[i].as_canonical_u64()));
        }
        let value = self.atom(child)?;
        let output = match tag {
            8 if value == 0 => return Err(Error::InverseZero),
            8 => F::new(value).inv().as_u64(),
            13 if value < 1 << 32 => (!value) & u32::MAX as u64,
            _ => return Err(Error::Type),
        };
        self.result_atom(result, output)
    }
    pub(super) fn binary(&self, tag: u64, a: u32, b: u32, result: u32) -> Result<(), Error> {
        if tag == 3 {
            let (left, right) = self.pair(result).map_err(|_| Error::Result)?;
            self.same(left, a)?;
            return self.same(right, b);
        }
        if tag == 9 {
            let equal = self.noun(a)?.particle() == self.noun(b)?.particle();
            return self.result_atom(result, u64::from(!equal));
        }
        let (a, b) = (self.atom(a)?, self.atom(b)?);
        let output = match tag {
            5 => (F::new(a) + F::new(b)).as_u64(),
            6 => (F::new(a) - F::new(b)).as_u64(),
            7 => (F::new(a) * F::new(b)).as_u64(),
            10 => u64::from(a >= b),
            11 | 12 | 14 if a < 1 << 32 && b < 1 << 32 => match tag {
                11 => a ^ b,
                12 => a & b,
                _ if b >= 32 => 0,
                _ => (a << b) & u32::MAX as u64,
            },
            _ => return Err(Error::Type),
        };
        self.result_atom(result, output)
    }
}
