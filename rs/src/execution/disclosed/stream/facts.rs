use super::{
    super::memory::{Particle, Value, View},
    types::Output,
    *,
};
use nebu::Goldilocks as F;

pub(super) fn particle(memory: &View<'_>, id: u32) -> Result<Particle, Error> {
    memory
        .get(id)
        .map(|n| n.particle())
        .map_err(|_| Error::Noun)
}
pub(super) fn pair(memory: &View<'_>, id: u32) -> Result<(u32, u32), Error> {
    match memory.get(id).map_err(|_| Error::Noun)?.value() {
        Value::Pair { left, right } => Ok((left, right)),
        _ => Err(Error::Shape),
    }
}
pub(super) fn atom(memory: &View<'_>, id: u32) -> Result<u64, Error> {
    match memory.get(id).map_err(|_| Error::Noun)?.value() {
        Value::Atom(value) => Ok(value),
        _ => Err(Error::Type),
    }
}

impl VerifiedResult {
    pub(super) fn read(memory: &View<'_>, id: u32) -> Result<Self, Error> {
        let node = memory.get(id).map_err(|_| Error::Noun)?;
        let value = match node.value() {
            Value::Atom(value) => ResultValue::Atom(value),
            Value::Pair { left, right } => ResultValue::Pair {
                left: particle(memory, left)?,
                right: particle(memory, right)?,
            },
        };
        Ok(Self {
            particle: node.particle(),
            value,
        })
    }
    pub(super) fn atom(self) -> Result<u64, Error> {
        match self.value {
            ResultValue::Atom(value) => Ok(value),
            _ => Err(Error::Type),
        }
    }
}

impl Output {
    pub(super) fn check(self, memory: &View<'_>, id: u32) -> Result<VerifiedResult, Error> {
        let result = VerifiedResult::read(memory, id)?;
        let good = match self {
            Self::Equal(expected) => result.particle == expected,
            Self::Atom(value) => result.value == ResultValue::Atom(value),
            Self::Pair(left, right) => result.value == ResultValue::Pair { left, right },
            Self::HashData(expected) => {
                let (left, right) = pair(memory, id).map_err(|_| Error::Output)?;
                let (h0, h1) = pair(memory, left).map_err(|_| Error::Output)?;
                let (h2, h3) = pair(memory, right).map_err(|_| Error::Output)?;
                let mut actual = [0u64; 4];
                for (out, noun) in actual.iter_mut().zip([h0, h1, h2, h3]) {
                    *out = atom(memory, noun).map_err(|_| Error::Output)?;
                }
                actual == expected
            }
        };
        if good { Ok(result) } else { Err(Error::Output) }
    }

    pub(super) fn axis(memory: &View<'_>, object: u32, address: u32) -> Result<Self, Error> {
        let address = atom(memory, address)?;
        if address == 0 {
            return Ok(Self::HashData(particle(memory, object)?));
        }
        let mut current = object;
        for bit in (0..63 - address.leading_zeros()).rev() {
            let (left, right) = pair(memory, current)?;
            current = if (address >> bit) & 1 == 0 {
                left
            } else {
                right
            };
        }
        Ok(Self::Equal(particle(memory, current)?))
    }

    pub(super) fn unary(tag: u64, child: VerifiedResult) -> Result<Self, Error> {
        if tag == 15 {
            let mut rate = [hemera::field::Goldilocks::ZERO; 8];
            for (to, from) in rate.iter_mut().zip(child.particle) {
                *to = hemera::field::Goldilocks::new(from);
            }
            let mut sponge = hemera::StepSponge::absorb(&rate);
            let mut state = [hemera::field::Goldilocks::ZERO; 16];
            while !sponge.done() {
                state = sponge.step();
            }
            return Ok(Self::HashData(std::array::from_fn(|i| {
                state[i].as_canonical_u64()
            })));
        }
        let value = child.atom()?;
        Ok(Self::Atom(match tag {
            8 if value == 0 => return Err(Error::InverseZero),
            8 => F::new(value).inv().as_u64(),
            13 if value < 1 << 32 => (!value) & u32::MAX as u64,
            _ => return Err(Error::Type),
        }))
    }

    pub(super) fn binary(tag: u64, a: VerifiedResult, b: VerifiedResult) -> Result<Self, Error> {
        if tag == 3 {
            return Ok(Self::Pair(a.particle, b.particle));
        }
        if tag == 9 {
            return Ok(Self::Atom(u64::from(a.particle != b.particle)));
        }
        let (a, b) = (a.atom()?, b.atom()?);
        Ok(Self::Atom(match tag {
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
        }))
    }
}
