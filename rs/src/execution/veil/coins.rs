//! The prover's randomness: a hemera keyed XOF seeded from the OS (or a
//! fixed seed in tests), read as uniform field elements by rejection.

use hemera::{Hasher, OutputReader};
use nebu::{Fp3, Goldilocks};

const DOMAIN: &[u8] = b"zheng-veil-coins-v1";

pub(crate) struct Coins {
    reader: OutputReader,
}

impl Coins {
    /// Fresh OS entropy.
    pub fn os() -> Result<Self, String> {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| "veil: entropy unavailable".to_string())?;
        Ok(Self::seeded(*seed))
    }

    /// A deterministic stream (tests and differential runs).
    pub fn seeded(seed: [u8; 32]) -> Self {
        let mut h = Hasher::new_keyed(&seed);
        h.update(DOMAIN);
        Self {
            reader: h.finalize_xof(),
        }
    }

    /// A uniform Goldilocks element.
    pub fn base(&mut self) -> Goldilocks {
        loop {
            let mut b = [0u8; 8];
            self.reader.fill(&mut b);
            let v = u64::from_le_bytes(b);
            if v < nebu::field::P {
                return Goldilocks::new(v);
            }
        }
    }

    pub fn bases(&mut self, n: usize) -> Vec<Goldilocks> {
        (0..n).map(|_| self.base()).collect()
    }

    /// A uniform Fp3 element.
    pub fn ext(&mut self) -> Fp3 {
        Fp3::new(self.base(), self.base(), self.base())
    }
}
