//! The Fiat–Shamir interface the sumcheck provers share: lens's byte
//! transcript (every profile but recursion) and the field-native duplex of
//! the recursion profile (`recursion::sponge`) both implement it, so one
//! prover serves both.

use nebu::Fp3;

pub trait FiatShamir {
    fn absorb_fp3(&mut self, x: Fp3);
    fn squeeze_fp3(&mut self) -> Fp3;
    fn absorb_fp3_slice(&mut self, xs: &[Fp3]) {
        for &x in xs {
            self.absorb_fp3(x);
        }
    }
}

impl FiatShamir for lens::Transcript {
    fn absorb_fp3(&mut self, x: Fp3) {
        lens::Transcript::absorb_fp3(self, x);
    }
    fn squeeze_fp3(&mut self) -> Fp3 {
        lens::Transcript::squeeze_fp3(self)
    }
    fn absorb_fp3_slice(&mut self, xs: &[Fp3]) {
        lens::Transcript::absorb_fp3_slice(self, xs);
    }
}
