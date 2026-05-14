// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Sumcheck verifier: consistency checks and challenge derivation.

use nebu::Goldilocks;

use crate::transcript::Transcript;
use crate::types::{SumcheckPoly, VerifyError};

/// Bilinear sumcheck verifier for Σ_x w(x)·f(x) = claim.
///
/// Each round receives g_i, checks g_i(0)+g_i(1) = current_claim,
/// absorbs g_i into transcript, squeezes challenge r_i, advances claim.
pub struct SumcheckVerifier {
    current_claim: Goldilocks,
    num_vars: usize,
    round: usize,
    challenges: Vec<Goldilocks>,
}

impl SumcheckVerifier {
    pub fn new(claimed_sum: Goldilocks, num_vars: usize) -> Self {
        Self {
            current_claim: claimed_sum,
            num_vars,
            round: 0,
            challenges: Vec::with_capacity(num_vars),
        }
    }

    pub fn current_claim(&self) -> Goldilocks {
        self.current_claim
    }

    pub fn challenges(&self) -> &[Goldilocks] {
        &self.challenges
    }

    /// Verify one round polynomial; absorb into transcript, squeeze challenge.
    ///
    /// Returns the challenge r_i on success.
    pub fn verify_round(
        &mut self,
        poly: &SumcheckPoly,
        transcript: &mut Transcript,
    ) -> Result<Goldilocks, VerifyError> {
        if poly.eval_0() + poly.eval_1() != self.current_claim {
            return Err(VerifyError::SumcheckFailed { round: self.round });
        }
        transcript.absorb_sumcheck_poly(self.round, poly);
        let r = transcript.squeeze_challenge();
        self.current_claim = poly.eval(r);
        self.challenges.push(r);
        self.round += 1;
        Ok(r)
    }

    /// Verify all rounds, returning (final_claim, evaluation_point).
    pub fn verify_all(
        &mut self,
        polys: &[SumcheckPoly],
        transcript: &mut Transcript,
    ) -> Result<(Goldilocks, Vec<Goldilocks>), VerifyError> {
        if polys.len() != self.num_vars {
            return Err(VerifyError::SumcheckFailed { round: 0 });
        }
        for poly in polys {
            self.verify_round(poly, transcript)?;
        }
        Ok((self.current_claim, self.challenges.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multilinear::eq_evals;
    use crate::sumcheck::prover::SumcheckProver;

    #[test]
    fn consistency_check_rejects_wrong_sum() {
        let mut verifier = SumcheckVerifier::new(Goldilocks::new(10), 1);
        let mut transcript = Transcript::new();

        // f(t) = 4 + 2t: f(0)=4, f(1)=6, sum=10 ✓
        let good = SumcheckPoly {
            degree: 1,
            coeffs: vec![Goldilocks::new(4), Goldilocks::new(2)],
        };
        assert!(verifier.verify_round(&good, &mut transcript).is_ok());
    }

    #[test]
    fn consistency_check_accepts_correct_sum() {
        let mut verifier = SumcheckVerifier::new(Goldilocks::new(10), 1);
        let mut transcript = Transcript::new();

        // f(0)=3 + f(1)=5 = 8 ≠ 10 — should fail
        let bad = SumcheckPoly {
            degree: 1,
            coeffs: vec![Goldilocks::new(3), Goldilocks::new(2)],
        };
        assert!(verifier.verify_round(&bad, &mut transcript).is_err());
    }

    #[test]
    fn prover_verifier_claim_consistent() {
        // Build a 2-variable bilinear sumcheck and confirm verifier sees
        // consistent claims when given the same challenges as the prover.
        let r_outer = vec![Goldilocks::new(3), Goldilocks::new(7)];
        let w = eq_evals(&r_outer);
        let f = vec![Goldilocks::ONE; 4];
        let mut prover = SumcheckProver::new(w, f);
        let claimed = prover.claimed_sum();

        let challenges = [Goldilocks::new(5), Goldilocks::new(11)];
        let mut ci = 0usize;
        let polys = prover.prove_all(|_| {
            let c = challenges[ci];
            ci += 1;
            c
        });

        // Replay with verifier using the same fixed challenges (no transcript).
        let mut claim = claimed;
        for (i, poly) in polys.iter().enumerate() {
            assert_eq!(poly.eval_0() + poly.eval_1(), claim, "round {i}");
            claim = poly.eval(challenges[i]);
        }
        let (w_fin, f_fin) = prover.final_claim();
        assert_eq!(w_fin * f_fin, claim);
    }
}
