use super::*;

// ── prover-active axis: trace binding harness ────────────────────────────

/// CallProvider that reports a fixed Lens commitment for every object.
/// The executor writes its limbs into r[11]-r[14] (prover-active mode),
/// arming the axis trace bindings in build_axis_steps_from_trace.
struct AxisProver {
    commitment: [u8; 32],
}

impl nox::LookProvider for AxisProver {
    fn look(
        &self,
        _commitment: Goldilocks,
        _namespace: Goldilocks,
        _key: Goldilocks,
    ) -> Option<Goldilocks> {
        None
    }
}

impl<const N: usize> nox::CallProvider<N> for AxisProver {
    fn provide(
        &self,
        _reduction: &mut Reduction<N>,
        _tag: Goldilocks,
        _object: nox::Order,
    ) -> Option<nox::Order> {
        None
    }

    fn axis_commitment(&self, _object_id: u64) -> Option<[u8; 32]> {
        Some(self.commitment)
    }
}

/// Run `axis(s, 5)` twice over s = [[a b] [c d]] with a prover-active
/// provider. The noun polynomial's evaluations are the particle ids at
/// depth-2 addresses 4..8, so its value at axis_eval_point(5) is the
/// result particle in r[7]. `tweak` perturbs the unopened leaves,
/// deriving a distinct commitment with the same value at the opened
/// point (used to build a second, different-but-valid proof).
fn prover_active_axis_setup(tweak: u64) -> (VecTrace, Vec<AxisOpening>) {
    use lens::Transcript as LensTranscript;

    let g = Goldilocks::new;
    let mut order = Reduction::<1024>::new();
    let a = order.atom(g(11)).unwrap();
    let b = order.atom(g(22)).unwrap();
    let c = order.atom(g(33)).unwrap();
    let d = order.atom(g(44)).unwrap();
    let left = order.pair(a, b).unwrap();
    let right = order.pair(c, d).unwrap();
    let s = order.pair(left, right).unwrap();
    let tag0 = order.atom(g(0)).unwrap();
    let addr = order.atom(g(5)).unwrap();
    let axis_f = order.pair(tag0, addr).unwrap();

    // Noun polynomial: particle ids at addresses 4, 5, 6, 7 (LSB-first
    // index = low address bits). Address 5 → index 1.
    let ids = [a as u64, b as u64, c as u64, d as u64];
    let evals: Vec<Goldilocks> = ids
        .iter()
        .enumerate()
        .map(|(i, &v)| if i == 1 { g(v) } else { g(v + tweak) })
        .collect();
    let poly = MultilinearPoly::new(evals);
    let commitment = Brakedown::commit(&poly);
    let prover = AxisProver {
        commitment: commitment.as_bytes().try_into().unwrap(),
    };

    let mut trace = VecTrace::default();
    nox::reduce(&mut order, s, axis_f, 100, &prover, &mut trace);
    nox::reduce(&mut order, s, axis_f, 99, &prover, &mut trace);
    assert_eq!(trace.0.len(), 2);
    assert_eq!(trace.0[0].r()[7], b as u64, "axis 5 = tail(head(s)) = b");
    assert_ne!(trace.0[0].r()[11], 0, "prover-active row carries the commitment");

    let point = crate::ccs::axis_eval_point(5);
    let value = poly.evaluate(&point);
    assert_eq!(
        value,
        g(b as u64),
        "noun polynomial at the address point is the result particle"
    );

    let openings = (0..2)
        .map(|_| {
            let mut lt = LensTranscript::new(b"e2e-axis-prover");
            AxisOpening {
                commitment,
                point: point.clone(),
                value,
                opening: Brakedown::open(&poly, &point, &mut lt),
                transcript_seed: b"e2e-axis-prover".to_vec(),
            }
        })
        .collect();
    (trace, openings)
}

#[test]
fn authenticated_recursive_openings_are_refused_until_constrained() {
    let (trace, openings) = prover_active_axis_setup(0);
    assert!(matches!(
        commit(&trace, &[], &openings, &[], &zero_statement(), &ProofParams::default()),
        Err(CommitError::UnsupportedRecursiveOpening)
    ));
}


/// Negative: a valid opening for a DIFFERENT commitment than the trace
/// carries (r11-r14) must be rejected — the swapped-opening attack.
#[test]
fn commit_rejects_swapped_axis_commitment() {
    let (trace_p, _) = prover_active_axis_setup(0);
    let (_, openings_q) = prover_active_axis_setup(7);
    let stmt = zero_statement();
    let params = ProofParams::default();
    let err = commit(&trace_p, &[], &openings_q, &[], &stmt, &params);
    assert!(matches!(err, Err(CommitError::UnsupportedRecursiveOpening)));
}

/// Negative: an opening whose claimed value differs from the result
/// particle nox produced (r7) must be rejected — the forged-result attack.
#[test]
fn commit_rejects_forged_axis_result() {
    let (trace, mut openings) = prover_active_axis_setup(0);
    openings[0].value += Goldilocks::ONE;
    let stmt = zero_statement();
    let params = ProofParams::default();
    let err = commit(&trace, &[], &openings, &[], &stmt, &params);
    assert!(matches!(err, Err(CommitError::UnsupportedRecursiveOpening)));
}

/// Negative: a corrupted opening proof (tampered final_poly byte) must be
/// rejected — the tampered-opening attack.
#[test]
fn commit_rejects_tampered_axis_opening() {
    let (trace, mut openings) = prover_active_axis_setup(0);
    if let Opening::TensorMerkle { row_combination, .. } = &mut openings[0].opening {
        row_combination[0] ^= 1;
    } else {
        panic!("current Brakedown opening must be TensorMerkle");
    }
    let stmt = zero_statement();
    let params = ProofParams::default();
    let err = commit(&trace, &[], &openings, &[], &stmt, &params);
    assert!(matches!(err, Err(CommitError::UnsupportedRecursiveOpening)));
}


/// Regression: the PUBLIC folding path (`fold_all`, which calls the
/// gated `fold_step`) now refuses an unsatisfied binding step before it
/// is folded in at all — a caller no longer needs `verify()`'s zero-error
/// rule to catch this; `fold_step` itself does. This is the fold-time
/// half of the fix; `verify_rejects_folded_wrong_commitment_binding` and
/// its siblings below pin the verify-time backstop for the (now
/// unreachable via the public API) case where the fold-time gate is
/// ALSO bypassed (`fold_step_unchecked`, test-only).
#[test]
fn fold_all_rejects_unsatisfied_eq_step() {
    use crate::ccs::eq_step;

    let eq = eq_instance();
    let (_, bad_step) = eq_step(Goldilocks::new(1), Goldilocks::new(2));
    let err = fold_all(&eq, &[bad_step]);
    assert!(matches!(err, Err(CommitError::TraceOverflow)), "{err:?}");
}

/// Negative: a prover who folds a commitment-binding step for the WRONG
/// commitment (valid opening of poly Q claimed against commitment P) and
/// bypasses the commit gate is caught at verify time — linear groups must
/// carry zero error.
#[test]
fn verify_rejects_folded_wrong_commitment_binding() {
    use crate::ccs::verifier_steps::read_limb;
    use crate::ccs::{eq_step, verifier_steps};
    use lens::Transcript as LensTranscript;

    let poly_q = MultilinearPoly::new(make_poly(&[9, 8, 7, 6]));
    let commitment_q = Brakedown::commit(&poly_q);
    let commitment_p = Brakedown::commit(&MultilinearPoly::new(make_poly(&[1, 2, 3, 4])));
    let point = vec![Goldilocks::ZERO, Goldilocks::ONE];
    let value = poly_q.evaluate(&point);
    let opening = {
        let mut lt = LensTranscript::new(b"raw-axis");
        Brakedown::open(&poly_q, &point, &mut lt)
    };

    // Internally-valid opening steps for Q…
    let mut steps = verifier_steps(&commitment_q, &point, value, &opening);
    // …plus the binding the trace would demand: Q's limbs against P's
    // registers. Unsatisfied — and folded in anyway.
    for k in 0..4 {
        steps.push(eq_step(
            read_limb(commitment_q.as_bytes(), k),
            read_limb(commitment_p.as_bytes(), k),
        ));
    }

    let trace_proof = prove_raw_linear_steps(&steps);
    let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
}

/// Negative: a prover who folds a value-binding step claiming a forged
/// result (opened value vs. a different r7) and bypasses the commit gate
/// is caught at verify time.
#[test]
fn verify_rejects_folded_forged_result_binding() {
    use crate::ccs::{eq_step, verifier_steps};
    use lens::Transcript as LensTranscript;

    let poly = MultilinearPoly::new(make_poly(&[5, 15, 25, 35]));
    let commitment = Brakedown::commit(&poly);
    let point = vec![Goldilocks::ONE, Goldilocks::ZERO];
    let value = poly.evaluate(&point);
    let opening = {
        let mut lt = LensTranscript::new(b"raw-axis-forge");
        Brakedown::open(&poly, &point, &mut lt)
    };

    let mut steps = verifier_steps(&commitment, &point, value, &opening);
    // Value binding against a forged result particle.
    let forged_r7 = value + Goldilocks::ONE;
    steps.push(eq_step(value, forged_r7));

    let trace_proof = prove_raw_linear_steps(&steps);
    let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
}

/// The zero-error rule accepts honest linear folds: the same raw route
/// with all steps satisfied verifies.
#[test]
fn verify_accepts_nonempty_satisfied_linear_bindings() {
    use crate::ccs::eq_step;
    let steps: Vec<_> = [5, 15, 25, 35].into_iter()
        .map(|v| eq_step(Goldilocks::new(v), Goldilocks::new(v))).collect();
    assert_eq!(steps.len(), 4);
    let trace_proof = prove_raw_linear_steps(&steps);
    assert_eq!(trace_proof.binding.as_ref().unwrap().accumulator.step_count, 4);
    assert!(verify(&trace_proof, &zero_statement(), &ProofParams::default()).is_ok());
}
