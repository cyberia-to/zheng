use super::*;
use lens::brakedown::Brakedown;
use lens::{Lens, MultilinearPoly};
use nox::{NullCalls, Reduction, VecTrace};

/// Two rows with tag=255 (unknown pattern). Under the universal step
/// instance no selector can be set for such a row — it is unprovable.
fn malformed_trace() -> VecTrace {
    let mut order = Reduction::<1024>::new();
    let obj = order.atom(Goldilocks::new(0)).unwrap();
    let tag_255 = order.atom(Goldilocks::new(255)).unwrap();
    let body = order.atom(Goldilocks::new(0)).unwrap();
    let formula = order.pair(tag_255, body).unwrap();
    let mut trace = VecTrace::default();
    nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
    nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
    trace
}

fn zero_statement() -> Statement {
    Statement {
        program_hash: [0u8; 32],
        input_hash: [0u8; 32],
        output_hash: [0u8; 32],
        focus_bound: 0,
    bbg_root: [0u8; 32],
    }
}

/// `[1 5]` reduced twice: two quote rows, the smallest provable trace.
fn quote_trace() -> VecTrace {
    let mut order = Reduction::<1024>::new();
    let obj = order.atom(Goldilocks::new(0)).unwrap();
    let t1 = order.atom(Goldilocks::new(1)).unwrap();
    let five = order.atom(Goldilocks::new(5)).unwrap();
    let formula = order.pair(t1, five).unwrap();
    let mut trace = VecTrace::default();
    nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
    nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
    assert_eq!(trace.0.len(), 2);
    trace
}

#[test]
fn commit_verify_roundtrip() {
    let trace = quote_trace();
    let stmt = zero_statement();
    let params = ProofParams::default();
    let trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    assert_eq!(trace_proof.group_count(), 1, "no openings: universal group only");
    assert!(verify(&trace_proof, &stmt, &params).is_ok());
}

/// An unknown pattern tag has no selector column: the row is
/// unprovable and commit names it.
#[test]
fn commit_rejects_unknown_pattern_tag() {
    let trace = malformed_trace();
    let err = commit(&trace, &[], &[], &[], &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(CommitError::StepUnsatisfied(0))), "{err:?}");
}

// ── helpers for manual witness construction ──────────────────────────────

/// A universal row of pattern `tag` with the given register values.
fn row(tag: u64, vals: &[(usize, u64)]) -> CCSWitness {
    let mut v = vec![(crate::ccs::reg_t(0), tag)];
    v.extend_from_slice(vals);
    crate::ccs::universal::test_witness(&v)
}

/// Fold universal rows and close them as a one-group TraceProof.
fn fold_universal(rows: &[CCSWitness]) -> ProofGroup {
    let instance = universal_ccs();
    let mut acc = Accumulator::blank(instance);
    let mut transcript = Transcript::new_v1();
    for w in rows {
        assert!(instance.is_satisfied_by(w));
        crate::folding::fold_step(&mut acc, instance, w, &mut transcript).unwrap();
    }
    let proof = decide(&acc, &zero_statement(), &ProofParams::default()).unwrap();
    ProofGroup { proof, accumulator: acc }
}

#[test]
fn fold_add_multi_step_commit_verify() {
    use crate::ccs::reg_t;
    let rows = [
        row(5, &[(reg_t(4), 3), (reg_t(5), 4), (reg_t(6), 7)]),
        row(5, &[(reg_t(4), 10), (reg_t(5), 20), (reg_t(6), 30)]),
        row(5, &[(reg_t(4), 1), (reg_t(5), 1), (reg_t(6), 2)]),
    ];
    let universal = fold_universal(&rows);
    assert_eq!(universal.accumulator.step_count, 3);
    let trace_proof = TraceProof { universal, binding: None };
    assert!(verify(&trace_proof, &zero_statement(), &ProofParams::default()).is_ok());
}

#[test]
fn fold_mixed_patterns_commit_verify() {
    use crate::ccs::reg_t;
    // add, mul and quote rows in one accumulator — the point of the
    // universal instance. Degree-2+ terms leave genuine cross-term
    // error; Spartan proves/verifies against the accumulated error.
    let rows = [
        row(7, &[(reg_t(4), 6), (reg_t(5), 7), (reg_t(6), 42)]),
        row(5, &[(reg_t(4), 2), (reg_t(5), 5), (reg_t(6), 7)]),
        row(1, &[(reg_t(4), 9), (reg_t(7), 9)]),
    ];
    let universal = fold_universal(&rows);
    assert_eq!(universal.accumulator.step_count, 3);
    let trace_proof = TraceProof { universal, binding: None };
    assert!(verify(&trace_proof, &zero_statement(), &ProofParams::default()).is_ok());
}

fn make_poly(values: &[u64]) -> Vec<Goldilocks> {
    values.iter().map(|&v| Goldilocks::new(v)).collect()
}

#[test]
fn open_verify_eval_roundtrip_small() {
    // 2-variable polynomial: f(x0,x1) evals [3, 7, 11, 19]
    let poly = make_poly(&[3, 7, 11, 19]);
    let point = vec![Goldilocks::new(2), Goldilocks::new(5)];
    let params = ProofParams::default();

    let (commitment, opening) = open(&poly, &point, &params).unwrap();

    // Compute expected value via multilinear extension.
    let mp = MultilinearPoly::new(poly.clone());
    let expected = mp.evaluate(&point);

    verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
}

#[test]
fn open_verify_eval_roundtrip_six_vars() {
    // 64 elements — the witness size used by SuperSpartan.
    let poly: Vec<Goldilocks> = (0u64..64).map(Goldilocks::new).collect();
    let point: Vec<Goldilocks> = (1u64..=6).map(Goldilocks::new).collect();
    let params = ProofParams::default();

    let (commitment, opening) = open(&poly, &point, &params).unwrap();
    let mp = MultilinearPoly::new(poly);
    let expected = mp.evaluate(&point);

    verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
}

#[test]
fn open_pads_short_poly_to_point_size() {
    // poly has 2 elements but point has 3 variables → padded to 8 elements.
    let poly = make_poly(&[5, 13]);
    let point = vec![Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO];
    let params = ProofParams::default();

    let (commitment, opening) = open(&poly, &point, &params).unwrap();
    // f(0,0,0) = poly[0] = 5 (zero-padding preserves this).
    let expected = Goldilocks::new(5);
    verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
}

#[test]
fn open_larger_than_witness_size() {
    // 256 elements (2^8) — larger than the 64-element witness vector.
    let poly: Vec<Goldilocks> = (0u64..256).map(|v| Goldilocks::new(v * 3 + 1)).collect();
    let point: Vec<Goldilocks> = (0u64..8).map(|v| Goldilocks::new(v + 2)).collect();
    let params = ProofParams::default();

    let (commitment, opening) = open(&poly, &point, &params).unwrap();
    let mp = MultilinearPoly::new(poly);
    let expected = mp.evaluate(&point);
    verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
}

#[test]
fn verify_eval_wrong_value_rejected() {
    let poly = make_poly(&[1, 2, 3, 4]);
    let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
    let params = ProofParams::default();

    let (commitment, opening) = open(&poly, &point, &params).unwrap();
    let wrong = Goldilocks::new(999);
    assert!(verify_eval(&commitment, &point, wrong, &opening, &params).is_err());
}

#[test]
fn open_zero_vars_rejected() {
    let poly = make_poly(&[42]);
    let params = ProofParams::default();
    assert!(open(&poly, &[], &params).is_err());
}

#[test]
fn open_poly_longer_than_point_rejected() {
    // poly has 8 elements but point has 2 vars → target = 4 < 8.
    let poly = make_poly(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
    let params = ProofParams::default();
    assert!(open(&poly, &point, &params).is_err());
}

/// Fold a hand-built eq step sequence as the binding group next to a
/// satisfied universal group — the route of a malicious prover who
/// bypasses commit()'s strictness gates AND `fold_step`'s own
/// per-witness satisfiability gate (`crate::folding::fold::fold_step_unchecked`,
/// test-only). These tests exist to pin the verify()-time zero-error
/// rule as a backstop independent of the fold-time gate — the fold-time
/// gate alone (reachable via the public `fold_step`/`commit()`) already
/// rejects an unsatisfied linear step before it can ever reach here; see
/// `folding::fold::tests` for that regression.
fn prove_raw_linear_steps(steps: &[(CCSInstance, CCSWitness)]) -> TraceProof {
    use crate::ccs::reg_t;
    use crate::folding::fold::fold_step_unchecked;

    let universal_acc = fold_all(
        universal_ccs(),
        &[row(1, &[(reg_t(4), 5), (reg_t(7), 5)])],
    )
    .unwrap();
    let eq = eq_instance();
    let mut binding_acc = Accumulator::blank(&eq);
    let mut transcript = Transcript::new_v1();
    for (_, w) in steps {
        fold_step_unchecked(&mut binding_acc, &eq, w, &mut transcript).unwrap();
    }
    let linkage = linkage_digest(&[
        &universal_acc.witness_commitment,
        &binding_acc.witness_commitment,
    ]);
    let stmt = zero_statement();
    let params = ProofParams::default();
    let close = |acc: Accumulator| ProofGroup {
        proof: run_decide(&acc, &stmt, &linkage, &params).unwrap(),
        accumulator: acc,
    };
    TraceProof { universal: close(universal_acc), binding: Some(close(binding_acc)) }
}

mod axis;
mod e2e;
mod hash;
mod look;
mod patterns;
