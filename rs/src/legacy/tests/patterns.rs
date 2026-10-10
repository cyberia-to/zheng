use super::*;

/// Real-trace guard for the pattern family: every universal row of a
/// real nox trace must SATISFY the universal instance (the commit gate).
/// This is the test that catches stale register wiring (the
/// pattern_quote bug class) for any pattern it covers — the old
/// add/sub/mul/eq/branch/inv encodings all fail it.
#[test]
fn real_traces_satisfy_pattern_family() {
    use crate::ccs::build_universal_steps_from_trace;

    let g = Goldilocks::new;
    // (tag, name): binary ops [tag [[1 a] [1 b]]] — field ops, eq, and
    // the multi-row bit patterns lt/xor/and/shl.
    for (tag, name) in [
        (5u64, "add"),
        (6, "sub"),
        (7, "mul"),
        (9, "eq"),
        (10, "lt"),
        (11, "xor"),
        (12, "and"),
        (14, "shl"),
    ] {
        for (a, b) in [(9u64, 4u64), (9, 9)] {
            let mut ar = Reduction::<1024>::new();
            let obj = ar.atom(g(1)).unwrap();
            let t = ar.atom(g(tag)).unwrap();
            let t1 = ar.atom(g(1)).unwrap();
            let va = ar.atom(g(a)).unwrap();
            let vb = ar.atom(g(b)).unwrap();
            let qa = ar.pair(t1, va).unwrap();
            let qb = ar.pair(t1, vb).unwrap();
            let body = ar.pair(qa, qb).unwrap();
            let formula = ar.pair(t, body).unwrap();
            let mut trace = VecTrace::default();
            nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
            nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
            assert!(trace.0.iter().any(|r| r.r()[0] == tag), "{name}: no tag row");
            let r = build_universal_steps_from_trace(&trace.0, &[]);
            assert!(r.is_ok(), "{name}({a},{b}): {r:?}");
        }
    }

    // unary ops [tag [1 a]]: inv (64-row Fermat chain), not (32-row).
    for (tag, name, a) in [(8u64, "inv", 7u64), (13, "not", 0xF0F0)] {
        let mut ar = Reduction::<1024>::new();
        let obj = ar.atom(g(1)).unwrap();
        let t = ar.atom(g(tag)).unwrap();
        let t1 = ar.atom(g(1)).unwrap();
        let va = ar.atom(g(a)).unwrap();
        let body = ar.pair(t1, va).unwrap();
        let formula = ar.pair(t, body).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        assert!(trace.0.iter().any(|r| r.r()[0] == tag), "{name}: no tag row");
        let r = build_universal_steps_from_trace(&trace.0, &[]);
        assert!(r.is_ok(), "{name}({a}): {r:?}");
    }

    // branch [4 [[1 t] [[1 10] [1 20]]]] — both arms
    for test in [0u64, 7] {
        let mut ar = Reduction::<1024>::new();
        let obj = ar.atom(g(1)).unwrap();
        let t4 = ar.atom(g(4)).unwrap();
        let t1 = ar.atom(g(1)).unwrap();
        let vt = ar.atom(g(test)).unwrap();
        let vy = ar.atom(g(10)).unwrap();
        let vn = ar.atom(g(20)).unwrap();
        let qt = ar.pair(t1, vt).unwrap();
        let qy = ar.pair(t1, vy).unwrap();
        let qn = ar.pair(t1, vn).unwrap();
        let arms = ar.pair(qy, qn).unwrap();
        let body = ar.pair(qt, arms).unwrap();
        let formula = ar.pair(t4, body).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        assert!(trace.0.iter().any(|r| r.r()[0] == 4), "no branch row");
        let r = build_universal_steps_from_trace(&trace.0, &[]);
        assert!(r.is_ok(), "branch(test={test}): {r:?}");
    }
}

/// Real-trace guard for call (16): a provider that answers, a check
/// formula that accepts (quotes 0), rows satisfy the universal instance
/// and the whole trace round-trips.
#[test]
fn real_call_trace_satisfies_and_roundtrips() {
    struct Answer;
    impl nox::LookProvider for Answer {
        fn look(&self, _c: Goldilocks, _n: Goldilocks, _k: Goldilocks) -> Option<Goldilocks> {
            None
        }
    }
    impl<const N: usize> nox::CallProvider<N> for Answer {
        fn provide(
            &self,
            reduction: &mut Reduction<N>,
            _tag: Goldilocks,
            _object: nox::Order,
        ) -> Option<nox::Order> {
            reduction.atom(Goldilocks::new(77))
        }
    }

    // [16 [[1 3] [1 0]]]: tag formula quotes 3, check formula quotes 0.
    let g = Goldilocks::new;
    let mut ar = Reduction::<1024>::new();
    let obj = ar.atom(g(1)).unwrap();
    let t16 = ar.atom(g(16)).unwrap();
    let t1 = ar.atom(g(1)).unwrap();
    let three = ar.atom(g(3)).unwrap();
    let zero = ar.atom(g(0)).unwrap();
    let tag_f = ar.pair(t1, three).unwrap();
    let check_f = ar.pair(t1, zero).unwrap();
    let body = ar.pair(tag_f, check_f).unwrap();
    let formula = ar.pair(t16, body).unwrap();
    let mut trace = VecTrace::default();
    nox::reduce(&mut ar, obj, formula, 1000, &Answer, &mut trace);
    nox::reduce(&mut ar, obj, formula, 1000, &Answer, &mut trace);
    assert!(trace.0.iter().any(|r| r.r()[0] == 16), "no call row");

    let stmt = zero_statement();
    let params = ProofParams::default();
    let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&tp, &stmt, &params).is_ok());
}

/// T-2: tampered eval_value causes verify() to reject.
#[test]
fn verify_rejects_tampered_eval_value() {
    let trace = quote_trace();
    let stmt = zero_statement();
    let params = ProofParams::default();
    let mut trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();

    // Flip the eval_value in the universal group's proof.
    let proof = &mut trace_proof.universal.proof;
    proof.eval_value = Goldilocks::new(proof.eval_value.as_u64().wrapping_add(1));

    assert!(verify(&trace_proof, &stmt, &params).is_err());
}

/// A proof cannot name its own instance: the error vector must have the
/// verifier's row count for the group's position.
#[test]
fn verify_rejects_foreign_group_layout() {
    let trace = quote_trace();
    let stmt = zero_statement();
    let params = ProofParams::default();
    let mut tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    tp.universal.accumulator.error_evals.truncate(1);
    assert!(matches!(verify(&tp, &stmt, &params), Err(VerifyError::GroupLayout)));
}
