use super::*;

// ── end-to-end tests ─────────────────────────────────────────────────────


/// E2E: trace with Poseidon2 hash operation → hash_aux drives particle CCS.
///
/// formula = [15, [1, s]] hashes subject s, producing 25 rows (tag=15)
/// plus 1 quote row (tag=1) — 26 total.  HashAux supplies the rate (the
/// structural digest of s) so build_hash_steps_from_trace can replay the
/// sponge and recover capacity elements.
#[test]
fn e2e_hash_accumulator_roundtrip() {
    let mut order = Reduction::<1024>::new();
    let s = order.atom(Goldilocks::new(42)).unwrap();
    let tag1 = order.atom(Goldilocks::new(1)).unwrap();
    let tag15 = order.atom(Goldilocks::new(15)).unwrap();
    let quote_f = order.pair(tag1, s).unwrap();
    let hash_f = order.pair(tag15, quote_f).unwrap();

    let mut trace = VecTrace::default();
    nox::reduce(&mut order, s, hash_f, 100, &NullCalls, &mut trace);
    // 1 quote row + 24 round rows + 1 squeeze row
    assert_eq!(trace.0.len(), 26);

    // Rate = structural digest of s (4 Goldilocks elements), zero-padded to 8.
    let in_digest = *order.digest(s).unwrap();
    let rate = [
        in_digest[0],
        in_digest[1],
        in_digest[2],
        in_digest[3],
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ];
    let hash_aux = HashAux { rate };

    let stmt = zero_statement();
    let params = ProofParams::default();
    let trace_proof = commit(&trace, &[hash_aux], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&trace_proof, &stmt, &params).is_ok());
}

/// E2E: trace with two axis operations → axis verifier steps fold into
/// separate accumulator group.  Statement input/output hashes are computed
/// from real trace rows and embedded in the statement, exercising all three
/// new commit() features simultaneously.
#[test]
fn e2e_axis_accumulator_and_statement_binding_roundtrip() {
    // Two axis identity operations: axis(s, 1) = s, cost 1 each.
    let mut order = Reduction::<1024>::new();
    let s = order.atom(Goldilocks::new(7)).unwrap();
    let tag0 = order.atom(Goldilocks::new(0)).unwrap();
    let addr1 = order.atom(Goldilocks::new(1)).unwrap();
    let axis_f = order.pair(tag0, addr1).unwrap();

    let mut trace = VecTrace::default();
    nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
    nox::reduce(&mut order, s, axis_f, 99, &NullCalls, &mut trace);
    // Two axis rows; consecutive pair satisfies pattern_axis budget-decrement constraint.
    assert_eq!(trace.0.len(), 2);

    // Interpreter-mode axis rows (NullCalls) carry no commitment and
    // owe no openings.

    // Statement binding: real hashes from first and last trace rows.
    let input_hash = super::row_hash(&trace.0[0]);
    let output_hash = super::row_hash(&trace.0[trace.0.len() - 1]);
    let stmt = Statement {
        program_hash: [0u8; 32],
        input_hash,
        output_hash,
        focus_bound: 10,
    bbg_root: [0u8; 32],
    };
    let params = ProofParams::default();

    let trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&trace_proof, &stmt, &params).is_ok());
}

/// E2E: commit() rejects a statement whose input_hash does not match the
/// hash of the first trace row.
#[test]
fn e2e_statement_binding_rejects_wrong_input_hash() {
    let mut order = Reduction::<1024>::new();
    let s = order.atom(Goldilocks::new(7)).unwrap();
    let tag0 = order.atom(Goldilocks::new(0)).unwrap();
    let addr = order.atom(Goldilocks::new(1)).unwrap();
    let axis_f = order.pair(tag0, addr).unwrap();

    let mut trace = VecTrace::default();
    nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
    nox::reduce(&mut order, s, axis_f, 99, &NullCalls, &mut trace);

    let mut wrong_hash = [0u8; 32];
    wrong_hash[0] = 0xff;

    let stmt = Statement {
        program_hash: [0u8; 32],
        input_hash: wrong_hash,
        output_hash: [0u8; 32],
        focus_bound: 0,
    bbg_root: [0u8; 32],
    };
    let params = ProofParams::default();
    let err = commit(&trace, &[], &[], &[], &stmt, &params);
    assert!(matches!(err, Err(CommitError::StatementMismatch)));
}

/// E2E: commit() rejects when trace length exceeds statement focus_bound.
#[test]
fn e2e_statement_binding_rejects_focus_exceeded() {
    let trace = malformed_trace(); // 2 rows
    let stmt = Statement {
        program_hash: [0u8; 32],
        input_hash: [0u8; 32],
        output_hash: [0u8; 32],
        focus_bound: 1, // trace has 2 rows > 1
        bbg_root: [0u8; 32],
    };
    let params = ProofParams::default();
    let err = commit(&trace, &[], &[], &[], &stmt, &params);
    assert!(matches!(err, Err(CommitError::FocusExhausted)));
}

// ── compose (2) and cons (3): real-trace e2e coverage ────────────────────
// These catch the pattern_quote bug class: a constraint wired to
// registers no real trace sets makes honest programs unprovable — the
// degree-1 zero-error rule turns the stale constraint into a rejection.

/// E2E: a real compose program, run twice so the compose row is followed
/// by another row (engaging pattern_compose in the main fold), commits
/// and verifies.
#[test]
fn e2e_compose_roundtrip() {
    // [2 [[1 5] [1 [1 9]]]] — quote-only sub-formulas keep the trace
    // free of axis rows (which would demand AxisOpenings):
    // evaluate(obj,[1 5]) = 5, evaluate(obj,[1 [1 9]]) = [1 9],
    // continuation reduce(5, [1 9]) = 9.
    let g = Goldilocks::new;
    let mut ar = Reduction::<1024>::new();
    let obj = ar.atom(g(5)).unwrap();
    let t1 = ar.atom(g(1)).unwrap();
    let five = ar.atom(g(5)).unwrap();
    let nine = ar.atom(g(9)).unwrap();
    let qx = ar.pair(t1, five).unwrap();
    let q9 = ar.pair(t1, nine).unwrap();
    let qq9 = ar.pair(t1, q9).unwrap();
    let body = ar.pair(qx, qq9).unwrap();
    let t2 = ar.atom(g(2)).unwrap();
    let formula = ar.pair(t2, body).unwrap();

    let mut trace = VecTrace::default();
    nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
    nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
    assert!(trace.0.iter().any(|r| r.r()[0] == 2), "trace has a compose row");

    let stmt = zero_statement();
    let params = ProofParams::default();
    let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&tp, &stmt, &params).is_ok());
}

/// E2E: a real cons program (`[3 [[1 7] [1 9]]]`), run twice, commits
/// and verifies.
#[test]
fn e2e_cons_roundtrip() {
    let g = Goldilocks::new;
    let mut ar = Reduction::<1024>::new();
    let obj = ar.atom(g(5)).unwrap();
    let t1 = ar.atom(g(1)).unwrap();
    let seven = ar.atom(g(7)).unwrap();
    let nine = ar.atom(g(9)).unwrap();
    let qa = ar.pair(t1, seven).unwrap();
    let qb = ar.pair(t1, nine).unwrap();
    let body = ar.pair(qa, qb).unwrap();
    let t3 = ar.atom(g(3)).unwrap();
    let formula = ar.pair(t3, body).unwrap();

    let mut trace = VecTrace::default();
    nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
    nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
    assert!(trace.0.iter().any(|r| r.r()[0] == 3), "trace has a cons row");

    let stmt = zero_statement();
    let params = ProofParams::default();
    let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&tp, &stmt, &params).is_ok());
}
