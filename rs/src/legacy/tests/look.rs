use super::*;
use crate::root_to_bytes;

// ── look (pattern 17): public-root e2e and negatives ─────────────────────
// The look chain (opening → value=r7 → point=r6 → leaf=dims[r5] → root =
// r4/r11-r13) previously ended at the object's root limbs — witness data.
// The recursive route is now rejected before processing these openings.
// Actual positive/root/substitution properties use state execution below.

/// Run `[17 [[1 ns] [1 key]]]` against a provider over `evals`; the
/// object carries the solo root limbs. Returns (trace, openings, root).
fn look_setup(evals: &[u64], key: u64) -> (VecTrace, Vec<LookOpening>, [u8; 32]) {
    use nox::{BrakedownLookProvider, reduce};

    let g = Goldilocks::new;
    let poly = MultilinearPoly::new(evals.iter().map(|&v| g(v)).collect());
    let provider = BrakedownLookProvider::new(poly);
    let root = crate::ccs::standalone_root(&provider, 0);
    let root_bytes = root_to_bytes(&root);

    let mut ar = Reduction::<1024>::new();
    // object [[l0 | [l1 | [l2 | l3]]] | rest]
    let l: Vec<_> = root.iter().map(|&x| ar.atom(x).unwrap()).collect();
    let inner = ar.pair(l[2], l[3]).unwrap();
    let mid = ar.pair(l[1], inner).unwrap();
    let root_pair = ar.pair(l[0], mid).unwrap();
    let rest = ar.atom(g(0)).unwrap();
    let obj = ar.pair(root_pair, rest).unwrap();
    // formula [17 [[1 0] [1 key]]]
    let t17 = ar.atom(g(17)).unwrap();
    let t1 = ar.atom(g(1)).unwrap();
    let vns = ar.atom(g(0)).unwrap();
    let vkey = ar.atom(g(key)).unwrap();
    let nf = ar.pair(t1, vns).unwrap();
    let kf = ar.pair(t1, vkey).unwrap();
    let body = ar.pair(nf, kf).unwrap();
    let formula = ar.pair(t17, body).unwrap();

    let mut trace = VecTrace::default();
    let _ = reduce(&mut ar, obj, formula, 1000, &provider, &mut trace);
    assert!(trace.0.iter().any(|r| r.r()[0] == 17), "trace has a look row");
    let openings = crate::ccs::look_openings_from_provider(&provider);
    assert_eq!(openings.len(), 1);
    (trace, openings, root_bytes)
}


fn look_statement(root: [u8; 32]) -> Statement {
    Statement { bbg_root: root, ..zero_statement() }
}


/// Negative: the public root names a different state — rejected at commit.
#[test]
fn commit_rejects_look_root_mismatch() {
    let (trace, openings, root) = look_setup(&[10, 20, 30, 40], 2);
    let mut wrong = root;
    wrong[0] ^= 1;
    let err = commit(&trace, &[], &[], &openings, &look_statement(wrong), &ProofParams::default());
    assert!(matches!(err, Err(CommitError::UnsupportedRecursiveOpening)));
}

/// Negative: a VALID opening of a different state (its own consistent
/// leaves and root) against this statement's root — rejected at commit.
#[test]
fn commit_rejects_swapped_look_opening() {
    let (trace, _, root) = look_setup(&[10, 20, 30, 40], 2);
    let (_, other_openings, _) = look_setup(&[11, 21, 31, 41], 2);
    let err = commit(&trace, &[], &[], &other_openings, &look_statement(root), &ProofParams::default());
    assert!(matches!(err, Err(CommitError::UnsupportedRecursiveOpening)));
}

/// Negative: tampered leaves — the recomputed root diverges from both the
/// trace registers and the public root — rejected at commit.
#[test]
fn commit_rejects_tampered_look_leaves() {
    let (trace, mut openings, root) = look_setup(&[10, 20, 30, 40], 2);
    openings[0].leaves.dims[3] = [Goldilocks::new(7); 4];
    let err = commit(&trace, &[], &[], &openings, &look_statement(root), &ProofParams::default());
    assert!(matches!(err, Err(CommitError::UnsupportedRecursiveOpening)));
}

/// Negative: look rows against the zero-root sentinel — a program that
/// reads state must declare its root — rejected at commit.
#[test]
fn commit_rejects_look_without_public_root() {
    let (trace, openings, _) = look_setup(&[10, 20, 30, 40], 2);
    let err = commit(&trace, &[], &[], &openings, &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(CommitError::UnsupportedRecursiveOpening)));
}

/// Negative: a prover who folds a root-vs-statement binding for the wrong
/// public root directly (bypassing the commit gate) is caught by the
/// degree-1 zero-error rule.
#[test]
fn verify_rejects_folded_wrong_statement_root() {
    use crate::ccs::eq_step;
    use crate::ccs::verifier_steps::read_limb;

    let (trace, openings, root) = look_setup(&[10, 20, 30, 40], 2);
    let (mut steps, _rows) =
        crate::ccs::build_look_steps_from_trace(&trace.0, &openings, &root).unwrap();
    // The forged binding: recomputed root limb vs a different public root.
    let limbs = crate::ccs::root_from_leaves(&openings[0].leaves);
    let mut wrong = root;
    wrong[0] ^= 1;
    steps.push(eq_step(limbs[0], read_limb(&wrong, 0)));

    let trace_proof = prove_raw_linear_steps(&steps);
    let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
}
