use super::*;

// ── hash (pattern 15): trace binding tests ───────────────────────────────
// Hash carries NO polynomial opening: the sponge is verified in-circuit,
// and HashAux's rate is the only prover-supplied input. The bindings tie
// every block row to the replay of that rate.

/// Build the trace and honest HashAux for `[15 [1 s]]` hashing atom `val`.
fn hash_setup(val: u64) -> (VecTrace, crate::ccs::HashAux) {
    let g = Goldilocks::new;
    let mut order = Reduction::<1024>::new();
    let s = order.atom(g(val)).unwrap();
    let tag1 = order.atom(g(1)).unwrap();
    let tag15 = order.atom(g(15)).unwrap();
    let quote_f = order.pair(tag1, s).unwrap();
    let hash_f = order.pair(tag15, quote_f).unwrap();
    let mut trace = VecTrace::default();
    nox::reduce(&mut order, s, hash_f, 100, &NullCalls, &mut trace);
    assert_eq!(trace.0.len(), 26);
    let d = *order.digest(s).unwrap();
    let rate = [
        d[0], d[1], d[2], d[3],
        Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO,
    ];
    (trace, crate::ccs::HashAux { rate })
}

/// E2E: two hash blocks in one trace — bindings, round CCS and linkage
/// all round-trip.
#[test]
fn e2e_two_hash_blocks_roundtrip() {
    let (mut trace, aux1) = hash_setup(42);
    let (trace2, aux2) = hash_setup(42);
    trace.0.extend(trace2.0);
    let stmt = zero_statement();
    let params = ProofParams::default();
    let tp = commit(&trace, &[aux1, aux2], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&tp, &stmt, &params).is_ok());
}

/// Group count is a function of which structures occur, never of trace
/// length: two hash blocks and three hash blocks yield the same number of
/// accumulator groups, and the step counts grow instead. (Two, not one:
/// a block followed by another block adds the squeeze→quote boundary
/// pair — a structure a single block never has.)
#[test]
fn group_count_independent_of_trace_length() {
    let stmt = zero_statement();
    let params = ProofParams::default();

    let (mut t1, a1) = hash_setup(42);
    let (t1b, a2) = hash_setup(43);
    t1.0.extend(t1b.0);
    let p1 = commit(&t1, &[a1, a2], &[], &[], &stmt, &params).unwrap();

    let (mut t3, b1) = hash_setup(42);
    let (t3b, b2) = hash_setup(43);
    let (t3c, b3) = hash_setup(44);
    t3.0.extend(t3b.0);
    t3.0.extend(t3c.0);
    let p3 = commit(&t3, &[b1, b2, b3], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&p3, &stmt, &params).is_ok());

    assert_eq!(p1.group_count(), 2, "universal + binding");
    assert_eq!(
        p1.group_count(),
        p3.group_count(),
        "groups are structures, not runs: 2 vs 3 hash blocks"
    );
    let steps = |p: &TraceProof| -> u64 { p.groups().map(|g| g.accumulator.step_count).sum() };
    assert!(steps(&p3) > steps(&p1), "the extra block folds into existing groups");
}

/// Negative: a tampered rate (not any digest) diverges from the trace at
/// every row — the binding gate rejects at commit.
#[test]
fn commit_rejects_tampered_hash_rate() {
    let (trace, _) = hash_setup(42);
    let forged = crate::ccs::HashAux { rate: [Goldilocks::new(3); 8] };
    let err = commit(&trace, &[forged], &[], &[], &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(CommitError::HashBinding)));
}

/// Negative: a VALID digest of a different particle (swapped input) still
/// diverges from the recorded sponge states — rejected at commit.
#[test]
fn commit_rejects_swapped_hash_rate() {
    let (trace, _) = hash_setup(42);
    let (_, aux_other) = hash_setup(43);
    let err = commit(&trace, &[aux_other], &[], &[], &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(CommitError::HashBinding)));
}

/// Negative: a prover who folds a forged output-digest binding directly
/// (bypassing the commit gate) is caught by the degree-1 zero-error rule
/// — the hash bindings inherit it from the axis machinery.
#[test]
fn verify_rejects_folded_forged_hash_digest() {
    use crate::ccs::eq_step;

    let (trace, aux) = hash_setup(42);
    let mut steps =
        crate::ccs::build_hash_binding_steps_from_trace(&trace.0, &[aux]).unwrap();
    // The squeeze row's recorded digest limb vs a forged replay value.
    let digest0 = Goldilocks::new(trace.0[25].r()[4]).canonicalize();
    steps.push(eq_step(digest0 + Goldilocks::ONE, digest0));

    let trace_proof = prove_raw_linear_steps(&steps);
    let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
    assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
}

/// Negative: the hash binding group of one valid proof spliced into
/// another valid proof breaks the option-A linkage digest — the hash
/// bindings inherit the cross-group linkage.
#[test]
fn verify_rejects_spliced_hash_binding_group() {
    let stmt = zero_statement();
    let params = ProofParams::default();
    let (t1, a1) = hash_setup(42);
    let (t2, a2) = hash_setup(43);
    let p1 = commit(&t1, &[a1], &[], &[], &stmt, &params).unwrap();
    let p2 = commit(&t2, &[a2], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&p1, &stmt, &params).is_ok());
    assert!(verify(&p2, &stmt, &params).is_ok());

    let b1 = p1.binding.as_ref().expect("hash proof has a binding group");
    let b2 = p2.binding.as_ref().expect("hash proof has a binding group");
    assert_ne!(
        b1.accumulator.witness_commitment.as_bytes(),
        b2.accumulator.witness_commitment.as_bytes(),
        "different hashed particles give different binding witnesses"
    );

    let mut spliced = p1.clone();
    spliced.binding = Some(b2.clone());
    assert!(
        verify(&spliced, &stmt, &params).is_err(),
        "hash binding group spliced from another proof must not verify"
    );

    // The universal group is linked too: swapping it between two
    // proofs of different hashed particles breaks both digests.
    let mut spliced = p1.clone();
    spliced.universal = p2.universal.clone();
    assert!(
        verify(&spliced, &stmt, &params).is_err(),
        "universal group spliced from another proof must not verify"
    );
}
