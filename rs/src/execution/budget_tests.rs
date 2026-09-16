use super::{ExecutionNoun as N, private, prove_execution, verify_execution};
use nebu::Goldilocks as F;
fn a(v: u64) -> N {
    N::Atom(v)
}
fn p(x: N, y: N) -> N {
    N::Pair(Box::new(x), Box::new(y))
}
fn q(v: u64) -> N {
    p(a(1), a(v))
}
fn axis(v: u64) -> N {
    p(a(0), a(v))
}
fn op(t: u64, x: N, y: N) -> N {
    p(a(t), p(x, y))
}
fn branch(test: N, yes: N, no: N) -> N {
    p(a(4), p(test, p(yes, no)))
}
#[test]
fn selected_branch_cost_can_fit_below_worst_case() {
    let program = branch(axis(2), q(7), p(a(8), q(2)));
    let (statement, prepared, witness) =
        private::prepare_execution(&program, &[0], &[], 3).unwrap();
    assert_eq!(statement.execution.cycles, 3);
    assert!(prepared.relation.max_cost > 3);
    assert_eq!(statement.execution.public_output, [7]);
    assert!(private::prepare_execution(&program, &[0], &[], 2).is_err());
    assert!(private::prepare_execution(&program, &[1], &[], 3).is_err());
    assert!(private::prepare_execution(&program, &[1], &[], 67).is_ok());
    let mut forged = crate::types::CCSWitness {
        z: witness.into_iter().map(F::new).collect(),
    };
    forged.z[prepared.relation.cost_index] -= F::ONE;
    assert!(!prepared.relation.instance.is_satisfied_by(&forged));
}
#[test]
fn cheap_paths_do_not_validate_inactive_inverse_words_or_calls() {
    for (inactive, secrets) in [
        (p(a(8), q(0)), vec![]),
        (p(a(13), q(1u64 << 32)), vec![]),
        (op(16, q(0), q(1)), vec![42]),
    ] {
        let program = branch(axis(2), q(7), inactive);
        let (statement, _, _) = private::prepare_execution(&program, &[0], &[], 3).unwrap();
        assert_eq!(statement.execution.public_output, [7]);
        assert_eq!(statement.execution.cycles, 3);
        assert!(private::prepare_execution(&program, &[1], &secrets, 1000).is_err());
    }
    // The branch selector itself can be secret; only an active call consumes it.
    let secret = op(16, q(0), q(0));
    let program = branch(secret, q(7), p(a(8), q(0)));
    let (statement, _, _) = private::prepare_execution(&program, &[], &[0], 5).unwrap();
    assert_eq!(statement.execution.cycles, 5);
    assert!(private::prepare_execution(&program, &[], &[1], 1000).is_err());
}
#[test]
fn public_cost_budget_and_selected_branch_are_authenticated() {
    let program = branch(axis(2), q(7), p(a(8), q(2)));
    let (statement, proof) = prove_execution(&program, &[0], 3).unwrap();
    verify_execution(&statement, &proof).unwrap();
    for mutation in 0..4 {
        let mut bad = statement.clone();
        match mutation {
            0 => bad.cycles = 2,
            1 => bad.budget = 2,
            2 => bad.budget = 4,
            _ => bad.public_input[0] = 1,
        }
        assert!(verify_execution(&bad, &proof).is_err());
    }
}
#[test]
fn state_wrappers_use_selected_cost_with_the_same_public_bindings() {
    let program = branch(q(0), q(7), p(a(8), q(0)));
    let root = [1, 2, 3, 4];
    let (statement, proof) =
        super::state::prove_state_execution(&program, &[], 3, root, false, [0; 32], &mut |_, _| {
            None
        })
        .unwrap();
    assert_eq!(statement.execution.cycles, 3);
    statement.verify(&proof, &mut |_, _| None).unwrap();
    let mut bad = statement.clone();
    bad.execution.cycles = 2;
    assert!(bad.verify(&proof, &mut |_, _| None).is_err());
    let tables = super::relation::PublicStateTables {
        root: root.map(F::new),
        dimensions: std::array::from_fn(|_| vec![]),
    };
    let (statement, prepared, witness) =
        super::private_state::prepare_execution(&program, &[], &[], 3, false, &tables).unwrap();
    assert_eq!(statement.execution.cycles, 3);
    assert!(prepared.relation.max_cost > 3);
    let mut forged = crate::types::CCSWitness {
        z: witness.into_iter().map(F::new).collect(),
    };
    forged.z[prepared.relation.cost_index] -= F::ONE;
    assert!(!prepared.relation.instance.is_satisfied_by(&forged));
    assert!(
        super::private_state::prepare_execution(&program, &[], &[], 2, false, &tables).is_err()
    );
}
#[test]
fn exact_selected_budget_matches_native_nox_sequential_fallback() {
    fn arena(r: &mut nox::Reduction<8192>, n: &N) -> nox::Order {
        match n {
            N::Atom(v) => r.atom(F::new(*v)).unwrap(),
            N::Pair(a, b) => {
                let a = arena(r, a);
                let b = arena(r, b);
                r.pair(a, b).unwrap()
            }
        }
    }
    for (program, budget, expected) in [
        (branch(axis(2), q(7), p(a(8), q(0))), 3, 7),
        (op(5, branch(axis(2), q(7), p(a(8), q(0))), q(2)), 5, 9),
    ] {
        let mut r = nox::Reduction::<8192>::new();
        let subject = arena(&mut r, &p(a(0), a(0)));
        let formula = arena(&mut r, &program);
        match nox::reduce(
            &mut r,
            subject,
            formula,
            budget,
            &nox::call::NullCalls,
            &mut nox::trace::NoTrace,
        ) {
            nox::Outcome::Ok(output, remaining) => {
                assert_eq!(remaining, 0);
                assert_eq!(r.atom_value(output).unwrap().as_u64(), expected);
            }
            outcome => panic!("native selected path failed: {outcome:?}"),
        }
        let (s, _, _) = private::prepare_execution(&program, &[0], &[], budget).unwrap();
        assert_eq!(s.execution.cycles, budget);
        assert_eq!(s.execution.public_output, [expected]);
    }
}
