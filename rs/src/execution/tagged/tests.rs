use super::super::relation::compile_relation;
use super::*;
use nox::call::NullCalls;
use nox::trace::NoTrace;
use nox::{Order, Outcome, Reduction, reduce};
fn a(x: u64) -> Noun {
    Noun::Atom(x)
}
fn p(a: Noun, b: Noun) -> Noun {
    Noun::Pair(Box::new(a), Box::new(b))
}
fn q(n: Noun) -> Noun {
    p(a(1), n)
}
fn axis(x: u64) -> Noun {
    p(a(0), a(x))
}
fn op(t: u64, x: Noun, y: Noun) -> Noun {
    p(a(t), p(x, y))
}
fn branch(t: Noun, y: Noun, n: Noun) -> Noun {
    p(a(4), p(t, p(y, n)))
}
fn shape() -> SubjectShape {
    SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom))
}
fn arena<const N: usize>(r: &mut Reduction<N>, n: &Noun) -> Order {
    match n {
        Noun::Atom(x) => r.atom(F::new(*x)).unwrap(),
        Noun::Pair(a, b) => {
            let a = arena(r, a);
            let b = arena(r, b);
            r.pair(a, b).unwrap()
        }
    }
}
fn read<const N: usize>(r: &Reduction<N>, o: Order) -> Noun {
    if let Some(x) = r.atom_value(o) {
        a(x.as_u64())
    } else {
        p(read(r, r.head(o).unwrap()), read(r, r.tail(o).unwrap()))
    }
}
fn native(program: &Noun, input: &[u64], budget: u64) -> Option<(Noun, u64)> {
    let mut r = Reduction::<8192>::new();
    let subject = match input {
        [x] => a(*x),
        [x, y] => p(a(*x), a(*y)),
        _ => panic!("test shape"),
    };
    let s = arena(&mut r, &subject);
    let f = arena(&mut r, program);
    match reduce(&mut r, s, f, budget, &NullCalls, &mut NoTrace) {
        Outcome::Ok(o, left) => Some((read(&r, o), budget - left)),
        _ => None,
    }
}
fn check(program: &Noun, shape: &SubjectShape, input: &[u64], output: &Noun) -> TaggedRelation {
    let relation = compile(program, shape).unwrap();
    let (actual, cost) = native(program, input, relation.max_cost).expect("native succeeds");
    assert_eq!(&actual, output);
    let w = relation.witness(input).unwrap();
    assert!(relation.instance.is_satisfied_by(&w));
    assert!(relation.verify_witness(input, output, cost, cost, &w));
    assert!(!relation.verify_witness(input, output, cost + 1, cost + 1, &w));
    if cost > 0 {
        assert!(!relation.verify_witness(input, output, cost, cost - 1, &w));
    }
    let mut bad = w.clone();
    bad.z[relation.cost] += F::ONE;
    assert!(!relation.instance.is_satisfied_by(&bad));
    relation
}
#[test]
fn mixed_atom_pair_branches_match_native_and_bind_topology() {
    let formula = branch(axis(2), q(a(7)), q(p(a(8), a(9))));
    assert!(compile_relation(&formula, &shape()).is_err());
    let r = check(&formula, &shape(), &[0, 0], &a(7));
    check(&formula, &shape(), &[1, 0], &p(a(8), a(9)));
    let second = compile(&formula, &shape()).unwrap();
    for (a, b) in r.instance.matrices.iter().zip(&second.instance.matrices) {
        assert_eq!(a.entries, b.entries);
    }
    let w = r.witness(&[1, 0]).unwrap();
    assert!(!r.verify_witness(&[1, 0], &p(a(9), a(8)), 3, 3, &w));
    assert!(!r.verify_witness(&[0, 0], &p(a(8), a(9)), 3, 3, &w));
    assert!(!r.verify_witness(&[1, 0], &a(8), 3, 3, &w));
    let mut changed_tag = w.clone();
    changed_tag.z[r.output.tag] = F::new(2);
    assert!(!r.instance.is_satisfied_by(&changed_tag));
    let mut changed_payload = w.clone();
    changed_payload.z[r.output.value] = F::ONE;
    assert!(!r.instance.is_satisfied_by(&changed_payload));
    let zero = CCSWitness {
        z: vec![F::ZERO; r.instance.num_cols],
    };
    assert!(
        r.instance.is_satisfied_by(&zero),
        "homogeneous rows need authenticated one"
    );
    assert!(!r.verify_witness(&[0, 0], &a(7), 3, 3, &zero));
}
#[test]
fn equal_flattened_leaves_do_not_hide_output_association_or_padding() {
    let left = p(p(a(1), a(2)), a(3));
    let right = p(a(1), p(a(2), a(3)));
    let f = branch(axis(1), q(left.clone()), q(right.clone()));
    let r = check(&f, &SubjectShape::Atom, &[0], &left);
    check(&f, &SubjectShape::Atom, &[2], &right);
    let w = r.witness(&[0]).unwrap();
    assert!(!r.verify_witness(&[0], &right, 3, 3, &w));
    let (_, right_schema) = r.output.children.as_ref().unwrap();
    let (absent, _) = right_schema.children.as_ref().unwrap();
    assert_eq!(w.z[absent.value], F::ZERO);
    let mut bad = w.clone();
    bad.z[absent.value] = F::ONE;
    assert!(!r.instance.is_satisfied_by(&bad));
    bad = w.clone();
    bad.z[absent.tag] = F::ONE;
    assert!(!r.instance.is_satisfied_by(&bad));
}
#[test]
fn inactive_invalid_axis_is_gated_and_active_projection_is_unsatisfiable() {
    let f = branch(axis(2), q(a(7)), axis(4));
    assert!(compile_relation(&f, &shape()).is_err());
    let r = check(&f, &shape(), &[0, 0], &a(7));
    assert!(native(&f, &[1, 0], r.max_cost).is_none());
    let bad = r.witness(&[1, 0]).unwrap();
    assert!(!r.instance.is_satisfied_by(&bad));
    assert!(!r.verify_witness(&[1, 0], &a(0), 3, 3, &bad));
    // Turn the honest invalid projection witness into an all-zero candidate;
    // even if all row constraints disappear, public subject/one pins cannot.
    let zero = CCSWitness {
        z: vec![F::ZERO; r.instance.num_cols],
    };
    assert!(!r.verify_witness(&[1, 0], &a(0), 3, 3, &zero));
}
#[test]
fn inactive_inverse_atom_errors_and_cost_follow_selected_execution() {
    let inverse_zero = p(a(8), q(a(0)));
    let f = branch(axis(1), q(p(a(17), a(19))), inverse_zero);
    let r = check(&f, &SubjectShape::Atom, &[0], &p(a(17), a(19)));
    assert_eq!(r.max_cost, 67);
    assert!(native(&f, &[1], r.max_cost).is_none());
    assert!(!r.instance.is_satisfied_by(&r.witness(&[1]).unwrap()));
    let bad_atom = op(5, q(p(a(1), a(2))), q(a(3)));
    let f = branch(axis(1), q(a(13)), bad_atom);
    let r = check(&f, &SubjectShape::Atom, &[0], &a(13));
    assert!(native(&f, &[1], r.max_cost).is_none());
    assert!(!r.instance.is_satisfied_by(&r.witness(&[1]).unwrap()));
    // A malformed supported arm is a gated native error, not an Unsupported op.
    let f = branch(axis(1), q(a(13)), p(a(5), a(0)));
    let r = check(&f, &SubjectShape::Atom, &[0], &a(13));
    assert!(!r.instance.is_satisfied_by(&r.witness(&[1]).unwrap()));
}
#[test]
fn arithmetic_nested_branches_and_nonzero_field_values_match_reference() {
    let f = branch(
        axis(1),
        q(a(11)),
        op(
            3,
            op(5, axis(1), q(a(9))),
            branch(
                op(6, axis(1), q(a(2))),
                q(p(a(7), a(8))),
                op(7, axis(1), q(a(3))),
            ),
        ),
    );
    for x in [0, 1, 2, 3, 100, nebu::field::P - 1] {
        let (out, _) = native(&f, &[x], 1000).unwrap();
        check(&f, &SubjectShape::Atom, &[x], &out);
    }
    let inv = p(a(8), axis(1));
    for x in [1, 2, nebu::field::P - 1] {
        let out = a(F::new(x).inv().as_u64());
        check(&inv, &SubjectShape::Atom, &[x], &out);
    }
}
#[test]
fn unsupported_and_resource_errors_do_not_claim_native_invalidity() {
    for f in [
        op(16, q(a(1)), q(a(1))),
        op(17, q(a(1)), q(a(1))),
        op(2, q(a(1)), axis(1)),
    ] {
        let conditional = branch(axis(1), q(a(7)), f);
        assert!(matches!(
            compile(&conditional, &SubjectShape::Atom),
            Err(Error::Unsupported(_))
        ));
        assert_eq!(native(&conditional, &[0], 1000).unwrap().0, a(7));
    }
    assert!(matches!(
        compile(&q(a(nebu::field::P)), &SubjectShape::Atom),
        Err(Error::NonCanonical)
    ));
    let mut too_deep = a(0);
    for _ in 0..130 {
        too_deep = p(a(0), too_deep);
    }
    assert!(matches!(
        compile(&q(too_deep), &SubjectShape::Atom),
        Err(Error::Limit)
    ));
    let r = compile(&axis(1), &SubjectShape::Atom).unwrap();
    assert!(r.witness(&[nebu::field::P]).is_err());
    assert!(r.witness(&[]).is_err());
    let short = CCSWitness { z: vec![] };
    assert!(!r.verify_witness(&[0], &a(0), 1, 1, &short));
}

#[test]
fn every_materialized_gate_coordinate_is_checked_independently_of_recipes() {
    let f = branch(
        axis(1),
        q(p(a(3), a(5))),
        op(3, p(a(8), axis(1)), op(7, axis(1), q(a(11)))),
    );
    let r = compile(&f, &SubjectShape::Atom).unwrap();
    let used = 2 + r.inputs.len() + r.ops.len();
    println!(
        "tagged mutation fixture: rows={}, columns={}, materialized_wires={}, max_cost={}, direct_mutations={}",
        r.instance.num_rows,
        r.instance.num_cols,
        used,
        r.max_cost,
        used * 8
    );
    for x in [0, 1, 2, nebu::field::P - 1] {
        let (out, cost) = native(&f, &[x], r.max_cost).unwrap();
        let w = r.witness(&[x]).unwrap();
        assert!(r.verify_witness(&[x], &out, cost, cost, &w));
        // Directly mutate every real wire, including inverse witnesses, branch
        // activity, projection payloads and intermediate cost. No recipe replay.
        for i in 0..used {
            for delta in [F::ONE, -F::ONE] {
                let mut bad = w.clone();
                bad.z[i] += delta;
                assert!(
                    !r.verify_witness(&[x], &out, cost, cost, &bad),
                    "unchecked wire {i}, input {x}"
                );
            }
        }
    }
}
