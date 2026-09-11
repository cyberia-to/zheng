use super::*;
use nox::call::NullCalls;
use nox::trace::NoTrace;
use nox::{Order, Outcome, Reduction, reduce};
fn atom(a: u64) -> ExecutionNoun {
    ExecutionNoun::Atom(a)
}
fn pair(a: ExecutionNoun, b: ExecutionNoun) -> ExecutionNoun {
    ExecutionNoun::Pair(Box::new(a), Box::new(b))
}
fn op(t: u64, a: ExecutionNoun, b: ExecutionNoun) -> ExecutionNoun {
    pair(atom(t), pair(a, b))
}
fn quote(a: u64) -> ExecutionNoun {
    pair(atom(1), atom(a))
}
fn axis(a: u64) -> ExecutionNoun {
    pair(atom(0), atom(a))
}
fn arena<const N: usize>(r: &mut Reduction<N>, n: &ExecutionNoun) -> Order {
    match n {
        ExecutionNoun::Atom(v) => r.atom(F::new(*v)).unwrap(),
        ExecutionNoun::Pair(a, b) => {
            let a = arena(r, a);
            let b = arena(r, b);
            r.pair(a, b).unwrap()
        }
    }
}
fn compare(program: &ExecutionNoun, input: u64) {
    let rel = compile_relation(program, &SubjectShape::Atom).unwrap();
    let w = rel.witness(&[F::new(input)]).unwrap();
    assert!(rel.instance.is_satisfied_by(&w));
    let mut ar = Reduction::<8192>::new();
    let s = ar.atom(F::new(input)).unwrap();
    let f = arena(&mut ar, program);
    let (out, remaining) = match reduce(&mut ar, s, f, rel.max_cost, &NullCalls, &mut NoTrace) {
        Outcome::Ok(o, b) => (o, b),
        o => panic!("{o:?}"),
    };
    assert_eq!(ar.atom_value(out).unwrap(), w.z[rel.output_indices[0]]);
    assert_eq!(rel.max_cost - remaining, w.z[rel.cost_index].as_u64());
    for &i in rel
        .output_indices
        .iter()
        .chain(std::iter::once(&rel.cost_index))
    {
        let mut bad = w.clone();
        bad.z[i] += F::ONE;
        assert!(!rel.instance.is_satisfied_by(&bad));
    }
}
#[test]
fn native_arithmetic_and_static_compose() {
    let arithmetic = op(7, op(5, axis(1), quote(9)), op(6, axis(1), quote(2)));
    let composed = op(2, arithmetic, pair(atom(1), op(5, axis(1), quote(7))));
    for x in [0, 1, 2, 13, 1000] {
        compare(&composed, x)
    }
}
#[test]
fn both_branch_arms_and_zero_test_are_constrained() {
    let p = pair(
        atom(4),
        pair(
            op(9, axis(1), quote(7)),
            pair(quote(123), op(7, axis(1), quote(2))),
        ),
    );
    for x in [0, 1, 7, 55] {
        compare(&p, x)
    }
    let rel = compile_relation(&p, &SubjectShape::Atom).unwrap();
    let w = rel.witness(&[F::new(7)]).unwrap();
    // Input substitution without recomputing the execution witness is rejected.
    let mut bad = w.clone();
    bad.z[rel.input_indices[0]] = F::new(8);
    assert!(!rel.instance.is_satisfied_by(&bad));
}
#[test]
fn inverse_and_zero_failure() {
    let p = pair(atom(8), axis(1));
    compare(&p, 7);
    let rel = compile_relation(&p, &SubjectShape::Atom).unwrap();
    assert!(
        !rel.instance
            .is_satisfied_by(&rel.witness(&[F::ZERO]).unwrap())
    );
}
#[test]
fn structural_aliases_are_shared_and_outputs_left_to_right() {
    let shape = SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom));
    let rel = compile_relation(&op(3, axis(3), axis(2)), &shape).unwrap();
    let w = rel.witness(&[F::new(4), F::new(9)]).unwrap();
    assert_eq!(
        rel.output_indices
            .iter()
            .map(|&i| w.z[i].as_u64())
            .collect::<Vec<_>>(),
        vec![9, 4]
    );
    assert!(rel.instance.is_satisfied_by(&w));
}
#[test]
fn unsupported_and_noncanonical_programs_fail_closed() {
    assert!(compile_relation(&pair(atom(17), atom(0)), &SubjectShape::Atom).is_err());
    assert!(compile_relation(&op(2, quote(5), axis(1)), &SubjectShape::Atom).is_err());
    assert!(compile_relation(&quote(u64::MAX), &SubjectShape::Atom).is_err());
}
#[test]
fn relation_is_witness_independent_and_public_constant_must_be_pinned() {
    let rel = compile_relation(&op(5, axis(1), quote(7)), &SubjectShape::Atom).unwrap();
    assert_eq!(
        rel.instance,
        compile_relation(&op(5, axis(1), quote(7)), &SubjectShape::Atom)
            .unwrap()
            .instance
    );
    assert!(
        rel.instance
            .is_satisfied_by(&rel.witness(&[F::new(1)]).unwrap())
    );
    assert!(
        rel.instance
            .is_satisfied_by(&rel.witness(&[F::new(200)]).unwrap())
    );
    // Homogeneous CCS alone permits the all-zero vector: outer PCS public
    // binding is an essential obligation, explicitly tested by proof.rs.
    let zero = CCSWitness {
        z: vec![F::ZERO; rel.instance.num_cols],
    };
    assert!(rel.instance.is_satisfied_by(&zero));
}
#[test]
fn canonical_comparison_boundaries() {
    for bound in [0, 1, 7, 0xffff_ffff, 0xffff_ffff_0000_0000] {
        let p = op(10, axis(1), quote(bound));
        for x in [0, 1, 6, 7, 8, 0xffff_fffe_ffff_ffff, 0xffff_ffff_0000_0000] {
            compare(&p, x)
        }
    }
}
#[test]
fn word_operations_match_nox_and_reject_large_operands() {
    for tag in [11, 12, 14] {
        for operand in [0, 1, 7, 31, 32, 255, u32::MAX as u64] {
            compare(&op(tag, axis(1), quote(operand)), 0x81234567)
        }
    }
    compare(&pair(atom(13), axis(1)), 0x81234567);
    let rel = compile_relation(&op(11, axis(1), quote(0)), &SubjectShape::Atom).unwrap();
    assert!(
        !rel.instance
            .is_satisfied_by(&rel.witness(&[F::new(1u64 << 32)]).unwrap())
    );
}
#[test]
fn noncanonical_bit_decomposition_cannot_forge_ordering() {
    let rel = compile_relation(&op(10, axis(1), quote(1)), &SubjectShape::Atom).unwrap();
    let mut z = vec![F::ONE, F::ZERO];
    let mut replaced = 0;
    for op in &rel.ops {
        let eval = |l: &Linear| l.iter().fold(F::ZERO, |s, &(i, c)| s + z[i] * c);
        let value = match op {
            // p represents zero in the field but must NOT be allowed as
            // zero's bit decomposition (it would reverse the comparison).
            Op::Bit(_, k) if replaced < 64 => {
                replaced += 1;
                F::new((0xffff_ffff_0000_0001u64 >> k) & 1)
            }
            Op::Bit(a, k) => F::new((eval(a).as_u64() >> k) & 1),
            Op::Linear(a) => eval(a),
            Op::Product(a, b) => eval(a) * eval(b),
            Op::Inverse(a) => {
                let v = eval(a);
                if v == F::ZERO { v } else { v.inv() }
            }
        };
        z.push(value);
    }
    z.resize(rel.instance.num_cols, F::ZERO);
    assert!(!rel.instance.is_satisfied_by(&CCSWitness { z }));
}
#[test]
fn unselected_invalid_inverse_is_conservatively_rejected() {
    // This program returns 7 in nox. The bounded circuit currently requires
    // both arms' arithmetic to be defined, so refuses this valid execution.
    let p = pair(
        atom(4),
        pair(quote(0), pair(quote(7), pair(atom(8), quote(0)))),
    );
    let rel = compile_relation(&p, &SubjectShape::Atom).unwrap();
    assert!(
        !rel.instance
            .is_satisfied_by(&rel.witness(&[F::ZERO]).unwrap())
    );
}
#[test]
fn symbolic_cons_expansion_is_bounded() {
    let mut p = axis(1);
    for _ in 0..20 {
        p = op(2, p, pair(atom(1), op(3, axis(1), axis(1))));
    }
    assert!(matches!(
        compile_relation(&p, &SubjectShape::Atom),
        Err(RelationError::Limit)
    ));
}

#[test]
fn compiled_trident_import_loop_branch_matches_native() {
    // Emitted by Trident 0.3.0 for main(x): start result=x; loop3 times
    // result=calc.step(result), imported step(x)=x+3; if result==13
    // result+=100 else result*=2; return result. Kept as compiler-output
    // regression; source-to-proof process integration is tested in Joy.
    let text = "[2 [[3 [[0 2] [0 1]]] [1 [2 [[2 [[3 [[1 0] [0 1]]] [1 [2 [[3 [[0 2] [3 [[2 [[3 [[0 6] [1 0]]] [1 [5 [[0 2] [1 3]]]]]] [0 7]]]]] [1 [3 [[0 6] [3 [[0 14] [0 15]]]]]]]]]]] [1 [2 [[2 [[3 [[1 1] [0 1]]] [1 [2 [[3 [[0 2] [3 [[2 [[3 [[0 6] [1 0]]] [1 [5 [[0 2] [1 3]]]]]] [0 7]]]]] [1 [3 [[0 6] [3 [[0 14] [0 15]]]]]]]]]]] [1 [2 [[2 [[3 [[1 2] [0 1]]] [1 [2 [[3 [[0 2] [3 [[2 [[3 [[0 6] [1 0]]] [1 [5 [[0 2] [1 3]]]]]] [0 7]]]]] [1 [3 [[0 6] [3 [[0 14] [0 15]]]]]]]]]]] [1 [2 [[4 [[9 [[0 2] [1 13]]] [[2 [[3 [[5 [[0 2] [1 100]]] [0 3]]] [1 [0 1]]]] [2 [[3 [[7 [[0 2] [1 2]]] [0 3]]] [1 [0 1]]]]]]] [1 [0 2]]]]]]]]]]]]]]]]";
    fn parse(bytes: &[u8], p: &mut usize) -> ExecutionNoun {
        while *p < bytes.len() && bytes[*p].is_ascii_whitespace() {
            *p += 1;
        }
        if bytes[*p] == b'[' {
            *p += 1;
            let a = parse(bytes, p);
            let b = parse(bytes, p);
            assert_eq!(bytes[*p], b']');
            *p += 1;
            pair(a, b)
        } else {
            let start = *p;
            while *p < bytes.len() && bytes[*p].is_ascii_digit() {
                *p += 1;
            }
            atom(
                std::str::from_utf8(&bytes[start..*p])
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
        }
    }
    let program = parse(text.as_bytes(), &mut 0);
    let shape = SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom));
    let relation = compile_relation(&program, &shape).unwrap();
    for (input, expected) in [(4, 113), (0, 18), (10, 38)] {
        let w = relation.witness(&[F::new(input), F::ZERO]).unwrap();
        assert!(relation.instance.is_satisfied_by(&w));
        assert_eq!(w.z[relation.output_indices[0]], F::new(expected));
        let mut ar = Reduction::<8192>::new();
        let subject = arena(&mut ar, &pair(atom(input), atom(0)));
        let formula = arena(&mut ar, &program);
        match reduce(
            &mut ar,
            subject,
            formula,
            relation.max_cost,
            &NullCalls,
            &mut NoTrace,
        ) {
            Outcome::Ok(out, remaining) => {
                assert_eq!(ar.atom_value(out).unwrap(), F::new(expected));
                assert_eq!(
                    relation.max_cost - remaining,
                    w.z[relation.cost_index].as_u64()
                );
            }
            outcome => panic!("{outcome:?}"),
        }
    }
}
