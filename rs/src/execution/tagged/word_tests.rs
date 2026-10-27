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
fn compose(subject: Noun, continuation: Noun) -> Noun {
    op(2, subject, q(continuation))
}
fn shape(n: &Noun) -> SubjectShape {
    match n {
        Noun::Atom(_) => SubjectShape::Atom,
        Noun::Pair(a, b) => SubjectShape::Pair(Box::new(shape(a)), Box::new(shape(b))),
    }
}
fn inputs(n: &Noun) -> Vec<u64> {
    match n {
        Noun::Atom(x) => vec![*x],
        Noun::Pair(a, b) => {
            let mut v = inputs(a);
            v.extend(inputs(b));
            v
        }
    }
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
fn native(f: &Noun, n: &Noun, budget: u64) -> Option<(Noun, u64)> {
    let mut r = Reduction::<8192>::new();
    let s = arena(&mut r, n);
    let f = arena(&mut r, f);
    match reduce(&mut r, s, f, budget, &NullCalls, &mut NoTrace) {
        Outcome::Ok(o, b) => Some((read(&r, o), budget - b)),
        _ => None,
    }
}
fn check(f: &Noun, n: &Noun, expected: &Noun) -> TaggedRelation {
    let r = compile(f, &shape(n)).unwrap();
    let x = inputs(n);
    let (out, cost) = native(f, n, r.max_cost).unwrap();
    assert_eq!(&out, expected);
    assert_eq!(
        native(f, n, cost),
        Some((out.clone(), cost)),
        "exact native budget"
    );
    let w = r.witness(&x).unwrap();
    assert!(r.verify_witness(&x, &out, cost, cost, &w));
    if cost > 0 {
        assert!(!r.verify_witness(&x, &out, cost, cost - 1, &w));
    }
    assert!(!r.verify_witness(&x, &out, cost + 1, cost + 1, &w));
    let mut bad = w.clone();
    bad.z[r.cost] += F::ONE;
    assert!(!r.instance.is_satisfied_by(&bad));
    bad = w;
    bad.z[r.output.value] += F::ONE;
    assert!(!r.instance.is_satisfied_by(&bad));
    r
}
#[test]
fn unsigned64_ordering_crosses_word_and_field_boundaries() {
    let f = op(10, axis(2), axis(3));
    let values = [
        0,
        1,
        (1 << 32) - 1,
        1 << 32,
        (1 << 63) - 1,
        1 << 63,
        nebu::field::P - 1,
    ];
    for x in values {
        for y in values {
            let r = check(&f, &p(a(x), a(y)), &a(u64::from(x >= y)));
            assert_eq!(r.max_cost, 66);
        }
    }
}
#[test]
fn words_match_native_xor_and_not_and_full_shift_amount() {
    let values = [0, 1, 31, 32, 0x8000_0000, 0xffff_ffff];
    for x in values {
        let r = check(&p(a(13), axis(1)), &a(x), &a((!x) & 0xffff_ffff));
        assert_eq!(r.max_cost, 33);
        for y in values {
            for (tag, expected) in [
                (11, x ^ y),
                (12, x & y),
                (14, if y >= 32 { 0 } else { (x << y) & 0xffff_ffff }),
            ] {
                let r = check(&op(tag, axis(2), axis(3)), &p(a(x), a(y)), &a(expected));
                assert_eq!(r.max_cost, 34);
            }
        }
    }
    for shift in [0, 1, 31, 32, 33, 63, 64, u32::MAX as u64] {
        let x = 0xffff_ffff;
        check(
            &op(14, axis(2), axis(3)),
            &p(a(x), a(shift)),
            &a(if shift >= 32 {
                0
            } else {
                (x << shift) & 0xffff_ffff
            }),
        );
    }
}
#[test]
fn inactive_invalid_word_range_and_atom_shape_are_gated() {
    let mut invalid = vec![p(a(13), q(a(1 << 32))), p(a(13), q(p(a(1), a(2))))];
    for tag in [11, 12, 14] {
        invalid.push(op(tag, q(a(1 << 32)), q(a(1))));
        invalid.push(op(tag, q(a(1)), q(a(nebu::field::P - 1))));
    }
    invalid.push(op(10, q(p(a(1), a(2))), q(a(1))));
    for bad in invalid {
        let f = branch(axis(1), q(a(71)), bad);
        let r = check(&f, &a(0), &a(71));
        assert!(native(&f, &a(1), r.max_cost).is_none());
        let w = r.witness(&[1]).unwrap();
        assert!(!r.instance.is_satisfied_by(&w));
        assert!(!r.verify_witness(&[1], &a(0), r.max_cost, r.max_cost, &w));
    }
}
#[test]
fn every_word_and_comparator_gate_rejects_single_wire_corruption() {
    for (tag, input) in [
        (10, p(a(nebu::field::P - 1), a(1 << 32))),
        (11, p(a(0x8765_4321), a(0xfedc_ba98))),
        (12, p(a(0x8765_4321), a(0xfedc_ba98))),
        (14, p(a(0xffff_ffff), a(33))),
    ] {
        let f = op(tag, axis(2), axis(3));
        let r = compile(&f, &shape(&input)).unwrap();
        let x = inputs(&input);
        let (out, cost) = native(&f, &input, r.max_cost).unwrap();
        let w = r.witness(&x).unwrap();
        let count = 2 + x.len() + r.ops.len();
        for i in 0..count {
            let mut bad = w.clone();
            bad.z[i] += F::ONE;
            assert!(
                !r.verify_witness(&x, &out, cost, cost, &bad),
                "tag{tag} wire{i}"
            );
        }
        println!(
            "opcode{tag}: rows={}, columns={}, mutated_wires={count}, native_cost={cost}",
            r.instance.num_rows, r.instance.num_cols
        );
    }
}
#[test]
fn quoted_composition_preserves_mixed_subjects_and_gates_projection() {
    let choice = branch(axis(1), q(a(7)), q(p(a(8), a(9))));
    let identity = compose(choice.clone(), axis(1));
    check(&identity, &a(0), &a(7));
    check(&identity, &a(1), &p(a(8), a(9)));
    // Composed subject is [flag optional]. Guard optional-pair projection by
    // the original flag, now reached through the newly constructed subject.
    let subject = op(3, axis(1), choice.clone());
    let continuation = branch(axis(2), axis(3), axis(6));
    let f = compose(subject, continuation);
    let r = check(&f, &a(0), &a(7));
    check(&f, &a(1), &a(8));
    let second = compile(&f, &SubjectShape::Atom).unwrap();
    for (a, b) in r.instance.matrices.iter().zip(&second.instance.matrices) {
        assert_eq!(a.entries, b.entries);
    }
    let unguarded = compose(choice, axis(2));
    let r = check(&unguarded, &a(1), &a(8));
    assert!(native(&unguarded, &a(0), r.max_cost).is_none());
    assert!(!r.instance.is_satisfied_by(&r.witness(&[0]).unwrap()));
    println!(
        "guarded mixed composition: rows={}, columns={}",
        second.instance.num_rows, second.instance.num_cols
    );
}
#[test]
fn composed_hash_words_nested_continuations_and_inactive_malformed_match_native() {
    let choice = branch(axis(1), q(a(17)), q(p(a(19), a(23))));
    for continuation in [axis(0), p(a(15), axis(1))] {
        let f = compose(choice.clone(), continuation);
        for x in [0, 1] {
            let (out, _) = native(&f, &a(x), 1000).unwrap();
            check(&f, &a(x), &out);
        }
    }
    let words = compose(op(3, axis(1), q(a(31))), op(14, axis(2), axis(3)));
    check(&words, &a(3), &a(0x8000_0000));
    let nested = compose(
        op(5, axis(1), q(a(3))),
        compose(op(7, axis(1), q(a(2))), axis(1)),
    );
    check(&nested, &a(5), &a(16));
    // The constant RHS is a quote but its continuation is a malformed formula.
    let malformed = compose(q(a(3)), a(17));
    let guarded = branch(axis(1), q(a(7)), malformed);
    let r = check(&guarded, &a(0), &a(7));
    assert!(native(&guarded, &a(1), r.max_cost).is_none());
    assert!(!r.instance.is_satisfied_by(&r.witness(&[1]).unwrap()));
}
#[test]
fn computed_continuations_stay_unsupported_even_when_native_happens_to_be_static() {
    // Native RHS axis1 yields the identity formula from this particular input;
    // a verifier must not use that witness to select a different matrix.
    let f = op(2, q(a(29)), axis(1));
    assert_eq!(native(&f, &axis(1), 100).unwrap().0, a(29));
    assert!(matches!(
        compile(&f, &shape(&axis(1))),
        Err(Error::Unsupported(_))
    ));
    let indirect_quote = branch(q(a(0)), q(axis(1)), q(axis(1)));
    assert!(matches!(
        compile(&op(2, q(a(29)), indirect_quote), &SubjectShape::Atom),
        Err(Error::Unsupported(_))
    ));
}
