use super::build::Builder;
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
fn hash(n: Noun) -> Noun {
    p(a(15), n)
}
fn eq(a: Noun, b: Noun) -> Noun {
    p(Noun::Atom(9), p(a, b))
}
fn branch(t: Noun, y: Noun, n: Noun) -> Noun {
    p(a(4), p(t, p(y, n)))
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
fn native(f: &Noun, n: &Noun, budget: u64) -> (Noun, u64) {
    let mut r = Reduction::<8192>::new();
    let s = arena(&mut r, n);
    let f = arena(&mut r, f);
    match reduce(&mut r, s, f, budget, &NullCalls, &mut NoTrace) {
        Outcome::Ok(o, b) => (read(&r, o), budget - b),
        o => panic!("{o:?}"),
    }
}
fn check(f: &Noun, n: &Noun) -> TaggedRelation {
    let r = compile(f, &shape(n)).unwrap();
    let x = inputs(n);
    let (out, cost) = native(f, n, r.max_cost);
    let w = r.witness(&x).unwrap();
    assert!(r.verify_witness(&x, &out, cost, cost, &w));
    let pins = r.public_coordinates(&x, &out, cost, cost).unwrap();
    // Includes all four output limbs, tags, selected cost and public inputs.
    for (i, _) in pins {
        let mut bad = w.clone();
        bad.z[i] += F::ONE;
        assert!(
            !r.verify_witness(&x, &out, cost, cost, &bad),
            "public wire {i}"
        );
    }
    for i in [2 + x.len() + 20, 2 + x.len() + 200, 2 + x.len() + 900] {
        if i < 2 + x.len() + r.ops.len() {
            let mut bad = w.clone();
            bad.z[i] += F::ONE;
            assert!(!r.instance.is_satisfied_by(&bad), "hash intermediate {i}");
        }
    }
    r
}
#[test]
fn structural_axis_and_pattern_hash_match_native_framing_at_boundaries() {
    for x in [0, 1, (1 << 56) - 1, 1 << 56, nebu::field::P - 1] {
        for f in [axis(0), hash(axis(1))] {
            check(&f, &a(x));
        }
    }
    for n in [
        p(a(0), a(nebu::field::P - 1)),
        p(p(a(3), a(5)), a(7)),
        p(a(3), p(a(5), a(7))),
    ] {
        for f in [axis(0), hash(axis(1))] {
            let r = check(&f, &n);
            println!(
                "native hash subject {n:?}: rows={}, cols={}, max_cost={}",
                r.instance.num_rows, r.instance.num_cols, r.max_cost
            );
        }
    }
}
#[test]
fn hash_optional_topology_is_selected_with_all_four_digest_limbs() {
    let optional = branch(axis(1), q(a(17)), q(p(a(19), p(a(23), a(29)))));
    let f = hash(optional);
    let r = check(&f, &a(0));
    check(&f, &a(1));
    check(&f, &a(nebu::field::P - 1));
    let r2 = compile(&f, &SubjectShape::Atom).unwrap();
    for (a, b) in r.instance.matrices.iter().zip(&r2.instance.matrices) {
        assert_eq!(a.entries, b.entries);
    }
    let (out, cost) = native(&f, &a(0), r.max_cost);
    let w = r.witness(&[0]).unwrap();
    let mut forged = out.clone();
    let Noun::Pair(_, right) = &mut forged else {
        panic!()
    };
    let Noun::Pair(_, fourth) = right.as_mut() else {
        panic!()
    };
    let Noun::Atom(value) = fourth.as_mut() else {
        panic!()
    };
    *value = (*value + 1) % nebu::field::P;
    assert!(!r.verify_witness(&[0], &forged, cost, cost, &w));
    println!(
        "optional nested hash: rows={}, cols={}, max_cost={}",
        r.instance.num_rows, r.instance.num_cols, r.max_cost
    );
}
#[test]
fn native_equality_covers_atoms_pairs_optional_shapes_and_association() {
    for x in [0, nebu::field::P - 1] {
        check(&eq(axis(1), q(a(x))), &a(x));
        check(&eq(axis(1), q(a(3))), &a(x));
    }
    let l = p(p(a(1), a(2)), a(3));
    let r = p(a(1), p(a(2), a(3)));
    for (left, right) in [(l.clone(), l.clone()), (l, r), (a(0), p(a(0), a(0)))] {
        let f = eq(q(left), q(right));
        check(&f, &a(0));
    }
    let choice = branch(axis(1), q(a(0)), q(p(a(0), a(0))));
    let f = eq(choice, q(a(0)));
    check(&f, &a(0));
    check(&f, &a(1));
}
#[test]
fn equality_gadget_checks_fourth_limb_when_first_three_match() {
    let mut b = Builder::new(8);
    let unequal = b.digest_unequal([2, 3, 4, 5], [6, 7, 8, 9]).unwrap();
    let out = b.node(ZERO, unequal, None).unwrap();
    let r = b.finish(out, ONE, 1).unwrap();
    for fourth in [4, 5, nebu::field::P - 1] {
        let input = [1, 2, 3, 4, 1, 2, 3, fourth];
        let result = u64::from(fourth != 4);
        let w = r.witness(&input).unwrap();
        assert!(r.verify_witness(&input, &a(result), 1, 1, &w));
        assert!(!r.verify_witness(&input, &a(1 - result), 1, 1, &w));
        let mut bad = w;
        bad.z[r.output.value] = F::new(1 - result);
        assert!(!r.instance.is_satisfied_by(&bad));
    }
}
#[test]
fn canonical_byte_decomposition_rejects_coherent_mod_p_aliases() {
    let mut b = Builder::new(1);
    b.canonical_bits(2).unwrap();
    let out = b.node(ZERO, 2, None).unwrap();
    let r = b.finish(out, ONE, 1).unwrap();
    for x in [0, 1, (1u64 << 32) - 2] {
        let w = r.witness(&[x]).unwrap();
        assert!(r.verify_witness(&[x], &a(x), 1, 1, &w));
        let alias = nebu::field::P.checked_add(x).unwrap();
        let mut bad = w.clone();
        // Recompute EVERY dependent gate from deliberately noncanonical bits,
        // leaving the bound field input unchanged. Only the <p constraint fails.
        for (offset, op) in r.ops.iter().enumerate() {
            let value = match op {
                Op::Bit(source, k) => {
                    assert_eq!(*source, 2);
                    F::new((alias >> k) & 1)
                }
                Op::Linear(l) => l.iter().fold(F::ZERO, |s, &(i, c)| s + bad.z[i] * c),
                Op::Product(a, b) => bad.z[*a] * bad.z[*b],
                Op::Inverse(i) => {
                    if bad.z[*i] == F::ZERO {
                        F::ZERO
                    } else {
                        bad.z[*i].inv()
                    }
                }
            };
            bad.z[3 + offset] = value;
        }
        let failed = (0..r.instance.num_rows)
            .filter(|&row| {
                let values: Vec<_> = r
                    .instance
                    .matrices
                    .iter()
                    .map(|m| {
                        m.entries[row]
                            .iter()
                            .fold(F::ZERO, |s, &(i, c)| s + bad.z[i] * c)
                    })
                    .collect();
                values[0] * values[1] != values[2]
            })
            .count();
        assert_eq!(failed, 1, "canonical range row alone must reject alias");
        assert!(!r.verify_witness(&[x], &a(x), 1, 1, &bad));
    }
}
#[test]
fn digest_memoization_is_stable_and_large_hashes_fail_at_gate_budget() {
    let mut b = Builder::new(1);
    let obj = b.subject(&SubjectShape::Atom, &mut 2).unwrap();
    let first = b.structural_digest(&obj).unwrap();
    let second = b.structural_digest(&obj).unwrap();
    assert_eq!(first, second);
    let out = b.digest_noun(first, ONE).unwrap();
    let cached = b.finish(out, ONE, 1).unwrap();
    let direct = compile(&axis(0), &SubjectShape::Atom).unwrap();
    assert_eq!(cached.ops.len(), direct.ops.len());
    assert_eq!(cached.instance.num_rows, direct.instance.num_rows);
    let mut noun = a(0);
    for i in 1..18 {
        noun = p(a(i), noun);
    }
    assert!(matches!(
        compile(&hash(q(noun)), &SubjectShape::Atom),
        Err(Error::Limit)
    ));
    // Total inverse at zero has no free nonzero witness.
    let mut b = Builder::new(1);
    let (inv, _) = b.inverse_or_zero(2).unwrap();
    let out = b.node(ZERO, inv, None).unwrap();
    let r = b.finish(out, ONE, 1).unwrap();
    let w = r.witness(&[0]).unwrap();
    assert!(r.verify_witness(&[0], &a(0), 1, 1, &w));
    let mut bad = w;
    bad.z[inv] = F::ONE;
    assert!(!r.instance.is_satisfied_by(&bad));
}

#[test]
fn absent_child_corruption_cannot_hide_behind_atom_hash_selection() {
    let mut b = Builder::new(1);
    let tag = b.lin(vec![(2, F::ONE)]).unwrap();
    let atom_value = b.lin(vec![(ONE, F::new(17)), (tag, -F::new(17))]).unwrap();
    let left_value = b.lin(vec![(tag, F::new(3))]).unwrap();
    let right_value = b.lin(vec![(tag, F::new(5))]).unwrap();
    let child_tag = b.lin(vec![(ZERO, F::ONE)]).unwrap();
    let left = b.node(child_tag, left_value, None).unwrap();
    let right = b.node(ZERO, right_value, None).unwrap();
    let optional = b.node(tag, atom_value, Some((left, right))).unwrap();
    let digest = b.structural_digest(&optional).unwrap();
    let output = b.digest_noun(digest, ONE).unwrap();
    let r = b.finish(output, ONE, 1).unwrap();
    let expected = hemera_digest_noun(nox::data::hash::hash_atom(F::new(17)));
    let w = r.witness(&[0]).unwrap();
    assert!(r.verify_witness(&[0], &expected, 1, 1, &w));
    for forced in [left_value, child_tag] {
        let mut bad = w.clone();
        // Recompute all hash rounds from a corrupted absent child. The selected
        // atom digest remains identical, so carrier rows must reject it.
        for (offset, op) in r.ops.iter().enumerate() {
            let i = 3 + offset;
            bad.z[i] = if i == forced {
                F::ONE
            } else {
                match op {
                    Op::Bit(a, k) => F::new((bad.z[*a].canonicalize().as_u64() >> k) & 1),
                    Op::Linear(l) => l.iter().fold(F::ZERO, |s, &(j, c)| s + bad.z[j] * c),
                    Op::Product(a, b) => bad.z[*a] * bad.z[*b],
                    Op::Inverse(a) => {
                        if bad.z[*a] == F::ZERO {
                            F::ZERO
                        } else {
                            bad.z[*a].inv()
                        }
                    }
                }
            };
        }
        for i in digest {
            assert_eq!(
                w.z[i], bad.z[i],
                "unselected branch must not change atom identity"
            );
        }
        assert!(!r.instance.is_satisfied_by(&bad));
        assert!(!r.verify_witness(&[0], &expected, 1, 1, &bad));
    }
    let mut bad = w;
    bad.z[tag] = F::ONE;
    assert!(!r.instance.is_satisfied_by(&bad));
}
fn hemera_digest_noun(d: [F; 4]) -> Noun {
    p(
        p(a(d[0].as_u64()), a(d[1].as_u64())),
        p(a(d[2].as_u64()), a(d[3].as_u64())),
    )
}
