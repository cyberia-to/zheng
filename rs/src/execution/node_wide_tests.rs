use super::*;
use crate::execution::node::{self, tests::nox_run, tests::nox_run_jets_with, tests::limbs};
use crate::execution::relation::{SubjectShape, compile_relation};
use nebu::Goldilocks as F;

fn limbs8(seed: &mut u64) -> [u64; 8] {
    let (a, b) = (limbs(seed), limbs(seed));
    core::array::from_fn(|i| if i < 4 { a[i] } else { b[i - 4] })
}

fn subject(l: [u64; 8], r: [u64; 8], flags: u64) -> N {
    pr(pr(digest_noun(l), digest_noun(r)), at(flags))
}

#[test]
fn native_is_two_hemera_permutations_over_the_rate() {
    let mut seed = 3;
    for _ in 0..8 {
        let (l, r) = (limbs8(&mut seed), limbs8(&mut seed));
        for flags in [FLAGS_NODE, FLAGS_ROOT] {
            // the definition, step by step through hemera
            let mut s = [H::ZERO; 16];
            for i in 0..8 {
                s[i] = H::new(l[i]);
            }
            s[9] = H::new(flags);
            hemera::permutation::permute(&mut s);
            let mut t = s;
            for i in 0..8 {
                t[i] = s[i] + H::new(r[i]);
            }
            hemera::permutation::permute(&mut t);
            let want: [u64; 8] = core::array::from_fn(|i| t[i].as_canonical_u64());
            assert_eq!(native(l, r, flags), want);
            // every limb canonical
            assert!(want.iter().all(|&v| v < nebu::field::P));
        }
        // the flags, the order and every limb of both children matter
        assert_ne!(native(l, r, FLAGS_NODE), native(l, r, FLAGS_ROOT));
        assert_ne!(native(l, r, FLAGS_NODE), native(r, l, FLAGS_NODE));
        for k in 0..8 {
            let mut l2 = l;
            l2[k] = (l2[k] + 1) % nebu::field::P;
            assert_ne!(native(l2, r, FLAGS_NODE), native(l, r, FLAGS_NODE), "left limb {k}");
            let mut r2 = r;
            r2[k] = (r2[k] + 1) % nebu::field::P;
            assert_ne!(native(l, r2, FLAGS_NODE), native(l, r, FLAGS_NODE), "right limb {k}");
        }
    }
    // the wide bit keeps the first permutation's input apart from a
    // narrow node's over the same limbs
    assert_eq!(FLAGS_NODE & FLAGS_WIDE, FLAGS_WIDE);
    assert_eq!(FLAGS_ROOT & FLAGS_WIDE, FLAGS_WIDE);
    assert_ne!(FLAGS_NODE, node::FLAGS_NODE);
    assert_ne!(FLAGS_ROOT, node::FLAGS_ROOT);
}

#[test]
fn the_formula_is_the_wide_node_and_its_cost_is_constant() {
    let mut seed = 17;
    let mut cases = vec![
        ([0; 8], [0; 8], FLAGS_NODE),
        ([nebu::field::P - 1; 8], [1, 0, 0, 0, 0, 0, 0, 0], FLAGS_ROOT),
    ];
    for k in 0..4 {
        cases.push((
            limbs8(&mut seed),
            limbs8(&mut seed),
            if k % 2 == 0 { FLAGS_NODE } else { FLAGS_ROOT },
        ));
    }
    for (l, r, flags) in cases {
        let (output, cost) =
            nox_run(&subject(l, r, flags), formula()).expect("wide node formula reduces");
        assert_eq!(output, digest_noun(native(l, r, flags)), "{l:?} {r:?} {flags}");
        assert_eq!(cost, COST, "cycles");
    }
}

#[test]
fn the_formula_fits_a_program() {
    let tokens = crate::execution::ExecutionStatement::encode_program(formula()).unwrap();
    println!("wide node formula {} nodes", tokens.len());
    assert!(tokens.len() <= 2_900, "{} nodes", tokens.len());
    assert!(tokens.len() > crate::execution::ExecutionStatement::encode_program(node::formula()).unwrap().len());
}

#[test]
fn the_nox_jet_equals_the_formula_and_declines_off_shape() {
    let mut seed = 23;
    let register = |reg: &mut nox::JetRegistry<{ 1 << 20 }>| jet::register(reg);
    for flags in [FLAGS_NODE, FLAGS_ROOT, 0, nebu::field::P - 1] {
        let s = subject(limbs8(&mut seed), limbs8(&mut seed), flags);
        assert_eq!(nox_run_jets_with(&s, formula(), register), nox_run(&s, formula()));
    }
    // off shape: a narrow digest, a pair for flags, an atom child
    for bad in [
        pr(pr(node::digest_noun([1, 2, 3, 4]), digest_noun([5; 8])), at(FLAGS_NODE)),
        pr(pr(digest_noun([1; 8]), digest_noun([2; 8])), pr(at(2), at(2))),
        pr(pr(digest_noun([1; 8]), at(7)), at(FLAGS_NODE)),
    ] {
        let pure = nox_run(&bad, formula());
        assert!(pure.is_err());
        assert_eq!(nox_run_jets_with(&bad, formula(), register), pure);
    }
}

/// The compiled relation (two permutation gadgets) is the formula: output
/// and cycles on random subjects, every limb an input.
#[test]
fn the_compiled_relation_is_the_formula() {
    // inputs: l0..l7, r0..r7, flags, as the subject [in0 [in1 … 0]]
    let input = |k: u64| ax((1u64 << (k + 2)) - 2);
    let digest = |k: u64| {
        let half = |k: u64| cons(cons(input(k), input(k + 1)), cons(input(k + 2), input(k + 3)));
        cons(half(k), half(k + 4))
    };
    let program = compose(cons(cons(digest(0), digest(8)), input(16)), q(formula().clone()));
    let shape = (0..17).fold(SubjectShape::Atom, |s, _| SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(s)));
    let relation = compile_relation(&program, &shape).expect("compile");
    // 17 axes, 16 conses, the compose and the quote, then the jet
    assert_eq!(relation.max_cost, COST + 17 + 16 + 1 + 1, "axes, conses, compose, quote and the jet");
    let mut seed = 29;
    for flags in [FLAGS_NODE, FLAGS_ROOT] {
        let (l, r) = (limbs8(&mut seed), limbs8(&mut seed));
        let mut z: Vec<F> = l.iter().chain(&r).map(|&v| F::new(v)).collect();
        z.push(F::new(flags));
        z.push(F::ZERO);
        let w = relation.witness(&z).expect("witness");
        assert!(relation.instance.is_satisfied_by(&w));
        let out: Vec<u64> = relation.output_indices.iter().map(|&i| w.z[i].as_u64()).collect();
        assert_eq!(out, native(l, r, flags).to_vec());
        let want = nox_run(&subject(l, r, flags), formula()).expect("nox");
        assert_eq!(digest_noun(out.try_into().unwrap()), want.0);
        // a forged output limb and a forged inner wire do not satisfy
        for &i in &[relation.output_indices[0], relation.output_indices[7], relation.output_indices[0] / 2] {
            let mut bad = w.clone();
            bad.z[i] += F::ONE;
            assert!(!relation.instance.is_satisfied_by(&bad), "wire {i}");
        }
    }
    println!("wide node relation: {} rows, {} wires", relation.instance.num_rows, relation.instance.num_cols);
}
