//! The hemera node jet (`execution::node`): the compiled relation agrees
//! with native nox (the formula reduced by `nox::reduce`, pure Layer 1) and
//! with hemera on random Merkle paths — output and cycles — and a path
//! with a tampered sibling, a flipped direction or a wrong flag does not
//! verify, natively or by proof.
mod common;

use common::{node_merkle_program, node_merkle_root};
use nebu::Goldilocks as F;
use zheng::envelope::{Envelope, SuccinctStatement};
use zheng::execution::relation::{SubjectShape, compile_relation};
use zheng::execution::{ExecutionNoun as N, node, succinct};

const BUDGET: u64 = 1 << 40;

fn pr(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}
fn at(v: u64) -> N {
    N::Atom(v)
}
fn ax(n: u64) -> N {
    pr(at(0), at(n))
}
fn op(t: u64, a: N, b: N) -> N {
    pr(at(t), pr(a, b))
}
fn q(x: N) -> N {
    pr(at(1), x)
}

/// Native nox, pure Layer 1, on the subject `[in0 [in1 … 0]]`: the output
/// noun and the cycles spent (a wide arena on a wide stack: one node is
/// ~29k reductions).
fn nox_run(program: &N, input: &[u64]) -> Result<(N, u64), String> {
    fn into<const S: usize>(r: &mut nox::Reduction<S>, n: &N) -> nox::Order {
        match n {
            N::Atom(v) => r.atom(F::new(*v)).expect("arena"),
            N::Pair(a, b) => {
                let (a, b) = (into(r, a), into(r, b));
                r.pair(a, b).expect("arena")
            }
        }
    }
    fn out<const S: usize>(r: &nox::Reduction<S>, o: nox::Order) -> N {
        match r.get(o).expect("noun").inner {
            nox::data::Data::Pair { left, right } => pr(out(r, left), out(r, right)),
            _ => N::Atom(r.atom_value(o).expect("atom").as_u64()),
        }
    }
    let subject = input.iter().rev().fold(at(0), |s, &v| pr(at(v), s));
    let program = program.clone();
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            let mut r = Box::new(nox::Reduction::<{ 1 << 21 }>::new());
            let s = into(&mut r, &subject);
            let f = into(&mut r, &program);
            match nox::reduce(
                &mut r,
                s,
                f,
                BUDGET,
                &nox::call::NullCalls,
                &mut nox::trace::NoTrace,
            ) {
                nox::Outcome::Ok(o, left) => Ok((out(&r, o), BUDGET - left)),
                other => Err(format!("{other:?}")),
            }
        })
        .expect("thread")
        .join()
        .expect("nox")
}

/// The input subject's axis of input `k`.
fn input(k: usize) -> N {
    ax((1u64 << (k + 2)) - 2)
}

/// A Merkle path whose leaf digest, siblings and directions are all program
/// INPUTS (the membership witness), in the shape of `node_merkle_program`:
/// inputs = leaf limbs (4), then per level 4 sibling limbs and a direction.
/// The output is the computed root (`flags` overrides the root's flag).
fn witness_path_program(levels: usize, root_flags: u64) -> N {
    let digest = |k: usize| {
        op(
            3,
            op(3, input(k), input(k + 1)),
            op(3, input(k + 2), input(k + 3)),
        )
    };
    let mut path = q(at(0));
    for i in (0..levels).rev() {
        let base = 4 + 5 * i;
        path = op(3, op(3, digest(base), input(base + 4)), path);
    }
    let level = |flags: u64| {
        let children = pr(
            at(4),
            pr(ax(25), pr(op(3, ax(24), ax(2)), op(3, ax(2), ax(24)))),
        );
        let next = op(2, op(3, children, q(at(flags))), ax(14));
        op(3, next, op(3, ax(13), ax(7)))
    };
    let lib = pr(
        node::formula().clone(),
        pr(level(node::FLAGS_NODE), level(root_flags)),
    );
    let start = op(3, digest(0), op(3, path, q(lib)));
    let step = |axis: u64| op(2, ax(1), ax(axis));
    let mut steps = step(31);
    for _ in 1..levels {
        steps = op(2, step(30), q(steps));
    }
    let folded = op(2, start, q(steps));
    op(2, folded, q(ax(2)))
}

fn splitmix(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

struct Path {
    leaf: [u64; 4],
    levels: Vec<([u64; 4], u64)>,
}

impl Path {
    fn random(levels: usize, seed: &mut u64) -> Self {
        let leaf = core::array::from_fn(|_| splitmix(seed) % nebu::field::P);
        let levels = (0..levels)
            .map(|_| {
                let sib = core::array::from_fn(|_| splitmix(seed) % nebu::field::P);
                (sib, splitmix(seed) & 1)
            })
            .collect();
        Self { leaf, levels }
    }
    fn inputs(&self) -> Vec<u64> {
        let mut v = self.leaf.to_vec();
        for (sib, dir) in &self.levels {
            v.extend_from_slice(sib);
            v.push(*dir);
        }
        v
    }
    /// hemera's root: `hash_node`, the root flag on the last level.
    fn root(&self) -> [u64; 4] {
        let n = self.levels.len();
        let mut cur = self.leaf;
        for (i, (sib, dir)) in self.levels.iter().enumerate() {
            let flags = if i + 1 == n {
                node::FLAGS_ROOT
            } else {
                node::FLAGS_NODE
            };
            cur = if *dir == 0 {
                node::native(*sib, cur, flags)
            } else {
                node::native(cur, *sib, flags)
            };
        }
        cur
    }
}

fn digest_of(n: &N) -> [u64; 4] {
    let N::Pair(ab, cd) = n else { panic!("digest") };
    let (N::Pair(a, b), N::Pair(c, d)) = (&**ab, &**cd) else {
        panic!("digest")
    };
    let v = |x: &N| match x {
        N::Atom(v) => *v,
        _ => panic!("limb"),
    };
    [v(a), v(b), v(c), v(d)]
}

/// Compiled relation (witness of the inputs) → output digest and cycles.
fn compiled(program: &N, inputs: &[u64]) -> ([u64; 4], u64) {
    let shape = inputs.iter().fold(SubjectShape::Atom, |s, _| {
        SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(s))
    });
    let relation = compile_relation(program, &shape).expect("compile");
    let mut z_in: Vec<F> = inputs.iter().map(|&v| F::new(v)).collect();
    z_in.push(F::ZERO);
    let w = relation.witness(&z_in).expect("witness");
    assert!(relation.instance.is_satisfied_by(&w));
    let out: Vec<u64> = relation
        .output_indices
        .iter()
        .map(|&i| w.z[i].as_u64())
        .collect();
    (
        out.try_into().expect("four limbs"),
        w.z[relation.cost_index].as_u64(),
    )
}

#[test]
fn compiled_paths_equal_native_nox_and_hemera_on_random_paths() {
    let mut seed = 0x5eed;
    for levels in [1, 2, 3, 5] {
        for _ in 0..3 {
            let path = Path::random(levels, &mut seed);
            let program = witness_path_program(levels, node::FLAGS_ROOT);
            let inputs = path.inputs();
            let (native_out, native_cycles) = nox_run(&program, &inputs).expect("native");
            let (out, cycles) = compiled(&program, &inputs);
            assert_eq!(
                digest_of(&native_out),
                path.root(),
                "native nox = hemera, depth {levels}"
            );
            assert_eq!(out, path.root(), "relation = hemera, depth {levels}");
            assert_eq!(
                cycles, native_cycles,
                "relation cycles = nox cycles, depth {levels}"
            );
        }
    }
}

#[test]
fn fixture_root_matches_native_nox_and_the_check_passes() {
    for levels in [1, 4, 12] {
        let (out, cycles) = nox_run(&node_merkle_program(levels, None), &[5]).expect("native");
        assert_eq!(
            digest_of(&out),
            node_merkle_root(levels, 5),
            "depth {levels}"
        );
        let root = zheng::execution::node::digest_noun(node_merkle_root(levels, 5));
        let check = node_merkle_program(levels, Some(&root));
        let (ok, check_cycles) = nox_run(&check, &[5]).expect("native");
        assert_eq!(ok, N::Atom(0), "path verifies natively, depth {levels}");
        let (statement, proof) =
            succinct::prove_with(&check, &[5], BUDGET, succinct::device_params).expect("prove");
        assert_eq!(statement.public_output, vec![0], "depth {levels}");
        assert_eq!(statement.cycles, check_cycles, "cycles, depth {levels}");
        let e = Envelope::Succinct {
            statement: SuccinctStatement::Execution(statement),
            proof,
        };
        Envelope::from_bytes(&e.to_bytes())
            .unwrap()
            .verify(None)
            .expect("verify");
        assert!(cycles > 0);
    }
}

#[test]
fn tampered_sibling_flipped_direction_and_wrong_flag_do_not_verify() {
    let mut seed = 0xbad;
    let levels = 4;
    let path = Path::random(levels, &mut seed);
    let root = path.root();
    let program = witness_path_program(levels, node::FLAGS_ROOT);
    let honest = path.inputs();
    let mut forged = vec![];
    for level in 0..levels {
        for limb in 0..4 {
            let mut v = honest.clone();
            v[4 + 5 * level + limb] = (v[4 + 5 * level + limb] + 1) % nebu::field::P;
            forged.push(("sibling", v));
        }
        let mut v = honest.clone();
        v[4 + 5 * level + 4] ^= 1;
        forged.push(("direction", v));
    }
    for (what, inputs) in &forged {
        let (out, _) = compiled(&program, inputs);
        assert_ne!(out, root, "a tampered {what} reaches the root");
        let (native_out, _) = nox_run(&program, inputs).unwrap();
        assert_eq!(
            digest_of(&native_out),
            out,
            "relation follows nox on the tampered {what}"
        );
    }
    // the root flag is part of the function: an interior flag at the top
    let interior = witness_path_program(levels, node::FLAGS_NODE);
    assert_ne!(compiled(&interior, &honest).0, root);
}

#[test]
fn a_proof_cannot_claim_the_root_for_a_tampered_path() {
    let mut seed = 0xface;
    let levels = 3;
    let path = Path::random(levels, &mut seed);
    let root = path.root();
    let program = witness_path_program(levels, node::FLAGS_ROOT);
    let mut inputs = path.inputs();
    inputs[4] = (inputs[4] + 1) % nebu::field::P;
    let (mut statement, proof) =
        succinct::prove_with(&program, &inputs, BUDGET, succinct::device_params).expect("prove");
    assert_ne!(statement.public_output, root.to_vec());
    let honest = Envelope::Succinct {
        statement: SuccinctStatement::Execution(statement.clone()),
        proof: proof.clone(),
    };
    honest
        .verify(None)
        .expect("the tampered path's own root verifies");
    statement.public_output = root.to_vec();
    let forged = Envelope::Succinct {
        statement: SuccinctStatement::Execution(statement),
        proof,
    };
    assert!(
        forged.verify(None).is_err(),
        "claimed the honest root for a tampered path"
    );
}

#[test]
fn a_node_subject_of_another_shape_fails_closed_like_nox() {
    // [[L R] flags] with L an atom: nox fails (axis into an atom); so does the compiler
    let bad = op(
        2,
        q(pr(pr(at(1), node::digest_noun([1, 2, 3, 4])), at(2))),
        q(node::formula().clone()),
    );
    assert!(nox_run(&bad, &[0]).is_err());
    assert!(
        compile_relation(
            &bad,
            &SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom))
        )
        .is_err()
    );
    // a pair where the flags atom belongs
    let bad = op(
        2,
        q(pr(
            pr(
                node::digest_noun([1, 2, 3, 4]),
                node::digest_noun([5, 6, 7, 8]),
            ),
            pr(at(2), at(2)),
        )),
        q(node::formula().clone()),
    );
    assert!(nox_run(&bad, &[0]).is_err());
    assert!(
        compile_relation(
            &bad,
            &SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom))
        )
        .is_err()
    );
}

#[test]
fn one_level_costs_one_permutation() {
    // wires and rows of the depth-d fixture grow by one permutation, the
    // direction mux and the subject plumbing per level, never by a
    // structural hash
    let size = |levels: usize| {
        let r = compile_relation(
            &node_merkle_program(levels, None),
            &SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom)),
        )
        .unwrap();
        r.instance.matrices[0]
            .entries
            .iter()
            .filter(|e| !e.is_empty())
            .count()
            + r.instance.matrices[3]
                .entries
                .iter()
                .filter(|e| !e.is_empty())
                .count()
    };
    let per_level = (size(9) - size(1)) / 8;
    println!("rows per level: {per_level}");
    assert!(per_level < 260, "{per_level} rows per level");
}

#[test]
fn nox_depth_limit_does_not_bind_inside_the_node() {
    const WRAP: usize = 640;
    // The compiler evaluates at most 128 nested formulas; nox refuses past
    // 1,000. The node formula must reduce natively when entered at any
    // depth the compiler admits, or the relation would accept a program
    // nox rejects: entered under WRAP = 640 nested cons operands (each one nox
    // level) it still reduces, to the same digest.
    let l = [1, 2, 3, 4];
    let r = [5, 6, 7, 8];
    let call = op(
        2,
        q(pr(
            pr(node::digest_noun(l), node::digest_noun(r)),
            at(node::FLAGS_ROOT),
        )),
        q(node::formula().clone()),
    );
    let mut program = call;
    for _ in 0..WRAP {
        program = op(3, program, q(at(0)));
    }
    let (out, _) = nox_run(&program, &[0]).expect("nox under WRAP levels");
    let mut v = &out;
    for _ in 0..WRAP {
        let N::Pair(a, _) = v else { panic!("wrapper") };
        v = a;
    }
    assert_eq!(digest_of(v), node::native(l, r, node::FLAGS_ROOT));
}

#[test]
fn zheng_machine_runs_the_node_formula_to_the_same_root() {
    let levels = 2;
    let program = node_merkle_program(levels, None);
    let run = zheng::machine::execute(&program, &[5], BUDGET).expect("machine");
    let out = zheng::machine::statement::parse(&run.statement.output).expect("output");
    assert_eq!(digest_of(&out), node_merkle_root(levels, 5));
    let (_, cycles) = nox_run(&program, &[5]).unwrap();
    assert_eq!(run.statement.cycles, cycles);
}
