//! Fixtures shared by the succinct-profile tests and the bake-off example:
//! joy's compiled `hash.tri` and `add.tri`, a chain of hemera hashes built
//! for the relation compiler, and synthetic CCS relations of a given size.
#![allow(dead_code)]

use nebu::Goldilocks as F;
use zheng::execution::ExecutionNoun;
use zheng::types::{CCSInstance, SparseMatrix};

/// joy 0.5 `hash.tri`, as compiled.
pub const HASH: &str = "[2 [[3 [[4 [[9 [[0 3] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [1 0]]] [1 [15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]]]]]]]]]]]]";
/// joy 0.5 `add.tri`, as compiled.
pub const ADD: &str = "[2 [[3 [[4 [[9 [[0 7] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [3 [[5 [[0 6] [1 0]]] [1 0]]]]] [1 [2 [[3 [[5 [[0 2] [1 0]]] [0 1]]] [1 [7 [[0 2] [0 14]]]]]]]]]]]]]]]";

pub const P: u64 = 0xFFFF_FFFF_0000_0001;

pub fn parse(text: &str) -> ExecutionNoun {
    fn go(b: &[u8], p: &mut usize) -> ExecutionNoun {
        while b[*p].is_ascii_whitespace() {
            *p += 1;
        }
        if b[*p] == b'[' {
            *p += 1;
            let a = go(b, p);
            let c = go(b, p);
            while b[*p].is_ascii_whitespace() {
                *p += 1;
            }
            *p += 1;
            ExecutionNoun::Pair(Box::new(a), Box::new(c))
        } else {
            let s = *p;
            while b[*p].is_ascii_digit() {
                *p += 1;
            }
            ExecutionNoun::Atom(std::str::from_utf8(&b[s..*p]).unwrap().parse().unwrap())
        }
    }
    go(text.as_bytes(), &mut 0)
}

fn pair(a: ExecutionNoun, b: ExecutionNoun) -> ExecutionNoun {
    ExecutionNoun::Pair(Box::new(a), Box::new(b))
}
fn op(tag: u64, arg: ExecutionNoun) -> ExecutionNoun {
    pair(ExecutionNoun::Atom(tag), arg)
}
fn axis(a: u64) -> ExecutionNoun {
    op(0, ExecutionNoun::Atom(a))
}
fn quote(v: u64) -> ExecutionNoun {
    op(1, ExecutionNoun::Atom(v))
}
/// `[3 [a [3 [b … [3 [g h]]]]]]`: the 8-element hash input.
fn cons8(items: Vec<ExecutionNoun>) -> ExecutionNoun {
    let mut it = items.into_iter().rev();
    let mut acc = it.next().unwrap();
    for x in it {
        acc = op(3, pair(x, acc));
    }
    acc
}
/// `[2 [x [1 y]]]`: run `x` on the subject, then `y` on its result.
fn compose(x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    op(2, pair(x, op(1, y)))
}

/// `n` chained hemera hashes: `d_1 = H(a, 0⁷)`, `d_{i+1} = H(d_i, 0⁴)`, over
/// the subject `[a 0]`; a digest is the noun `[[d0 d1] [d2 d3]]` (axes 4–7). Composition is balanced so the formula depth stays
/// `O(log n)` within the statement's depth limit. Each hash of a digest
/// costs ~2,670 wires; the compiler's cap of 32,768 ops/rows admits
/// `n ≤ 11` (27,520 free wires).
pub fn hash_chain(n: usize) -> ExecutionNoun {
    assert!(n >= 1);
    let first = op(
        15,
        cons8(std::iter::once(axis(2)).chain((0..7).map(|_| quote(0))).collect()),
    );
    let step = || {
        op(
            15,
            cons8(
                [4, 5, 6, 7]
                    .into_iter()
                    .map(axis)
                    .chain((0..4).map(|_| quote(0)))
                    .collect(),
            ),
        )
    };
    fn tree(lo: usize, hi: usize, leaf: &dyn Fn(usize) -> ExecutionNoun) -> ExecutionNoun {
        if hi - lo == 1 {
            return leaf(lo);
        }
        let mid = lo + (hi - lo) / 2;
        compose(tree(lo, mid, leaf), tree(mid, hi, leaf))
    }
    let leaf = |i: usize| if i == 0 { first.clone() } else { step() };
    tree(0, n, &leaf)
}

/// A synthetic relation with `2^k` rows and `2^k` columns in the shape the
/// compiler emits (five matrices: `a·b = c` and `x^7 = w`):
/// `z = (1, x, w_2, …, w_{2^k−1})`, row `r` defines `w_{r+2}` as
/// `(w_{r+1} + (r+1))^7` for even `r` and `w_{r+1} · w_r` for odd `r`.
/// Pinned: `z[0] = 1`, the input `z[1]` and the output `z[2^k − 1]`.
pub struct Synthetic {
    pub instance: CCSInstance,
    pub z: Vec<F>,
    pub pins: Vec<(usize, F)>,
    pub statement: Vec<u8>,
}

pub fn synthetic(k: u32, x: u64) -> Synthetic {
    let n = 1usize << k;
    let mut m = vec![SparseMatrix::new(n, n); 5];
    let mut z = vec![F::ZERO; n];
    z[0] = F::ONE;
    z[1] = F::new(x);
    for r in 0..n - 2 {
        if r % 2 == 0 {
            let c = F::new(r as u64 + 1);
            m[3].set(r, r + 1, F::ONE);
            m[3].set(r, 0, c);
            m[4].set(r, r + 2, F::ONE);
            z[r + 2] = (z[r + 1] + c).exp(7);
        } else {
            m[0].set(r, r + 1, F::ONE);
            m[1].set(r, r, F::ONE);
            m[2].set(r, r + 2, F::ONE);
            z[r + 2] = z[r + 1] * z[r];
        }
    }
    let instance = CCSInstance {
        matrices: m,
        multisets: vec![vec![0, 1], vec![2], vec![3; 7], vec![4]],
        coeffs: vec![F::ONE, -F::ONE, F::ONE, -F::ONE],
        num_rows: n,
        num_cols: n,
    };
    let pins = vec![(0, F::ONE), (1, z[1]), (n - 1, z[n - 1])];
    let mut statement = b"zheng-synthetic-v1".to_vec();
    statement.extend((k as u64).to_le_bytes());
    for &(_, v) in &pins[1..] {
        statement.extend(v.as_u64().to_le_bytes());
    }
    Synthetic {
        instance,
        z,
        pins,
        statement,
    }
}

/// Run `program` on the subject `[input… 0]` with native nox; returns the
/// output atoms (left to right) and the reductions spent.
pub fn native(program: &ExecutionNoun, input: &[u64], budget: u64) -> (Vec<u64>, u64) {
    fn arena(r: &mut nox::Reduction<8192>, n: &ExecutionNoun) -> nox::Order {
        match n {
            ExecutionNoun::Atom(v) => r.atom(F::new(*v)).unwrap(),
            ExecutionNoun::Pair(a, b) => {
                let a = arena(r, a);
                let b = arena(r, b);
                r.pair(a, b).unwrap()
            }
        }
    }
    fn leaves(r: &nox::Reduction<8192>, n: nox::Order, out: &mut Vec<u64>) {
        match r.atom_value(n) {
            Some(v) => out.push(v.as_u64()),
            None => {
                leaves(r, r.head(n).unwrap(), out);
                leaves(r, r.tail(n).unwrap(), out);
            }
        }
    }
    let mut subject = ExecutionNoun::Atom(0);
    for &v in input.iter().rev() {
        subject = pair(ExecutionNoun::Atom(v), subject);
    }
    let mut r = Box::new(nox::Reduction::<8192>::new());
    let s = arena(&mut r, &subject);
    let f = arena(&mut r, program);
    match nox::reduce(&mut r, s, f, budget, &nox::call::NullCalls, &mut nox::trace::NoTrace) {
        nox::Outcome::Ok(out, remaining) => {
            let mut atoms = Vec::new();
            leaves(&r, out, &mut atoms);
            (atoms, budget - remaining)
        }
        other => panic!("native nox: {other:?}"),
    }
}
