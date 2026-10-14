//! The hemera node jet: one hemera compression of two 4-limb digests.
//!
//! `node([[L R] flags]) = permute(L ‖ R ‖ 0 ‖ flags ‖ 0⁶)[0..4]` as the
//! digest noun `[[o0 o1] [o2 o3]]`, where `L = [[l0 l1] [l2 l3]]` and `R`
//! are digest nouns and `flags` sits in capacity lane 9. With `flags = 2`
//! this is `hemera::tree::hash_node(L, R, false)` — `nox::data::hash::
//! hash_pair` on raw digests — and with `flags = 3` the root node
//! (`is_root = true`): one hemera Merkle level of `hemera::merkle`, the
//! tree bbg's paths use.
//!
//! Semantics are a pure Layer-1 nox formula, [`formula`]: the permutation
//! written in nox arithmetic (add, mul, eq, branch, compose; the partial
//! round's inverse is `x^(p−2)` by square-and-multiply, so `0 ↦ 0` as in
//! hemera). Any nox reducer runs it and gets the same digest and the same
//! cost, [`COST`], whatever the input (every branch tests a constant of the
//! formula, never data). The relation compiler recognises the formula and
//! emits one permutation gadget over the eight limbs instead of compiling
//! the arithmetic (`relation::node_gadget`); the gadget is the same
//! function, so the compiled relation keeps nox's input → output and cost.
//!
//! Compared with pattern 15 on `[L R]` (structural hashing: every atom
//! bit-decomposed and hashed by two permutations, then the pair node and
//! the sponge, 24 permutations and 512 bit wires for two digests), one
//! node is one permutation and no bit wires. The two are different
//! functions: a program chooses which tree it verifies.
use super::ExecutionNoun as N;
use hemera::field::Goldilocks as H;
use std::sync::OnceLock;

/// nox cycles of one node: the formula's reduction cost on any subject of
/// the node's shape (asserted against native nox in the tests).
pub const COST: u64 = 39_818;

/// Capacity flags of an interior node and of the root (`hemera::tree`).
pub const FLAGS_NODE: u64 = 2;
pub const FLAGS_ROOT: u64 = 3;

fn at(v: u64) -> N {
    N::Atom(v)
}
fn pr(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}
fn ax(n: u64) -> N {
    pr(at(0), at(n))
}
fn q(x: N) -> N {
    pr(at(1), x)
}
fn op(tag: u64, a: N, b: N) -> N {
    pr(at(tag), pr(a, b))
}
fn compose(s: N, f: N) -> N {
    op(2, s, f)
}
fn cons(a: N, b: N) -> N {
    op(3, a, b)
}
fn branch(test: N, yes: N, no: N) -> N {
    pr(at(4), pr(test, pr(yes, no)))
}
fn add(a: N, b: N) -> N {
    op(5, a, b)
}
fn mul(a: N, b: N) -> N {
    op(7, a, b)
}
fn eq(a: N, b: N) -> N {
    op(9, a, b)
}

/// The axis of `rel` inside the noun at axis `parent`.
fn sub(parent: u64, rel: u64) -> u64 {
    let depth = 63 - rel.leading_zeros();
    (parent << depth) | (rel & ((1 << depth) - 1))
}

/// A balanced tree of 16 lanes: lane `i` at relative axis `16 + i`.
fn tree16(mut lanes: Vec<N>, join: fn(N, N) -> N) -> N {
    debug_assert_eq!(lanes.len(), 16);
    while lanes.len() > 1 {
        let mut next = Vec::with_capacity(lanes.len() / 2);
        let mut it = lanes.into_iter();
        while let (Some(a), Some(b)) = (it.next(), it.next()) {
            next.push(join(a, b));
        }
        lanes = next;
    }
    lanes.pop().expect("one root")
}

/// Every helper runs on the subject `[data LIB]`: data at axis 2, the
/// library list at axis 3. Library entries, in list order.
const SBOX: u64 = 0;
const M4: u64 = 1;
const EXT: u64 = 2;
const INT: u64 = 3;
const INVLOOP: u64 = 4;
const INV: u64 = 5;
const FULL: u64 = 6;
const PARTIAL: u64 = 7;
const ROUNDS: u64 = 8;

/// The axis of library entry `j` in a subject `[data LIB]`.
fn lib(j: u64) -> u64 {
    sub(3, (1 << (j + 2)) - 2)
}

/// Run library entry `j` on `[data LIB]`.
fn call(j: u64, data: N) -> N {
    compose(cons(data, ax(3)), ax(lib(j)))
}

/// `x^7` on `[x LIB]`.
fn sbox() -> N {
    let x3 = mul(ax(2), mul(ax(2), ax(2)));
    let x6 = compose(cons(x3, ax(3)), q(mul(ax(2), ax(2))));
    mul(ax(2), x6)
}

/// hemera's 4×4 MDS block on `[[[a b] [c d]] LIB]`.
fn m4() -> N {
    let term = |k: u64, axis: u64| {
        if k == 1 {
            ax(axis)
        } else {
            mul(q(at(k)), ax(axis))
        }
    };
    let lin = |c: [u64; 4]| {
        add(
            add(term(c[0], 8), term(c[1], 9)),
            add(term(c[2], 10), term(c[3], 11)),
        )
    };
    cons(
        cons(lin([2, 3, 1, 1]), lin([1, 2, 3, 1])),
        cons(lin([1, 1, 2, 3]), lin([3, 1, 1, 2])),
    )
}

/// The external linear layer on `[S LIB]`: M4 on each block of four, then
/// each lane plus its column's sum over the blocks.
fn ext() -> N {
    let blocks = cons(
        cons(call(M4, ax(8)), call(M4, ax(9))),
        cons(call(M4, ax(10)), call(M4, ax(11))),
    );
    // [[Y SUMS] LIB]: y_i at 64 + i, sum_k at 20 + k
    let out = tree16(
        (0..16).map(|i| add(ax(64 + i), ax(20 + i % 4))).collect(),
        cons,
    );
    // [Y LIB]: y_i at 32 + i
    let sum = |k: u64| add(add(ax(32 + k), ax(36 + k)), add(ax(40 + k), ax(44 + k)));
    let sums = cons(cons(sum(0), sum(1)), cons(sum(2), sum(3)));
    let with_sums = compose(cons(cons(ax(2), sums), ax(3)), q(out));
    compose(cons(blocks, ax(3)), q(with_sums))
}

/// The internal linear layer on `[S LIB]`: `s_i·d_i + Σ s`.
fn int() -> N {
    let mut total: Vec<N> = (0..16).map(|i| ax(32 + i)).collect();
    while total.len() > 1 {
        let mut next = vec![];
        let mut it = total.into_iter();
        while let (Some(a), Some(b)) = (it.next(), it.next()) {
            next.push(add(a, b));
        }
        total = next;
    }
    // [[S sum] LIB]: s_i at 64 + i, the sum at 5
    let out = tree16(
        (0..16)
            .map(|i| {
                let d = hemera::field::MATRIX_DIAG_16[i as usize].as_canonical_u64();
                add(mul(q(at(d)), ax(64 + i)), ax(5))
            })
            .collect(),
        cons,
    );
    compose(cons(cons(ax(2), total.pop().expect("sum")), ax(3)), q(out))
}

/// Square-and-multiply on `[[acc [x runs]] LIB]`, the exponent MSB first
/// as runs `[count bit]` of equal bits, ended by the run `[0 2]`.
fn invloop() -> N {
    let again =
        |acc: N, runs: N| compose(cons(cons(acc, cons(ax(10), runs)), ax(3)), ax(lib(INVLOOP)));
    let factor = branch(ax(45), q(at(1)), ax(10));
    let step = again(
        mul(mul(ax(4), ax(4)), factor),
        cons(cons(op(6, ax(44), q(at(1))), ax(45)), ax(23)),
    );
    let next_run = again(ax(4), ax(23));
    branch(
        eq(ax(45), q(at(2))),
        ax(4),
        branch(eq(ax(44), q(at(0))), next_run, step),
    )
}

/// `x^(p−2)` on `[x LIB]` (0 ↦ 0): `p − 2 = 0xFFFFFFFE_FFFFFFFF`, 31
/// ones, a zero, 32 ones.
fn inv() -> N {
    let runs = [(31, 1), (1, 0), (32, 1), (0, 2)]
        .into_iter()
        .rev()
        .fold(at(0), |rest, (n, b)| pr(pr(at(n), at(b)), rest));
    compose(
        cons(cons(q(at(1)), cons(ax(2), q(runs))), ax(3)),
        ax(lib(INVLOOP)),
    )
}

/// A full round on `[[S rc] LIB]`: S-box of every lane plus its constant,
/// then the external layer.
fn full() -> N {
    let lanes = (0..16)
        .map(|i| call(SBOX, add(ax(64 + i), ax(80 + i))))
        .collect();
    call(EXT, tree16(lanes, cons))
}

/// A partial round on `[[S rc] LIB]`: lane 0 plus its constant, inverted,
/// then the internal layer.
fn partial() -> N {
    let lanes = (0..16)
        .map(|i| {
            if i == 0 {
                call(INV, add(ax(64), ax(5)))
            } else {
                ax(64 + i)
            }
        })
        .collect();
    call(INT, tree16(lanes, cons))
}

/// The round loop on `[[S rounds] LIB]`; a round is `[kind rc]`: 0 full,
/// 1 partial, 3 the external layer alone, 2 the end.
fn rounds() -> N {
    let with_rc = |j| compose(cons(cons(ax(4), ax(21)), ax(3)), ax(lib(j)));
    let stepped = branch(
        eq(ax(20), q(at(0))),
        with_rc(FULL),
        branch(eq(ax(20), q(at(1))), with_rc(PARTIAL), call(EXT, ax(4))),
    );
    let next = compose(cons(cons(stepped, ax(11)), ax(3)), ax(lib(ROUNDS)));
    branch(eq(ax(20), q(at(2))), ax(4), next)
}

/// hemera's schedule: the initial external layer, 4 full, 16 partial, 4
/// full rounds, with their constants.
fn schedule() -> N {
    let rc = hemera::constants::ROUND_CONSTANTS_U64;
    let mut list = pr(pr(at(2), at(0)), at(0));
    for round in (0..24).rev() {
        let entry = if (4..20).contains(&round) {
            pr(at(1), at(rc[128 + round - 4]))
        } else {
            let offset = if round < 4 {
                round * 16
            } else {
                (round - 16) * 16
            };
            pr(
                at(0),
                tree16((0..16).map(|l| at(rc[offset + l])).collect(), pr),
            )
        };
        list = pr(entry, list);
    }
    pr(pr(at(3), at(0)), list)
}

fn library() -> N {
    [
        sbox(),
        m4(),
        ext(),
        int(),
        invloop(),
        inv(),
        full(),
        partial(),
        rounds(),
    ]
    .into_iter()
    .rev()
    .fold(at(0), |rest, f| pr(f, rest))
}

fn build() -> N {
    // subject [[L R] flags]: l_i at 16 + i, r_i at 20 + i, flags at 3
    let state = tree16(
        (0..16)
            .map(|i| match i {
                0..=7 => ax(16 + i),
                9 => ax(3),
                _ => q(at(0)),
            })
            .collect(),
        cons,
    );
    let start = cons(cons(state, q(schedule())), q(library()));
    let run = compose(start, q(compose(ax(1), ax(lib(ROUNDS)))));
    // the final state's lanes 0..4 are its axis 4: [[s0 s1] [s2 s3]]
    compose(run, q(ax(4)))
}

/// The node jet's nox formula, on the subject `[[L R] flags]`.
pub fn formula() -> &'static N {
    static F: OnceLock<N> = OnceLock::new();
    F.get_or_init(build)
}

/// Is `f` the node formula? Cheap on every other formula: the comparison
/// stops at the first differing atom, which for most formulas is the tag.
pub(crate) fn is_node(f: &N) -> bool {
    f == formula()
}

/// The node natively: `permute(L ‖ R ‖ 0 ‖ flags ‖ 0⁶)[0..4]`.
pub fn native(left: [u64; 4], right: [u64; 4], flags: u64) -> [u64; 4] {
    let mut state = [H::ZERO; 16];
    for i in 0..4 {
        state[i] = H::new(left[i]);
        state[4 + i] = H::new(right[i]);
    }
    state[9] = H::new(flags);
    hemera::permutation::permute(&mut state);
    core::array::from_fn(|i| state[i].as_canonical_u64())
}

/// `[[a b] [c d]]`.
pub fn digest_noun(d: [u64; 4]) -> N {
    pr(pr(at(d[0]), at(d[1])), pr(at(d[2]), at(d[3])))
}

#[path = "node_jet.rs"]
pub mod jet;

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
