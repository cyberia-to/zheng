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
//! Semantics are a pure Layer-1 nox formula, [`formula`]: the hemera 0.4
//! permutation written in nox arithmetic (add, mul, eq, branch, compose;
//! x⁷ in every round, 6 + 6 full and 48 partial). Any nox reducer runs it
//! and gets the same digest and the same cost, [`COST`], whatever the
//! input (every branch tests a constant of the formula, never data). The
//! relation compiler recognises the formula and emits one permutation
//! gadget over the eight limbs instead of compiling the arithmetic
//! (`relation::node_gadget`); the gadget is the same function, so the
//! compiled relation keeps nox's input → output and cost.
//!
//! Compared with pattern 15 on `[L R]` (structural hashing: every atom
//! bit-decomposed and hashed by two permutations, then the pair node and
//! the sponge, 24 permutations and 512 bit wires for two digests), one
//! node is one permutation and no bit wires. The two are different
//! functions: a program chooses which tree it verifies. The wide node of
//! the pool's tree (64-byte digests, two permutations) is [`wide`].
use super::ExecutionNoun as N;
use hemera::field::Goldilocks as H;
use std::sync::OnceLock;

/// nox cycles of one node: the formula's reduction cost on any subject of
/// the node's shape (asserted against native nox in the tests).
pub const COST: u64 = 19_105;

/// Capacity flags of an interior node and of the root (`hemera::tree`).
pub const FLAGS_NODE: u64 = 2;
pub const FLAGS_ROOT: u64 = 3;

pub(crate) fn at(v: u64) -> N {
    N::Atom(v)
}
pub(crate) fn pr(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}
pub(crate) fn ax(n: u64) -> N {
    pr(at(0), at(n))
}
pub(crate) fn q(x: N) -> N {
    pr(at(1), x)
}
fn op(tag: u64, a: N, b: N) -> N {
    pr(at(tag), pr(a, b))
}
pub(crate) fn compose(s: N, f: N) -> N {
    op(2, s, f)
}
pub(crate) fn cons(a: N, b: N) -> N {
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
pub(crate) fn tree16(mut lanes: Vec<N>, join: fn(N, N) -> N) -> N {
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
const FULL: u64 = 4;
const PARTIAL: u64 = 5;
pub(crate) const ROUNDS: u64 = 6;

/// The axis of library entry `j` in a subject `[data LIB]`.
pub(crate) fn lib(j: u64) -> u64 {
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

/// hemera's 4×4 MDS block on `[[[a b] [c d]] LIB]`: the matrix read off
/// `hemera::field::apply_mat4` (Poseidon2's M4), row by row.
fn m4() -> N {
    let matrix: [[u64; 4]; 4] = {
        let mut m = [[0u64; 4]; 4];
        for (col, m_col) in (0..4).map(|col| {
            let mut e = [H::ZERO; 4];
            e[col] = H::new(1);
            hemera::field::apply_mat4(&mut e);
            (col, e)
        }) {
            for (row, v) in m_col.iter().enumerate() {
                m[row][col] = v.as_canonical_u64();
            }
        }
        m
    };
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
        cons(lin(matrix[0]), lin(matrix[1])),
        cons(lin(matrix[2]), lin(matrix[3])),
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

/// A full round on `[[S rc] LIB]`: S-box of every lane plus its constant,
/// then the external layer.
fn full() -> N {
    let lanes = (0..16)
        .map(|i| call(SBOX, add(ax(64 + i), ax(80 + i))))
        .collect();
    call(EXT, tree16(lanes, cons))
}

/// A partial round on `[[S rc] LIB]`: lane 0 plus its constant through
/// the S-box, then the internal layer.
fn partial() -> N {
    let lanes = (0..16)
        .map(|i| {
            if i == 0 {
                call(SBOX, add(ax(64), ax(5)))
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

/// Parts of hemera's schedule, in order, each a list of rounds `[kind rc]`
/// ended by `[2 0]`: the initial external layer and the first 20 rounds,
/// then 20, then the last 20 (three short lists keep the formula's
/// nesting below the program depth limit).
pub(crate) fn schedule_parts() -> [N; 3] {
    use crate::machine::hemera::{PARTIAL_FIRST, ROUNDS as TOTAL, RP, is_full};
    let rc = hemera::constants::ROUND_CONSTANTS_U64;
    let entry = |round: usize| {
        if !is_full(round) {
            pr(
                at(1),
                at(rc[hemera::constants::NUM_EXTERNAL + round - PARTIAL_FIRST]),
            )
        } else {
            let offset = if round < PARTIAL_FIRST {
                round * 16
            } else {
                (round - RP) * 16
            };
            pr(
                at(0),
                tree16((0..16).map(|l| at(rc[offset + l])).collect(), pr),
            )
        }
    };
    let part = |rounds: core::ops::Range<usize>, head: Option<N>| {
        let mut list = pr(pr(at(2), at(0)), at(0));
        for round in rounds.rev() {
            list = pr(entry(round), list);
        }
        match head {
            Some(h) => pr(h, list),
            None => list,
        }
    };
    let third = TOTAL / 3;
    [
        part(0..third, Some(pr(at(3), at(0)))),
        part(third..2 * third, None),
        part(2 * third..TOTAL, None),
    ]
}

/// The environment every node formula carries in its subject:
/// `[LIB [A [B C]]]` — the library and the three schedule parts.
pub(crate) fn env() -> N {
    let [a, b, c] = schedule_parts();
    pr(library(), pr(a, pr(b, c)))
}
/// Axes of the environment's members inside `[S ENV]`.
const ENV_LIB: u64 = 6;
const ENV_PARTS: [u64; 3] = [14, 30, 31];

/// Run one schedule part (at `part` of `[S ENV]`) on `S`: the state after
/// its rounds.
fn run_part(part: u64) -> N {
    compose(
        cons(cons(ax(2), ax(part)), ax(ENV_LIB)),
        q(compose(ax(1), ax(lib(ROUNDS)))),
    )
}

/// The whole permutation on `[S ENV]`: the three schedule parts in turn.
pub(crate) fn permutation() -> N {
    let mut f = run_part(ENV_PARTS[0]);
    for part in &ENV_PARTS[1..] {
        f = compose(cons(f, ax(3)), q(run_part(*part)));
    }
    f
}

fn library() -> N {
    [sbox(), m4(), ext(), int(), full(), partial(), rounds()]
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
    // the final state's lanes 0..4 are its axis 4: [[s0 s1] [s2 s3]]
    compose(cons(state, q(env())), q(compose(permutation(), q(ax(4)))))
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

#[path = "node_wide.rs"]
pub mod wide;

#[cfg(test)]
#[path = "node_tests.rs"]
pub(crate) mod tests;
