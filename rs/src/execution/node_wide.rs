//! The wide hemera node jet: two hemera permutations compressing two
//! 8-limb (64-byte) digests into one, for the pool's commitment tree
//! (soft3 `specs/chain.md` § 11: 64-byte digests, `node(L, R)`).
//!
//! `node_wide([[L R] flags]) = out[0..8]` of
//!
//! ```text
//! s  = permute(L ‖ 0 ‖ flags ‖ 0⁶)            // L in the 8 rate lanes, flags in capacity lane 9
//! out = permute((s[0..8] + R) ‖ s[8..16])      // R added into the rate (hemera's absorb), capacity kept
//! ```
//!
//! as the 8-limb digest noun `[[[o0 o1] [o2 o3]] [[o4 o5] [o6 o7]]]`, where
//! `L` and `R` are 8-limb digest nouns of the same shape. This is hemera's
//! sponge over two rate blocks of eight canonical limbs each — the
//! "children absorbed as elements, two permutations at width 16"
//! construction soft3's § 11.4 names: the byte sponge `W(D_NODE ‖ L ‖ R)`
//! of that section packs seven bytes a lane and costs four permutations
//! per node; this jet costs two, and adopting it for the pool's tree is a
//! format decision soft3 takes before genesis (a re-blessing), never
//! after. The flags lane separates the wide node from every narrow
//! hemera input: [`FLAGS_NODE`] and [`FLAGS_ROOT`] set the `WIDE` bit
//! (`1 << 3`), unused by hemera's tree flags.
//!
//! Semantics are a pure Layer-1 nox formula, [`formula`], built from the
//! narrow node's library (`super`: the same permutation, run twice); it
//! reduces to the same digest at the same cost, [`COST`], for every
//! subject of the shape. The relation compiler recognises the formula and
//! emits two permutation gadgets (`relation::node_gadget`); the nox jet
//! ([`jet`]) runs [`native`] under nox's registry.
use crate::execution::ExecutionNoun as N;
use crate::execution::node::{self, at, ax, compose, cons, env, permutation, pr, q, tree16};
use hemera::field::Goldilocks as H;
use std::sync::OnceLock;

/// nox cycles of one wide node: the formula's reduction cost on any
/// subject of the node's shape (asserted against native nox in the tests).
pub const COST: u64 = 38_232;

/// The wide bit of the flags lane: a wide node's first permutation input
/// never equals a narrow node's, a leaf's or the hash opcode's.
pub const FLAGS_WIDE: u64 = 1 << 3;
/// Capacity flags of an interior wide node and of the wide root.
pub const FLAGS_NODE: u64 = node::FLAGS_NODE | FLAGS_WIDE;
pub const FLAGS_ROOT: u64 = node::FLAGS_ROOT | FLAGS_WIDE;

fn add(a: N, b: N) -> N {
    pr(at(5), pr(a, b))
}

fn build() -> N {
    // on [subject ENV], subject = [[L R] flags]: l_i at 64 + i, r_i at
    // 72 + i, flags at 5, the environment at 3
    let first = tree16(
        (0..16)
            .map(|i| match i {
                0..=7 => ax(64 + i),
                9 => ax(5),
                _ => q(at(0)),
            })
            .collect(),
        cons,
    );
    let run1 = compose(cons(first, ax(3)), q(permutation()));
    // on [S [subject ENV]]: s_i at 32 + i, r_i at 200 + i, the environment at 7
    let second = tree16(
        (0..16)
            .map(|i| {
                if i < 8 {
                    add(ax(32 + i), ax(200 + i))
                } else {
                    ax(32 + i)
                }
            })
            .collect(),
        cons,
    );
    let run2 = compose(cons(second, ax(7)), q(permutation()));
    // the final state's lanes 0..8 are its axis 2
    let body = compose(cons(run1, ax(1)), q(compose(run2, q(ax(2)))));
    compose(cons(ax(1), q(env())), q(body))
}

/// The wide node's nox formula, on the subject `[[L R] flags]`.
pub fn formula() -> &'static N {
    static F: OnceLock<N> = OnceLock::new();
    F.get_or_init(build)
}

/// Is `f` the wide node formula?
pub(crate) fn is_node(f: &N) -> bool {
    f == formula()
}

/// The wide node natively: two hemera permutations.
pub fn native(left: [u64; 8], right: [u64; 8], flags: u64) -> [u64; 8] {
    let mut state = [H::ZERO; 16];
    for i in 0..8 {
        state[i] = H::new(left[i]);
    }
    state[9] = H::new(flags);
    hemera::permutation::permute(&mut state);
    for i in 0..8 {
        state[i] += H::new(right[i]);
    }
    hemera::permutation::permute(&mut state);
    core::array::from_fn(|i| state[i].as_canonical_u64())
}

/// `[[[a b] [c d]] [[e f] [g h]]]`.
pub fn digest_noun(d: [u64; 8]) -> N {
    let half = |k: usize| pr(pr(at(d[k]), at(d[k + 1])), pr(at(d[k + 2]), at(d[k + 3])));
    pr(half(0), half(4))
}

/// The wide node as a nox jet (`super::jet`'s shape: dispatch on the
/// formula's digest, charge [`COST`], decline off shape).
pub mod jet {
    use super::{COST, N, formula, native};
    use nebu::Goldilocks as F;
    use nox::{DigestKey, JetRegistry, Order, Outcome, Reduction, TraceRow};
    use std::sync::OnceLock;

    /// The formula's structural digest: nox's jet key.
    pub fn key() -> DigestKey {
        static KEY: OnceLock<DigestKey> = OnceLock::new();
        *KEY.get_or_init(|| {
            fn digest(n: &N) -> nox::Digest {
                match n {
                    N::Atom(v) => nox::data::hash::hash_atom(F::new(*v)),
                    N::Pair(a, b) => nox::data::hash::hash_pair(&digest(a), &digest(b)),
                }
            }
            nox::digest_key(&digest(formula()))
        })
    }

    /// Register the wide node jet in a nox registry.
    pub fn register<const S: usize>(registry: &mut JetRegistry<S>) {
        registry.insert_exact_guarded(key(), jet::<S>, admit::<S>);
    }

    fn children<const S: usize>(r: &Reduction<S>, n: Order) -> Option<(Order, Order)> {
        match r.get(n)?.inner {
            nox::data::Data::Pair { left, right } => Some((left, right)),
            _ => None,
        }
    }

    /// Eight limbs of a wide digest noun (two 4-limb halves).
    fn limbs8<const S: usize>(r: &Reduction<S>, d: Order) -> Option<[u64; 8]> {
        let (lo, hi) = children(r, d)?;
        let half = |d| r.read_hash_data(d).map(|v| v.map(|x: F| x.as_u64()));
        let (lo, hi) = (half(lo)?, half(hi)?);
        Some(core::array::from_fn(|i| if i < 4 { lo[i] } else { hi[i - 4] }))
    }

    /// `(L limbs, R limbs, flags)` of a wide node subject, or `None`.
    fn operands<const S: usize>(r: &Reduction<S>, object: Order) -> Option<([u64; 8], [u64; 8], u64)> {
        let (lr, flags) = children(r, object)?;
        let (left, right) = children(r, lr)?;
        Some((limbs8(r, left)?, limbs8(r, right)?, r.atom_value(flags)?.as_u64()))
    }

    fn admit<const S: usize>(r: &Reduction<S>, object: Order, _: &DigestKey, budget: u64) -> bool {
        budget >= COST && operands(r, object).is_some()
    }

    #[allow(clippy::too_many_arguments)]
    fn jet<const S: usize>(
        r: &mut Reduction<S>,
        object: Order,
        _body: Order,
        budget: u64,
        _hints: &dyn nox::CallProvider<S>,
        _tracer: &mut dyn nox::Tracer,
        _depth: u64,
        _row: &mut TraceRow,
    ) -> Outcome {
        let Some((left, right, flags)) = operands(r, object) else {
            return Outcome::Error(nox::ErrorKind::TypeError);
        };
        let out = native(left, right, flags).map(F::new);
        let lo: [F; 4] = core::array::from_fn(|i| out[i]);
        let hi: [F; 4] = core::array::from_fn(|i| out[4 + i]);
        let (Some(lo), Some(hi)) = (r.hash_data(&lo), r.hash_data(&hi)) else {
            return Outcome::Error(nox::ErrorKind::Unavailable);
        };
        match r.pair(lo, hi) {
            Some(result) => Outcome::Ok(result, budget - COST),
            None => Outcome::Error(nox::ErrorKind::Unavailable),
        }
    }
}

#[cfg(test)]
#[path = "node_wide_tests.rs"]
mod tests;
