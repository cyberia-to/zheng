//! The node formula as a nox jet, for native runs (joy's independent
//! check, `joy run`): nox's registry dispatches on the formula's structural
//! digest and runs [`super::native`] instead of ~40k reductions. A jet is an
//! optimisation of nox, never a change of meaning: it charges
//! [`super::COST`], returns the digest noun the formula returns, and its
//! admission declines (pure dispatch runs the formula itself) on any subject
//! that is not `[[L R] flags]` with atom limbs and flags, or when the budget
//! is below the cost — so errors and halts stay exactly the formula's.
use super::{COST, formula, native};
use nebu::Goldilocks as F;
use nox::{DigestKey, JetRegistry, Order, Outcome, Reduction, TraceRow};
use std::sync::OnceLock;

/// The formula's structural digest: nox's jet key.
pub fn key() -> DigestKey {
    static KEY: OnceLock<DigestKey> = OnceLock::new();
    *KEY.get_or_init(|| {
        fn digest(n: &super::N) -> nox::Digest {
            match n {
                super::N::Atom(v) => nox::data::hash::hash_atom(F::new(*v)),
                super::N::Pair(a, b) => nox::data::hash::hash_pair(&digest(a), &digest(b)),
            }
        }
        nox::digest_key(&digest(formula()))
    })
}

/// Register the node jet in a nox registry.
pub fn register<const S: usize>(registry: &mut JetRegistry<S>) {
    registry.insert_exact_guarded(key(), jet::<S>, admit::<S>);
}

fn children<const S: usize>(r: &Reduction<S>, n: Order) -> Option<(Order, Order)> {
    match r.get(n)?.inner {
        nox::data::Data::Pair { left, right } => Some((left, right)),
        _ => None,
    }
}

/// `([L limbs], [R limbs], flags)` of a node subject, or `None`.
fn operands<const S: usize>(r: &Reduction<S>, object: Order) -> Option<([u64; 4], [u64; 4], u64)> {
    let (lr, flags) = children(r, object)?;
    let (left, right) = children(r, lr)?;
    let limbs = |d| r.read_hash_data(d).map(|v| v.map(|x: F| x.as_u64()));
    Some((limbs(left)?, limbs(right)?, r.atom_value(flags)?.as_u64()))
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
    match r.hash_data(&out) {
        Some(result) => Outcome::Ok(result, budget - COST),
        None => Outcome::Error(nox::ErrorKind::Unavailable),
    }
}
