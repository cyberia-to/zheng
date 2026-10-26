//! The hemera node jets as gadgets: the compiler meets the node formula
//! (`super::super::node`) and emits one permutation over the eight limbs
//! and the flags instead of compiling the formula's arithmetic — or, for
//! the wide node (`node::wide`, two 8-limb digests), two permutations. The
//! gadgets are the same functions (hemera's permutation, `hash_permute`,
//! checked against native nox in `node_tests` / `node_wide_tests`) and
//! charge the formulas' constant nox costs, so the relation's output and
//! cycles are nox's.
use super::*;

fn atom(v: &Value) -> Result<Value, RelationError> {
    match v {
        Value::Pair(..) => Err(RelationError::Unsupported("node: limb must be an atom")),
        v => Ok(v.clone()),
    }
}

fn halves(v: &Value) -> Result<(&Value, &Value), RelationError> {
    match v {
        Value::Pair(a, b) => Ok((a, b)),
        _ => Err(RelationError::Unsupported("node: subject is [[L R] flags]")),
    }
}

fn limbs(digest: &Value) -> Result<[Value; 4], RelationError> {
    let (ab, cd) = halves(digest)?;
    let (a, b) = halves(ab)?;
    let (c, d) = halves(cd)?;
    Ok([atom(a)?, atom(b)?, atom(c)?, atom(d)?])
}

impl Builder {
    /// `permute(L ‖ R ‖ 0 ‖ flags ‖ 0⁶)[0..4]` on the subject `[[L R] flags]`
    /// as the digest noun `[[o0 o1] [o2 o3]]`. A subject of another shape
    /// fails closed, as nox's reduction of the formula does (an axis into
    /// an atom, or arithmetic on a pair).
    pub(super) fn node(&mut self, subject: &Value) -> Result<Value, RelationError> {
        let (children, flags) = halves(subject)?;
        let (left, right) = halves(children)?;
        let mut state: [Value; 16] = core::array::from_fn(|_| Value::Constant(F::ZERO));
        state[..4].clone_from_slice(&limbs(left)?);
        state[4..8].clone_from_slice(&limbs(right)?);
        state[9] = atom(flags)?;
        let out = self.hash_permute(state)?;
        Ok(Value::Pair(
            Box::new(Value::Pair(
                Box::new(out[0].clone()),
                Box::new(out[1].clone()),
            )),
            Box::new(Value::Pair(
                Box::new(out[2].clone()),
                Box::new(out[3].clone()),
            )),
        ))
    }

    /// The wide node on the subject `[[L R] flags]` (8-limb digests): the
    /// digest noun of `permute((permute(L ‖ 0 ‖ flags ‖ 0⁶)[0..8] + R) ‖
    /// capacity)[0..8]`.
    pub(super) fn node_wide(&mut self, subject: &Value) -> Result<Value, RelationError> {
        let (children, flags) = halves(subject)?;
        let (left, right) = halves(children)?;
        let limbs8 = |v: &Value| -> Result<[Value; 8], RelationError> {
            let (lo, hi) = halves(v)?;
            let (lo, hi) = (limbs(lo)?, limbs(hi)?);
            Ok(core::array::from_fn(|i| {
                if i < 4 {
                    lo[i].clone()
                } else {
                    hi[i - 4].clone()
                }
            }))
        };
        let (left, right) = (limbs8(left)?, limbs8(right)?);
        let mut state: [Value; 16] = core::array::from_fn(|_| Value::Constant(F::ZERO));
        state[..8].clone_from_slice(&left);
        state[9] = atom(flags)?;
        let mid = self.hash_permute(state)?;
        let mut state: [Value; 16] = core::array::from_fn(|i| mid[i].clone());
        for (lane, r) in state.iter_mut().take(8).zip(&right) {
            *lane = self.add(lane, r, false)?;
        }
        let out = self.hash_permute(state)?;
        let half = |k: usize| {
            Value::Pair(
                Box::new(Value::Pair(
                    Box::new(out[k].clone()),
                    Box::new(out[k + 1].clone()),
                )),
                Box::new(Value::Pair(
                    Box::new(out[k + 2].clone()),
                    Box::new(out[k + 3].clone()),
                )),
            )
        };
        Ok(Value::Pair(Box::new(half(0)), Box::new(half(4))))
    }
}
