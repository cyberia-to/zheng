//! The hemera node jet as a gadget: the compiler meets the node formula
//! (`super::super::node`) and emits one permutation over the eight limbs
//! and the flags instead of compiling the formula's arithmetic. The gadget
//! is the same function (hemera's permutation, `hash_permute`, checked
//! against native nox in `node_tests`) and charges the formula's constant
//! nox cost, so the relation's output and cycles are nox's.
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
}
