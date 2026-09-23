use super::*;
/// Every consumed state value must be externally authenticated and pinned to
/// these exact wires under the same execution proof. Inactive calls bind activity
/// to zero and require no lookup evidence. The plain/private statements reject
/// all relations containing lookups; only the state protocol supplies bindings.
#[derive(Clone, Debug)]
pub struct LookupCoordinates {
    pub active: usize,
    pub root: [usize; 4],
    pub namespace: usize,
    pub key: usize,
    pub value: usize,
}
impl Builder {
    fn coordinate(&mut self, value: &Value) -> Result<usize, RelationError> {
        match self.alloc_linear(self.linear(value)?) {
            Value::Wire(i) => Ok(i),
            _ => unreachable!(),
        }
    }
    pub(super) fn look(
        &mut self,
        obj: &Value,
        body: &ExecutionNoun,
        depth: usize,
    ) -> Result<(Value, Value, u64), RelationError> {
        let (ns, key) = pair(body)?;
        let (ns, nc, nm) = self.eval(obj, ns, depth + 1)?;
        let (key, kc, km) = self.eval(obj, key, depth + 1)?;
        let mut roots = Vec::new();
        for axis in [4u64, 10, 22, 23] {
            let mut v = obj;
            let bits = 63 - axis.leading_zeros();
            for b in (0..bits).rev() {
                v = match v {
                    Value::Pair(l, r) => {
                        if (axis >> b) & 1 == 0 {
                            l
                        } else {
                            r
                        }
                    }
                    _ => return Err(RelationError::Unsupported("look root shape")),
                };
            }
            roots.push(v.clone());
        }
        let active = self.active.clone();
        let root = [
            self.linear(&roots[0])?,
            self.linear(&roots[1])?,
            self.linear(&roots[2])?,
            self.linear(&roots[3])?,
        ];
        let value = self.wire(Op::Look {
            active: self.linear(&active)?,
            root,
            namespace: self.linear(&ns)?,
            key: self.linear(&key)?,
        });
        let record = LookupCoordinates {
            active: self.coordinate(&active)?,
            root: [
                self.coordinate(&roots[0])?,
                self.coordinate(&roots[1])?,
                self.coordinate(&roots[2])?,
                self.coordinate(&roots[3])?,
            ],
            namespace: self.coordinate(&ns)?,
            key: self.coordinate(&key)?,
            value,
        };
        self.lookups.push(record);
        if let Some(state) = self.state.clone() {
            self.authenticate_lookup(&roots, &ns, &key, &Value::Wire(value), &state)?;
        }
        let cost = self.add(&nc, &kc, false)?;
        let cost = self.add(&Value::Constant(F::ONE), &cost, false)?;
        Ok((Value::Wire(value), cost, 1 + nm + km))
    }
}

impl Builder {
    fn authenticate_lookup(
        &mut self,
        roots: &[Value],
        ns: &Value,
        key: &Value,
        value: &Value,
        state: &PublicStateTables,
    ) -> Result<(), RelationError> {
        for (actual, expected) in roots.iter().zip(state.root) {
            self.enforce_equal(self.linear(actual)?, vec![(0, expected)])?;
        }
        let one = Value::Constant(F::ONE);
        let mut selected = Vec::new();
        let mut expected = Vec::new();
        for (namespace, fields) in state.dimensions.iter().enumerate() {
            let delta = self.add(ns, &Value::Constant(F::new(namespace as u64)), true)?;
            let unequal = self.nonzero(&delta)?;
            let namespace_equal = self.add(&one, &unequal, true)?;
            for (index, &field) in fields.iter().enumerate() {
                if self.ops.len() > 32768 || self.rows.len() > 32768 {
                    return Err(RelationError::Limit);
                }
                let delta = self.add(key, &Value::Constant(F::new(index as u64)), true)?;
                let unequal = self.nonzero(&delta)?;
                let index_equal = self.add(&one, &unequal, true)?;
                let selector =
                    self.product(self.linear(&namespace_equal)?, self.linear(&index_equal)?);
                let l = self.linear(&selector)?;
                selected.extend(l.iter().copied());
                expected.extend(l.into_iter().map(|(i, c)| (i, c * field)));
            }
        }
        self.enforce_equal(selected, vec![(0, F::ONE)])?;
        self.enforce_equal(self.linear(value)?, expected)?;
        Ok(())
    }
}
