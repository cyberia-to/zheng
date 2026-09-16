use super::*;
impl Builder {
    pub(super) fn eval(
        &mut self,
        obj: &Value,
        f: &ExecutionNoun,
        depth: usize,
    ) -> Result<(Value, Value, u64), RelationError> {
        if self.ops.len() > 32768 || self.rows.len() > 32768 {
            return Err(RelationError::Limit);
        }
        let result = self.eval_inner(obj, f, depth)?;
        check_value(&result.0, 0, &mut 0)?;
        if self.ops.len() > 32768 || self.rows.len() > 32768 {
            return Err(RelationError::Limit);
        }
        Ok(result)
    }
    fn eval_inner(
        &mut self,
        obj: &Value,
        f: &ExecutionNoun,
        depth: usize,
    ) -> Result<(Value, Value, u64), RelationError> {
        self.calls += 1;
        if self.calls > MAX_CALLS || depth > MAX_DEPTH {
            return Err(RelationError::Limit);
        }
        let (tag, body) = pair(f)?;
        let tag = match tag {
            ExecutionNoun::Atom(t) => *t,
            _ => return Err(RelationError::Malformed),
        };
        let one = Value::Constant(F::ONE);
        match tag {
            0 => {
                let a = match body {
                    ExecutionNoun::Atom(a) => *a,
                    _ => return Err(RelationError::Malformed),
                };
                if a == 0 {
                    return Ok((self.axis_hash(obj)?, one, 1));
                }
                let mut v = obj;
                let bits = 63 - a.leading_zeros();
                for b in (0..bits).rev() {
                    v = match v {
                        Value::Pair(l, r) => {
                            if (a >> b) & 1 == 0 {
                                l
                            } else {
                                r
                            }
                        }
                        _ => return Err(RelationError::Unsupported("axis into atom")),
                    };
                }
                Ok((v.clone(), one, 1))
            }
            1 => Ok((constant(body, depth + 1)?, one, 1)),
            15 => {
                let (v, c, m) = self.eval(obj, body, depth + 1)?;
                let out = self.hash(&v)?;
                let cost = self.add(&c, &Value::Constant(F::new(25)), false)?;
                Ok((out, cost, m + 25))
            }
            13 => {
                let (v, c, m) = self.eval(obj, body, depth + 1)?;
                let bits = self.bits(&v, 32)?;
                let word = self.pack(&bits)?;
                let out = self.add(&Value::Constant(F::new(u32::MAX as u64)), &word, true)?;
                let cost = self.add(&c, &Value::Constant(F::new(32)), false)?;
                Ok((out, cost, m + 32))
            }
            8 => {
                let (v, c, m) = self.eval(obj, body, depth + 1)?;
                let a = self.linear(&v)?;
                let i = self.wire(Op::Inverse(a.clone()));
                let check = self.product(a, vec![(i, F::ONE)]);
                self.enforce_equal(self.linear(&check)?, vec![(0, F::ONE)])?;
                let cost = self.add(&c, &Value::Constant(F::new(64)), false)?;
                Ok((Value::Wire(i), cost, m + 64))
            }
            2 | 3 | 5 | 6 | 7 | 9 | 10 | 11 | 12 | 14 => {
                let (a, b) = pair(body)?;
                let (av, ac, am) = self.eval(obj, a, depth + 1)?;
                let (bv, bc, bm) = self.eval(obj, b, depth + 1)?;
                let own_cost = if tag == 10 {
                    64
                } else if tag >= 11 {
                    32
                } else {
                    1
                };
                let ab = self.add(&ac, &bc, false)?;
                let mut cost = self.add(&Value::Constant(F::new(own_cost)), &ab, false)?;
                let mut max = own_cost + am + bm;
                let value = match tag {
                    2 => {
                        let continuation = static_noun(&bv, depth + 1)?;
                        let (v, c, m) = self.eval(&av, &continuation, depth + 1)?;
                        cost = self.add(&cost, &c, false)?;
                        max += m;
                        v
                    }
                    3 => Value::Pair(Box::new(av), Box::new(bv)),
                    5 | 6 => self.add(&av, &bv, tag == 6)?,
                    7 => self.product(self.linear(&av)?, self.linear(&bv)?),
                    9 => self.equal(&av, &bv)?,
                    10 => self.less_than(&av, &bv)?,
                    11 | 12 | 14 => self.word_binary(tag, &av, &bv)?,
                    _ => unreachable!(),
                };
                Ok((value, cost, max))
            }
            4 => {
                let (t, arms) = pair(body)?;
                let (a, b) = pair(arms)?;
                let (tv, tc, tm) = self.eval(obj, t, depth + 1)?;
                let s = self.nonzero(&tv)?;
                let parent = self.active.clone();
                let yes = self.add(&one, &s, true)?;
                self.active = self.product(self.linear(&parent)?, self.linear(&yes)?);
                let (av, ac, am) = self.eval(obj, a, depth + 1)?;
                self.active = self.product(self.linear(&parent)?, self.linear(&s)?);
                let (bv, bc, bm) = self.eval(obj, b, depth + 1)?;
                self.active = parent;
                let value = self.mux(&s, &av, &bv)?;
                let arm = self.mux(&s, &ac, &bc)?;
                let c = self.add(&tc, &arm, false)?;
                let c = self.add(&one, &c, false)?;
                Ok((value, c, 1 + tm + am.max(bm)))
            }
            17 => self.look(obj, body, depth),
            16 => {
                let (tag, check) = pair(body)?;
                let (tag, tag_cost, tag_max) = self.eval(obj, tag, depth + 1)?;
                self.linear(&tag)?; // Native calls require an atom tag.
                let witness = Value::Wire(self.wire(Op::Secret(self.linear(&self.active)?)));
                let check_obj = Value::Pair(Box::new(witness.clone()), Box::new(obj.clone()));
                let (checked, check_cost, check_max) = self.eval(&check_obj, check, depth + 1)?;
                self.enforce_equal(self.linear(&checked)?, vec![])?;
                let cost = self.add(&tag_cost, &check_cost, false)?;
                let cost = self.add(&one, &cost, false)?;
                Ok((witness, cost, 1 + tag_max + check_max))
            }
            _ => Err(RelationError::Unsupported(
                "pattern requires an execution gadget",
            )),
        }
    }
}
