use super::{build::Builder, *};
fn pair(n: &Noun) -> Option<(&Noun, &Noun)> {
    if let Noun::Pair(a, b) = n {
        Some((a, b))
    } else {
        None
    }
}
impl Builder {
    fn invalid(&mut self, active: Wire) -> Result<(Rc<Node>, Wire, u64), Error> {
        self.zero_product(ONE, vec![(active, F::ONE)])?;
        Ok((self.zero()?, ZERO, 0))
    }
    pub fn eval(
        &mut self,
        obj: &Rc<Node>,
        formula: &Noun,
        active: Wire,
        depth: usize,
    ) -> Result<(Rc<Node>, Wire, u64), Error> {
        self.calls += 1;
        if depth > MAX_DEPTH || self.calls > MAX_NODES {
            return Err(Error::Limit);
        }
        let Some((Noun::Atom(tag), body)) = pair(formula) else {
            return self.invalid(active);
        };
        match *tag {
            0 => {
                let Noun::Atom(axis) = body else {
                    return self.invalid(active);
                };
                if *axis == 0 {
                    let digest = self.structural_digest(obj)?;
                    return Ok((self.digest_noun(digest, active)?, active, 1));
                }
                let mut node = obj.clone();
                let bits = 63 - axis.leading_zeros();
                for bit in (0..bits).rev() {
                    self.zero_product(active, vec![(ONE, F::ONE), (node.tag, -F::ONE)])?;
                    node = match &node.children {
                        Some((a, b)) => {
                            if (axis >> bit) & 1 == 0 {
                                a.clone()
                            } else {
                                b.clone()
                            }
                        }
                        None => self.zero()?,
                    };
                }
                Ok((self.mask(&node, active)?, active, 1))
            }
            1 => Ok((self.quoted(body, active)?, active, 1)),
            2 => {
                let Some((subject, quoted)) = pair(body) else {
                    return self.invalid(active);
                };
                let Some((Noun::Atom(1), continuation)) = pair(quoted) else {
                    return Err(Error::Unsupported(
                        "tagged composition requires literal quoted continuation",
                    ));
                };
                let (subject, subject_cost, subject_max) =
                    self.eval(obj, subject, active, depth + 1)?;
                let (out, cost, max) = self.eval(&subject, continuation, active, depth + 1)?;
                // The literal RHS quote contributes1, plus compose's own1.
                let cost = self.lin(vec![
                    (active, F::new(2)),
                    (subject_cost, F::ONE),
                    (cost, F::ONE),
                ])?;
                Ok((out, cost, 2 + subject_max + max))
            }
            10 | 11 | 12 | 14 => {
                let Some((left, right)) = pair(body) else {
                    return self.invalid(active);
                };
                let (left, lc, lm) = self.eval(obj, left, active, depth + 1)?;
                let (right, rc, rm) = self.eval(obj, right, active, depth + 1)?;
                let a = self.atom(&left, active)?;
                let b = self.atom(&right, active)?;
                let value = if *tag == 10 {
                    self.unsigned_less(a, b)?
                } else {
                    self.word_binary(*tag, a, b, active)?
                };
                let value = self.mul(active, value)?;
                let out = self.node(ZERO, value, None)?;
                let own = if *tag == 10 { 64 } else { 32 };
                let cost = self.lin(vec![(active, F::new(own)), (lc, F::ONE), (rc, F::ONE)])?;
                Ok((out, cost, own + lm + rm))
            }
            13 => {
                let (value, cost, max) = self.eval(obj, body, active, depth + 1)?;
                let value = self.atom(&value, active)?;
                let value = self.word_not(value, active)?;
                let value = self.mul(active, value)?;
                let out = self.node(ZERO, value, None)?;
                let cost = self.lin(vec![(active, F::new(32)), (cost, F::ONE)])?;
                Ok((out, cost, 32 + max))
            }
            3 | 5 | 6 | 7 | 9 => {
                let Some((a, b)) = pair(body) else {
                    return self.invalid(active);
                };
                let (av, ac, am) = self.eval(obj, a, active, depth + 1)?;
                let (bv, bc, bm) = self.eval(obj, b, active, depth + 1)?;
                let out = if *tag == 3 {
                    self.node(active, ZERO, Some((av, bv)))?
                } else if *tag == 9 {
                    let a = self.structural_digest(&av)?;
                    let b = self.structural_digest(&bv)?;
                    let unequal = self.digest_unequal(a, b)?;
                    let value = self.mul(active, unequal)?;
                    self.node(ZERO, value, None)?
                } else {
                    let a = self.atom(&av, active)?;
                    let b = self.atom(&bv, active)?;
                    let v = match tag {
                        5 => self.lin(vec![(a, F::ONE), (b, F::ONE)])?,
                        6 => self.lin(vec![(a, F::ONE), (b, -F::ONE)])?,
                        _ => self.mul(a, b)?,
                    };
                    let v = self.mul(active, v)?;
                    self.node(ZERO, v, None)?
                };
                let cost = self.lin(vec![(active, F::ONE), (ac, F::ONE), (bc, F::ONE)])?;
                Ok((out, cost, 1 + am + bm))
            }
            8 => {
                let (v, c, m) = self.eval(obj, body, active, depth + 1)?;
                let x = self.atom(&v, active)?;
                let inverse = self.inv(x)?;
                let product = self.mul(x, inverse)?;
                self.zero_product(active, vec![(product, F::ONE), (ONE, -F::ONE)])?;
                let inactive = self.lin(vec![(ONE, F::ONE), (active, -F::ONE)])?;
                self.zero_product(inactive, vec![(inverse, F::ONE)])?;
                let out = self.node(ZERO, inverse, None)?;
                let cost = self.lin(vec![(active, F::new(64)), (c, F::ONE)])?;
                Ok((out, cost, 64 + m))
            }
            4 => {
                let Some((t, arms)) = pair(body) else {
                    return self.invalid(active);
                };
                let Some((yes, no)) = pair(arms) else {
                    return self.invalid(active);
                };
                let (test, tc, tm) = self.eval(obj, t, active, depth + 1)?;
                let x = self.atom(&test, active)?;
                let inverse = self.inv(x)?;
                let s = self.mul(x, inverse)?;
                let not_s = self.lin(vec![(ONE, F::ONE), (s, -F::ONE)])?;
                self.zero_product(s, vec![(not_s, F::ONE)])?;
                self.zero_product(x, vec![(not_s, F::ONE)])?;
                self.zero_product(not_s, vec![(inverse, F::ONE)])?;
                let ay = self.mul(active, not_s)?;
                let an = self.mul(active, s)?;
                let (y, yc, ym) = self.eval(obj, yes, ay, depth + 1)?;
                let (n, nc, nm) = self.eval(obj, no, an, depth + 1)?;
                let out = self.mux(s, &y, &n)?;
                let cost = self.lin(vec![
                    (active, F::ONE),
                    (tc, F::ONE),
                    (yc, F::ONE),
                    (nc, F::ONE),
                ])?;
                Ok((out, cost, 1 + tm + ym.max(nm)))
            }
            15 => {
                let (value, cost, max_cost) = self.eval(obj, body, active, depth + 1)?;
                let digest = self.structural_digest(&value)?;
                let mut state = [ZERO; 16];
                state[..4].copy_from_slice(&digest);
                let out = self.permute(state)?;
                let digest = std::array::from_fn(|i| out[i]);
                let output = self.digest_noun(digest, active)?;
                let cost = self.lin(vec![(active, F::new(25)), (cost, F::ONE)])?;
                Ok((output, cost, 25 + max_cost))
            }
            16 | 17 => Err(Error::Unsupported(
                "opcode outside experimental tagged kernel",
            )),
            _ => self.invalid(active),
        }
    }
}
