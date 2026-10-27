use super::*;

impl Evaluations<'_> {
    fn decode(&self, formula: u32) -> Result<(u64, u32), Error> {
        let (tag, body) = self.pair(formula).map_err(|_| Error::Formula)?;
        let tag = self.atom(tag).map_err(|_| Error::Formula)?;
        if tag > 15 {
            return Err(Error::UnsupportedOpcode);
        }
        Ok((tag, body))
    }
    pub(super) fn dispatch_cost(&self, formula: u32) -> Result<u64, Error> {
        let (tag, _) = self.decode(formula)?;
        Ok([1, 1, 1, 1, 1, 1, 1, 1, 64, 1, 64, 32, 32, 32, 32, 25][tag as usize])
    }
    fn child(
        &self,
        c: Candidate,
        position: usize,
        object: u32,
        formula: u32,
    ) -> Result<u32, Error> {
        let &id = c.premises.as_slice().get(position).ok_or(Error::Arity)?;
        let child = self.get(id)?.candidate;
        self.same(child.object, object)
            .map_err(|_| Error::Premise)?;
        self.same(child.formula, formula)
            .map_err(|_| Error::Premise)?;
        Ok(child.result)
    }
    pub(super) fn check_rule(&self, c: Candidate) -> Result<(), Error> {
        let (tag, body) = self.decode(c.formula)?;
        let arity = match tag {
            0 | 1 => 0,
            8 | 13 | 15 => 1,
            2 => 3,
            _ => 2,
        };
        if c.premises.as_slice().len() != arity {
            return Err(Error::Arity);
        }
        match tag {
            0 => self.axis(c.object, body, c.result),
            1 => self.same(c.result, body),
            8 | 13 | 15 => {
                let value = self.child(c, 0, c.object, body)?;
                self.unary(tag, value, c.result)
            }
            4 => {
                let (test, arms) = self.pair(body).map_err(|_| Error::Formula)?;
                let (yes, no) = self.pair(arms).map_err(|_| Error::Formula)?;
                let test = self.child(c, 0, c.object, test)?;
                let chosen = if self.atom(test)? == 0 { yes } else { no };
                let result = self.child(c, 1, c.object, chosen)?;
                self.same(c.result, result)
            }
            _ => {
                let (a, b) = self.pair(body).map_err(|_| Error::Formula)?;
                let left = self.child(c, 0, c.object, a)?;
                let right = self.child(c, 1, c.object, b)?;
                if tag == 2 {
                    let result = self.child(c, 2, left, right)?;
                    self.same(c.result, result)
                } else {
                    self.binary(tag, left, right, c.result)
                }
            }
        }
    }
}
