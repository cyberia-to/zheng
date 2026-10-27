use super::{Cost, Error, Memory, Value, VerifiedNode};

fn combine(base: u64, a: Cost, b: Cost, force_dynamic: bool) -> Cost {
    let value = base.saturating_add(a.value()).saturating_add(b.value());
    if force_dynamic || a.is_dynamic() || b.is_dynamic() {
        Cost::Dynamic(value)
    } else {
        Cost::Exact(value)
    }
}

impl Memory {
    fn children(
        &self,
        node: &VerifiedNode,
    ) -> Result<Option<(&VerifiedNode, &VerifiedNode)>, Error> {
        match node.value() {
            Value::Pair { left, right } => Ok(Some((self.node(left)?, self.node(right)?))),
            Value::Atom(_) => Ok(None),
        }
    }

    pub(super) fn pair_cost(
        &self,
        head: &VerifiedNode,
        body: &VerifiedNode,
    ) -> Result<Cost, Error> {
        let Value::Atom(tag) = head.value() else {
            return Ok(Cost::Exact(0));
        };
        // Canonical nox dispatch metadata, including services as quoted data.
        let costs = [1, 1, 1, 1, 1, 1, 1, 1, 64, 1, 64, 32, 32, 32, 32, 25, 1, 1];
        let Some(&base) = usize::try_from(tag).ok().and_then(|i| costs.get(i)) else {
            return Ok(Cost::Exact(0));
        };
        let zero = Cost::Exact(0);
        Ok(match tag {
            0 | 1 => Cost::Exact(base),
            8 | 13 | 15 => combine(base, body.cost(), zero, false),
            _ => match self.children(body)? {
                None => Cost::Exact(base),
                Some((a, b)) => match tag {
                    2 => combine(base, a.cost(), b.cost(), true),
                    4 => match self.children(b)? {
                        None => Cost::Exact(base),
                        Some((yes, no)) => {
                            let arm = yes.cost().value().max(no.cost().value());
                            let dynamic = yes.cost().is_dynamic() || no.cost().is_dynamic();
                            combine(
                                base,
                                a.cost(),
                                if dynamic {
                                    Cost::Dynamic(arm)
                                } else {
                                    Cost::Exact(arm)
                                },
                                false,
                            )
                        }
                    },
                    16 => combine(base, a.cost(), zero, true),
                    _ => combine(base, a.cost(), b.cost(), false),
                },
            },
        })
    }
}
