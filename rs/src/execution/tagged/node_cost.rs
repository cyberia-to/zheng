//! Local header/Cost constraints with six unresolved authenticated-read premises.
//! Contract: specs/noun-cost-component.md. No memory membership or execution API.
use super::{build::Builder, uint64::U64, *};

pub(super) const RECORD_FIELDS: usize = 18;
pub(super) const READ_PORTS: usize = 6;
pub(super) const INPUT_FIELDS: usize = 1 + (1 + READ_PORTS) * RECORD_FIELDS;
pub(super) const VERSION: u64 = 1;

#[derive(Clone, Copy, Debug)]
pub(super) struct Record {
    pub active: Wire,
    pub pair: Wire,
    pub value: Wire,
    pub particle: [Wire; 4],
    pub left: [Wire; 4],
    pub right: [Wire; 4],
    pub dynamic: Wire,
    pub bound: U64,
}

impl Record {
    pub fn from_fields(fields: [Wire; RECORD_FIELDS]) -> Self {
        Self {
            active: fields[0],
            pair: fields[1],
            value: fields[2],
            particle: std::array::from_fn(|i| fields[3 + i]),
            left: std::array::from_fn(|i| fields[7 + i]),
            right: std::array::from_fn(|i| fields[11 + i]),
            dynamic: fields[15],
            bound: U64 {
                lo: fields[16],
                hi: fields[17],
            },
        }
    }
    pub fn fields(self) -> [Wire; RECORD_FIELDS] {
        let mut fields = [
            self.active,
            self.pair,
            self.value,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            self.dynamic,
            self.bound.lo,
            self.bound.hi,
        ];
        fields[3..7].copy_from_slice(&self.particle);
        fields[7..11].copy_from_slice(&self.left);
        fields[11..15].copy_from_slice(&self.right);
        fields
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ReadObligation {
    pub active: Wire,
    pub requested_particle: [Wire; 4],
    pub returned: Record,
}

/// Consuming/ignoring this handle cannot resolve the builder's pending reads.
/// A future memory gadget must authenticate their complete returned records.
#[must_use]
pub(super) struct PendingNodeCost {
    pub candidate: Record,
    pub reads: [ReadObligation; READ_PORTS],
}

impl Builder {
    fn boolean(&mut self, value: Wire) -> Result<(), Error> {
        self.zero_product(value, vec![(ONE, F::ONE), (value, -F::ONE)])
    }
    fn equal(&mut self, a: Wire, b: Wire) -> Result<Wire, Error> {
        let difference = self.lin(vec![(a, F::ONE), (b, -F::ONE)])?;
        let nonzero = self.inverse_or_zero(difference)?.1;
        self.lin(vec![(ONE, F::ONE), (nonzero, -F::ONE)])
    }
    fn bind(&mut self, a: Wire, b: Wire) -> Result<(), Error> {
        self.zero_product(ONE, vec![(a, F::ONE), (b, -F::ONE)])
    }
    fn sum_selectors(&mut self, selectors: &[Wire]) -> Result<Wire, Error> {
        self.lin(selectors.iter().map(|&wire| (wire, F::ONE)).collect())
    }
    fn either(&mut self, a: Wire, b: Wire) -> Result<Wire, Error> {
        let both = self.mul(a, b)?;
        self.lin(vec![(a, F::ONE), (b, F::ONE), (both, -F::ONE)])
    }

    pub(super) fn constrain_record(&mut self, record: Record) -> Result<(), Error> {
        self.boolean(record.active)?;
        self.boolean(record.pair)?;
        self.boolean(record.dynamic)?;
        let inactive = self.lin(vec![(ONE, F::ONE), (record.active, -F::ONE)])?;
        for wire in record.fields() {
            self.zero_product(inactive, vec![(wire, F::ONE)])?;
        }
        self.zero_product(record.pair, vec![(record.value, F::ONE)])?;
        let atom = self.lin(vec![(ONE, F::ONE), (record.pair, -F::ONE)])?;
        for wire in record.left.into_iter().chain(record.right).chain([
            record.dynamic,
            record.bound.lo,
            record.bound.hi,
        ]) {
            self.zero_product(atom, vec![(wire, F::ONE)])?;
        }
        self.range_u64(record.bound)?;
        let atom_digest = self.atom_digest(record.value)?;
        let pair_digest = self.pair_digest(record.left, record.right)?;
        for i in 0..4 {
            let digest = self.select(record.pair, atom_digest[i], pair_digest[i])?;
            let digest = self.mul(record.active, digest)?;
            self.bind(record.particle[i], digest)?;
        }
        Ok(())
    }

    fn read_port(
        &mut self,
        active: Wire,
        particle: [Wire; 4],
        returned: Record,
    ) -> Result<ReadObligation, Error> {
        self.bind(returned.active, active)?;
        let mut requested_particle = [ZERO; 4];
        for i in 0..4 {
            requested_particle[i] = self.mul(active, particle[i])?;
            self.bind(returned.particle[i], requested_particle[i])?;
        }
        Ok(ReadObligation {
            active,
            requested_particle,
            returned,
        })
    }

    fn coherent(&mut self, a: Record, b: Record) -> Result<(), Error> {
        let mut same = self.mul(a.active, b.active)?;
        for i in 0..4 {
            let equal = self.equal(a.particle[i], b.particle[i])?;
            same = self.mul(same, equal)?;
        }
        for (a, b) in a.fields().into_iter().zip(b.fields()) {
            self.zero_product(same, vec![(a, F::ONE), (b, -F::ONE)])?;
        }
        Ok(())
    }

    fn weighted_bound(&mut self, a: Wire, x: U64, b: Wire, y: U64) -> Result<U64, Error> {
        let ax = self.mul(a, x.lo)?;
        let by = self.mul(b, y.lo)?;
        let lo = self.lin(vec![(ax, F::ONE), (by, F::ONE)])?;
        let ax = self.mul(a, x.hi)?;
        let by = self.mul(b, y.hi)?;
        let hi = self.lin(vec![(ax, F::ONE), (by, F::ONE)])?;
        Ok(U64 { lo, hi })
    }

    pub(super) fn noun_cost(
        &mut self,
        version: Wire,
        candidate: Record,
        ports: [Record; READ_PORTS],
    ) -> Result<PendingNodeCost, Error> {
        // Reserve before any fallible extension. Neither a dropped handle nor
        // a partly built/rejected gadget may become an execution relation.
        if self.unresolved_reads != 0 {
            return Err(Error::Limit);
        }
        self.unresolved_reads = READ_PORTS;
        let expected_version = self.constant(VERSION)?;
        self.bind(version, expected_version)?;
        let all = [
            candidate, ports[0], ports[1], ports[2], ports[3], ports[4], ports[5],
        ];
        for record in all {
            self.constrain_record(record)?;
        }
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                self.coherent(all[i], all[j])?;
            }
        }
        let [l, r, a, b, y, n] = ports;
        let pair = self.mul(candidate.active, candidate.pair)?;
        let atom_head = self.lin(vec![(ONE, F::ONE), (l.pair, -F::ONE)])?;
        let formula = self.mul(pair, atom_head)?;
        let mut tags = [ZERO; 18];
        for (tag, selector) in tags.iter_mut().enumerate() {
            let tag = self.constant(tag as u64)?;
            let equal = self.equal(l.value, tag)?;
            *selector = self.mul(formula, equal)?;
        }
        let binary = self.sum_selectors(&[
            tags[2], tags[3], tags[5], tags[6], tags[7], tags[9], tags[10], tags[11], tags[12],
            tags[14], tags[17],
        ])?;
        let binary = self.mul(binary, r.pair)?;
        let call = self.mul(tags[16], r.pair)?;
        let branch_body = self.mul(tags[4], r.pair)?;
        let branch = self.mul(branch_body, b.pair)?;
        let unary = self.sum_selectors(&[tags[8], tags[13], tags[15]])?;
        let active_a = self.sum_selectors(&[binary, call, branch])?;
        let active_b = self.sum_selectors(&[binary, branch_body])?;
        let reads = [
            self.read_port(pair, candidate.left, l)?,
            self.read_port(pair, candidate.right, r)?,
            self.read_port(active_a, r.left, a)?,
            self.read_port(active_b, r.right, b)?,
            self.read_port(branch, b.left, y)?,
            self.read_port(branch, b.right, n)?,
        ];
        // Fixed metadata costs mirror nox::data::cost::PATTERN_COSTS.
        let costs = [1, 1, 1, 1, 1, 1, 1, 1, 64, 1, 64, 32, 32, 32, 32, 25, 1, 1];
        let base = self.lin(
            tags.into_iter()
                .zip(costs)
                .map(|(tag, cost)| (tag, F::new(cost)))
                .collect(),
        )?;
        let first = self.weighted_bound(active_a, a.bound, unary, r.bound)?;
        let arms = self.max_u64(y.bound, n.bound)?;
        let second = self.weighted_bound(binary, b.bound, branch, arms)?;
        let total = self.saturating_u64_add(U64 { lo: base, hi: ZERO }, first)?;
        let total = self.saturating_u64_add(total, second)?;
        self.bind(candidate.bound.lo, total.lo)?;
        self.bind(candidate.bound.hi, total.hi)?;

        let compose = self.mul(tags[2], r.pair)?;
        let binary_static = self.lin(vec![(binary, F::ONE), (compose, -F::ONE)])?;
        let binary_dynamic = self.either(a.dynamic, b.dynamic)?;
        let binary_dynamic = self.mul(binary_static, binary_dynamic)?;
        let arms_dynamic = self.either(y.dynamic, n.dynamic)?;
        let branch_dynamic = self.either(a.dynamic, arms_dynamic)?;
        let branch_dynamic = self.mul(branch, branch_dynamic)?;
        let unary_dynamic = self.mul(unary, r.dynamic)?;
        let dynamic =
            self.sum_selectors(&[compose, call, binary_dynamic, branch_dynamic, unary_dynamic])?;
        self.bind(candidate.dynamic, dynamic)?;
        Ok(PendingNodeCost { candidate, reads })
    }
}
