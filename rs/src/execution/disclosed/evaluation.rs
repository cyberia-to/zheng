//! Experimental successful derivations; contract: specs/disclosed-evaluation-dag.md.
use super::memory::{Cost, Particle, View};
use std::mem::size_of;

mod primitives;
mod rules;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Premises {
    None,
    One(u32),
    Two([u32; 2]),
    Three([u32; 3]),
}

impl Premises {
    pub fn as_slice(&self) -> &[u32] {
        match self {
            Self::None => &[],
            Self::One(id) => std::slice::from_ref(id),
            Self::Two(ids) => ids,
            Self::Three(ids) => ids,
        }
    }
}

/// Untrusted indices into this store's fixed noun view and prior evaluations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub object: u32,
    pub formula: u32,
    pub result: u32,
    pub premises: Premises,
}

/// Stable semantic keys; noun occurrence indices remain local to one view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationParticles {
    pub object: Particle,
    pub formula: Particle,
    pub result: Particle,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_evaluations: u32,
    pub max_buffer_bytes: usize,
    pub max_cost: u64,
    pub max_frames: u32,
    pub max_steps: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Allocation,
    Noun,
    Premise,
    Arity,
    Formula,
    UnsupportedOpcode,
    Type,
    InverseZero,
    Result,
    Cost,
    Claim,
}

/// An admitted semantic derivation, with verifier-derived integer metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedEvaluation {
    candidate: Candidate,
    cost: u64,
    occurrences: u64,
    peak_frames: u32,
    steps: u64,
}

impl VerifiedEvaluation {
    pub fn candidate(&self) -> Candidate {
        self.candidate
    }
    pub fn cost(&self) -> u64 {
        self.cost
    }
    pub fn occurrences(&self) -> u64 {
        self.occurrences
    }
    pub fn peak_frames(&self) -> u32 {
        self.peak_frames
    }
    pub fn steps(&self) -> u64 {
        self.steps
    }
}

/// Expected public values supplied by the surrounding authenticated statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub object: Particle,
    pub formula: Particle,
    pub result: Particle,
    pub cost: u64,
    pub budget: u64,
    pub max_frames: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedClaim {
    evaluation: VerifiedEvaluation,
    remaining: u64,
}

impl VerifiedClaim {
    pub fn evaluation(&self) -> &VerifiedEvaluation {
        &self.evaluation
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

/// The noun view stays fixed while all candidates and their premises are checked.
pub struct Evaluations<'a> {
    memory: View<'a>,
    records: Vec<VerifiedEvaluation>,
    limits: Limits,
}

impl<'a> Evaluations<'a> {
    pub fn new(memory: View<'a>, limits: Limits) -> Result<Self, Error> {
        let bytes = (limits.max_evaluations as usize)
            .checked_mul(size_of::<VerifiedEvaluation>())
            .ok_or(Error::Limit)?;
        if bytes > limits.max_buffer_bytes || bytes > isize::MAX as usize {
            return Err(Error::Limit);
        }
        Ok(Self {
            memory,
            records: Vec::new(),
            limits,
        })
    }

    pub fn len(&self) -> u32 {
        self.records.len() as u32
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn buffer_bytes(&self) -> usize {
        self.records.capacity() * size_of::<VerifiedEvaluation>()
    }
    pub fn get(&self, index: u32) -> Result<&VerifiedEvaluation, Error> {
        self.records.get(index as usize).ok_or(Error::Premise)
    }
    pub fn particles(&self, index: u32) -> Result<EvaluationParticles, Error> {
        let c = self.get(index)?.candidate;
        Ok(EvaluationParticles {
            object: self.noun(c.object)?.particle(),
            formula: self.noun(c.formula)?.particle(),
            result: self.noun(c.result)?.particle(),
        })
    }

    pub fn append(&mut self, candidate: Candidate) -> Result<u32, Error> {
        if self.len() == self.limits.max_evaluations {
            return Err(Error::Limit);
        }
        self.noun(candidate.object)?;
        let formula = self.noun(candidate.formula)?;
        self.noun(candidate.result)?;
        let mut cost = self.dispatch_cost(candidate.formula)?;
        let mut occurrences = 1u64;
        let mut peak = 0u32;
        for &id in candidate.premises.as_slice() {
            let child = self.get(id)?;
            cost = cost.checked_add(child.cost).ok_or(Error::Limit)?;
            occurrences = occurrences
                .checked_add(child.occurrences)
                .ok_or(Error::Limit)?;
            peak = peak.max(child.peak_frames);
        }
        let peak_frames = peak.checked_add(1).ok_or(Error::Limit)?;
        let steps = occurrences.checked_mul(2).ok_or(Error::Limit)?;
        if cost > self.limits.max_cost
            || peak_frames > self.limits.max_frames
            || steps > self.limits.max_steps
        {
            return Err(Error::Limit);
        }
        self.check_rule(candidate)?;
        if let Cost::Exact(bound) = formula.cost()
            && cost > bound
        {
            return Err(Error::Cost);
        }
        if self.records.len() == self.records.capacity() {
            let next = self
                .records
                .capacity()
                .saturating_mul(2)
                .max(64)
                .min(self.limits.max_evaluations as usize);
            self.records
                .try_reserve_exact(next - self.records.len())
                .map_err(|_| Error::Allocation)?;
        }
        let index = self.len();
        self.records.push(VerifiedEvaluation {
            candidate,
            cost,
            occurrences,
            peak_frames,
            steps,
        });
        Ok(index)
    }

    /// Bind the complete store's last record; an empty store rejects.
    pub fn bind_last(&self, claim: Claim) -> Result<VerifiedClaim, Error> {
        let evaluation = *self.records.last().ok_or(Error::Claim)?;
        let candidate = evaluation.candidate;
        for (id, expected) in [
            (candidate.object, claim.object),
            (candidate.formula, claim.formula),
            (candidate.result, claim.result),
        ] {
            self.memory.bind(id, expected).map_err(|_| Error::Claim)?;
        }
        if evaluation.cost != claim.cost
            || evaluation.peak_frames > claim.max_frames
            || claim.max_frames > self.limits.max_frames
        {
            return Err(Error::Claim);
        }
        let remaining = claim
            .budget
            .checked_sub(evaluation.cost)
            .ok_or(Error::Claim)?;
        Ok(VerifiedClaim {
            evaluation,
            remaining,
        })
    }
}
