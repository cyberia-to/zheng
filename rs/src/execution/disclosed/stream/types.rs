use super::super::memory::{Cost, Particle};

pub use super::super::evaluation::Claim;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputKey {
    pub object: Particle,
    pub formula: Particle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultValue {
    Atom(u64),
    Pair { left: Particle, right: Particle },
}

/// Checked header facts, independent of any noun table's occurrence indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedResult {
    pub(super) particle: Particle,
    pub(super) value: ResultValue,
}
impl VerifiedResult {
    pub fn particle(&self) -> Particle {
        self.particle
    }
    pub fn value(&self) -> ResultValue {
        self.value
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedSummary {
    pub(super) key: InputKey,
    pub(super) result: VerifiedResult,
    pub(super) metrics: Metrics,
}
impl VerifiedSummary {
    pub fn key(&self) -> InputKey {
        self.key
    }
    pub fn result(&self) -> &VerifiedResult {
        &self.result
    }
    pub fn cost(&self) -> u64 {
        self.metrics.cost
    }
    pub fn occurrences(&self) -> u64 {
        self.metrics.occurrences
    }
    pub fn peak_frames(&self) -> u32 {
        self.metrics.peak_frames
    }
    pub fn steps(&self) -> u64 {
        self.metrics.steps
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedTerminal {
    pub(super) summary: VerifiedSummary,
    pub(super) remaining: u64,
    pub(super) events: u64,
}
impl VerifiedTerminal {
    pub fn summary(&self) -> &VerifiedSummary {
        &self.summary
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn events(&self) -> u64 {
        self.events
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheHandle {
    pub slot: u32,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_frames: u32,
    pub max_cache_slots: u32,
    pub max_buffer_bytes: usize,
    pub max_cost: u64,
    pub max_steps: u64,
    pub max_events: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Allocation,
    Noun,
    Key,
    Shape,
    UnsupportedOpcode,
    Type,
    InverseZero,
    Output,
    State,
    Cache,
    Poisoned,
    Claim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Metrics {
    pub cost: u64,
    pub occurrences: u64,
    pub peak_frames: u32,
    pub steps: u64,
}
impl Metrics {
    pub fn leaf(cost: u64, limits: Limits) -> Result<Self, Error> {
        Self {
            cost,
            occurrences: 1,
            peak_frames: 1,
            steps: 2,
        }
        .check(limits)
    }
    pub fn add(self, child: Self, limits: Limits) -> Result<Self, Error> {
        let cost = self.cost.checked_add(child.cost).ok_or(Error::Limit)?;
        let occurrences = self
            .occurrences
            .checked_add(child.occurrences)
            .ok_or(Error::Limit)?;
        let peak_frames = self
            .peak_frames
            .max(child.peak_frames.checked_add(1).ok_or(Error::Limit)?);
        let steps = occurrences.checked_mul(2).ok_or(Error::Limit)?;
        Self {
            cost,
            occurrences,
            peak_frames,
            steps,
        }
        .check(limits)
    }
    fn check(self, limits: Limits) -> Result<Self, Error> {
        if self.cost > limits.max_cost
            || self.peak_frames > limits.max_frames
            || self.steps > limits.max_steps
        {
            Err(Error::Limit)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Output {
    Equal(Particle),
    Atom(u64),
    Pair(Particle, Particle),
    HashData(Particle),
}

#[derive(Clone, Copy)]
pub(super) enum Stage {
    Ready(Output),
    Unary {
        tag: u64,
        formula: Particle,
    },
    BinaryLeft {
        tag: u64,
        a: Particle,
        b: Particle,
    },
    BinaryRight {
        tag: u64,
        b: Particle,
        left: VerifiedResult,
    },
    BranchTest {
        test: Particle,
        yes: Particle,
        no: Particle,
    },
    BranchChosen {
        formula: Particle,
    },
    Continuation(InputKey),
}

#[derive(Clone, Copy)]
pub(super) struct Activation {
    pub key: InputKey,
    pub bound: Cost,
    pub metrics: Metrics,
    pub stage: Stage,
}

#[derive(Clone, Copy, Default)]
pub(super) struct Slot {
    pub generation: u64,
    pub summary: Option<VerifiedSummary>,
}
