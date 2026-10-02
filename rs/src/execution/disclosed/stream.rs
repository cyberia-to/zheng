//! Bounded successful semantic verification; specs/disclosed-semantic-stream.md.
use super::memory::{Cost, View};
use std::mem::size_of;

mod facts;
mod rules;
#[cfg(test)]
mod tests;
mod types;

use types::{Activation, Slot, Stage};
pub use types::{
    CacheHandle, Claim, Error, InputKey, Limits, ResultValue, VerifiedResult, VerifiedSummary,
    VerifiedTerminal,
};

pub struct SemanticStream {
    root: InputKey,
    stack: Vec<Activation>,
    cache: Vec<Slot>,
    limits: Limits,
    events: u64,
    completed: Option<VerifiedSummary>,
    poisoned: bool,
}

impl SemanticStream {
    /// Requested stack/cache bytes, excluding the stream object and allocator overhead.
    pub fn storage_bytes(max_frames: u32, max_cache_slots: u32) -> Option<usize> {
        let stack = (max_frames as usize).checked_mul(size_of::<Activation>())?;
        let cache = (max_cache_slots as usize).checked_mul(size_of::<Slot>())?;
        let total = stack.checked_add(cache)?;
        (total <= isize::MAX as usize).then_some(total)
    }

    pub fn new(root: InputKey, limits: Limits) -> Result<Self, Error> {
        if root
            .object
            .into_iter()
            .chain(root.formula)
            .any(|v| v >= nebu::field::P)
        {
            return Err(Error::Key);
        }
        let bytes =
            Self::storage_bytes(limits.max_frames, limits.max_cache_slots).ok_or(Error::Limit)?;
        if bytes > limits.max_buffer_bytes {
            return Err(Error::Limit);
        }
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(limits.max_frames as usize)
            .map_err(|_| Error::Allocation)?;
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(limits.max_cache_slots as usize)
            .map_err(|_| Error::Allocation)?;
        cache.resize(limits.max_cache_slots as usize, Slot::default());
        Ok(Self {
            root,
            stack,
            cache,
            limits,
            events: 0,
            completed: None,
            poisoned: false,
        })
    }

    pub fn expected(&self) -> Option<InputKey> {
        if self.poisoned || self.completed.is_some() {
            return None;
        }
        self.stack
            .last()
            .map_or(Some(self.root), Activation::expected)
    }
    pub fn active_frames(&self) -> u32 {
        self.stack.len() as u32
    }
    pub fn events(&self) -> u64 {
        self.events
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn cache(&self, slot: u32) -> Option<(CacheHandle, VerifiedSummary)> {
        if self.poisoned {
            return None;
        }
        let entry = self.cache.get(slot as usize)?;
        Some((
            CacheHandle {
                slot,
                generation: entry.generation,
            },
            entry.summary?,
        ))
    }

    fn event<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let result = if self.completed.is_some() {
            Err(Error::State)
        } else if self.events == self.limits.max_events {
            Err(Error::Limit)
        } else {
            self.events += 1;
            action(self)
        };
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub fn enter(&mut self, memory: &View<'_>, object: u32, formula: u32) -> Result<(), Error> {
        self.event(|this| {
            if this.stack.len() == this.limits.max_frames as usize {
                return Err(Error::Limit);
            }
            let expected = this.expected().ok_or(Error::State)?;
            let activation = Activation::enter(memory, object, formula, expected, this.limits)?;
            this.stack.push(activation);
            Ok(())
        })
    }

    pub fn finish(
        &mut self,
        memory: &View<'_>,
        result: u32,
        cache_slot: Option<u32>,
    ) -> Result<Option<CacheHandle>, Error> {
        self.event(|this| {
            let frame = *this.stack.last().ok_or(Error::State)?;
            let Stage::Ready(output) = frame.stage else {
                return Err(Error::State);
            };
            let result = output.check(memory, result)?;
            if let Cost::Exact(bound) = frame.bound
                && frame.metrics.cost > bound
            {
                return Err(Error::Limit);
            }
            let summary = VerifiedSummary {
                key: frame.key,
                result,
                metrics: frame.metrics,
            };
            let handle = if let Some(slot) = cache_slot {
                let entry = this.cache.get_mut(slot as usize).ok_or(Error::Cache)?;
                let generation = entry.generation.checked_add(1).ok_or(Error::Limit)?;
                *entry = Slot {
                    generation,
                    summary: Some(summary),
                };
                Some(CacheHandle { slot, generation })
            } else {
                None
            };
            this.stack.pop();
            this.accept(summary)?;
            Ok(handle)
        })
    }

    pub fn reuse(&mut self, handle: CacheHandle) -> Result<(), Error> {
        self.event(|this| {
            let entry = this.cache.get(handle.slot as usize).ok_or(Error::Cache)?;
            if entry.generation != handle.generation {
                return Err(Error::Cache);
            }
            let summary = entry.summary.ok_or(Error::Cache)?;
            if this.expected() != Some(summary.key) {
                return Err(Error::Key);
            }
            let depth = (this.stack.len() as u64)
                .checked_add(u64::from(summary.peak_frames()))
                .ok_or(Error::Limit)?;
            if depth > u64::from(this.limits.max_frames) {
                return Err(Error::Limit);
            }
            this.accept(summary)
        })
    }

    fn accept(&mut self, summary: VerifiedSummary) -> Result<(), Error> {
        if let Some(parent) = self.stack.last_mut() {
            parent.accept(summary, self.limits)
        } else if summary.key == self.root {
            self.completed = Some(summary);
            Ok(())
        } else {
            Err(Error::Key)
        }
    }

    /// Consume the session and authenticate its one closed root derivation.
    pub fn bind_terminal(self, claim: Claim) -> Result<VerifiedTerminal, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if !self.stack.is_empty() {
            return Err(Error::State);
        }
        let summary = self.completed.ok_or(Error::State)?;
        if summary.key.object != claim.object
            || summary.key.formula != claim.formula
            || summary.result.particle() != claim.result
            || summary.cost() != claim.cost
            || summary.peak_frames() > claim.max_frames
            || claim.max_frames > self.limits.max_frames
        {
            return Err(Error::Claim);
        }
        let remaining = claim
            .budget
            .checked_sub(summary.cost())
            .ok_or(Error::Claim)?;
        Ok(VerifiedTerminal {
            summary,
            remaining,
            events: self.events,
        })
    }
}
