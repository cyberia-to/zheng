//! Verifier-owned noun definitions. Contract: specs/disclosed-noun-memory.md.
use std::mem::size_of;

mod cost;
mod identity;
#[cfg(test)]
mod tests;

pub type Particle = [u64; 4];

/// Untrusted noun header. Pair indices address this table, not a host arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Atom(u64),
    Pair { left: u32, right: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cost {
    Exact(u64),
    Dynamic(u64),
}

impl Cost {
    pub fn value(self) -> u64 {
        match self {
            Self::Exact(n) | Self::Dynamic(n) => n,
        }
    }
    pub fn is_dynamic(self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

/// Claimed metadata is untrusted until `Memory::append` checks every field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Definition {
    pub value: Value,
    pub particle: Particle,
    pub cost: Cost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedNode(Definition);

impl VerifiedNode {
    pub fn value(&self) -> Value {
        self.0.value
    }
    pub fn particle(&self) -> Particle {
        self.0.particle
    }
    pub fn cost(&self) -> Cost {
        self.0.cost
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Allocation,
    NonCanonical,
    Reference,
    Particle,
    Cost,
}

/// Validated append-only table; no unchecked import or mutable record access.
pub struct Memory {
    nodes: Vec<VerifiedNode>,
    max_nodes: u32,
}

impl Memory {
    pub fn new(max_nodes: u32, max_buffer_bytes: usize) -> Result<Self, Error> {
        let bytes = (max_nodes as usize)
            .checked_mul(size_of::<VerifiedNode>())
            .ok_or(Error::Limit)?;
        if bytes > max_buffer_bytes || bytes > isize::MAX as usize {
            return Err(Error::Limit);
        }
        Ok(Self {
            nodes: Vec::new(),
            max_nodes,
        })
    }

    pub fn len(&self) -> u32 {
        // Growth always stays within the u32 caller limit.
        self.nodes.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn buffer_bytes(&self) -> usize {
        self.nodes.capacity() * size_of::<VerifiedNode>()
    }

    pub fn append(&mut self, definition: Definition) -> Result<u32, Error> {
        if self.len() == self.max_nodes {
            return Err(Error::Limit);
        }
        if definition.particle.iter().any(|&x| x >= nebu::field::P) {
            return Err(Error::NonCanonical);
        }
        let (particle, cost) = match definition.value {
            Value::Atom(value) => {
                if value >= nebu::field::P {
                    return Err(Error::NonCanonical);
                }
                (identity::atom(value), Cost::Exact(0))
            }
            Value::Pair { left, right } => {
                let a = self.node(left)?;
                let b = self.node(right)?;
                (
                    identity::pair(a.particle(), b.particle()),
                    self.pair_cost(a, b)?,
                )
            }
        };
        if particle != definition.particle {
            return Err(Error::Particle);
        }
        if cost != definition.cost {
            return Err(Error::Cost);
        }
        if self.nodes.len() == self.nodes.capacity() {
            let next = self
                .nodes
                .capacity()
                .saturating_mul(2)
                .max(64)
                .min(self.max_nodes as usize);
            self.nodes
                .try_reserve_exact(next - self.nodes.len())
                .map_err(|_| Error::Allocation)?;
        }
        let index = self.len();
        self.nodes.push(VerifiedNode(definition));
        Ok(index)
    }

    pub fn view(&self, frontier: u32) -> Result<View<'_>, Error> {
        if frontier > self.len() {
            return Err(Error::Reference);
        }
        Ok(View {
            nodes: &self.nodes[..frontier as usize],
        })
    }

    fn node(&self, index: u32) -> Result<&VerifiedNode, Error> {
        self.nodes.get(index as usize).ok_or(Error::Reference)
    }
}

/// Immutable read set limited to the caller's verified birth frontier.
pub struct View<'a> {
    nodes: &'a [VerifiedNode],
}

impl<'a> View<'a> {
    pub fn get(&self, index: u32) -> Result<&'a VerifiedNode, Error> {
        self.nodes.get(index as usize).ok_or(Error::Reference)
    }

    pub fn bind(&self, index: u32, expected: Particle) -> Result<&'a VerifiedNode, Error> {
        let node = self.get(index)?;
        if node.particle() != expected {
            return Err(Error::Particle);
        }
        Ok(node)
    }
}
