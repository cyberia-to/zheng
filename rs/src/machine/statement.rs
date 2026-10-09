//! The machine statement — program, inputs, output noun, cycles, budget —
//! and everything the verifier derives from it: the init entries, the
//! subject, the initial ids and the output digest.

use std::collections::BTreeMap;

use nebu::Goldilocks;

use super::exec::{Entry, intern};
use crate::execution::{ExecutionNoun as N, NounToken};

/// Largest program / output in tokens.
pub const MAX_TOKENS: usize = 1 << 20;
pub const MAX_INPUTS: usize = 64;

/// A public nox execution statement proven by the machine.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MachineStatement {
    pub program: Vec<NounToken>,
    pub input: Vec<u64>,
    /// The output noun (prefix tokens).
    pub output: Vec<NounToken>,
    pub cycles: u64,
    pub budget: u64,
}

/// Parse prefix tokens into a noun (canonical atoms, exact length).
pub fn parse(tokens: &[NounToken]) -> Result<N, String> {
    if tokens.is_empty() || tokens.len() > MAX_TOKENS {
        return Err("machine: noun size".into());
    }
    let mut stack: Vec<N> = Vec::new();
    for t in tokens.iter().rev() {
        match t {
            NounToken::Atom(v) if *v < nebu::field::P => stack.push(N::Atom(*v)),
            NounToken::Atom(_) => return Err("machine: noncanonical atom".into()),
            NounToken::Pair => {
                let a = stack.pop().ok_or("machine: malformed noun")?;
                let b = stack.pop().ok_or("machine: malformed noun")?;
                stack.push(N::Pair(Box::new(a), Box::new(b)));
            }
        }
    }
    match (stack.pop(), stack.is_empty()) {
        (Some(n), true) => Ok(n),
        _ => Err("machine: malformed noun".into()),
    }
}

/// Prefix tokens of a noun.
pub fn tokens(noun: &N) -> Vec<NounToken> {
    let mut out = Vec::new();
    let mut pending = vec![noun];
    while let Some(n) = pending.pop() {
        match n {
            N::Atom(v) => out.push(NounToken::Atom(*v)),
            N::Pair(a, b) => {
                out.push(NounToken::Pair);
                pending.push(b);
                pending.push(a);
            }
        }
    }
    out
}

/// The subject of public inputs `[x_k [… [x_1 0]]]`.
pub fn subject(input: &[u64]) -> N {
    input.iter().fold(N::Atom(0), |acc, &x| N::Pair(Box::new(N::Atom(x)), Box::new(acc)))
}

/// The structural digest of a noun (nox identity).
pub fn digest(noun: &N) -> [Goldilocks; 4] {
    match noun {
        N::Atom(v) => nox::data::hash_atom(Goldilocks::new(*v)),
        N::Pair(a, b) => nox::data::hash_pair(&digest(a), &digest(b)),
    }
}

/// What the verifier derives from a statement.
pub(crate) struct Derived {
    pub entries: Vec<Entry>,
    pub fml0: u64,
    pub obj0: u64,
    pub output: [Goldilocks; 4],
}

impl MachineStatement {
    pub fn validate(&self) -> Result<(), String> {
        if self.input.len() > MAX_INPUTS
            || self.input.iter().any(|&v| v >= nebu::field::P)
            || self.cycles > self.budget
            || self.budget >= nebu::field::P
        {
            return Err("machine: statement bounds".into());
        }
        Ok(())
    }

    pub(crate) fn derive(&self) -> Result<Derived, String> {
        let output = parse(&self.output)?;
        let mut d = self.init()?;
        d.output = digest(&output);
        Ok(d)
    }

    /// The init DAG and initial ids (the output digest left zero).
    pub(crate) fn init(&self) -> Result<Derived, String> {
        self.validate()?;
        let program = parse(&self.program)?;
        let mut ids = BTreeMap::new();
        let mut entries = Vec::new();
        let fml0 = intern(&program, &mut ids, &mut entries);
        let obj0 = intern(&subject(&self.input), &mut ids, &mut entries);
        Ok(Derived {
            entries,
            fml0,
            obj0,
            output: [Goldilocks::ZERO; 4],
        })
    }

    /// Canonical bytes bound into every transcript.
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = b"zheng-nox-machine-statement-v1".to_vec();
        for list in [&self.program, &self.output] {
            b.extend_from_slice(&(list.len() as u64).to_le_bytes());
            for t in list.iter() {
                match t {
                    NounToken::Atom(v) => {
                        b.push(0);
                        b.extend_from_slice(&v.to_le_bytes());
                    }
                    NounToken::Pair => b.push(1),
                }
            }
        }
        b.extend_from_slice(&(self.input.len() as u64).to_le_bytes());
        for v in &self.input {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.cycles.to_le_bytes());
        b.extend_from_slice(&self.budget.to_le_bytes());
        b
    }
}

/// `(tag, p0, p1)` of every init entry.
pub(crate) fn init_columns(entries: &[Entry]) -> Vec<(u64, u64, u64)> {
    use super::layout::{TAG_ATOM, TAG_PAIR};
    entries
        .iter()
        .map(|e| match *e {
            Entry::Atom(v) => (TAG_ATOM, v, 0),
            Entry::Pair(a, b) => (TAG_PAIR, a, b),
            Entry::Frame(..) => unreachable!("init entries are nouns"),
        })
        .collect()
}
