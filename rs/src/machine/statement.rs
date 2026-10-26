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
/// Bound on the state reads a statement may carry.
pub const MAX_READS: usize = 4096;
/// Namespaces `look` reads (nox: `namespace > 9` is unavailable).
pub const MAX_LOOK_NAMESPACE: u64 = 9;

/// The state a run's `look`s read: the root every look's subject carries
/// at axis 2 as `[r0 [r1 [r2 r3]]]`, and every read `(namespace, key,
/// value)` once. The verifier authenticates evidence under `root` and
/// checks each read against it before the reads enter the trace.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MachineState {
    pub root: [u64; 4],
    pub reads: Vec<(u64, u64, u64)>,
}

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
    /// The state read by `look` (`None`: the run reads no state).
    #[cfg_attr(feature = "serde", serde(default))]
    pub state: Option<MachineState>,
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
    input.iter().fold(N::Atom(0), |acc, &x| {
        N::Pair(Box::new(N::Atom(x)), Box::new(acc))
    })
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
    /// Digest of the state root noun (zero without state).
    pub root: [Goldilocks; 4],
}

/// The state root noun `[r0 [r1 [r2 r3]]]`.
pub fn root_noun(root: &[u64; 4]) -> N {
    let a = |i: usize| Box::new(N::Atom(root[i]));
    N::Pair(a(0), Box::new(N::Pair(a(1), Box::new(N::Pair(a(2), a(3))))))
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
        if let Some(st) = &self.state {
            let canonical = |v: u64| v < nebu::field::P;
            let mut keys: Vec<(u64, u64)> = st.reads.iter().map(|&(n, k, _)| (n, k)).collect();
            keys.sort_unstable();
            keys.dedup();
            if st.reads.is_empty()
                || st.reads.len() > MAX_READS
                || keys.len() != st.reads.len()
                || !st.root.iter().all(|&v| canonical(v))
                || st
                    .reads
                    .iter()
                    .any(|&(n, k, v)| n > MAX_LOOK_NAMESPACE || !canonical(k) || !canonical(v))
            {
                return Err("machine: state bounds".into());
            }
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
        let mut root = [Goldilocks::ZERO; 4];
        if let Some(st) = &self.state {
            entries.extend(st.reads.iter().map(|&(n, k, v)| Entry::State(n, k, v)));
            root = digest(&root_noun(&st.root));
        }
        Ok(Derived {
            entries,
            fml0,
            obj0,
            output: [Goldilocks::ZERO; 4],
            root,
        })
    }

    /// Canonical bytes bound into every transcript (the machine's, the
    /// IVC statement digest and through it every wrap level's public
    /// digest): the program by its digest ([`program_digest`]), then the
    /// output tokens, inputs, cycles, budget and state.
    pub fn bytes(&self) -> Vec<u8> {
        self.public().bytes()
    }

    /// The statement as it travels: the program by its digest.
    pub fn public(&self) -> MachinePublic {
        MachinePublic {
            program: program_digest(&self.program),
            input: self.input.clone(),
            output: self.output.clone(),
            cycles: self.cycles,
            budget: self.budget,
            state: self.state.clone(),
        }
    }
}

/// Domain of a program's digest.
const PROGRAM_DOMAIN: &[u8] = b"zheng-nox-program-v1";

fn put_tokens(b: &mut Vec<u8>, list: &[NounToken]) {
    b.extend_from_slice(&(list.len() as u64).to_le_bytes());
    for t in list {
        match t {
            NounToken::Atom(v) => {
                b.push(0);
                b.extend_from_slice(&v.to_le_bytes());
            }
            NounToken::Pair => b.push(1),
        }
    }
}

/// The program's particle: the hemera digest of its canonical token
/// encoding (`len`, then per token `0 ‖ atom u64 LE` or `1`) under the
/// domain `zheng-nox-program-v1`.
pub fn program_digest(program: &[NounToken]) -> [u8; 32] {
    let mut b = Vec::with_capacity(16 + 9 * program.len());
    put_tokens(&mut b, program);
    let mut h = hemera::Hasher::new();
    h.update(PROGRAM_DOMAIN);
    h.update(&b);
    *h.finalize().as_bytes()
}

/// A machine statement with the program bound by its digest — what the
/// envelopes of profiles 4–6 carry. The verifier is given the program out
/// of band; [`MachinePublic::with_program`] checks it against the digest
/// before anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MachinePublic {
    pub program: [u8; 32],
    pub input: Vec<u64>,
    /// The output noun (prefix tokens).
    pub output: Vec<NounToken>,
    pub cycles: u64,
    pub budget: u64,
    #[cfg_attr(feature = "serde", serde(default))]
    pub state: Option<MachineState>,
}

impl MachinePublic {
    /// The full statement of `program`, if its digest is this statement's.
    pub fn with_program(&self, program: &[NounToken]) -> Result<MachineStatement, String> {
        if program_digest(program) != self.program {
            return Err("machine: the program's digest is not the statement's".into());
        }
        Ok(MachineStatement {
            program: program.to_vec(),
            input: self.input.clone(),
            output: self.output.clone(),
            cycles: self.cycles,
            budget: self.budget,
            state: self.state.clone(),
        })
    }

    /// Canonical bytes bound into every transcript (`MachineStatement::bytes`).
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = b"zheng-nox-machine-statement-v2".to_vec();
        b.extend_from_slice(&self.program);
        put_tokens(&mut b, &self.output);
        b.extend_from_slice(&(self.input.len() as u64).to_le_bytes());
        for v in &self.input {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.cycles.to_le_bytes());
        b.extend_from_slice(&self.budget.to_le_bytes());
        if let Some(st) = &self.state {
            b.extend_from_slice(b"state");
            for v in st.root {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&(st.reads.len() as u64).to_le_bytes());
            for &(n, k, v) in &st.reads {
                for x in [n, k, v] {
                    b.extend_from_slice(&x.to_le_bytes());
                }
            }
        }
        b
    }
}

/// `(tag, p0, p1, p2)` of every init entry.
pub(crate) fn init_columns(entries: &[Entry]) -> Vec<(u64, u64, u64, u64)> {
    use super::layout::{TAG_ATOM, TAG_PAIR, TAG_STATE};
    entries
        .iter()
        .map(|e| match *e {
            Entry::Atom(v) => (TAG_ATOM, v, 0, 0),
            Entry::Pair(a, b) => (TAG_PAIR, a, b, 0),
            Entry::State(n, k, v) => (TAG_STATE, n, k, v),
            Entry::Frame(..) => unreachable!("init entries are nouns and reads"),
        })
        .collect()
}
