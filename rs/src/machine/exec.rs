//! The machine's native run: nox semantics as a continuation machine that
//! records one row per step and every memory access, and the digest jobs
//! the run needs (`specs/machine.md` § transitions). Every error native
//! `nox::reduce` raises is an error here; opcodes the machine does not
//! cover are refused with `Unsupported`.

use std::collections::BTreeMap;

use nebu::Goldilocks;

use super::layout::*;

pub(crate) type Row = [Goldilocks; W1];

/// Native outcome classes the machine distinguishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineError {
    /// `nox::reduce` would fail (malformed formula, type or axis error,
    /// inverse of zero, depth limit).
    Native(&'static str),
    /// A valid nox program outside the machine's coverage.
    Unsupported(&'static str),
    /// More cycles than the budget.
    Budget,
}

/// A stored entry: nouns and continuation frames, keyed by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Atom(u64),
    Pair(u64, u64),
    Frame(u64, [u64; 4]),
}

/// One memory access: `(tag, key, payload)`, at `(row, slot)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MemOp {
    pub row: usize,
    pub slot: usize,
    pub tuple: [u64; 6],
    pub write: bool,
}

#[derive(Default)]
pub(crate) struct Builder {
    pub rows: Vec<Row>,
    pub ops: Vec<MemOp>,
    pub store: Vec<Option<Entry>>,
    pub alloc: u64,
    /// Noun ids whose digest is read, and whose hash-opcode output is read.
    pub need_dig: Vec<u64>,
    pub need_hop: Vec<u64>,
}

pub(crate) fn g(v: u64) -> Goldilocks {
    Goldilocks::new(v)
}

impl Builder {
    pub fn row(&mut self, kind: usize) -> usize {
        let mut r = [Goldilocks::ZERO; W1];
        r[kind] = Goldilocks::ONE;
        self.rows.push(r);
        self.rows.len() - 1
    }
    pub fn set(&mut self, r: usize, col: usize, v: u64) {
        self.rows[r][col] = g(v);
    }
    pub fn setf(&mut self, r: usize, col: usize, v: Goldilocks) {
        self.rows[r][col] = v;
    }
    fn access(&mut self, r: usize, s: usize, tag: u64, key: u64, p: [u64; 4], write: bool) {
        self.set(r, slot(s, KEY), key);
        for (i, &v) in p.iter().enumerate() {
            self.set(r, slot(s, P0 + i), v);
        }
        self.ops.push(MemOp {
            row: r,
            slot: s,
            tuple: [tag, key, p[0], p[1], p[2], p[3]],
            write,
        });
    }
    pub fn read(&mut self, r: usize, s: usize, tag: u64, key: u64, p: [u64; 4]) {
        self.access(r, s, tag, key, p, false);
    }
    pub fn write(&mut self, r: usize, s: usize, tag: u64, key: u64, p: [u64; 4]) {
        self.access(r, s, tag, key, p, true);
    }
    pub fn entry(&self, id: u64) -> Option<Entry> {
        self.store.get(id as usize).copied().flatten()
    }
    pub fn put(&mut self, id: u64, e: Entry) {
        let i = id as usize;
        if self.store.len() <= i {
            self.store.resize(i + 1, None);
        }
        self.store[i] = Some(e);
    }
    /// Allocate a fresh id (frames and nouns share the counter).
    pub fn fresh(&mut self) -> u64 {
        let id = self.alloc;
        self.alloc += 1;
        id
    }
    pub fn atom(&self, id: u64) -> Result<u64, MachineError> {
        match self.entry(id) {
            Some(Entry::Atom(v)) => Ok(v),
            _ => Err(MachineError::Native("type error: atom expected")),
        }
    }
    pub fn pair(&self, id: u64) -> Result<(u64, u64), MachineError> {
        match self.entry(id) {
            Some(Entry::Pair(l, r)) => Ok((l, r)),
            _ => Err(MachineError::Native("pair expected")),
        }
    }
    /// Write a noun entry into slot `s` of row `r` and the store.
    pub fn alloc_noun(&mut self, r: usize, s: usize, id: u64, e: Entry) {
        match e {
            Entry::Atom(v) => self.write(r, s, TAG_ATOM, id, [v, 0, 0, 0]),
            Entry::Pair(a, b) => self.write(r, s, TAG_PAIR, id, [a, b, 0, 0]),
            Entry::Frame(..) => unreachable!("frames go through alloc_frame"),
        }
        self.put(id, e);
    }
    pub fn alloc_frame(&mut self, r: usize, s: usize, id: u64, tag: u64, p: [u64; 4]) {
        self.write(r, s, tag, id, p);
        self.put(id, Entry::Frame(tag, p));
    }
    /// Read a noun with the right tag into slot `s`.
    pub fn read_noun(&mut self, r: usize, s: usize, id: u64) -> Result<Entry, MachineError> {
        let e = self
            .entry(id)
            .ok_or(MachineError::Native("dangling noun"))?;
        match e {
            Entry::Atom(v) => self.read(r, s, TAG_ATOM, id, [v, 0, 0, 0]),
            Entry::Pair(a, b) => self.read(r, s, TAG_PAIR, id, [a, b, 0, 0]),
            Entry::Frame(..) => return Err(MachineError::Native("frame read as noun")),
        }
        Ok(e)
    }
}

/// Canonical init DAG: post-order, structurally equal nouns share an id;
/// ids from 1. Returns the root's id.
pub(crate) fn intern(
    noun: &crate::execution::ExecutionNoun,
    ids: &mut BTreeMap<(u64, u64, u64), u64>,
    order: &mut Vec<Entry>,
) -> u64 {
    use crate::execution::ExecutionNoun as N;
    let key = match noun {
        N::Atom(v) => (0, *v, 0),
        N::Pair(a, b) => {
            let l = intern(a, ids, order);
            let r = intern(b, ids, order);
            (1, l, r)
        }
    };
    if let Some(&id) = ids.get(&key) {
        return id;
    }
    order.push(if key.0 == 0 {
        Entry::Atom(key.1)
    } else {
        Entry::Pair(key.1, key.2)
    });
    let id = order.len() as u64;
    ids.insert(key, id);
    id
}

/// The tag-ordered frame flag for an EVAL binary opcode flag.
pub(crate) fn b1_flag(op: usize) -> (usize, u64) {
    match op {
        OP_ADD => (F_B1ADD, TAG_B1ADD),
        OP_SUB => (F_B1SUB, TAG_B1SUB),
        OP_MUL => (F_B1MUL, TAG_B1MUL),
        _ => (F_B1EQ, TAG_B1EQ),
    }
}

pub(crate) fn b2_of_b1(f: usize) -> (usize, u64) {
    match f {
        F_B1ADD => (F_B2ADD, TAG_B2ADD),
        F_B1SUB => (F_B2SUB, TAG_B2SUB),
        F_B1MUL => (F_B2MUL, TAG_B2MUL),
        _ => (F_B2EQ, TAG_B2EQ),
    }
}

/// The RET frame flag of a frame tag.
pub(crate) fn frame_flag(tag: u64) -> Option<usize> {
    FRAME_TAGS.iter().find(|&&(_, t)| t == tag).map(|&(f, _)| f)
}

/// The EVAL opcode flag and cost of a nox tag.
pub(crate) fn op_of(tag: u64) -> Option<(usize, u64)> {
    OPS.iter()
        .find(|&&(_, t, _)| t == tag)
        .map(|&(o, _, c)| (FLAG0 + o, c))
}
