//! Trace assembly: init rows, the run's rows, padding, and the permutation
//! region (one 32-row block per digest job), then write multiplicities.
//!
//! ```text
//! [0, P)            INIT   one init entry per row (pinned by the statement)
//! [P, P + M)        machine rows, the last one TERM
//! [P + M, start)    PAD    (start a multiple of 32)
//! [start, N)        PERM   blocks: jobs, then idle blocks
//! ```

use std::collections::BTreeMap;

use nebu::Goldilocks;

use super::exec::{Builder, Entry, g};
use super::hemera::{Tables, atom1_input, atom2_input, head4, hop_input, pair_input};
use super::layout::*;
use super::run::Digests;
use crate::air::Trace;

/// A permutation job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Job {
    Atom1(u64),
    Atom2(u64),
    Pair(u64),
    Hop(u64),
}

/// Write the init entries as rows `0..P` (ids `1..=P`).
pub(crate) fn init_rows(b: &mut Builder, entries: &[Entry]) {
    for (i, e) in entries.iter().enumerate() {
        let r = b.row(K_INIT);
        b.alloc_noun(r, 0, i as u64 + 1, *e);
    }
    b.alloc = entries.len() as u64 + 1;
}

fn schedule_dig(b: &Builder, id: u64, done: &mut BTreeMap<u64, ()>, jobs: &mut Vec<Job>) {
    if done.insert(id, ()).is_some() {
        return;
    }
    match b.entry(id) {
        Some(Entry::Atom(_)) => {
            jobs.push(Job::Atom1(id));
            jobs.push(Job::Atom2(id));
        }
        Some(Entry::Pair(l, r)) => {
            schedule_dig(b, l, done, jobs);
            schedule_dig(b, r, done, jobs);
            jobs.push(Job::Pair(id));
        }
        _ => unreachable!("digest of a noun"),
    }
}

/// Every job the run's digest and hash-opcode reads need, children first.
pub(crate) fn jobs(b: &Builder) -> Vec<Job> {
    let mut done = BTreeMap::new();
    let mut hops = BTreeMap::new();
    let mut out = Vec::new();
    for &id in &b.need_dig {
        schedule_dig(b, id, &mut done, &mut out);
    }
    for &id in &b.need_hop {
        schedule_dig(b, id, &mut done, &mut out);
        if hops.insert(id, ()).is_none() {
            out.push(Job::Hop(id));
        }
    }
    out
}

fn u4(d: [Goldilocks; 4]) -> [u64; 4] {
    d.map(|x| x.as_u64())
}

/// The bits rows (phases 0, 1) of a block for value `v` (0 unless the job
/// is an atom's first permutation: the canonical check runs on every
/// block).
fn bits_rows(b: &mut Builder, base: usize, v: u64) {
    let (lo, hi) = (v & 0xFFFF_FFFF, v >> 32);
    let (r0, r1) = (base + PH_BITS0, base + PH_BITS1);
    b.set(r0, B_LO, lo);
    b.set(r1, B_HL, hi & 0xFF_FFFF);
    b.set(r1, B_HT, hi >> 24);
    b.set(r1, B_LOC, lo);
    let max = hi == 0xFFFF_FFFF;
    b.set(r1, B_MAX, u64::from(max));
    if !max {
        b.setf(r1, B_MINV, (g(hi) - g(0xFFFF_FFFF)).inv());
    }
    for i in 0..32 {
        b.set(r0, B_BITS + i, (lo >> i) & 1);
        b.set(r1, B_BITS + i, (hi >> i) & 1);
    }
}

/// The permutation rows of a block (phases 2..=27) for `input`; the
/// output row's slot 0 carries the output under `id`.
fn perm_rows(b: &mut Builder, t: &Tables, base: usize, input: &[Goldilocks; 16], id: u64) -> [u64; 4] {
    let (states, invs) = t.trace(input);
    for (i, &x) in input.iter().enumerate() {
        b.setf(base + PH_MDS, STATE + i, x);
    }
    for (k, s) in states.iter().enumerate() {
        for (i, &x) in s.iter().enumerate() {
            b.setf(base + PH_ROUND0 + k, STATE + i, x);
        }
        if k < invs.len() {
            b.setf(base + PH_ROUND0 + k, PINV, invs[k]);
        }
    }
    let out = u4(head4(states.last().expect("output")));
    b.set(base + PH_OUT, slot(0, KEY), id);
    for (i, &o) in out.iter().enumerate() {
        b.set(base + PH_OUT, slot(0, P0 + i), o);
    }
    out
}

/// An idle block: no job, the permutation of the zero state.
fn idle_block(b: &mut Builder, t: &Tables) {
    let base = b.rows.len();
    for _ in 0..BLOCK {
        b.row(K_PERM);
    }
    bits_rows(b, base, 0);
    perm_rows(b, t, base, &[Goldilocks::ZERO; 16], 0);
}

/// Emit one job's 32-row block.
fn block(b: &mut Builder, dg: &mut Digests, t: &Tables, job: Job) {
    let (flag, id) = match job {
        Job::Atom1(id) => (J_ATOM1, id),
        Job::Atom2(id) => (J_ATOM2, id),
        Job::Pair(id) => (J_PAIR, id),
        Job::Hop(id) => (J_HOP, id),
    };
    let base = b.rows.len();
    for _ in 0..BLOCK {
        let r = b.row(K_PERM);
        b.set(r, flag, 1);
        b.set(r, JOB_ID, id);
    }
    let atom_value = match (job, b.entry(id)) {
        (Job::Atom1(_), Some(Entry::Atom(v))) => v,
        _ => 0,
    };
    bits_rows(b, base, atom_value);
    let input = match job {
        Job::Atom1(id) => {
            let v = atom_value;
            b.read(base + PH_MDS, 0, TAG_ATOM, id, [v, 0, 0, 0]);
            atom1_input(v)
        }
        Job::Atom2(id) => {
            let Some(Entry::Atom(v)) = b.entry(id) else { unreachable!() };
            let bd = head4(&t.permute(&atom1_input(v)));
            b.read(base + PH_MDS, 0, TAG_ABASE, id, u4(bd));
            atom2_input(bd)
        }
        Job::Pair(id) => {
            let Some(Entry::Pair(l, r)) = b.entry(id) else { unreachable!() };
            let (dl, dr) = (dg.digest(b, l), dg.digest(b, r));
            b.read(base + PH_MDS, 0, TAG_PAIR, id, [l, r, 0, 0]);
            b.read(base + PH_MDS, 1, TAG_DIG, l, u4(dl));
            b.read(base + PH_MDS, 2, TAG_DIG, r, u4(dr));
            pair_input(dl, dr)
        }
        Job::Hop(id) => {
            let d = dg.digest(b, id);
            b.read(base + PH_MDS, 0, TAG_DIG, id, u4(d));
            hop_input(d)
        }
    };
    let out = perm_rows(b, t, base, &input, id);
    let tag = match job {
        Job::Atom1(_) => TAG_ABASE,
        Job::Hop(_) => TAG_HOP,
        _ => TAG_DIG,
    };
    b.write(base + PH_OUT, 0, tag, id, out);
}

/// Pad, emit the region, size the trace — one power-of-two segment, or a
/// multiple of `2^seg_max` rows — and fill the write multiplicities.
/// Returns the trace, the region start and `log2` of the segment rows.
pub(crate) fn finish(mut b: Builder, dg: &mut Digests, t: &Tables, seg_max: u32) -> (Trace, usize, u32) {
    let jobs = jobs(&b);
    while !b.rows.len().is_multiple_of(BLOCK) {
        b.row(K_PAD);
    }
    let start = b.rows.len();
    for job in jobs {
        block(&mut b, dg, t, job);
    }
    if b.rows.len() == start {
        idle_block(&mut b, t);
    }
    let single = b.rows.len().next_power_of_two().max(2 * BLOCK);
    let (n, seg_log) = if single <= 1 << seg_max {
        (single, single.trailing_zeros())
    } else {
        (b.rows.len().div_ceil(1 << seg_max) << seg_max, seg_max)
    };
    while b.rows.len() < n {
        idle_block(&mut b, t);
    }
    let mut reads: BTreeMap<[u64; 6], u64> = BTreeMap::new();
    for op in b.ops.iter().filter(|o| !o.write) {
        *reads.entry(op.tuple).or_default() += 1;
    }
    let writes: Vec<(usize, usize, [u64; 6])> = b
        .ops
        .iter()
        .filter(|o| o.write)
        .map(|o| (o.row, o.slot, o.tuple))
        .collect();
    for (row, s, tuple) in writes {
        let c = reads.remove(&tuple).unwrap_or(0);
        b.set(row, slot(s, M), c);
    }
    assert!(reads.is_empty(), "a read without a write: {reads:?}");
    let cells: Vec<Goldilocks> = b.rows.iter().flatten().copied().collect();
    (Trace { width: W1, cells }, start, seg_log)
}
