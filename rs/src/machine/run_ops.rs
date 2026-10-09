//! Native steps of the word opcodes and lt (32 WBIT rows), look (the
//! authenticated read and its AUX row) and call (the witness rows).

use std::collections::BTreeMap;

use nebu::Goldilocks;

use super::exec::{Builder, Entry, Hints, MachineError, g};
use super::layout::*;
use super::run::{Digests, RunState as State, indicator, inv_or_zero, state, u};
use crate::execution::ExecutionNoun as N;
use crate::execution::state_evidence::AuthenticatedState;

const WORD_MASK: u64 = 0xFFFF_FFFF;

#[cfg(test)]
thread_local! {
    /// Test-only: build the non-canonical alias `v + p` of a small value
    /// (lt's first operand, an axis address) to check that the relation
    /// refuses it.
    pub(crate) static ALIAS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `v + p` when the alias hook is on and `v + p < 2^64`, else `v`.
pub(crate) fn alias(v: u64) -> u64 {
    #[cfg(test)]
    if ALIAS.with(std::cell::Cell::get) && v < WORD_MASK {
        return v + nebu::field::P;
    }
    v
}

/// What a run carries besides the trace: its hints, the authenticated
/// state, the init ids of the statement's reads and the reads it made.
pub(crate) struct Ctx<'a> {
    pub hints: Hints<'a>,
    pub auth: Option<AuthenticatedState<'a>>,
    pub root: [u64; 4],
    pub state_ids: BTreeMap<(u64, u64), u64>,
    /// `(namespace, key, value)` in order of first use.
    pub reads: Vec<(u64, u64, u64)>,
    /// A read had no init entry: the trace is a dry run.
    pub missing: bool,
}

/// The result of a word opcode or lt on atoms `u`, `w` (nox semantics).
pub(crate) fn word_result(op: u64, u: u64, w: u64) -> Result<u64, MachineError> {
    if op != T_LT && (u > WORD_MASK || w > WORD_MASK) {
        return Err(MachineError::Native("type error: word expected"));
    }
    Ok(match op {
        T_LT => u64::from(u >= w),
        T_XOR => u ^ w,
        T_AND => u & w,
        T_NOT => !w & WORD_MASK,
        _ if w >= 32 => 0,
        _ => (u << w) & WORD_MASK,
    })
}

/// B2W: read both operands, write the result atom, prove it on 32 rows.
pub(crate) fn word(
    b: &mut Builder,
    r: usize,
    op: u64,
    x: u64,
    val: u64,
    parent: u64,
    cyc: u64,
) -> Result<State, MachineError> {
    let ua = b.atom(x)?;
    let wa = b.atom(val)?;
    b.read(r, 1, TAG_ATOM, x, [ua, 0, 0, 0]);
    b.read(r, 2, TAG_ATOM, val, [wa, 0, 0, 0]);
    b.set(r, R_OP, op);
    let lt_u = if op == T_LT { alias(ua) } else { ua };
    let res = if op == T_LT {
        u64::from(lt_u >= wa)
    } else {
        word_result(op, ua, wa)?
    };
    let id = b.fresh();
    b.alloc_noun(r, 3, id, Entry::Atom(res));
    wbit_rows(b, op, [ua, lt_u], wa, res, parent, cyc);
    Ok(State::Ret { val: id, k: parent })
}

/// `u = [value, its 64-bit form]` (the form differs only under the test
/// alias hook).
fn wbit_rows(b: &mut Builder, op: u64, u: [u64; 2], wa: u64, res: u64, k: u64, cyc: u64) {
    let [ua, lt_u] = u;
    let flag = WOPS.iter().find(|&&(_, t)| t == op).expect("word op").0;
    let (ci, hi2) = if op == T_SHL && wa < 32 {
        let t = u128::from(ua) << wa;
        ((t as u64) & WORD_MASK, ((t >> 32) as u64) * 2)
    } else {
        (0, 0)
    };
    let rs = match op {
        T_LT => [lt_u & WORD_MASK, wa & WORD_MASK, lt_u >> 32, wa >> 32],
        T_SHL => [ua, wa, ci, hi2],
        _ => [ua, wa, res, 0],
    };
    let one = Goldilocks::ONE;
    // shl
    let (mut pw, mut q) = (one, g(2));
    let z = u64::from(wa < 32);
    // lt: canonical checks and comparisons so far
    let (mut na, mut oa, mut nb, mut ob) = (1u64, 0u64, 1u64, 0u64);
    let (mut ll, mut lh, mut eh) = (0u64, 0u64, 1u64);
    for cnt in 0..32u64 {
        let r = b.row(K_AUX);
        state(b, r, ua, wa, k, res, cyc);
        b.set(r, S_WBIT, 1);
        b.set(r, flag, 1);
        b.set(r, B_CNT, cnt);
        indicator(b, r, B_LAST, B_LINV, cnt, 31);
        indicator(b, r, B_FIRST, B_FINV, cnt, 0);
        let bits: Vec<u64> = rs.iter().map(|&v| (v >> cnt) & 1).collect();
        for (i, (&v, &bit)) in rs.iter().zip(&bits).enumerate() {
            b.set(r, [G_R0, G_R1, G_R2, G_R3][i], v >> cnt);
            b.set(r, [G_B0, G_B1, G_B2, G_B3][i], bit);
        }
        match op {
            T_SHL => {
                b.setf(r, G_P, pw);
                b.setf(r, G_Q, q);
                indicator(b, r, G_I5, G_V5, cnt, 5);
                b.set(r, G_Z, z);
                b.setf(r, G_ZI, inv_or_zero(g(wa >> 5)));
                b.set(r, G_CI, ci);
                b.set(r, G_HI, hi2);
                if bits[1] == 1 {
                    pw *= q;
                }
                q = q * q;
            }
            T_LT => {
                let (al, bl, ah, bh) = (bits[0], bits[1], bits[2], bits[3]);
                let na2 = na & ah;
                let oa2 = oa | al;
                let nb2 = nb & bh;
                let ob2 = ob | bl;
                let ll2 = if al != bl { bl } else { ll };
                let lh2 = if ah != bh { bh } else { lh };
                let eh2 = eh & u64::from(ah == bh);
                for (col, v) in [
                    (G_NA, na),
                    (G_OA, oa),
                    (G_NB, nb),
                    (G_OB, ob),
                    (G_LL, ll),
                    (G_LH, lh),
                    (G_EH, eh),
                    (G_NA2, na2),
                    (G_OA2, oa2),
                    (G_NB2, nb2),
                    (G_OB2, ob2),
                    (G_LL2, ll2),
                    (G_LH2, lh2),
                    (G_EH2, eh2),
                ] {
                    b.set(r, col, v);
                }
                (na, oa, nb, ob, ll, lh, eh) = (na2, oa2, nb2, ob2, ll2, lh2, eh2);
            }
            _ => {}
        }
    }
}

/// The subject's state root noun `[r0 [r1 [r2 r3]]]` at axis 2, as limbs.
fn root_limbs(b: &Builder, obj: u64) -> Option<([u64; 4], u64)> {
    let (root, _) = b.pair(obj).ok()?;
    let (l0, m) = b.pair(root).ok()?;
    let (l1, i) = b.pair(m).ok()?;
    let (l2, l3) = b.pair(i).ok()?;
    let limbs = [
        b.atom(l0).ok()?,
        b.atom(l1).ok()?,
        b.atom(l2).ok()?,
        b.atom(l3).ok()?,
    ];
    Some((limbs, root))
}

/// B2LOOK: `(namespace, key)` atoms, the authenticated read, then the AUX
/// row that checks the subject's root noun and writes the value atom.
#[allow(clippy::too_many_arguments)]
pub(crate) fn look(
    b: &mut Builder,
    dg: &mut Digests,
    ctx: &mut Ctx<'_>,
    r: usize,
    x: u64,
    val: u64,
    fobj: u64,
    parent: u64,
    cyc: u64,
) -> Result<State, MachineError> {
    let unavailable = MachineError::Native("look: unavailable");
    let ns = b.atom(x)?;
    let key = b.atom(val)?;
    b.read(r, 1, TAG_ATOM, x, [ns, 0, 0, 0]);
    b.read(r, 2, TAG_ATOM, val, [key, 0, 0, 0]);
    let auth = ctx.auth.ok_or(unavailable.clone())?;
    let (limbs, root) = root_limbs(b, fobj).ok_or(unavailable.clone())?;
    if ns > 9 || limbs != ctx.root {
        return Err(unavailable);
    }
    let value = auth.cell(ns, key).ok_or(unavailable)?;
    if !ctx.reads.iter().any(|&(n, k, _)| (n, k) == (ns, key)) {
        ctx.reads.push((ns, key, value));
    }
    let sid = match ctx.state_ids.get(&(ns, key)) {
        Some(&id) => id,
        None => {
            ctx.missing = true;
            0
        }
    };
    if !ctx.missing {
        b.read(r, 3, TAG_STATE, sid, [ns, key, value, 0]);
    }
    let rl = b.row(K_AUX);
    state(b, rl, fobj, value, parent, 0, cyc);
    b.set(rl, S_LOOK, 1);
    let (_, rest) = b.pair(fobj)?;
    b.read(rl, 0, TAG_PAIR, fobj, [root, rest, 0, 0]);
    let dr = dg.digest(b, root);
    b.need_dig.push(root);
    b.read(rl, 1, TAG_DIG, root, dr.map(u));
    let id = b.fresh();
    b.alloc_noun(rl, 2, id, Entry::Atom(value));
    Ok(State::Ret { val: id, k: parent })
}

/// A noun of the store (nouns only).
pub(crate) fn noun_of(b: &Builder, id: u64) -> N {
    match b.entry(id) {
        Some(Entry::Atom(v)) => N::Atom(v),
        Some(Entry::Pair(l, r)) => N::Pair(Box::new(noun_of(b, l)), Box::new(noun_of(b, r))),
        _ => unreachable!("a noun"),
    }
}

/// CALL1: the tag atom, the prover's witness on witness rows (post-order,
/// a stack of cells), the join that evaluates the check on `[w subject]`.
pub(crate) fn call(
    b: &mut Builder,
    ctx: &Ctx<'_>,
    r: usize,
    frame: [u64; 4],
    val: u64,
    cyc: u64,
) -> Result<State, MachineError> {
    let [check, fobj, fd, parent] = frame;
    let tag = b.atom(val)?;
    b.read(r, 1, TAG_ATOM, val, [tag, 0, 0, 0]);
    let provide = ctx
        .hints
        .witness
        .ok_or(MachineError::Native("call: no witness"))?;
    let witness =
        provide(tag, &noun_of(b, fobj)).ok_or(MachineError::Native("call: no witness"))?;
    // post-order without recursion: (noun, children done)
    let mut todo: Vec<(&N, bool)> = vec![(&witness, false)];
    let mut cells: Vec<u64> = Vec::new(); // cell ids, top last
    let mut tops: Vec<u64> = Vec::new(); // noun ids, top last
    let mut sp = 0u64;
    let row = |b: &mut Builder, kind: usize, sp: u64| {
        let rr = b.row(K_AUX);
        state(b, rr, fobj, check, parent, fd, cyc);
        b.set(rr, kind, 1);
        b.set(rr, W_SP, sp);
        rr
    };
    while let Some((n, done)) = todo.pop() {
        match (n, done) {
            (N::Pair(x, y), false) => {
                todo.push((n, true));
                todo.push((y, false));
                todo.push((x, false));
                continue;
            }
            (N::Atom(v), _) => {
                if *v >= nebu::field::P {
                    return Err(MachineError::Native("call: noncanonical witness"));
                }
                let rr = row(b, S_WATOM, sp);
                let id = b.fresh();
                b.alloc_noun(rr, 0, id, Entry::Atom(*v));
                let cell = b.fresh();
                b.alloc_frame(rr, 1, cell, TAG_SCELL, [id, sp, 0, 0]);
                cells.push(cell);
                tops.push(id);
                sp = cell;
            }
            (N::Pair(..), true) => {
                let rr = row(b, S_WPAIR, sp);
                let (rid, rcell) = (tops.pop().expect("right"), cells.pop().expect("right"));
                let (lid, lcell) = (tops.pop().expect("left"), cells.pop().expect("left"));
                let s2 = cells.last().copied().unwrap_or(0);
                b.read(rr, 0, TAG_SCELL, rcell, [rid, lcell, 0, 0]);
                b.read(rr, 1, TAG_SCELL, lcell, [lid, s2, 0, 0]);
                let id = b.fresh();
                b.alloc_noun(rr, 2, id, Entry::Pair(lid, rid));
                let cell = b.fresh();
                b.alloc_frame(rr, 3, cell, TAG_SCELL, [id, s2, 0, 0]);
                cells.push(cell);
                tops.push(id);
                sp = cell;
            }
        }
    }
    let rj = row(b, S_WJOIN, sp);
    let w = tops.pop().expect("witness");
    b.read(rj, 0, TAG_SCELL, sp, [w, 0, 0, 0]);
    let pid = b.fresh();
    b.alloc_noun(rj, 1, pid, Entry::Pair(w, fobj));
    let fid = b.fresh();
    b.alloc_frame(rj, 2, fid, TAG_CALL2, [w, 0, 0, parent]);
    Ok(State::Eval {
        obj: pid,
        fml: check,
        k: fid,
        d: fd + 1,
    })
}
