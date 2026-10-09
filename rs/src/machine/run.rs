//! The continuation machine's run loop (`specs/machine.md` § transitions).

use std::collections::BTreeMap;

use nebu::Goldilocks;

use super::exec::{Builder, Entry, MachineError, frame_flag, g, op_of};
use super::hemera::{Tables, head4, hop_input};
use super::layout::*;
use super::run_ops::{self, Ctx};

pub(crate) enum State {
    Eval { obj: u64, fml: u64, k: u64, d: u64 },
    Ret { val: u64, k: u64 },
}

/// Noun digests and hash-opcode outputs, memoized by id.
#[derive(Default)]
pub(crate) struct Digests {
    pub dig: BTreeMap<u64, [Goldilocks; 4]>,
    pub hop: BTreeMap<u64, [Goldilocks; 4]>,
}

impl Digests {
    pub fn digest(&mut self, b: &Builder, id: u64) -> [Goldilocks; 4] {
        if let Some(d) = self.dig.get(&id) {
            return *d;
        }
        let d = match b.entry(id) {
            Some(Entry::Atom(v)) => nox::data::hash_atom(g(v)),
            Some(Entry::Pair(l, r)) => {
                let (dl, dr) = (self.digest(b, l), self.digest(b, r));
                nox::data::hash_pair(&dl, &dr)
            }
            _ => unreachable!("digest of a noun"),
        };
        self.dig.insert(id, d);
        d
    }
    pub fn hop(&mut self, b: &Builder, t: &Tables, id: u64) -> [Goldilocks; 4] {
        if let Some(h) = self.hop.get(&id) {
            return *h;
        }
        let d = self.digest(b, id);
        let h = head4(&t.permute(&hop_input(d)));
        self.hop.insert(id, h);
        h
    }
}

pub(crate) fn u(x: Goldilocks) -> u64 {
    x.as_u64()
}

pub(crate) fn inv_or_zero(x: Goldilocks) -> Goldilocks {
    if x == Goldilocks::ZERO { Goldilocks::ZERO } else { x.inv() }
}

pub(crate) fn state(b: &mut Builder, r: usize, obj: u64, x: u64, k: u64, d: u64, cyc: u64) {
    b.set(r, OBJ, obj);
    b.set(r, X, x);
    b.set(r, K, k);
    b.set(r, D, d);
    b.set(r, CYC, cyc);
    let a = b.alloc;
    b.set(r, ALLOC, a);
}

/// hash_data(h): 4 atoms then 3 pairs; returns the top pair's id.
pub(crate) fn hash_data(b: &mut Builder, h: [Goldilocks; 4], k: u64, cyc: u64) -> u64 {
    let ra = b.row(K_HDA);
    state(b, ra, 0, 0, k, 0, cyc);
    let a0 = b.alloc;
    for (i, &hi) in h.iter().enumerate() {
        let id = b.fresh();
        b.alloc_noun(ra, i, id, Entry::Atom(u(hi)));
    }
    let rb = b.row(K_HDB);
    state(b, rb, 0, 0, k, 0, cyc);
    for (s, (l, r)) in [(a0, a0 + 1), (a0 + 2, a0 + 3), (a0 + 4, a0 + 5)].into_iter().enumerate() {
        let id = b.fresh();
        b.alloc_noun(rb, s, id, Entry::Pair(l, r));
    }
    a0 + 6
}

/// `e = [cnt = k]` and its witness in columns `(e, i)`.
pub(crate) fn indicator(b: &mut Builder, r: usize, e: usize, i: usize, cnt: u64, k: u64) {
    b.set(r, e, u64::from(cnt == k));
    b.setf(r, i, inv_or_zero(g(cnt) - g(k)));
}

/// Axis `a ≥ 2` from `obj`: one AXW row per level, the most significant
/// path bit first; returns the node.
fn axis(b: &mut Builder, obj: u64, a: u64, k: u64, cyc: u64) -> Result<u64, MachineError> {
    let path = run_ops::alias(a);
    let levels = u64::from(63 - path.leading_zeros());
    let (mut node, mut x) = (obj, 1u64);
    let (mut ph, mut ah, mut ol) = (1u64, 1u64, 0u64);
    for cnt in 0..levels {
        let bit = (path >> (levels - 1 - cnt)) & 1;
        let r = b.row(K_AXW);
        state(b, r, node, x, k, a, cyc);
        b.set(r, A_BIT, bit);
        b.set(r, A_CNT, cnt);
        b.setf(r, A_C63, (g(cnt) - g(AXIS_LEVELS)).inv());
        b.set(r, A_PH, ph);
        b.set(r, A_AH, ah);
        b.set(r, A_OL, ol);
        indicator(b, r, A_E30, A_I30, cnt, 30);
        indicator(b, r, A_E62, A_I62, cnt, 62);
        let (l, rr) = match b.entry(node) {
            Some(Entry::Pair(l, rr)) => (l, rr),
            _ => return Err(MachineError::Native("axis error")),
        };
        b.read(r, 0, TAG_PAIR, node, [l, rr, 0, 0]);
        node = if bit == 1 { rr } else { l };
        x = 2 * x + bit;
        if ph == 1 {
            ah &= bit;
        } else {
            ol |= bit;
        }
        if cnt == 30 {
            ph = 0;
        }
    }
    Ok(node)
}

/// Run `fml` on `obj` (both init ids); returns `(result id, cycles)`.
pub(crate) fn run(
    b: &mut Builder,
    dg: &mut Digests,
    t: &Tables,
    ctx: &mut Ctx<'_>,
    fml: u64,
    obj: u64,
    budget: u64,
) -> Result<(u64, u64), MachineError> {
    let mut st = State::Eval { obj, fml, k: 0, d: 0 };
    let mut cyc = 0u64;
    loop {
        if cyc > budget {
            return Err(MachineError::Budget);
        }
        st = match st {
            State::Eval { obj, fml, k, d } => {
                if d > MAX_DEPTH {
                    return Err(MachineError::Native("depth limit"));
                }
                let r = b.row(K_EVAL);
                state(b, r, obj, fml, k, d, cyc);
                b.setf(r, E_DINV, inv_or_zero(g(d) - g(MAX_DEPTH + 1)));
                let (tid, body) = match b.entry(fml) {
                    Some(Entry::Pair(t, bd)) => (t, bd),
                    _ => return Err(MachineError::Native("malformed formula")),
                };
                b.read(r, 0, TAG_PAIR, fml, [tid, body, 0, 0]);
                let tag = match b.entry(tid) {
                    Some(Entry::Atom(t)) => t,
                    _ => return Err(MachineError::Native("malformed formula tag")),
                };
                b.read(r, 1, TAG_ATOM, tid, [tag, 0, 0, 0]);
                let (op, cost) = op_of(tag).ok_or(MachineError::Native("unknown opcode"))?;
                b.set(r, op, 1);
                cyc += cost;
                if cyc > budget {
                    return Err(MachineError::Budget);
                }
                eval(b, dg, r, op, tag, tid, obj, body, k, d, cyc)?
            }
            State::Ret { val, k } => {
                let r = b.row(K_RET);
                state(b, r, 0, val, k, 0, cyc);
                if k == 0 {
                    b.set(r, F_TERM, 1);
                    let dv = dg.digest(b, val);
                    b.need_dig.push(val);
                    b.read(r, 0, TAG_DIG, val, dv.map(u));
                    return Ok((val, cyc));
                }
                let Some(Entry::Frame(tag, p)) = b.entry(k) else {
                    unreachable!("continuation is a frame")
                };
                let f = frame_flag(tag).expect("known frame");
                b.set(r, f, 1);
                b.read(r, 0, tag, k, p);
                ret(b, dg, t, ctx, r, f, tag, p, val, cyc)?
            }
        };
    }
}

#[allow(clippy::too_many_arguments)]
fn eval(
    b: &mut Builder,
    dg: &mut Digests,
    r: usize,
    op: usize,
    tag: u64,
    tid: u64,
    obj: u64,
    body: u64,
    k: u64,
    d: u64,
    cyc: u64,
) -> Result<State, MachineError> {
    Ok(match op {
        OP_QUOTE => State::Ret { val: body, k },
        OP_AXIS => {
            let a = match b.entry(body) {
                Some(Entry::Atom(a)) => a,
                _ => return Err(MachineError::Native("malformed axis")),
            };
            b.read(r, 2, TAG_ATOM, body, [a, 0, 0, 0]);
            b.setf(r, E_A0INV, inv_or_zero(g(a)));
            b.setf(r, E_A1INV, inv_or_zero(g(a) - Goldilocks::ONE));
            b.set(r, E_IS0, u64::from(a == 0));
            b.set(r, E_IS1, u64::from(a == 1));
            match a {
                1 => State::Ret { val: obj, k },
                0 => {
                    let h = dg.digest(b, obj);
                    b.need_dig.push(obj);
                    b.read(r, 3, TAG_DIG, obj, h.map(u));
                    State::Ret { val: hash_data(b, h, k, cyc), k }
                }
                _ => State::Ret { val: axis(b, obj, a, k, cyc)?, k },
            }
        }
        OP_HASH | OP_INV => {
            let fid = b.fresh();
            let tag = if op == OP_HASH { TAG_UHASH } else { TAG_UINV };
            b.alloc_frame(r, 3, fid, tag, [0, 0, 0, k]);
            State::Eval { obj, fml: body, k: fid, d: d + 1 }
        }
        OP_NOT => {
            let fid = b.fresh();
            b.alloc_frame(r, 3, fid, TAG_B2 + T_NOT, [tid, obj, 0, k]);
            State::Eval { obj, fml: body, k: fid, d: d + 1 }
        }
        _ => {
            let (f, gg) = match b.entry(body) {
                Some(Entry::Pair(f, gg)) => (f, gg),
                _ => return Err(MachineError::Native("malformed body")),
            };
            b.read(r, 2, TAG_PAIR, body, [f, gg, 0, 0]);
            let ftag = match op {
                OP_COMPOSE => TAG_COMP1,
                OP_CONS => TAG_CONS1,
                OP_BRANCH => TAG_BR,
                OP_CALL => TAG_CALL1,
                _ => TAG_B1 + tag,
            };
            let fid = b.fresh();
            b.alloc_frame(r, 3, fid, ftag, [gg, obj, d, k]);
            State::Eval { obj, fml: f, k: fid, d: d + 1 }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn ret(
    b: &mut Builder,
    dg: &mut Digests,
    t: &Tables,
    ctx: &mut Ctx<'_>,
    r: usize,
    f: usize,
    tag: u64,
    p: [u64; 4],
    val: u64,
    cyc: u64,
) -> Result<State, MachineError> {
    let [x, fobj, fd, parent] = p;
    Ok(match f {
        F_CONS1 | F_COMP1 | F_B1 => {
            let fid = b.fresh();
            let (ntag, pay) = match f {
                F_CONS1 => (TAG_CONS2, [val, 0, 0, parent]),
                F_COMP1 => (TAG_COMP2, [val, 0, fd, parent]),
                _ => {
                    let op = tag - TAG_B1;
                    b.set(r, R_OP, op);
                    let y = B1_OPS[..5].iter().fold(Goldilocks::ONE, |a, &o| a * (g(op) - g(o)));
                    b.setf(r, R_OPY, y);
                    (tag - TAG_B1 + TAG_B2, [val, fobj, 0, parent])
                }
            };
            b.alloc_frame(r, 1, fid, ntag, pay);
            State::Eval { obj: fobj, fml: x, k: fid, d: fd + 1 }
        }
        F_CONS2 => {
            let id = b.fresh();
            b.alloc_noun(r, 1, id, Entry::Pair(x, val));
            State::Ret { val: id, k: parent }
        }
        F_COMP2 => State::Eval { obj: x, fml: val, k: parent, d: fd + 1 },
        F_BR => {
            let tv = b.atom(val)?;
            b.read(r, 1, TAG_ATOM, val, [tv, 0, 0, 0]);
            let z = tv == 0;
            b.setf(r, R_TINV, inv_or_zero(g(tv)));
            b.set(r, R_Z, u64::from(z));
            let (yes, no) = b.pair(x).map_err(|_| MachineError::Native("malformed branch"))?;
            b.read(r, 2, TAG_PAIR, x, [yes, no, 0, 0]);
            State::Eval { obj: fobj, fml: if z { yes } else { no }, k: parent, d: fd + 1 }
        }
        F_B2AR => {
            let ua = b.atom(x)?;
            let wa = b.atom(val)?;
            b.read(r, 1, TAG_ATOM, x, [ua, 0, 0, 0]);
            b.read(r, 2, TAG_ATOM, val, [wa, 0, 0, 0]);
            let op = tag - TAG_B2;
            b.set(r, R_OP, op);
            let (a, c) = (g(ua), g(wa));
            let (sel, res) = match op {
                5 => (R_SADD, a + c),
                6 => (R_SSUB, a - c),
                _ => (R_SMUL, a * c),
            };
            b.set(r, sel, 1);
            let id = b.fresh();
            b.alloc_noun(r, 3, id, Entry::Atom(u(res)));
            State::Ret { val: id, k: parent }
        }
        F_B2EQ => super::run_eq::eq(b, dg, r, x, val, parent, cyc)?,
        F_B2W => run_ops::word(b, r, tag - TAG_B2, x, val, parent, cyc)?,
        F_B2LOOK => run_ops::look(b, dg, ctx, r, x, val, fobj, parent, cyc)?,
        F_CALL1 => run_ops::call(b, ctx, r, p, val, cyc)?,
        F_CALL2 => {
            match b.entry(val) {
                Some(Entry::Atom(0)) => {}
                _ => return Err(MachineError::Native("call rejected")),
            }
            b.read(r, 1, TAG_ATOM, val, [0, 0, 0, 0]);
            State::Ret { val: x, k: parent }
        }
        F_UHASH => {
            let h = dg.hop(b, t, val);
            b.need_hop.push(val);
            b.read(r, 1, TAG_HOP, val, h.map(u));
            State::Ret { val: hash_data(b, h, parent, cyc), k: parent }
        }
        F_UINV => {
            let ua = b.atom(val)?;
            if ua == 0 {
                return Err(MachineError::Native("inverse of zero"));
            }
            b.read(r, 1, TAG_ATOM, val, [ua, 0, 0, 0]);
            let id = b.fresh();
            b.alloc_noun(r, 2, id, Entry::Atom(u(g(ua).inv())));
            State::Ret { val: id, k: parent }
        }
        _ => unreachable!("frame flag"),
    })
}

pub(crate) use State as RunState;
