//! The `eq` opcode's return step. Native `eq` compares structural digests.
//! Two atoms are compared by value and an atom against a pair is unequal —
//! both agree with the digest comparison unless hemera collides (a leaf
//! and a node are domain-separated, distinct atoms hash apart), the
//! assumption nox's identity already rests on. Two pairs are compared by
//! their digests on a following `EQD` row.

use nebu::Goldilocks;

use super::exec::{Builder, Entry, MachineError, g};
use super::layout::*;
use super::run::{Digests, RunState};

fn inv_or_zero(x: Goldilocks) -> Goldilocks {
    if x == Goldilocks::ZERO { Goldilocks::ZERO } else { x.inv() }
}

pub(crate) fn eq(
    b: &mut Builder,
    dg: &mut Digests,
    r: usize,
    x: u64,
    val: u64,
    parent: u64,
    cyc: u64,
) -> Result<RunState, MachineError> {
    let ea = b.read_noun(r, 1, x)?;
    let eb = b.read_noun(r, 2, val)?;
    let atom = |e: &Entry| matches!(e, Entry::Atom(_));
    b.set(r, Q_KA, u64::from(atom(&ea)));
    b.set(r, Q_KB, u64::from(atom(&eb)));
    let res = match (ea, eb) {
        (Entry::Atom(u1), Entry::Atom(u2)) => {
            b.setf(r, Q_EINV, inv_or_zero(g(u1) - g(u2)));
            b.set(r, Q_ISEQ, u64::from(u1 == u2));
            u64::from(u1 != u2)
        }
        (Entry::Pair(..), Entry::Pair(..)) => {
            let re = b.row(K_EQD);
            b.set(re, OBJ, x);
            b.set(re, X, val);
            b.set(re, K, parent);
            b.set(re, CYC, cyc);
            let a = b.alloc;
            b.set(re, ALLOC, a);
            let da = dg.digest(b, x);
            let db = dg.digest(b, val);
            b.need_dig.push(x);
            b.need_dig.push(val);
            b.read(re, 0, TAG_DIG, x, da.map(|v| v.as_u64()));
            b.read(re, 1, TAG_DIG, val, db.map(|v| v.as_u64()));
            let equal = da == db;
            b.set(re, Q_ISEQ, u64::from(equal));
            if let Some(i) = (0..4).find(|&i| da[i] != db[i]) {
                b.setf(re, Q_DW + i, (da[i] - db[i]).inv());
            }
            let id = b.fresh();
            b.alloc_noun(re, 2, id, Entry::Atom(u64::from(!equal)));
            return Ok(RunState::Ret { val: id, k: parent });
        }
        _ => 1,
    };
    let id = b.fresh();
    b.alloc_noun(r, 3, id, Entry::Atom(res));
    Ok(RunState::Ret { val: id, k: parent })
}
