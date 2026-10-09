//! AUX rows: the tail of a look (the subject's state root against the
//! statement, the value atom) and the call witness (built in post-order on
//! a stack of cells, then paired with the subject).

use nebu::Fp3;

use super::air::{Machine, Out, c};
use super::control_eval::go;
use super::layout::*;
use crate::air::Vals;

pub(crate) fn constrain(m: &Machine, v: &Vals<'_>, out: &mut Out<'_>) {
    let l = v.local;
    let n = v.next;
    let one = Fp3::ONE;
    let aux = l[K_AUX];
    let key = |s: usize| l[slot(s, KEY)];
    let pay = |s: usize, i: usize| l[slot(s, P0 + i)];
    let alloc = l[ALLOC];

    // LOOK: OBJ = [root rest], DIG(root) = the statement's root noun, the
    // value X written as a fresh atom
    let g = aux * l[S_LOOK];
    out.push(g * (key(0) - l[OBJ]));
    out.push(g * (key(1) - pay(0, 0)));
    for i in 0..4 {
        out.push(g * (pay(1, i) - Fp3::from_base(m.constants.root[i])));
    }
    out.push(g * (key(2) - alloc));
    out.push(g * (pay(2, 0) - l[X]));
    for i in 1..4 {
        out.push(g * pay(2, i));
    }
    go(
        out,
        n,
        g,
        K_RET,
        &[(X, alloc), (K, l[K]), (ALLOC, alloc + one)],
    );

    // witness rows carry the call's subject, check formula, depth, parent
    let carry = |out: &mut Out<'_>, g: Fp3, sp: Fp3| {
        go(
            out,
            n,
            g,
            K_AUX,
            &[
                (OBJ, l[OBJ]),
                (X, l[X]),
                (D, l[D]),
                (K, l[K]),
                (ALLOC, alloc + c(2)),
                (W_SP, sp),
            ],
        );
        out.push(g * (one - n[S_WATOM] - n[S_WPAIR] - n[S_WJOIN]));
    };
    let sp = l[W_SP];
    // WATOM: ATOM(alloc) = free value, CELL(alloc + 1) = (alloc, sp)
    let g = aux * l[S_WATOM];
    out.push(g * (key(0) - alloc));
    for i in 1..4 {
        out.push(g * pay(0, i));
    }
    out.push(g * (key(1) - alloc - one));
    out.push(g * (pay(1, 0) - alloc));
    out.push(g * (pay(1, 1) - sp));
    out.push(g * pay(1, 2));
    out.push(g * pay(1, 3));
    carry(out, g, alloc + one);
    // WPAIR: pop CELL(sp) = (r, s1), CELL(s1) = (l, s2); PAIR(alloc) =
    // (l, r); push CELL(alloc + 1) = (alloc, s2)
    let g = aux * l[S_WPAIR];
    out.push(g * (key(0) - sp));
    out.push(g * (key(1) - pay(0, 1)));
    out.push(g * (key(2) - alloc));
    out.push(g * (pay(2, 0) - pay(1, 0)));
    out.push(g * (pay(2, 1) - pay(0, 0)));
    out.push(g * pay(2, 2));
    out.push(g * pay(2, 3));
    out.push(g * (key(3) - alloc - one));
    out.push(g * (pay(3, 0) - alloc));
    out.push(g * (pay(3, 1) - pay(1, 1)));
    out.push(g * pay(3, 2));
    out.push(g * pay(3, 3));
    carry(out, g, alloc + one);
    // WJOIN: the only cell CELL(sp) = (w, 0); PAIR(alloc) = (w, OBJ);
    // CALL2(alloc + 1) = (w, 0, 0, K); evaluate the check on the pair
    let g = aux * l[S_WJOIN];
    let w = pay(0, 0);
    out.push(g * (key(0) - sp));
    out.push(g * pay(0, 1));
    out.push(g * (key(1) - alloc));
    out.push(g * (pay(1, 0) - w));
    out.push(g * (pay(1, 1) - l[OBJ]));
    out.push(g * pay(1, 2));
    out.push(g * pay(1, 3));
    out.push(g * (key(2) - alloc - one));
    out.push(g * (pay(2, 0) - w));
    out.push(g * pay(2, 1));
    out.push(g * pay(2, 2));
    out.push(g * (pay(2, 3) - l[K]));
    go(
        out,
        n,
        g,
        K_EVAL,
        &[
            (OBJ, alloc),
            (X, l[X]),
            (K, alloc + one),
            (D, l[D] + one),
            (ALLOC, alloc + c(2)),
        ],
    );
}
