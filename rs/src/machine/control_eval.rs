//! EVAL (dispatch) rows and the axis rows AX1 / AX2.

use nebu::Fp3;

use super::air::{Out, c};
use super::layout::*;
use crate::air::Vals;

/// `gate ⇒ next row is kind nk and n[col] = value` for every pair.
pub(crate) fn go(out: &mut Out<'_>, n: &[Fp3], gate: Fp3, nk: usize, set: &[(usize, Fp3)]) {
    out.push(gate * (Fp3::ONE - n[nk]));
    for &(col, value) in set {
        out.push(gate * (n[col] - value));
    }
}

pub(crate) fn constrain(v: &Vals<'_>, out: &mut Out<'_>) {
    let l = v.local;
    let n = v.next;
    let one = Fp3::ONE;
    let ev = l[K_EVAL];
    let f = |i: usize| l[i];
    let key = |s: usize| l[slot(s, KEY)];
    let pay = |s: usize, i: usize| l[slot(s, P0 + i)];

    // decode: formula pair, tag atom, body; depth within the native limit
    out.push(ev * (key(0) - l[X]));
    out.push(ev * (key(1) - pay(0, 0)));
    let tag = OPS.iter().fold(Fp3::ZERO, |a, &(o, t, _)| a + f(FLAG0 + o) * c(t));
    out.push(ev * (pay(1, 0) - tag));
    out.push(ev * ((l[D] - c(MAX_DEPTH + 1)) * l[E_DINV] - one));
    let binary = f(OP_COMPOSE) + f(OP_CONS) + f(OP_BRANCH) + f(OP_ADD) + f(OP_SUB) + f(OP_MUL) + f(OP_EQ);
    let unary = f(OP_HASH) + f(OP_INV);
    out.push(ev * (f(OP_AXIS) + binary) * (key(2) - pay(0, 1)));

    // binary: push the frame (g, obj, d, k), evaluate the first child
    let alloc = l[ALLOC];
    out.push(ev * (binary + unary) * (key(3) - alloc));
    let gb = ev * binary;
    out.push(gb * (pay(3, 0) - pay(2, 1)));
    out.push(gb * (pay(3, 1) - l[OBJ]));
    out.push(gb * (pay(3, 2) - l[D]));
    out.push(gb * (pay(3, 3) - l[K]));
    let gu = ev * unary;
    out.push(gu * pay(3, 0));
    out.push(gu * pay(3, 1));
    out.push(gu * pay(3, 2));
    out.push(gu * (pay(3, 3) - l[K]));
    let push = [
        (OBJ, l[OBJ]),
        (K, alloc),
        (D, l[D] + one),
        (ALLOC, alloc + one),
    ];
    let mut set = push.to_vec();
    set.push((X, pay(2, 0)));
    go(out, n, gb, K_EVAL, &set);
    let mut set = push.to_vec();
    set.push((X, pay(0, 1)));
    go(out, n, gu, K_EVAL, &set);
    // quote
    go(out, n, ev * f(OP_QUOTE), K_RET, &[(X, pay(0, 1)), (K, l[K]), (ALLOC, alloc)]);

    // axis: a = 0 (digest noun), 1 (the subject), ≥ 2 (navigate)
    let ga = ev * f(OP_AXIS);
    let a = pay(2, 0);
    let (is0, is1) = (l[E_IS0], l[E_IS1]);
    out.push(ga * (a * l[E_A0INV] - (one - is0)));
    out.push(ga * a * is0);
    out.push(ga * ((a - one) * l[E_A1INV] - (one - is1)));
    out.push(ga * (a - one) * is1);
    out.push(ga * is0 * (key(3) - l[OBJ]));
    go(out, n, ga * is1, K_RET, &[(X, l[OBJ]), (K, l[K]), (ALLOC, alloc)]);
    let mut hda = vec![(K, l[K]), (ALLOC, alloc)];
    for i in 0..4 {
        hda.push((slot(i, P0), pay(3, i)));
    }
    go(out, n, ga * is0, K_HDA, &hda);
    let an = ga * (one - is0 - is1);
    go(
        out,
        n,
        an,
        K_AX1,
        &[(OBJ, l[OBJ]), (X, a), (K, l[K]), (ALLOC, alloc), (A_R, one), (A_CNT, Fp3::ZERO)],
    );

    // AX1: peel the address into the reversed path R
    let g1 = l[K_AX1];
    let bit = l[A_BIT];
    out.push(g1 * bit * (bit - one));
    out.push(g1 * ((l[A_CNT] - c(AXIS_LEVELS)) * l[A_CINV] - one));
    out.push(g1 * (one - n[K_AX1] - n[K_AX2]));
    let keep = [(K, l[K]), (ALLOC, alloc), (OBJ, l[OBJ])];
    let t1 = g1 * n[K_AX1];
    out.push(t1 * (l[X] - c(2) * n[X] - bit));
    out.push(t1 * (n[A_R] - c(2) * l[A_R] - bit));
    out.push(t1 * (n[A_CNT] - l[A_CNT] - one));
    for &(col, val) in &keep {
        out.push(t1 * (n[col] - val));
    }
    let t2 = g1 * n[K_AX2];
    out.push(t2 * (l[X] - c(2) - bit));
    out.push(t2 * (n[X] - c(2) * l[A_R] - bit));
    out.push(t2 * n[A_CNT]);
    for &(col, val) in &keep {
        out.push(t2 * (n[col] - val));
    }

    // AX2: walk R from the low bit, one child per row
    let g2 = l[K_AX2];
    let cbit = l[A_BIT];
    out.push(g2 * cbit * (cbit - one));
    out.push(g2 * ((l[A_CNT] - c(AXIS_LEVELS)) * l[A_CINV] - one));
    out.push(g2 * (key(0) - l[OBJ]));
    out.push(g2 * (one - n[K_AX2] - n[K_RET]));
    let child = pay(0, 0) + cbit * (pay(0, 1) - pay(0, 0));
    let s1 = g2 * n[K_AX2];
    out.push(s1 * (l[X] - c(2) * n[X] - cbit));
    out.push(s1 * (n[OBJ] - child));
    out.push(s1 * (n[A_CNT] - l[A_CNT] - one));
    out.push(s1 * (n[K] - l[K]));
    out.push(s1 * (n[ALLOC] - alloc));
    let s2 = g2 * n[K_RET];
    out.push(s2 * (l[X] - c(2) - cbit));
    out.push(s2 * (n[X] - child));
    out.push(s2 * (n[K] - l[K]));
    out.push(s2 * (n[ALLOC] - alloc));
}
