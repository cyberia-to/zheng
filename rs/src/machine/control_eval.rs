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
    let t = pay(1, 0);
    let tag = OPS.iter().fold(Fp3::ZERO, |a, &(o, tg, _)| a + f(FLAG0 + o) * c(tg));
    out.push(ev * ((one - f(OP_WORD)) * t - tag));
    let gw = ev * f(OP_WORD);
    out.push(gw * WORD_TAGS.iter().fold(one, |a, &w| a * (t - c(w))));
    out.push(ev * ((l[D] - c(MAX_DEPTH + 1)) * l[E_DINV] - one));
    let b1ops = f(OP_ADD) + f(OP_SUB) + f(OP_MUL) + f(OP_EQ) + f(OP_LT) + f(OP_WORD) + f(OP_LOOK);
    let binary = f(OP_COMPOSE) + f(OP_CONS) + f(OP_BRANCH) + f(OP_CALL) + b1ops;
    let unary = f(OP_HASH) + f(OP_INV);
    out.push(ev * (f(OP_AXIS) + binary) * (key(2) - pay(0, 1)));

    // binary: push the frame (g, obj, d, k), evaluate the first child
    let alloc = l[ALLOC];
    out.push(ev * (binary + unary + f(OP_NOT)) * (key(3) - alloc));
    let gb = ev * binary;
    out.push(gb * (pay(3, 0) - pay(2, 1)));
    out.push(gb * (pay(3, 1) - l[OBJ]));
    out.push(gb * (pay(3, 2) - l[D]));
    out.push(gb * (pay(3, 3) - l[K]));
    // hash / inv: push (0, 0, 0, k); not: push B2(not) = (tag atom, obj,
    // 0, k) — the tag atom (13, a word) stands in as the first operand
    let gu = ev * unary;
    let gn = ev * f(OP_NOT);
    out.push(gu * pay(3, 0) + gn * (pay(3, 0) - key(1)));
    out.push(gu * pay(3, 1) + gn * (pay(3, 1) - l[OBJ]));
    out.push((gu + gn) * pay(3, 2));
    out.push((gu + gn) * (pay(3, 3) - l[K]));
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
    go(out, n, gu + gn, K_EVAL, &set);
    // quote
    go(out, n, ev * f(OP_QUOTE), K_RET, &[(X, pay(0, 1)), (K, l[K]), (ALLOC, alloc)]);

    // axis: a = 0 (digest noun), 1 (the subject), ≥ 2 (walk)
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
        K_AXW,
        &[
            (OBJ, l[OBJ]),
            (X, one),
            (D, a),
            (K, l[K]),
            (ALLOC, alloc),
            (A_CNT, Fp3::ZERO),
            (A_PH, one),
            (A_AH, one),
            (A_OL, Fp3::ZERO),
        ],
    );

    // AXW: one level per row from the root; X = the address of the node
    // so far, D = the target; the path ends when 2X + bit = D
    let g = l[K_AXW];
    let bit = l[A_BIT];
    let cnt = l[A_CNT];
    out.push(g * bit * (bit - one));
    out.push(g * ((cnt - c(AXIS_LEVELS)) * l[A_C63] - one));
    for (e, i, k) in [(A_E30, A_I30, 30u64), (A_E62, A_I62, 62)] {
        out.push(g * ((cnt - c(k)) * l[i] - (one - l[e])));
        out.push(g * (cnt - c(k)) * l[e]);
    }
    out.push(g * (key(0) - l[OBJ]));
    out.push(g * (one - n[K_AXW] - n[K_RET]));
    let child = pay(0, 0) + bit * (pay(0, 1) - pay(0, 0));
    let next_x = c(2) * l[X] + bit;
    let (ph, ah, ol) = (l[A_PH], l[A_AH], l[A_OL]);
    let s1 = g * n[K_AXW];
    out.push(s1 * (n[OBJ] - child));
    out.push(s1 * (n[X] - next_x));
    out.push(s1 * (n[D] - l[D]));
    out.push(s1 * (n[A_CNT] - cnt - one));
    out.push(s1 * (n[K] - l[K]));
    out.push(s1 * (n[ALLOC] - alloc));
    out.push(s1 * (n[A_PH] - ph + l[A_E30]));
    out.push(s1 * (n[A_AH] - ah * (one - ph + ph * bit)));
    out.push(s1 * (n[A_OL] - ol - (one - ph) * bit * (one - ol)));
    let s2 = g * n[K_RET];
    out.push(s2 * (next_x - l[D]));
    out.push(s2 * (n[X] - child));
    out.push(s2 * (n[K] - l[K]));
    out.push(s2 * (n[ALLOC] - alloc));
    // a 63-level path is the canonical address: not (bits 62..32 all one
    // and a low bit set), i.e. the walked integer is below p
    out.push(g * l[A_E62] * ah * (ol + bit * (one - ol)));
}
