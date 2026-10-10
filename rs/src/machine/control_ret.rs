//! RET rows (a value meets the top frame), the hash_data rows HDA / HDB
//! and the pair-equality row EQD.

use nebu::Fp3;

use super::air::{Out, c};
use super::control_eval::go;
use super::layout::*;
use crate::air::Vals;

pub(crate) fn constrain(v: &Vals<'_>, out: &mut Out<'_>) {
    let l = v.local;
    let n = v.next;
    let one = Fp3::ONE;
    let rt = l[K_RET];
    let f = |i: usize| rt * l[i];
    let key = |s: usize| l[slot(s, KEY)];
    let pay = |s: usize, i: usize| l[slot(s, P0 + i)];
    let alloc = l[ALLOC];
    let val = l[X];
    // the frame: slot 0 under the frame id, payload (x, obj, d, parent)
    let nonterm = rt * (one - l[F_TERM]);
    out.push(nonterm * (key(0) - l[K]));
    let (x, fobj, fd, parent) = (pay(0, 0), pay(0, 1), pay(0, 2), pay(0, 3));

    // push a successor frame and evaluate the frame's formula
    let push2 = f(F_CONS1) + f(F_COMP1) + f(F_B1ADD) + f(F_B1SUB) + f(F_B1MUL) + f(F_B1EQ);
    out.push(push2 * (key(1) - alloc));
    out.push(push2 * (pay(1, 0) - val));
    out.push(push2 * pay(1, 1));
    out.push((push2 - f(F_COMP1)) * pay(1, 2));
    out.push(f(F_COMP1) * (pay(1, 2) - fd));
    out.push(push2 * (pay(1, 3) - parent));
    go(
        out,
        n,
        push2,
        K_EVAL,
        &[(OBJ, fobj), (X, x), (K, alloc), (D, fd + one), (ALLOC, alloc + one)],
    );
    // CONS2: allocate the pair (x, val)
    let g = f(F_CONS2);
    out.push(g * (key(1) - alloc));
    out.push(g * (pay(1, 0) - x));
    out.push(g * (pay(1, 1) - val));
    out.push(g * pay(1, 2));
    out.push(g * pay(1, 3));
    go(out, n, g, K_RET, &[(X, alloc), (K, parent), (ALLOC, alloc + one)]);
    // COMP2: evaluate the computed formula on the computed subject
    go(
        out,
        n,
        f(F_COMP2),
        K_EVAL,
        &[(OBJ, x), (X, val), (K, parent), (D, fd + one), (ALLOC, alloc)],
    );
    // BR: test atom, select an arm
    let g = f(F_BR);
    let (tv, z) = (pay(1, 0), l[R_Z]);
    out.push(g * (key(1) - val));
    out.push(g * (tv * l[R_TINV] - (one - z)));
    out.push(g * tv * z);
    out.push(g * (key(2) - x));
    let arm = z * pay(2, 0) + (one - z) * pay(2, 1);
    go(
        out,
        n,
        g,
        K_EVAL,
        &[(OBJ, fobj), (X, arm), (K, parent), (D, fd + one), (ALLOC, alloc)],
    );
    // B2 add / sub / mul: two atoms, one result atom
    let (u, w) = (pay(1, 0), pay(2, 0));
    let b2 = f(F_B2ADD) + f(F_B2SUB) + f(F_B2MUL);
    out.push(b2 * (key(1) - x));
    out.push(b2 * (key(2) - val));
    let res = f(F_B2ADD) * (u + w) + f(F_B2SUB) * (u - w) + f(F_B2MUL) * u * w;
    out.push(b2 * pay(3, 0) - res);
    // B2 eq: kinds, atom compare; pairs go to EQD
    let g = f(F_B2EQ);
    let (ka, kb) = (l[Q_KA], l[Q_KB]);
    out.push(g * ka * (ka - one));
    out.push(g * kb * (kb - one));
    out.push(g * (key(1) - x));
    out.push(g * (key(2) - val));
    let atoms = g * ka * kb;
    let iseq = l[Q_ISEQ];
    out.push(atoms * ((u - w) * l[Q_EINV] - (one - iseq)));
    out.push(atoms * (u - w) * iseq);
    let mixed = g * (ka + kb - c(2) * ka * kb);
    out.push(atoms * (pay(3, 0) - (one - iseq)) + mixed * (pay(3, 0) - one));
    let pairs = g * (one - ka) * (one - kb);
    go(out, n, pairs, K_EQD, &[(OBJ, x), (X, val), (K, parent), (ALLOC, alloc)]);
    // the atom result of add / sub / mul / eq(atom|mixed)
    let wr = b2 + g - pairs;
    out.push(wr * (key(3) - alloc));
    for i in 1..4 {
        out.push(wr * pay(3, i));
    }
    go(out, n, wr, K_RET, &[(X, alloc), (K, parent), (ALLOC, alloc + one)]);
    // UHASH: the hash opcode's output, as hash_data
    let g = f(F_UHASH);
    out.push(g * (key(1) - val));
    let mut hda = vec![(K, parent), (ALLOC, alloc)];
    for i in 0..4 {
        hda.push((slot(i, P0), pay(1, i)));
    }
    go(out, n, g, K_HDA, &hda);
    // UINV: the inverse atom
    let g = f(F_UINV);
    out.push(g * (key(1) - val));
    out.push(g * (key(2) - alloc));
    out.push(g * (pay(2, 0) * pay(1, 0) - one));
    for i in 1..4 {
        out.push(g * pay(2, i));
    }
    go(out, n, g, K_RET, &[(X, alloc), (K, parent), (ALLOC, alloc + one)]);

    // HDA: atoms h0..h3 at ALLOC..ALLOC+3; HDB: their pairs
    let ga = l[K_HDA];
    for s in 0..4 {
        out.push(ga * (key(s) - alloc - c(s as u64)));
        for i in 1..4 {
            out.push(ga * pay(s, i));
        }
    }
    go(out, n, ga, K_HDB, &[(K, l[K]), (ALLOC, alloc + c(4))]);
    let gb = l[K_HDB];
    let base = alloc - c(4);
    let pairs3 = [
        (base, base + one),
        (base + c(2), base + c(3)),
        (alloc, alloc + one),
    ];
    for (s, &(a, b)) in pairs3.iter().enumerate() {
        out.push(gb * (key(s) - alloc - c(s as u64)));
        out.push(gb * (pay(s, 0) - a));
        out.push(gb * (pay(s, 1) - b));
        out.push(gb * pay(s, 2));
        out.push(gb * pay(s, 3));
    }
    go(out, n, gb, K_RET, &[(X, alloc + c(2)), (K, l[K]), (ALLOC, alloc + c(3))]);

    // EQD: two digests, all four limbs equal or not
    let ge = l[K_EQD];
    out.push(ge * (key(0) - l[OBJ]));
    out.push(ge * (key(1) - l[X]));
    let iseq = l[Q_ISEQ];
    out.push(ge * iseq * (iseq - one));
    let mut dot = Fp3::ZERO;
    for i in 0..4 {
        let d = pay(0, i) - pay(1, i);
        out.push(ge * iseq * d);
        dot += d * l[Q_DW + i];
    }
    out.push(ge * (dot - (one - iseq)));
    out.push(ge * (key(2) - alloc));
    out.push(ge * (pay(2, 0) - (one - iseq)));
    for i in 1..4 {
        out.push(ge * pay(2, i));
    }
    go(out, n, ge, K_RET, &[(X, alloc), (K, l[K]), (ALLOC, alloc + one)]);
}
