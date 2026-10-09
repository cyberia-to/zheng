//! WBIT rows: the word opcodes (xor, and, not, shl) and lt, one bit
//! position per row, exactly 32 rows per opcode.
//!
//! The RET row of the opcode writes the result atom `D` and hands over the
//! operands `OBJ = u`, `X = w`; the rows prove `D = op(u, w)`. Four
//! remainders are peeled one bit per row (`R = bit + 2·R'`, the last row's
//! remainder after the peel is 0), so each starts below `2^32` and its bits
//! are its binary digits:
//!
//! - xor / and / not: `R0 = u`, `R1 = w`, `R2 = D`, `R3 = 0`, and the
//!   result bit is `a ⊕ b`, `a·b`, `1 − b` (not: `u` is the formula's tag
//!   atom 13, `w` the operand);
//! - shl: `R0 = u`, `R1 = n`, `R2 = c'`, `R3 = 2h` with `u·2^(n mod 32) =
//!   c' + 2^32·h` (both sides below `2^63 < p`); `D = c'` when `n < 32`
//!   (the remainder of `n` after five bits is 0), else `D = 0`;
//! - lt (operands any field elements): `R0 + 2^32·R2 = u`, `R1 + 2^32·R3
//!   = w` with the canonical check (high half all ones ⇒ low half 0), the
//!   comparison runs from the low bit (the last differing bit decides) on
//!   both halves, `D = 1 − [u < w]`.

use nebu::Fp3;

use super::air::{Out, c};
use super::control_eval::go;
use super::layout::*;
use crate::air::Vals;

pub(crate) fn constrain(v: &Vals<'_>, out: &mut Out<'_>) {
    let l = v.local;
    let n = v.next;
    let one = Fp3::ONE;
    let g = l[K_AUX] * l[S_WBIT];
    let (cnt, last, first) = (l[B_CNT], l[B_LAST], l[B_FIRST]);

    // opcode flags: boolean, one-hot
    let mut fsum = Fp3::ZERO;
    for &(col, _) in &WOPS {
        out.push(g * l[col] * (l[col] - one));
        fsum += l[col];
    }
    out.push(g * (fsum - one));
    // the counter: 0 on the first row, 31 on the last
    out.push(g * ((cnt - c(31)) * l[B_LINV] - (one - last)));
    out.push(g * (cnt - c(31)) * last);
    out.push(g * (cnt * l[B_FINV] - (one - first)));
    out.push(g * cnt * first);
    let gc = g * (one - last);
    let mut keep = vec![
        (OBJ, l[OBJ]),
        (X, l[X]),
        (D, l[D]),
        (K, l[K]),
        (ALLOC, l[ALLOC]),
        (S_WBIT, one),
        (B_CNT, cnt + one),
    ];
    keep.extend(WOPS.iter().map(|&(col, _)| (col, l[col])));
    go(out, n, gc, K_AUX, &keep);
    go(
        out,
        n,
        g * last,
        K_RET,
        &[(X, l[ALLOC] - one), (K, l[K]), (ALLOC, l[ALLOC])],
    );
    // four remainders, one bit each per row
    let rs = [G_R0, G_R1, G_R2, G_R3];
    let bs = [G_B0, G_B1, G_B2, G_B3];
    for (&r, &b) in rs.iter().zip(&bs) {
        out.push(g * l[b] * (l[b] - one));
        out.push(g * (l[r] - l[b] - c(2) * (one - last) * n[r]));
    }
    let (b0, b1, b2, b3) = (l[G_B0], l[G_B1], l[G_B2], l[G_B3]);
    let xor = |a: Fp3, b: Fp3| a + b - c(2) * a * b;

    // xor / and / not
    let fl = |col: usize| g * l[col];
    let bitwise = fl(B_XOR) + fl(B_AND) + fl(B_NOT);
    out.push(
        fl(B_XOR) * (b2 - xor(b0, b1)) + fl(B_AND) * (b2 - b0 * b1) + fl(B_NOT) * (b2 - one + b1),
    );
    out.push(bitwise * b3);
    let start = (bitwise + fl(B_SHL)) * first;
    out.push(start * (l[G_R0] - l[OBJ]));
    out.push(start * (l[G_R1] - l[X]));
    out.push(bitwise * first * (l[G_R2] - l[D]));
    out.push(bitwise * first * l[G_R3]);

    // shl
    let gs = fl(B_SHL);
    let sf = gs * first;
    out.push(sf * (l[G_R2] - l[G_CI]));
    out.push(sf * (l[G_R3] - l[G_HI]));
    out.push(sf * b3);
    out.push(sf * (l[G_P] - one));
    out.push(sf * (l[G_Q] - c(2)));
    let sc = gs * (one - last);
    for col in [G_Z, G_CI, G_HI] {
        out.push(sc * (n[col] - l[col]));
    }
    out.push(sc * (n[G_P] - l[G_P] * (one + b1 * (l[G_Q] - one))));
    out.push(sc * (n[G_Q] - l[G_Q] * l[G_Q]));
    let (z, i5) = (l[G_Z], l[G_I5]);
    out.push(gs * z * (z - one));
    out.push(gs * ((cnt - c(5)) * l[G_V5] - (one - i5)));
    out.push(gs * (cnt - c(5)) * i5);
    out.push(gs * i5 * z * l[G_R1]);
    out.push(gs * i5 * (l[G_R1] * l[G_ZI] - (one - z)));
    out.push(gs * i5 * z * (l[OBJ] * l[G_P] - l[G_CI] - c(1 << 31) * l[G_HI]));
    out.push(gs * (l[D] - z * l[G_CI]));

    // lt
    let gl = fl(B_LT);
    let lf = gl * first;
    let two32 = c(1 << 32);
    out.push(lf * (l[G_R0] + two32 * l[G_R2] - l[OBJ]));
    out.push(lf * (l[G_R1] + two32 * l[G_R3] - l[X]));
    for (col, init) in [
        (G_NA, one),
        (G_OA, Fp3::ZERO),
        (G_NB, one),
        (G_OB, Fp3::ZERO),
        (G_LL, Fp3::ZERO),
        (G_LH, Fp3::ZERO),
        (G_EH, one),
    ] {
        out.push(lf * (l[col] - init));
    }
    let or = |acc: Fp3, b: Fp3| acc + b - acc * b;
    let (ll, lh, eh) = (l[G_LL], l[G_LH], l[G_EH]);
    let after = [
        (G_NA, G_NA2, l[G_NA] * b2),
        (G_OA, G_OA2, or(l[G_OA], b0)),
        (G_NB, G_NB2, l[G_NB] * b3),
        (G_OB, G_OB2, or(l[G_OB], b1)),
        (G_LL, G_LL2, ll + xor(b0, b1) * (b1 - ll)),
        (G_LH, G_LH2, lh + xor(b2, b3) * (b3 - lh)),
        (G_EH, G_EH2, eh * (one - xor(b2, b3))),
    ];
    let lc = gl * (one - last);
    for &(cur, nxt, val) in &after {
        out.push(gl * (l[nxt] - val));
        out.push(lc * (n[cur] - l[nxt]));
    }
    let le = gl * last;
    out.push(le * l[G_NA2] * l[G_OA2]);
    out.push(le * l[G_NB2] * l[G_OB2]);
    out.push(le * (l[D] - one + l[G_LH2] + l[G_EH2] * l[G_LL2]));
}
