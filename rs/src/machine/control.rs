//! Constraints of the init rows and the continuation machine
//! (`specs/machine.md` § transitions). Every constraint is gated by the row
//! kind and, for EVAL / RET rows, by the opcode / frame flag; `n(·)` reads
//! the next row.

use crate::air::num::Num;

use super::air::*;
use super::layout::*;
use crate::air::Vals;

pub(crate) fn constrain<T: Num>(m: &Machine, k: &KConst<T>, v: &Vals<'_, T>, out: &mut Out<'_, T>) {
    let l = v.local;
    let n = v.next;
    let p = v.publics;
    let one = T::ONE;
    // kinds: boolean, one-hot; INIT exactly on the init region
    let mut sum = T::ZERO;
    for &x in &l[..KINDS] {
        out.push(x * (x - one));
        sum += x;
    }
    out.push(sum - one);
    out.push(l[K_INIT] - p[PUB_INIT_REG]);
    // INIT: slot 0 is the pinned entry
    let init = l[K_INIT];
    out.push(init * (l[slot(0, KEY)] - p[PUB_INIT_KEY]));
    out.push(init * (l[slot(0, P0)] - p[PUB_INIT_P0]));
    out.push(init * (l[slot(0, P0 + 1)] - p[PUB_INIT_P1]));
    out.push(init * (l[slot(0, P0 + 2)] - p[PUB_INIT_P2]));
    out.push(init * l[slot(0, P0 + 3)]);
    // the first machine row: EVAL of the program on the subject
    let first = p[PUB_FIRST_M];
    out.push(first * (l[K_EVAL] - one));
    out.push(first * (l[X] - k.fml0));
    out.push(first * (l[OBJ] - k.obj0));
    out.push(first * l[K]);
    out.push(first * l[D]);
    out.push(first * l[CYC]);
    out.push(first * (l[ALLOC] - k.p1));

    // flags: boolean and one-hot in EVAL and RET rows (RET uses 15)
    let (ev, rt) = (l[K_EVAL], l[K_RET]);
    let mut fsum = T::ZERO;
    for i in 0..FLAGS {
        let f = l[FLAG0 + i];
        out.push((ev + rt) * f * (f - one));
        fsum += f;
    }
    out.push((ev + rt) * (fsum - one));
    for i in RET_FLAGS..FLAGS {
        out.push(rt * l[FLAG0 + i]);
    }
    // AUX sub-kinds: boolean, one-hot
    let aux = l[K_AUX];
    let mut ssum = T::ZERO;
    for &sk in &SUBKINDS {
        out.push(aux * l[sk] * (l[sk] - one));
        ssum += l[sk];
    }
    out.push(aux * (ssum - one));

    // sequencing: machine rows chain until TERM; TERM and PAD end it
    let mach = MACHINE.iter().fold(T::ZERO, |a, &kd| a + l[kd]);
    let nmach = MACHINE.iter().fold(T::ZERO, |a, &kd| a + n[kd]);
    let term = rt * l[F_TERM];
    out.push((mach - term) * (one - nmach));
    out.push(term * nmach);
    out.push(l[K_PAD] * nmach);
    // CYC carries through every machine step (EVAL adds the cost)
    let cost = OPS.iter().fold(T::ZERO, |a, &(o, _, cst)| a + l[FLAG0 + o] * c::<T>(cst))
        + l[OP_WORD] * c::<T>(WORD_COST);
    out.push((mach - term) * (n[CYC] - l[CYC] - ev * cost));
    // TERM: empty continuation, the expected output digest and cycles
    out.push(term * l[K]);
    out.push(term * (l[slot(0, KEY)] - l[X]));
    for i in 0..4 {
        out.push(term * (l[slot(0, P0 + i)] - k.output[i]));
    }
    out.push(term * (l[CYC] - k.cycles));

    super::control_eval::constrain(v, out);
    super::control_ret::constrain(m, v, out);
    super::control_aux::constrain(k, v, out);
    super::control_word::constrain(v, out);
}
