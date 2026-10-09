//! Constraints of the init rows and the continuation machine
//! (`specs/machine.md` § transitions). Every constraint is gated by the row
//! kind and, for EVAL / RET rows, by the opcode / frame flag; `n(·)` reads
//! the next row.

use nebu::Fp3;

use super::air::*;
use super::layout::*;
use crate::air::Vals;

pub(crate) fn constrain(m: &Machine, v: &Vals<'_>, out: &mut Out<'_>) {
    let l = v.local;
    let n = v.next;
    let p = v.publics;
    let one = Fp3::ONE;
    // kinds: boolean, one-hot; INIT exactly on the init region
    let mut sum = Fp3::ZERO;
    for k in 0..KINDS {
        out.push(l[k] * (l[k] - one));
        sum += l[k];
    }
    out.push(sum - one);
    out.push(l[K_INIT] - p[PUB_INIT_REG]);
    // INIT: slot 0 is the pinned entry
    let init = l[K_INIT];
    out.push(init * (l[slot(0, KEY)] - p[PUB_INIT_KEY]));
    out.push(init * (l[slot(0, P0)] - p[PUB_INIT_P0]));
    out.push(init * (l[slot(0, P0 + 1)] - p[PUB_INIT_P1]));
    out.push(init * l[slot(0, P0 + 2)]);
    out.push(init * l[slot(0, P0 + 3)]);
    // the first machine row: EVAL of the program on the subject
    let first = p[PUB_FIRST_M];
    let k = &m.constants;
    out.push(first * (l[K_EVAL] - one));
    out.push(first * (l[X] - c(k.fml0)));
    out.push(first * (l[OBJ] - c(k.obj0)));
    out.push(first * l[K]);
    out.push(first * l[D]);
    out.push(first * l[CYC]);
    out.push(first * (l[ALLOC] - c(k.p + 1)));

    // flags: boolean and one-hot in EVAL and RET rows
    let (ev, rt) = (l[K_EVAL], l[K_RET]);
    let mut fsum = Fp3::ZERO;
    for i in 0..FLAGS {
        let f = l[FLAG0 + i];
        out.push((ev + rt) * f * (f - one));
        fsum += f;
    }
    out.push((ev + rt) * (fsum - one));
    for i in OPS.len()..FLAGS {
        out.push(ev * l[FLAG0 + i]);
    }

    // sequencing: machine rows chain until TERM; TERM and PAD end it
    let mach = MACHINE.iter().fold(Fp3::ZERO, |a, &kd| a + l[kd]);
    let nmach = MACHINE.iter().fold(Fp3::ZERO, |a, &kd| a + n[kd]);
    let term = rt * l[F_TERM];
    out.push((mach - term) * (one - nmach));
    out.push(term * nmach);
    out.push(l[K_PAD] * nmach);
    // CYC carries through every machine step (EVAL adds the cost)
    let cost = OPS.iter().fold(Fp3::ZERO, |a, &(o, _, cst)| a + l[FLAG0 + o] * c(cst));
    out.push((mach - term) * (n[CYC] - l[CYC] - ev * cost));
    // TERM: empty continuation, the expected output digest and cycles
    out.push(term * l[K]);
    out.push(term * (l[slot(0, KEY)] - l[X]));
    for i in 0..4 {
        out.push(term * (l[slot(0, P0 + i)] - Fp3::from_base(k.output[i])));
    }
    out.push(term * (l[CYC] - c(k.cycles)));

    super::control_eval::constrain(v, out);
    super::control_ret::constrain(v, out);
}
