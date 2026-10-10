//! Constraints of the permutation region: 32-row blocks, one hemera
//! permutation each (`specs/machine.md` § permutation region).
//!
//! Phases (public periodic columns): 0–1 the bits of an atom job, 2 the job
//! input and hemera's initial linear layer, 3–26 the 24 rounds (state
//! before the round on the round's row, round constants as public
//! columns), 27 the output written to the table, 28–31 idle. The job (kind
//! flags, id) is constant on phases 0–30.

use nebu::Fp3;

use super::air::*;
use super::hemera::{ATOM_LEN, DOMAIN_HASH, FLAG_CHUNK, FLAG_PARENT};
use super::layout::*;
use crate::air::Vals;

fn pow7(x: Fp3) -> Fp3 {
    let x2 = x * x;
    let x3 = x2 * x;
    x3 * x2 * x2
}

pub(crate) fn constrain(m: &Machine, v: &Vals<'_>, out: &mut Out<'_>) {
    let l = v.local;
    let n = v.next;
    let p = v.publics;
    let perm = l[K_PERM];
    let jobs = [J_PAIR, J_ATOM1, J_ATOM2, J_HOP];
    // the region is exactly the PERM rows
    out.push(perm - p[PUB_REGION]);
    // job flags boolean, at most one, constant along the block
    let mut any = Fp3::ZERO;
    for &j in &jobs {
        out.push(perm * l[j] * (l[j] - Fp3::ONE));
        out.push(p[PUB_CONT] * (n[j] - l[j]));
        any += l[j];
    }
    out.push(perm * any * (any - Fp3::ONE));
    out.push(p[PUB_CONT] * (n[JOB_ID] - l[JOB_ID]));

    // bits rows: boolean, sums, canonical, hand-off to the job input
    let (b0, b1) = (p[PUB_BITS0], p[PUB_BITS1]);
    let mut lo = Fp3::ZERO;
    let (mut hl, mut ht) = (Fp3::ZERO, Fp3::ZERO);
    for i in 0..32 {
        let b = l[B_BITS + i];
        out.push((b0 + b1) * b * (b - Fp3::ONE));
        lo += b * c(1 << i);
        if i < 24 {
            hl += b * c(1 << i);
        } else {
            ht += b * c(1 << (i - 24));
        }
    }
    out.push(b0 * (l[B_LO] - lo));
    out.push(b0 * (n[B_LOC] - l[B_LO]));
    out.push(b1 * (l[B_HL] - hl));
    out.push(b1 * (l[B_HT] - ht));
    let hi = l[B_HL] + c(1 << 24) * l[B_HT];
    let max = c(0xFFFF_FFFF);
    out.push(b1 * ((hi - max) * l[B_MINV] - (Fp3::ONE - l[B_MAX])));
    out.push(b1 * (hi - max) * l[B_MAX]);
    out.push(b1 * l[B_MAX] * l[B_LOC]);
    let a1 = b1 * l[J_ATOM1];
    out.push(a1 * (n[STATE] - (l[B_LOC] + c(1 << 32) * l[B_HL])));
    out.push(a1 * (n[STATE + 1] - (l[B_HT] + c(256))));
    out.push(a1 * (n[slot(0, P0)] - (l[B_LOC] + c(1 << 32) * hi)));

    // job input at the MDS phase
    let md = p[PUB_MDS];
    let st = |i: usize| l[STATE + i];
    let key = |s: usize| l[slot(s, KEY)];
    let pay = |s: usize, i: usize| l[slot(s, P0 + i)];
    for &j in &jobs {
        out.push(md * l[j] * (key(0) - l[JOB_ID]));
    }
    let (jp, j1, j2, jh) = (l[J_PAIR], l[J_ATOM1], l[J_ATOM2], l[J_HOP]);
    out.push(md * jp * (key(1) - pay(0, 0)));
    out.push(md * jp * (key(2) - pay(0, 1)));
    for i in 0..16 {
        let pair = match i {
            0..=3 => pay(1, i),
            4..=7 => pay(2, i - 4),
            9 => c(FLAG_PARENT),
            _ => Fp3::ZERO,
        };
        let atom1 = match i {
            0 | 1 => st(i), // set by the bits rows
            10 => c(ATOM_LEN),
            11 => c(DOMAIN_HASH),
            _ => Fp3::ZERO,
        };
        let atom2 = match i {
            0..=3 => pay(0, i),
            9 => c(FLAG_CHUNK),
            _ => Fp3::ZERO,
        };
        let hop = if i < 4 { pay(0, i) } else { Fp3::ZERO };
        out.push(md * (st(i) - (jp * pair + j1 * atom1 + j2 * atom2 + jh * hop)));
    }
    // hemera's initial linear layer, then the rounds
    let t = &m.tables;
    for j in 0..16 {
        let lin = (0..16).fold(Fp3::ZERO, |a, i| a + Fp3::from_base(t.mds[j][i]) * st(i));
        out.push(md * (n[STATE + j] - lin));
    }
    let full = p[PUB_FULL];
    let sbox: Vec<Fp3> = (0..16).map(|i| pow7(st(i) + p[PUB_RC + i])).collect();
    for j in 0..16 {
        let mix = (0..16).fold(Fp3::ZERO, |a, i| a + Fp3::from_base(t.mds[j][i]) * sbox[i]);
        out.push(full * (n[STATE + j] - mix));
    }
    let part = p[PUB_PART];
    let u = st(0) + p[PUB_RC];
    let w = l[PINV];
    out.push(part * (u * w * u - u));
    out.push(part * (w * u * w - w));
    for j in 0..16 {
        let mix = (0..16).fold(Fp3::ZERO, |a, i| {
            let x = if i == 0 { w } else { st(i) };
            a + Fp3::from_base(t.internal[j][i]) * x
        });
        out.push(part * (n[STATE + j] - mix));
    }
    // the output row writes the first four lanes under the job id
    let o = p[PUB_OUT];
    out.push(o * (key(0) - l[JOB_ID]));
    for i in 0..4 {
        out.push(o * (pay(0, i) - st(i)));
    }
}
