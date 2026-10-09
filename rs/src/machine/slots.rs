//! Per-slot table tag and access mode of a row, as polynomials in the row's
//! own cells (kind, opcode/frame/job flags, phase columns). The phase-2
//! fingerprint, the mode constraints and the native phase-2 builder all
//! read these, so the tag a slot is checked under is forced by the row's
//! kind — never chosen by the prover.

use crate::air::num::Num;

use super::layout::*;

pub(crate) fn c<T: Num>(v: u64) -> T {
    T::from_u64(v)
}

/// Per-slot `(tag, read, write)`; the slot is inactive where
/// `read + write = 0`, and its contribution `(read − write·M)·h` is then 0
/// whatever its cells hold (bits rows reuse slot columns).
pub(crate) struct SlotModes<T> {
    pub tag: [T; SLOTS],
    pub read: [T; SLOTS],
    pub write: [T; SLOTS],
}

/// `local`: the row's phase-1 cells; `ph_mds`, `ph_out`: the permutation
/// phase columns at this row (0 outside the region).
pub(crate) fn modes<T: Num>(l: &[T], init_tag: T, ph_mds: T, ph_out: T) -> SlotModes<T> {
    let one = T::ONE;
    let (ev, rt, perm) = (l[K_EVAL], l[K_RET], l[K_PERM]);
    let f = |i: usize| l[i];
    let mut tag = [T::ZERO; SLOTS];
    let mut read = [T::ZERO; SLOTS];
    let mut write = [T::ZERO; SLOTS];

    // INIT: slot 0 writes the pinned entry
    tag[0] += l[K_INIT] * init_tag;
    write[0] += l[K_INIT];

    // EVAL
    let b1ops = f(OP_ADD) + f(OP_SUB) + f(OP_MUL) + f(OP_EQ) + f(OP_LT) + f(OP_WORD) + f(OP_LOOK);
    let binary = f(OP_COMPOSE) + f(OP_CONS) + f(OP_BRANCH) + f(OP_CALL) + b1ops;
    let unary = f(OP_HASH) + f(OP_INV) + f(OP_NOT);
    let optag = l[slot(1, P0)];
    tag[0] += ev * c::<T>(TAG_PAIR);
    read[0] += ev;
    tag[1] += ev * c::<T>(TAG_ATOM);
    read[1] += ev;
    tag[2] += ev * (f(OP_AXIS) * c::<T>(TAG_ATOM) + binary * c::<T>(TAG_PAIR));
    read[2] += ev * (f(OP_AXIS) + binary);
    let frame_tag = f(OP_COMPOSE) * c::<T>(TAG_COMP1)
        + f(OP_CONS) * c::<T>(TAG_CONS1)
        + f(OP_BRANCH) * c::<T>(TAG_BR)
        + f(OP_CALL) * c::<T>(TAG_CALL1)
        + b1ops * (c::<T>(TAG_B1) + optag)
        + f(OP_HASH) * c::<T>(TAG_UHASH)
        + f(OP_INV) * c::<T>(TAG_UINV)
        + f(OP_NOT) * c::<T>(TAG_B2 + T_NOT);
    let axis0 = f(OP_AXIS) * l[E_IS0];
    tag[3] += ev * (frame_tag + axis0 * c::<T>(TAG_DIG));
    write[3] += ev * (binary + unary);
    read[3] += ev * axis0;

    // RET: slot 0 reads the frame (or, terminal, the result's digest)
    let op = l[R_OP];
    let frames = FRAME_TAGS.iter().fold(T::ZERO, |a, &(fl, t)| a + f(fl) * c::<T>(t))
        + f(F_B1) * (c::<T>(TAG_B1) + op)
        + (f(F_B2AR) + f(F_B2W)) * (c::<T>(TAG_B2) + op);
    tag[0] += rt * (frames + f(F_TERM) * c::<T>(TAG_DIG));
    read[0] += rt * (0..RET_FLAGS).fold(T::ZERO, |a, i| a + f(FLAG0 + i));
    let atom1 = f(F_BR) + f(F_B2AR) + f(F_UINV) + f(F_B2W) + f(F_B2LOOK) + f(F_CALL1) + f(F_CALL2);
    tag[1] += rt
        * (f(F_CONS1) * c::<T>(TAG_CONS2)
            + f(F_COMP1) * c::<T>(TAG_COMP2)
            + f(F_B1) * (c::<T>(TAG_B2) + op)
            + f(F_CONS2) * c::<T>(TAG_PAIR)
            + atom1 * c::<T>(TAG_ATOM)
            + f(F_UHASH) * c::<T>(TAG_HOP)
            + f(F_B2EQ) * (l[Q_KA] * c::<T>(TAG_ATOM) + (one - l[Q_KA]) * c::<T>(TAG_PAIR)));
    write[1] += rt * (f(F_CONS1) + f(F_COMP1) + f(F_B1) + f(F_CONS2));
    read[1] += rt * (atom1 + f(F_UHASH) + f(F_B2EQ));
    let atom2 = f(F_B2AR) + f(F_UINV) + f(F_B2W) + f(F_B2LOOK);
    tag[2] += rt
        * (f(F_BR) * c::<T>(TAG_PAIR)
            + atom2 * c::<T>(TAG_ATOM)
            + f(F_B2EQ) * (l[Q_KB] * c::<T>(TAG_ATOM) + (one - l[Q_KB]) * c::<T>(TAG_PAIR)));
    read[2] += rt * (f(F_BR) + f(F_B2AR) + f(F_B2W) + f(F_B2LOOK) + f(F_B2EQ));
    write[2] += rt * f(F_UINV);
    let both_pairs = (one - l[Q_KA]) * (one - l[Q_KB]);
    tag[3] += rt * ((f(F_B2AR) + f(F_B2W) + f(F_B2EQ)) * c::<T>(TAG_ATOM) + f(F_B2LOOK) * c::<T>(TAG_STATE));
    write[3] += rt * (f(F_B2AR) + f(F_B2W) + f(F_B2EQ) * (one - both_pairs));
    read[3] += rt * f(F_B2LOOK);

    // AXW reads the node's children
    tag[0] += l[K_AXW] * c::<T>(TAG_PAIR);
    read[0] += l[K_AXW];

    // AUX
    let aux = l[K_AUX];
    let (lk, wa, wp, wj) = (aux * f(S_LOOK), aux * f(S_WATOM), aux * f(S_WPAIR), aux * f(S_WJOIN));
    // look: the subject's root pair, its root noun's digest, the value atom
    tag[0] += lk * c::<T>(TAG_PAIR);
    read[0] += lk;
    tag[1] += lk * c::<T>(TAG_DIG);
    read[1] += lk;
    tag[2] += lk * c::<T>(TAG_ATOM);
    write[2] += lk;
    // witness atom: the atom and a stack cell
    tag[0] += wa * c::<T>(TAG_ATOM);
    write[0] += wa;
    tag[1] += wa * c::<T>(TAG_SCELL);
    write[1] += wa;
    // witness pair: two cells popped, the pair and a cell pushed
    tag[0] += wp * c::<T>(TAG_SCELL);
    read[0] += wp;
    tag[1] += wp * c::<T>(TAG_SCELL);
    read[1] += wp;
    tag[2] += wp * c::<T>(TAG_PAIR);
    write[2] += wp;
    tag[3] += wp * c::<T>(TAG_SCELL);
    write[3] += wp;
    // join: the last cell, the pair [witness subject], the CALL2 frame
    tag[0] += wj * c::<T>(TAG_SCELL);
    read[0] += wj;
    tag[1] += wj * c::<T>(TAG_PAIR);
    write[1] += wj;
    tag[2] += wj * c::<T>(TAG_CALL2);
    write[2] += wj;

    // HDA: four atoms; HDB: three pairs
    for s in 0..4 {
        tag[s] += l[K_HDA] * c::<T>(TAG_ATOM);
        write[s] += l[K_HDA];
    }
    for s in 0..3 {
        tag[s] += l[K_HDB] * c::<T>(TAG_PAIR);
        write[s] += l[K_HDB];
    }

    // EQD: two digests read, the result written
    tag[0] += l[K_EQD] * c::<T>(TAG_DIG);
    read[0] += l[K_EQD];
    tag[1] += l[K_EQD] * c::<T>(TAG_DIG);
    read[1] += l[K_EQD];
    tag[2] += l[K_EQD] * c::<T>(TAG_ATOM);
    write[2] += l[K_EQD];

    // permutation jobs: reads at the MDS phase, the result at OUT
    let (jp, j1, j2, jh) = (l[J_PAIR], l[J_ATOM1], l[J_ATOM2], l[J_HOP]);
    let pm = perm * ph_mds;
    tag[0] += pm * (jp * c::<T>(TAG_PAIR) + j1 * c::<T>(TAG_ATOM) + j2 * c::<T>(TAG_ABASE) + jh * c::<T>(TAG_DIG));
    read[0] += pm * (jp + j1 + j2 + jh);
    tag[1] += pm * jp * c::<T>(TAG_DIG);
    read[1] += pm * jp;
    tag[2] += pm * jp * c::<T>(TAG_DIG);
    read[2] += pm * jp;
    let po = perm * ph_out;
    tag[0] += po * ((jp + j2) * c::<T>(TAG_DIG) + j1 * c::<T>(TAG_ABASE) + jh * c::<T>(TAG_HOP));
    write[0] += po * (jp + j1 + j2 + jh);

    SlotModes { tag, read, write }
}

/// The fingerprint `tag + β·key + β²·p0 + … + β⁵·p3` of slot `s`.
pub(crate) fn fingerprint<T: Num>(l: &[T], tag: T, s: usize, beta: T) -> T {
    let mut acc = tag;
    let mut b = beta;
    for i in 0..5 {
        acc += b * l[slot(s, i)];
        b *= beta;
    }
    acc
}
