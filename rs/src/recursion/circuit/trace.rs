//! Rows of a recorded verifier run: phase-1 cells, the preprocessed
//! columns (the circuit's key) and the phase-2 memory columns.
//!
//! Regions, in order: ARITH (gates, four a row; row 0 also writes `live`),
//! BITS (four rows per decomposition), PERM (chains, each contiguous, four
//! rows per block), padding. A block's input flags sit on the row before
//! it (the previous block's last row, or the last row before the region).

use nebu::{Fp3, Goldilocks};

use super::air::{CircuitAir, slot_values};
use super::builder::{BlockIn, Builder, GateKind, Var};
use super::layout::*;
use crate::air::Trace;
use crate::recursion::ops::In;
use crate::recursion::perm::RATE;

/// The preprocessed columns, column-major (`COUNT × rows`).
pub struct Pre {
    pub cols: Vec<Vec<Fp3>>,
}

impl Pre {
    fn new(rows: usize) -> Self {
        Self { cols: vec![vec![Fp3::ZERO; rows]; pre::COUNT] }
    }
    fn set(&mut self, col: usize, row: usize, v: Fp3) {
        self.cols[col][row] = v;
    }
    fn one(&mut self, col: usize, row: usize) {
        self.cols[col][row] = Fp3::ONE;
    }
    pub fn row(&self, r: usize) -> Vec<Fp3> {
        self.cols.iter().map(|c| c[r]).collect()
    }
    /// A digest of the columns (layout equality across steps).
    pub fn digest(&self) -> [Goldilocks; 4] {
        let mut o = crate::recursion::ops::Native::new();
        let mut sp = crate::recursion::sponge::Sponge::new(&mut o, crate::recursion::perm::tag::CTX);
        for col in &self.cols {
            for &v in col {
                if v != Fp3::ZERO {
                    sp.absorb_ext(&mut o, v);
                }
            }
            sp.absorb(&mut o, Fp3::ONE);
        }
        let d: Vec<Fp3> = (0..4).map(|_| sp.squeeze(&mut o)).collect();
        [d[0].c0, d[1].c0, d[2].c0, d[3].c0]
    }
}

fn addr(v: Var) -> Fp3 {
    Fp3::from_base(Goldilocks::new(u64::from(v.0) + 1))
}

fn neg_count(b: &Builder, v: Var) -> Fp3 {
    -Fp3::from_base(Goldilocks::new(u64::from(b.reads[v.0 as usize])))
}

fn put3(row: &mut [Goldilocks], at: usize, x: Fp3) {
    row[at] = x.c0;
    row[at + 1] = x.c1;
    row[at + 2] = x.c2;
}

/// Lay out a recorded run over `2^n` rows: phase-1 trace, key and the
/// public-input row (the marked chain's last row).
pub fn generate(b: &Builder, air: &CircuitAir, n: usize) -> Result<(Trace, Pre, usize), String> {
    let rows = 1usize << n;
    if b.rows() > rows {
        return Err(format!("circuit: {} rows needed, 2^{n} available", b.rows()));
    }
    let mut t = Trace::new(V1, rows);
    let mut p = Pre::new(rows);
    let live = if b.live_value { Goldilocks::ONE } else { Goldilocks::ZERO };
    for r in 0..rows {
        t.row_mut(r)[LIVE] = live;
    }
    let mut r = 0;
    // ARITH
    let arith_rows = b.gates.len().div_ceil(GATES).max(1);
    for ar in 0..arith_rows {
        p.one(pre::ARITH, r);
        p.one(pre::MEM, r);
        for k in 0..GATES {
            let Some(gr) = b.gates.get(ar * GATES + k) else { break };
            let row = t.row_mut(r);
            let at = [gate_x(k), gate_y(k), gate_z(k)];
            for (&col, v) in at.iter().zip(&gr.ops) {
                put3(row, col, b.vals[v.0 as usize]);
            }
            if let Some(o) = gr.out {
                put3(row, gate_out(k), b.vals[o.0 as usize]);
            }
            let q = [gr.g.qm, gr.g.qs, gr.g.qa, gr.g.qb, gr.g.qc, gr.g.qk];
            for (i, &v) in q.iter().enumerate() {
                p.set(pre::gate(k, i), r, v);
            }
            match gr.kind {
                GateKind::Compute => p.one(pre::gate(k, pre::QCOMP), r),
                GateKind::Assert => p.one(pre::gate(k, pre::QASSERT), r),
                GateKind::Free => {}
            }
            for i in 0..3 {
                if gr.used[i] {
                    p.set(pre::ADDR + 4 * k + i, r, addr(gr.ops[i]));
                    p.one(pre::E + 4 * k + i, r);
                }
            }
            if let Some(o) = gr.out {
                p.set(pre::ADDR + 4 * k + 3, r, addr(o));
                p.set(pre::E + 4 * k + 3, r, neg_count(b, o));
            }
        }
        if ar == 0 {
            p.set(pre::ADDR + 16, r, addr(b.live));
            p.set(pre::E + 16, r, neg_count(b, b.live));
        }
        r += 1;
    }
    // BITS
    for br in &b.bits {
        let v = br.value;
        let lo = v & 0xFFFF_FFFF;
        let hi = v >> 32;
        let mut acc = 0u64;
        for ph in 0..4 {
            p.one(pre::BITS + ph, r);
            p.one(pre::MEM, r);
            let row = t.row_mut(r);
            let chunk = (v >> (16 * ph)) & 0xFFFF;
            for (j, cell) in row[..BITS_ROW].iter_mut().enumerate() {
                *cell = Goldilocks::new((chunk >> j) & 1);
            }
            acc = acc.wrapping_add(chunk << (16 * ph));
            row[BACC] = Goldilocks::new(acc);
            row[BVAL] = Goldilocks::new(v);
            if ph >= 1 {
                row[BLO] = Goldilocks::new(lo);
            }
            if ph == 3 {
                let d = Goldilocks::new(hi) - Goldilocks::new(0xFFFF_FFFF);
                if d == Goldilocks::ZERO {
                    row[BMAX] = Goldilocks::ONE;
                } else {
                    row[BMINV] = d.inv();
                }
            }
            if ph == 0 {
                p.set(pre::ADDR + 16, r, addr(br.v));
                p.one(pre::E + 16, r);
            }
            for j in 0..BITS_ROW {
                if let Some(&bv) = br.bits.get(16 * ph + j) {
                    p.set(pre::ADDR + j, r, addr(bv));
                    p.set(pre::E + j, r, neg_count(b, bv));
                }
            }
            r += 1;
        }
    }
    // PERM
    let mut out_row = 0;
    for (ci, ch) in b.chains.iter().enumerate() {
        for (k, blk) in ch.blocks.iter().enumerate() {
            let pre_row = r - 1;
            let cells = air.rows_of(&blk.x);
            for (ph, c) in cells.iter().enumerate() {
                p.one(pre::PERM + ph, r + ph);
                p.one(pre::MEM, r + ph);
                t.row_mut(r + ph)[..48].copy_from_slice(c);
            }
            match &blk.input {
                BlockIn::Sponge(items) => {
                    if k == 0 {
                        p.one(pre::FRESH, pre_row);
                        p.set(pre::TAGV, pre_row, Fp3::from_base(Goldilocks::new(ch.tag)));
                    } else {
                        p.one(pre::CONT, pre_row);
                    }
                    let mut lane = 0;
                    for it in items {
                        match *it {
                            In::Var(v, ext) => {
                                p.set(pre::ADDR + lane, r, addr(v));
                                p.one(pre::E + lane, r);
                                if ext {
                                    p.one(pre::WIDE + lane, r);
                                }
                            }
                            In::Free(v, ext) => {
                                p.set(pre::ADDR + lane, r, addr(v));
                                p.set(pre::E + lane, r, neg_count(b, v));
                                if ext {
                                    p.one(pre::WIDE + lane, r);
                                }
                            }
                            In::Zero => p.one(pre::ZERO + lane, pre_row),
                            In::Keep => {
                                if k == 0 {
                                    p.one(pre::ZERO + lane, pre_row);
                                } else {
                                    p.one(pre::KEEP + lane, pre_row);
                                }
                            }
                        }
                        lane += it.width();
                    }
                    debug_assert_eq!(lane, RATE);
                }
                BlockIn::Node(bit, _) => {
                    assert!(k > 0, "a node continues a chain");
                    p.one(pre::NODE, pre_row);
                    t.row_mut(pre_row)[PBIT] = b.vals[bit.0 as usize].c0;
                    p.set(pre::ADDR + RATE + 4, pre_row, addr(*bit));
                    p.one(pre::E + RATE + 4, pre_row);
                }
            }
            let last = r + 3;
            for &(lane, wide, v) in &blk.outs {
                p.set(pre::ADDR + lane, last, addr(v));
                p.set(pre::E + lane, last, neg_count(b, v));
                if wide {
                    p.one(pre::WIDE + lane, last);
                }
            }
            if b.out_chain == Some(ci) && k + 1 == ch.blocks.len() {
                p.one(pre::OUT, last);
                out_row = last;
            }
            if let Some(root) = blk.root {
                p.one(pre::ROOTCHK, last);
                for (i, &rv) in root.iter().enumerate() {
                    t.row_mut(last)[PRT + i] = b.vals[rv.0 as usize].c0;
                    p.set(pre::ADDR + RATE + i, last, addr(rv));
                    p.one(pre::E + RATE + i, last);
                }
            }
            r += 4;
        }
    }
    Ok((t, p, out_row))
}

/// The phase-2 columns: slot inverses and the running memory sum.
pub fn phase2(t1: &Trace, p: &Pre, alpha: Fp3, beta: Fp3) -> Trace {
    let rows = t1.rows();
    let mut t2 = Trace::new(V2, rows);
    let mut sum = Fp3::ZERO;
    let mut fps = Vec::with_capacity(rows * SLOTS);
    for r in 0..rows {
        let pr = p.row(r);
        if pr[pre::MEM] == Fp3::ZERO {
            continue;
        }
        let l: Vec<Fp3> = t1.row(r).iter().map(|&x| Fp3::from_base(x)).collect();
        let vals = slot_values(&l, &pr);
        for (s, v) in vals.iter().enumerate() {
            fps.push((r, s, alpha - (pr[pre::ADDR + s] + beta * *v)));
        }
    }
    let invs = batch_inverse(&fps.iter().map(|f| f.2).collect::<Vec<_>>());
    let mut deltas = vec![Fp3::ZERO; rows];
    for ((r, s, _), h) in fps.iter().zip(invs) {
        put3(t2.row_mut(*r), 3 * s, h);
        deltas[*r] += p.cols[pre::E + s][*r] * h;
    }
    for (r, d) in deltas.iter().enumerate() {
        put3(t2.row_mut(r), SUM, sum);
        sum += *d;
    }
    t2
}

fn batch_inverse(xs: &[Fp3]) -> Vec<Fp3> {
    let mut prefix = Vec::with_capacity(xs.len());
    let mut acc = Fp3::ONE;
    for &x in xs {
        prefix.push(acc);
        acc *= x;
    }
    let mut inv = acc.inv();
    let mut out = vec![Fp3::ZERO; xs.len()];
    for i in (0..xs.len()).rev() {
        out[i] = prefix[i] * inv;
        inv *= xs[i];
    }
    out
}

/// The running sum after the last row (zero for a consistent memory).
pub fn closing_sum(t2: &Trace, p: &Pre) -> Fp3 {
    let rows = t2.rows();
    let last = t2.row(rows - 1);
    let s = Fp3::new(last[SUM], last[SUM + 1], last[SUM + 2]);
    let mut d = Fp3::ZERO;
    for sl in 0..SLOTS {
        let h = Fp3::new(last[3 * sl], last[3 * sl + 1], last[3 * sl + 2]);
        d += p.cols[pre::E + sl][rows - 1] * h;
    }
    s + d
}
