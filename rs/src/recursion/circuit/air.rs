//! The recursion circuit's row constraints (`specs/recursion.md` §
//! circuit). Every value of a row is read as Fp3 (the verifier evaluates
//! at extension points); `T` is the Fp3 basis element (`T³ = T + 1`).

use nebu::{Fp3, Goldilocks};

use super::layout::*;
use crate::air::num::Num;
use crate::machine::hemera::{Tables, is_full};
use crate::recursion::perm::{NODE_TAG, RATE, WIDTH};

/// Coefficients of the partial rounds: lane `i` of the state before
/// partial round `k` as a combination of the 16 lanes after round 3 and
/// the inverses `w_0..w_{k−1}`.
type Lin = [[Goldilocks; 32]; WIDTH];

pub struct CircuitAir {
    tables: Tables,
    /// `z_k`, `k = 0..=16`.
    partial: Vec<Lin>,
    constraints: usize,
}

fn t<T: Num>() -> T {
    T::from_fp3(Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO))
}

fn ext3<T: Num>(c: &[T]) -> T {
    let t = t::<T>();
    c[0] + t * c[1] + t * t * c[2]
}

fn c<T: Num>(v: u64) -> T {
    T::from_u64(v)
}

fn pow7<T: Num>(x: T) -> T {
    let x2 = x * x;
    let x3 = x2 * x;
    x3 * x2 * x2
}

/// Collects constraint values (or counts them).
pub struct Sink<'a, T = Fp3> {
    pub buf: &'a mut [T],
    pub i: usize,
}

impl<T: Num> Sink<'_, T> {
    fn push(&mut self, v: T) {
        if let Some(b) = self.buf.get_mut(self.i) {
            *b = v;
        }
        self.i += 1;
    }
}

/// One row's values: phase 1, phase 2, next row's, the preprocessed
/// columns, the circuit's memory challenges.
pub struct Row<'a, T = Fp3> {
    pub l1: &'a [T],
    pub l2: &'a [T],
    pub n1: &'a [T],
    pub n2: &'a [T],
    pub p: &'a [T],
    /// The public-input columns at this row.
    pub pin: &'a [T],
    pub alpha: T,
    pub beta: T,
}

impl Default for CircuitAir {
    fn default() -> Self {
        let tables = Tables::default();
        let mut partial = Vec::with_capacity(17);
        let mut z: Lin = [[Goldilocks::ZERO; 32]; WIDTH];
        for (i, row) in z.iter_mut().enumerate() {
            row[i] = Goldilocks::ONE;
        }
        partial.push(z);
        for k in 0..16 {
            let mut v = z;
            v[0] = [Goldilocks::ZERO; 32];
            v[0][16 + k] = Goldilocks::ONE;
            let mut nz: Lin = [[Goldilocks::ZERO; 32]; WIDTH];
            for (i, nrow) in nz.iter_mut().enumerate() {
                for (j, vrow) in v.iter().enumerate() {
                    let m = tables.internal[i][j];
                    if m != Goldilocks::ZERO {
                        for (a, &b) in nrow.iter_mut().zip(vrow) {
                            *a += m * b;
                        }
                    }
                }
            }
            z = nz;
            partial.push(z);
        }
        let mut air = Self { tables, partial, constraints: 0 };
        let z1 = vec![Fp3::ZERO; V1];
        let z2 = vec![Fp3::ZERO; V2];
        let p = vec![Fp3::ZERO; pre::COUNT];
        let mut s = Sink { buf: &mut [], i: 0 };
        air.eval(
            &Row { l1: &z1, l2: &z2, n1: &z1, n2: &z2, p: &p, pin: &[Fp3::ZERO; PIN], alpha: Fp3::ZERO, beta: Fp3::ZERO },
            &mut s,
        );
        air.constraints = s.i;
        air
    }
}

impl CircuitAir {
    pub fn constraints(&self) -> usize {
        self.constraints
    }
    pub fn tables(&self) -> &Tables {
        &self.tables
    }

    /// `MDS·(s + rc_k)^7`.
    fn full<T: Num>(&self, s: &[T], k: usize) -> [T; WIDTH] {
        debug_assert!(is_full(k));
        let rc = &self.tables.rc[k];
        let sb: Vec<T> = (0..WIDTH).map(|i| pow7(s[i] + T::from_base(rc[i]))).collect();
        core::array::from_fn(|j| {
            (0..WIDTH).fold(T::ZERO, |a, i| a + T::from_base(self.tables.mds[j][i]) * sb[i])
        })
    }

    fn lin<T: Num>(&self, k: usize, i: usize, y4: &[T], w: &[T]) -> T {
        let co = &self.partial[k][i];
        let mut acc = T::ZERO;
        for j in 0..16 {
            if co[j] != Goldilocks::ZERO {
                acc += T::from_base(co[j]) * y4[j];
            }
        }
        for j in 0..k {
            if co[16 + j] != Goldilocks::ZERO {
                acc += T::from_base(co[16 + j]) * w[j];
            }
        }
        acc
    }

    /// The permutation's output for input `x` from the row function (a
    /// self-check of the layout against hemera).
    pub fn rows_of(&self, x: &[Goldilocks; WIDTH]) -> [[Goldilocks; 48]; 4] {
        let mds = |s: &[Goldilocks; WIDTH]| -> [Goldilocks; WIDTH] {
            core::array::from_fn(|j| (0..WIDTH).fold(Goldilocks::ZERO, |a, i| a + self.tables.mds[j][i] * s[i]))
        };
        let full = |s: &[Goldilocks; WIDTH], k: usize| -> [Goldilocks; WIDTH] {
            let rc = &self.tables.rc[k];
            let sb: [Goldilocks; WIDTH] = core::array::from_fn(|i| (s[i] + rc[i]).pow7());
            mds(&sb)
        };
        let y0 = mds(x);
        let y1 = full(&y0, 0);
        let y2 = full(&y1, 1);
        let y3 = full(&y2, 2);
        let y4 = full(&y3, 3);
        let mut w = [Goldilocks::ZERO; 16];
        let mut z = y4;
        for (k, wk) in w.iter_mut().enumerate() {
            let u = z[0] + self.tables.rc[4 + k][0];
            *wk = if u == Goldilocks::ZERO { Goldilocks::ZERO } else { u.inv() };
            let mut v = z;
            v[0] = *wk;
            z = core::array::from_fn(|i| (0..WIDTH).fold(Goldilocks::ZERO, |a, j| a + self.tables.internal[i][j] * v[j]));
        }
        let y5 = full(&z, 20);
        let y6 = full(&y5, 21);
        let y7 = full(&y6, 22);
        let y8 = full(&y7, 23);
        let mut rows = [[Goldilocks::ZERO; 48]; 4];
        let put = |r: &mut [Goldilocks; 48], at: usize, v: &[Goldilocks]| r[at..at + v.len()].copy_from_slice(v);
        put(&mut rows[0], PX, x);
        put(&mut rows[0], PY1, &y1);
        put(&mut rows[0], PY2, &y2);
        put(&mut rows[1], PY3, &y3);
        put(&mut rows[1], PY4, &y4);
        put(&mut rows[1], PW, &w);
        put(&mut rows[2], PY5, &y5);
        put(&mut rows[2], PY6, &y6);
        put(&mut rows[2], PY7, &y7);
        put(&mut rows[3], PY8, &y8);
        rows
    }

    /// Every constraint of a row, in a fixed order.
    pub fn eval<T: Num>(&self, r: &Row<'_, T>, out: &mut Sink<'_, T>) {
        let (l, n, p) = (r.l1, r.n1, r.p);
        let one = T::ONE;
        let live = l[LIVE];
        out.push(n[LIVE] - live);
        out.push(live * (live - one));

        // ARITH
        for g in 0..GATES {
            let q = |k: usize| p[pre::gate(g, k)];
            let x = ext3(&l[gate_x(g)..gate_x(g) + 3]);
            let y = ext3(&l[gate_y(g)..gate_y(g) + 3]);
            let z = ext3(&l[gate_z(g)..gate_z(g) + 3]);
            let o = ext3(&l[gate_out(g)..gate_out(g) + 3]);
            let val = q(pre::QM) * x * (y + q(pre::QS) * z)
                + q(pre::QA) * x
                + q(pre::QB) * y
                + q(pre::QC) * z
                + q(pre::QK);
            out.push(q(pre::QCOMP) * (o - val) + q(pre::QASSERT) * live * val);
        }

        // BITS
        let b: [T; 4] = core::array::from_fn(|k| p[pre::BITS + k]);
        let any = b[0] + b[1] + b[2] + b[3];
        let chunk = |row: &[T]| (0..BITS_ROW).fold(T::ZERO, |a, j| a + c::<T>(1 << j) * row[j]);
        for &x in &l[..BITS_ROW] {
            out.push(any * x * (x - one));
        }
        let first3 = b[0] + b[1] + b[2];
        out.push(b[0] * (l[BACC] - chunk(l)));
        out.push(first3 * (n[BVAL] - l[BVAL]));
        let scale = b[0] * c::<T>(1 << 16) + b[1] * c::<T>(1 << 32) + b[2] * c::<T>(1 << 48);
        out.push(first3 * (n[BACC] - l[BACC]) - scale * chunk(n));
        out.push(b[1] * (l[BLO] - l[BACC]));
        out.push((b[1] + b[2]) * (n[BLO] - l[BLO]));
        out.push(b[3] * (l[BACC] - l[BVAL]));
        let two32inv = T::from_base(Goldilocks::new(1 << 32).inv());
        let hi = (l[BACC] - l[BLO]) * two32inv;
        let max = c::<T>(0xFFFF_FFFF);
        out.push(b[3] * ((hi - max) * l[BMINV] - (one - l[BMAX])));
        out.push(b[3] * (hi - max) * l[BMAX]);
        out.push(b[3] * l[BMAX] * l[BLO]);

        // PERM
        let ph: [T; 4] = core::array::from_fn(|k| p[pre::PERM + k]);
        let mdsx: Vec<T> = (0..WIDTH)
            .map(|j| (0..WIDTH).fold(T::ZERO, |a, i| a + T::from_base(self.tables.mds[j][i]) * l[PX + i]))
            .collect();
        let y1 = self.full(&mdsx, 0);
        let y2 = self.full(&l[PY1..PY1 + 16], 1);
        let y3 = self.full(&l[PY2..PY2 + 16], 2);
        for j in 0..WIDTH {
            out.push(ph[0] * (l[PY1 + j] - y1[j]));
            out.push(ph[0] * (l[PY2 + j] - y2[j]));
            out.push(ph[0] * (n[PY3 + j] - y3[j]));
        }
        let y4 = self.full(&l[PY3..PY3 + 16], 3);
        let wv = &l[PW..PW + 16];
        let y4c = &l[PY4..PY4 + 16];
        for j in 0..WIDTH {
            out.push(ph[1] * (l[PY4 + j] - y4[j]));
        }
        for k in 0..16 {
            let u = self.lin(k, 0, y4c, wv) + T::from_base(self.tables.rc[4 + k][0]);
            let w = wv[k];
            out.push(ph[1] * (u * w * u - u));
            out.push(ph[1] * (w * u * w - w));
        }
        let z16: Vec<T> = (0..WIDTH).map(|i| self.lin(16, i, y4c, wv)).collect();
        let y5 = self.full(&z16, 20);
        let y6 = self.full(&l[PY5..PY5 + 16], 21);
        let y7 = self.full(&l[PY6..PY6 + 16], 22);
        let y8 = self.full(&l[PY7..PY7 + 16], 23);
        for j in 0..WIDTH {
            out.push(ph[1] * (n[PY5 + j] - y5[j]));
            out.push(ph[2] * (l[PY6 + j] - y6[j]));
            out.push(ph[2] * (l[PY7 + j] - y7[j]));
            out.push(ph[2] * (n[PY8 + j] - y8[j]));
        }

        // the next block's input, from flags on this row
        let o8 = &l[PY8..PY8 + 16];
        let nx = &n[PX..PX + 16];
        for j in 0..RATE {
            out.push(p[pre::KEEP + j] * (nx[j] - o8[j]));
            out.push(p[pre::ZERO + j] * nx[j]);
        }
        let (cont, fresh, node) = (p[pre::CONT], p[pre::FRESH], p[pre::NODE]);
        for j in RATE..WIDTH {
            out.push(cont * (nx[j] - o8[j]));
            let init = if j == RATE { p[pre::TAGV] } else { T::ZERO };
            out.push(fresh * (nx[j] - init));
            out.push(node * nx[j]);
        }
        let bit = l[PBIT];
        for j in 0..4 {
            out.push(node * (one - bit) * (nx[j] - o8[j]));
            out.push(node * bit * (nx[4 + j] - o8[j]));
        }
        out.push(node * (nx[8] - c::<T>(NODE_TAG)));
        out.push(node * bit * (bit - one));
        let rc = p[pre::ROOTCHK];
        for j in 0..4 {
            out.push(live * rc * (o8[j] - l[PRT + j]));
            out.push(p[pre::OUT] * (o8[j] - r.pin[j]));
        }

        // memory
        let vals = slot_values(l, p);
        let mut delta = T::ZERO;
        for (s, &val) in vals.iter().enumerate() {
            let fp = p[pre::ADDR + s] + r.beta * val;
            let h = ext3(&r.l2[3 * s..3 * s + 3]);
            out.push(p[pre::MEM] * (h * (r.alpha - fp) - one));
            delta += p[pre::E + s] * h;
        }
        let sum = ext3(&r.l2[SUM..SUM + 3]);
        let next = ext3(&r.n2[SUM..SUM + 3]);
        out.push(next - sum - delta);
    }
}

/// The value each memory slot of a row fingerprints (by row kind).
pub fn slot_values<T: Num>(l: &[T], p: &[T]) -> [T; SLOTS] {
    let tt = t::<T>();
    let wide = |j: usize| if j < pre::WIDES { p[pre::WIDE + j] } else { T::ZERO };
    let packed = |v: &[T], j: usize| {
        let w = wide(j);
        v[j] + tt * w * v[j + 1] + tt * tt * w * v[j + 2]
    };
    let arith = p[pre::ARITH];
    let any = p[pre::BITS] + p[pre::BITS + 1] + p[pre::BITS + 2] + p[pre::BITS + 3];
    let (ph0, ph3) = (p[pre::PERM], p[pre::PERM + 3]);
    core::array::from_fn(|s| {
        let av = if s < 4 * GATES {
            let g = s / 4;
            let at = [gate_x(g), gate_y(g), gate_z(g), gate_out(g)][s % 4];
            ext3(&l[at..at + 3])
        } else {
            l[LIVE]
        };
        let bv = if s < BITS_ROW { l[s] } else { l[BVAL] };
        let p0 = if s < RATE { packed(&l[PX..PX + 16], s) } else { T::ZERO };
        let p3 = match s {
            s if s < RATE => packed(&l[PY8..PY8 + 16], s),
            s if s < RATE + 4 => l[PRT + s - RATE],
            s if s == RATE + 4 => l[PBIT],
            _ => T::ZERO,
        };
        arith * av + any * bv + ph0 * p0 + ph3 * p3
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_row_layout_computes_hemera() {
        let air = CircuitAir::default();
        let x: [Goldilocks; WIDTH] = core::array::from_fn(|i| Goldilocks::new(i as u64 * 31 + 5));
        let rows = air.rows_of(&x);
        let mut y = x;
        crate::recursion::perm::permute(&mut y);
        assert_eq!(&rows[3][PY8..PY8 + 16], &y[..]);
        // the PERM constraints hold on the four rows
        let mut p = vec![Fp3::ZERO; pre::COUNT];
        let z2 = vec![Fp3::ZERO; V2];
        for ph in 0..3 {
            p.iter_mut().for_each(|v| *v = Fp3::ZERO);
            p[pre::PERM + ph] = Fp3::ONE;
            let lift = |r: &[Goldilocks; 48]| {
                let mut v: Vec<Fp3> = r.iter().map(|&x| Fp3::from_base(x)).collect();
                v.push(Fp3::ONE);
                v
            };
            let (l1, n1) = (lift(&rows[ph]), lift(&rows[ph + 1]));
            let mut buf = vec![Fp3::ZERO; air.constraints()];
            let mut s = Sink { buf: &mut buf, i: 0 };
            air.eval(&Row { l1: &l1, l2: &z2, n1: &n1, n2: &z2, p: &p, pin: &[Fp3::ZERO; PIN], alpha: Fp3::ONE, beta: Fp3::ONE }, &mut s);
            assert!(buf.iter().all(|&v| v == Fp3::ZERO), "phase {ph}: {:?}", buf.iter().position(|&v| v != Fp3::ZERO));
        }
        assert!(air.constraints() > 200);
    }
}
