//! The phase-2 columns: slot inverses and the running logUp sum, from the
//! phase-1 trace and the challenges `(α, β)`.

use nebu::{Fp3, Goldilocks};

use super::air::{Machine, PUB_INIT_TAG, PUB_MDS, PUB_OUT};
use super::layout::*;
use super::slots::{fingerprint, modes};
use crate::air::{Air, Trace};

fn split(x: Fp3) -> [Goldilocks; 3] {
    [x.c0, x.c1, x.c2]
}

pub(crate) fn build(m: &Machine, w1: &Trace, ch: &[Fp3]) -> Trace {
    let (alpha, beta) = (ch[0], ch[1]);
    let rows = w1.rows();
    let n = rows.trailing_zeros() as usize;
    let pubs = m.publics();
    let (tag_col, mds_col, out_col) = (
        pubs[PUB_INIT_TAG].table(n),
        pubs[PUB_MDS].table(n),
        pubs[PUB_OUT].table(n),
    );
    let mut w2 = Trace::new(W2, rows);
    let mut sum = Fp3::ZERO;
    let mut fps = vec![Fp3::ZERO; rows * SLOTS];
    let mut mult = vec![Fp3::ZERO; rows * SLOTS];
    for r in 0..rows {
        let l: Vec<Fp3> = w1.row(r).iter().map(|&x| Fp3::from_base(x)).collect();
        let md = modes(&l, tag_col[r], mds_col[r], out_col[r]);
        for s in 0..SLOTS {
            fps[r * SLOTS + s] = alpha - fingerprint(&l, md.tag[s], s, beta);
            mult[r * SLOTS + s] = md.read[s] - md.write[s] * l[slot(s, M)];
        }
    }
    let invs = batch_inverse(&fps);
    for r in 0..rows {
        let row = w2.row_mut(r);
        let mut delta = Fp3::ZERO;
        for s in 0..SLOTS {
            let h = invs[r * SLOTS + s];
            row[H0 + 3 * s..H0 + 3 * s + 3].copy_from_slice(&split(h));
            delta += mult[r * SLOTS + s] * h;
        }
        row[SUM..SUM + 3].copy_from_slice(&split(sum));
        sum += delta;
    }
    debug_assert_eq!(sum, Fp3::ZERO, "logUp sum must close");
    w2
}

/// Montgomery's batch inversion (all inputs nonzero with overwhelming
/// probability over α).
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
