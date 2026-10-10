//! The memory argument (phase 2): every slot's fingerprint has a committed
//! inverse `h_s = 1/(α − enc_s)`, and the cyclic running sum
//! `S' = S + Σ_s (read_s − write_s·M_s)·h_s` closes at zero — the logUp
//! identity `Σ_reads 1/(α − e) = Σ_writes M/(α − e)`: every read tuple
//! equals a written one (`specs/machine.md` § memory).

use nebu::{Fp3, Goldilocks};

use super::air::{Out, PUB_FIRST_ROW, PUB_INIT_TAG, PUB_MDS, PUB_OUT};
use super::layout::*;
use super::slots::{fingerprint, modes};
use crate::air::Vals;

/// `c0 + T·c1 + T²·c2` for the Fp3 basis element `T`.
pub(crate) fn ext(c: &[Fp3]) -> Fp3 {
    let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
    c[0] + t * c[1] + t * t * c[2]
}

pub(crate) fn constrain(v: &Vals<'_>, ch: &[Fp3], out: &mut Out<'_>) {
    let (alpha, beta) = (ch[0], ch[1]);
    let l = &v.local[..W1];
    let h2 = &v.local[W1..];
    let n2 = &v.next[W1..];
    let p = v.publics;
    let md = modes(l, p[PUB_INIT_TAG], p[PUB_MDS], p[PUB_OUT]);
    let mut delta = Fp3::ZERO;
    for s in 0..SLOTS {
        let h = ext(&h2[H0 + 3 * s..H0 + 3 * s + 3]);
        let enc = fingerprint(l, md.tag[s], s, beta);
        out.push(h * (alpha - enc) - Fp3::ONE);
        delta += (md.read[s] - md.write[s] * l[slot(s, M)]) * h;
    }
    let sum = ext(&h2[SUM..SUM + 3]);
    let next = ext(&n2[SUM..SUM + 3]);
    out.push(next - sum - delta);
    // the cyclic transition alone forces Σ delta = 0; the pin fixes where
    // the running sum starts so honest traces are canonical
    out.push(p[PUB_FIRST_ROW] * sum);
}
