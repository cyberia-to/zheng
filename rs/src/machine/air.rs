//! The machine as a uniform AIR: one fixed row relation (the verifier key
//! is its constraint structure, identical for every program); a statement
//! enters only through public columns (the init entries, the first machine
//! row, the permutation region) and five constants (initial formula and
//! subject ids, expected output digest, cycles).

use nebu::{Fp3, Goldilocks};

use super::layout::*;
use crate::air::{Air, Public, Shape, Vals};

// public columns
pub const PUB_INIT_REG: usize = 0;
pub const PUB_INIT_TAG: usize = 1;
pub const PUB_INIT_KEY: usize = 2;
pub const PUB_INIT_P0: usize = 3;
pub const PUB_INIT_P1: usize = 4;
pub const PUB_FIRST_M: usize = 5;
pub const PUB_FIRST_ROW: usize = 6;
pub const PUB_REGION: usize = 7;
pub const PUB_BITS0: usize = 8;
pub const PUB_BITS1: usize = 9;
pub const PUB_MDS: usize = 10;
pub const PUB_FULL: usize = 11;
pub const PUB_PART: usize = 12;
pub const PUB_OUT: usize = 13;
pub const PUB_CONT: usize = 14;
pub const PUB_RC: usize = 15;
pub const PUBLICS: usize = PUB_RC + 16;

/// Statement constants the constraints read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constants {
    /// Ids of the program formula and of the subject in the init DAG.
    pub fml0: u64,
    pub obj0: u64,
    /// Number of init entries (`ALLOC` starts at `P + 1`).
    pub p: u64,
    /// Digest of the expected output noun.
    pub output: [Goldilocks; 4],
    pub cycles: u64,
}

/// The machine AIR for one statement and trace geometry.
pub struct Machine {
    pub constants: Constants,
    pub publics: Vec<Public>,
    pub(crate) tables: super::hemera::Tables,
    constraints: usize,
}

/// Collects constraint values in order.
pub(crate) struct Out<'a> {
    buf: &'a mut [Fp3],
    i: usize,
}

impl Out<'_> {
    pub fn push(&mut self, v: Fp3) {
        if let Some(b) = self.buf.get_mut(self.i) {
            *b = v;
        }
        self.i += 1;
    }
}

pub(crate) fn c(v: u64) -> Fp3 {
    Fp3::from_base(Goldilocks::new(v))
}

fn region(pattern: impl Fn(usize) -> Fp3, start: usize) -> Public {
    Public::Region {
        pattern: (0..BLOCK).map(pattern).collect(),
        start,
    }
}

impl Machine {
    /// The AIR of rows `[offset, offset + rows)` of a trace whose init
    /// entries are `init` (`(tag, p0, p1)`) and whose region starts at
    /// `start` (all global row indices).
    pub fn new(
        constants: Constants,
        init: &[(u64, u64, u64)],
        start: usize,
        offset: usize,
        rows: usize,
    ) -> Self {
        let tables = super::hemera::Tables::default();
        let p = init.len();
        let pre = |f: &dyn Fn(usize) -> u64| Public::Prefix((0..p).map(|i| c(f(i))).collect());
        let one = |cond: bool| if cond { Fp3::ONE } else { Fp3::ZERO };
        let round = |ph: usize| ph.checked_sub(PH_ROUND0).filter(|&k| k < 24);
        let mut publics = vec![
            pre(&|_| 1),
            pre(&|i| init[i].0),
            pre(&|i| i as u64 + 1),
            pre(&|i| init[i].1),
            pre(&|i| init[i].2),
            Public::Sparse(vec![(p, Fp3::ONE)]),
            Public::Sparse(vec![(0, Fp3::ONE)]),
            region(|_| Fp3::ONE, start),
            region(|ph| one(ph == PH_BITS0), start),
            region(|ph| one(ph == PH_BITS1), start),
            region(|ph| one(ph == PH_MDS), start),
            region(|ph| one(round(ph).is_some_and(super::hemera::is_full)), start),
            region(|ph| one(round(ph).is_some_and(|k| !super::hemera::is_full(k))), start),
            region(|ph| one(ph == PH_OUT), start),
            region(|ph| one(ph + 1 < BLOCK), start),
        ];
        for i in 0..16 {
            let rc = tables.rc;
            publics.push(region(
                |ph| round(ph).map_or(Fp3::ZERO, |k| Fp3::from_base(rc[k][i])),
                start,
            ));
        }
        let publics = publics.iter().map(|p| p.window(offset, rows)).collect();
        let mut m = Self {
            constants,
            publics,
            tables,
            constraints: 0,
        };
        m.constraints = m.count();
        m
    }

    fn count(&self) -> usize {
        let z = vec![Fp3::ZERO; W1 + W2];
        let p = vec![Fp3::ZERO; PUBLICS];
        let mut out = Out { buf: &mut [], i: 0 };
        self.constrain(
            &Vals {
                local: &z,
                next: &z,
                publics: &p,
            },
            &[Fp3::ZERO, Fp3::ZERO],
            &mut out,
        );
        out.i
    }

    fn constrain(&self, v: &Vals<'_>, ch: &[Fp3], out: &mut Out<'_>) {
        super::control::constrain(self, v, out);
        super::perm::constrain(self, v, out);
        super::memory::constrain(v, ch, out);
    }
}

impl Air for Machine {
    fn shape(&self) -> Shape {
        Shape {
            w1: W1,
            w2: W2,
            challenges: 2,
            constraints: self.constraints,
            degree: 8,
        }
    }
    fn publics(&self) -> &[Public] {
        &self.publics
    }
    fn eval(&self, v: &Vals<'_>, ch: &[Fp3], out: &mut [Fp3]) {
        let mut o = Out { buf: out, i: 0 };
        self.constrain(v, ch, &mut o);
        debug_assert_eq!(o.i, self.constraints);
    }
}
