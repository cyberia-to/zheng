//! Uniform AIRs: one fixed set of row constraints over a trace of `N = 2^n`
//! rows, with next-row references (cyclic), public columns the verifier
//! evaluates itself, and an optional second phase of columns committed
//! after verifier challenges (lookup arguments).
//!
//! The verifier's work is independent of the program: it evaluates the
//! row constraints once at a random point (`O(constraints)`), the public
//! columns (`O(public data · log N)`), the successor polynomial
//! (`O(log N)`) and runs `O(log N)` sumcheck rounds. Nothing of size `N` —
//! no matrix — is touched; this replaces the unstructured Spartan matrix
//! evaluation of the per-program relation.
//!
//! Protocol (`specs/machine.md` § proving):
//! 1. commit `W1` (column-major, padded to `2^c` columns, so a table index
//!    is `col·N + row`); draw the AIR's challenges;
//! 2. commit `W2` (same padding);
//! 3. zerocheck `Σ_x eq(τ,x)·Σ_k μ^k C_k(W(x), W(x+1), P(x)) = 0`;
//!    the prover sends every column at `ρ` and at `ρ`'s successor;
//! 4. `γ1, γ2, β, ζ`; one product sumcheck reduces
//!    `Σ_y (eq(ρ,y) + β·nxt(ρ,y))·(W̃1(y,γ1) + ζ·W̃2(y,γ2))` to a point
//!    `ρ'`; the prover sends `W̃1(ρ',γ1)`, `W̃2(ρ',γ2)`.
//!
//! The output is two evaluation claims on the committed words — instances
//! for [`crate::accumulate`] (or a direct decider).

mod prove;
pub mod public;
mod shift;
mod zerocheck;

#[cfg(test)]
mod tests;

pub use prove::{AirProof, prove, verify};
pub use public::Public;

use nebu::{Fp3, Goldilocks};

/// Dimensions of an AIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// Phase-1 columns.
    pub w1: usize,
    /// Phase-2 columns (committed after the challenges).
    pub w2: usize,
    /// Fp3 challenges drawn between the phases.
    pub challenges: usize,
    pub constraints: usize,
    /// Largest total degree of a constraint in the column values.
    pub degree: usize,
}

impl Shape {
    /// Columns of each committed word after padding (a power of two).
    pub fn padded_width(&self) -> usize {
        self.w1.max(self.w2).max(1).next_power_of_two()
    }
}

/// Column values at one row (or one point): `local = W1 ‖ W2`.
pub struct Vals<'a> {
    pub local: &'a [Fp3],
    pub next: &'a [Fp3],
    pub publics: &'a [Fp3],
}

/// A uniform AIR.
pub trait Air: Sync {
    fn shape(&self) -> Shape;
    /// The public columns (their order is the order in `Vals::publics`).
    fn publics(&self) -> &[Public];
    /// Constraint values; all must vanish on every row of a valid trace.
    fn eval(&self, v: &Vals<'_>, challenges: &[Fp3], out: &mut [Fp3]);
}

/// A row-major trace of base-field cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    pub width: usize,
    pub cells: Vec<Goldilocks>,
}

impl Trace {
    pub fn new(width: usize, rows: usize) -> Self {
        Self {
            width,
            cells: vec![Goldilocks::ZERO; width * rows],
        }
    }
    pub fn rows(&self) -> usize {
        self.cells.len() / self.width.max(1)
    }
    pub fn row(&self, r: usize) -> &[Goldilocks] {
        &self.cells[r * self.width..(r + 1) * self.width]
    }
    pub fn row_mut(&mut self, r: usize) -> &mut [Goldilocks] {
        &mut self.cells[r * self.width..(r + 1) * self.width]
    }
    /// Column-major table over `2^n × padded` (index `col·N + row`).
    pub(crate) fn column_major(&self, padded: usize) -> Vec<Goldilocks> {
        let rows = self.rows();
        let mut out = vec![Goldilocks::ZERO; rows * padded];
        for r in 0..rows {
            for (c, &v) in self.row(r).iter().enumerate() {
                out[c * rows + r] = v;
            }
        }
        out
    }
}

/// Check every constraint on every row of a full trace (`W1 ‖ W2`) — a
/// debugging aid and the definition the protocol enforces.
pub fn first_violation<A: Air>(
    air: &A,
    w1: &Trace,
    w2: &Trace,
    challenges: &[Fp3],
) -> Option<(usize, usize)> {
    let rows = w1.rows();
    let n = rows.trailing_zeros() as usize;
    let pubs: Vec<Vec<Fp3>> = air.publics().iter().map(|p| p.table(n)).collect();
    let k = air.shape().constraints;
    let local_of = |r: usize| -> Vec<Fp3> {
        w1.row(r)
            .iter()
            .chain(w2.row(r))
            .map(|&x| Fp3::from_base(x))
            .collect()
    };
    let mut out = vec![Fp3::ZERO; k];
    for r in 0..rows {
        let local = local_of(r);
        let next = local_of((r + 1) % rows);
        let publics: Vec<Fp3> = pubs.iter().map(|p| p[r]).collect();
        for o in out.iter_mut() {
            *o = Fp3::ZERO;
        }
        air.eval(
            &Vals {
                local: &local,
                next: &next,
                publics: &publics,
            },
            challenges,
            &mut out,
        );
        if let Some(c) = out.iter().position(|&x| x != Fp3::ZERO) {
            return Some((r, c));
        }
    }
    None
}
