//! Parameters of a recursion profile instance: the WHIR parameters of
//! every committed word, the step size, the accumulation configuration
//! derived from them, and the shapes they fix.

use lens::WhirParams;

use super::circuit::layout as cl;
use super::relation::{self, G_POINT, SEEDS};
use super::state::{Dims, ZeroWord};
use super::word::Digest;
use crate::accumulate::{self, AccConfig};
use crate::machine::air::{Constants, Machine};
use crate::machine::layout::{W1, W2};

/// Input words of an accumulation step: the accumulator and words a, b, c.
pub const INPUTS: usize = 4;
/// Segment-index bits in the nox public claim.
pub const STEP_BITS: usize = 32;
/// Column-index variables of the nox public claim (31 columns → 32).
pub const PN_COLS: usize = 5;
/// Variables of a word's column index (64 columns).
pub const CBITS: usize = 6;
/// Circuit columns in the boundary row.
pub const BV: usize = cl::V1 + cl::V2;

#[derive(Clone, Debug, PartialEq)]
pub struct Params {
    pub whir: WhirParams,
    /// `log2` of a step's rows.
    pub n: usize,
    /// `ℓ = n + 6`.
    pub vars: usize,
    pub cfg: AccConfig,
    /// OOD samples binding each fresh word.
    pub fresh: usize,
    pub dims: Dims,
    pub base: usize,
    pub g_deg: usize,
    pub pn_deg: usize,
    pub pv_deg: usize,
    pub zero_root: Digest,
    /// The circuit row carrying the step's public input.
    pub out_row: usize,
}

impl Params {
    /// Derive everything but `out_row` (set from the circuit layout).
    pub fn new(whir: &WhirParams, n: usize) -> Result<Self, String> {
        let vars = n + CBITS;
        crate::execution::succinct::admit::<lens::Whir>(whir, vars)?;
        let fresh = accumulate::fresh_ood(whir, vars)?;
        let probe = AccConfig::derive(whir, vars, INPUTS, 3 * (fresh + 2))?;
        let claims = probe.acc_claims() + 3 * (fresh + 2);
        let cfg = AccConfig::derive(whir, vars, INPUTS, claims)?;
        let constants = Constants { fml0: 0, obj0: 0, p: 0, output: [nebu::Goldilocks::ZERO; 4], cycles: 0 };
        let machine = Machine::new(constants, &[], 1 << n, 0, 1 << n);
        let rel = relation::Relation::new(machine, [nebu::Fp3::ZERO; 2]);
        let dims = Dims {
            boundary: W1 + W2,
            vars,
            ood: cfg.ood,
            spot: cfg.queries,
            g: G_POINT,
            pn: n + STEP_BITS + PN_COLS,
            pv: n + cl::pre::LOG,
        };
        let zero = ZeroWord::new(&cfg.layout);
        Ok(Self {
            whir: *whir,
            n,
            vars,
            cfg,
            fresh,
            dims,
            base: rel.base,
            g_deg: rel.g_degree(),
            pn_deg: dims.pn,
            pv_deg: dims.pv,
            zero_root: zero.root,
            out_row: 0,
        })
    }

    /// The zerocheck's round degree (`D + 1`).
    pub fn zc_deg(&self) -> usize {
        9
    }
    pub fn seeds(&self) -> usize {
        SEEDS
    }
}
