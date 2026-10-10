//! Verifying keys: the part of a [`WrapKey`] its verifier reads, as
//! canonical bytes, so a verifier loads a key instead of deriving the
//! whole chain of levels (minutes). The opening's configuration is
//! re-derived from the parameters; the circuit's preprocessed columns
//! (the prover's) are not carried, so a loaded key verifies and does not
//! prove.
//!
//! ```text
//! "ZWVK0001" · params · the IVC's parameters · fresh · out_row ·
//! constraints · pn · rows · census · key_ext · key root? · next columns ·
//! sparse key columns · wiring? · the constraint graph
//! ```
//!
//! A loaded key is as trustworthy as its bytes: pin them by
//! [`WrapKey::vk_digest`] (hemera over the bytes), or derive the key.

use lens::PcsError;
use lens::rspcs::wire::{Reader, Writer};
use lens::WhirParams;
use lens::rspcs::whir::Decoding;

use super::{Coef, Mode, Wiring, WrapKey, WrapParams};
use crate::air::num::{Graph, Node, Sym};
use crate::recursion::circuit::trace::Pre;
use crate::recursion::wire::{digest, read_digest};

type R<T> = Result<T, PcsError>;

const MAGIC: &[u8; 8] = b"ZWVK0001";

fn whir_params(w: &mut Writer, p: &WhirParams) {
    w.u8(p.log_inv_rate);
    w.u8(p.folding_factor);
    w.u16(p.security_target);
    w.u8(p.pow_bits);
    w.u8(match p.decoding {
        Decoding::Unique => 0,
        Decoding::Johnson => 1,
    });
    w.u8(p.max_final_vars);
}

fn read_whir_params(r: &mut Reader<'_>) -> R<WhirParams> {
    let log_inv_rate = r.u8()?;
    let folding_factor = r.u8()?;
    let security_target = r.u16()?;
    let pow_bits = r.u8()?;
    let decoding = match r.u8()? {
        0 => Decoding::Unique,
        1 => Decoding::Johnson,
        _ => return Err(PcsError::Malformed),
    };
    let max_final_vars = r.u8()?;
    Ok(WhirParams { log_inv_rate, folding_factor, security_target, pow_bits, decoding, max_final_vars })
}

fn coef(w: &mut Writer, c: Coef) {
    match c {
        Coef::One => w.u8(0),
        Coef::T => w.u8(1),
        Coef::T2 => w.u8(2),
        Coef::Other(x) => {
            w.u8(3);
            w.ext(x);
        }
    }
}

fn read_coef(r: &mut Reader<'_>) -> R<Coef> {
    Ok(match r.u8()? {
        0 => Coef::One,
        1 => Coef::T,
        2 => Coef::T2,
        3 => Coef::Other(r.ext()?),
        _ => return Err(PcsError::Malformed),
    })
}

fn sym(w: &mut Writer, s: Sym) {
    match s {
        Sym::C(c) => {
            w.u8(0);
            w.ext(c);
        }
        Sym::N(i) => {
            w.u8(1);
            w.u32(i as usize);
        }
    }
}

fn read_sym(r: &mut Reader<'_>, below: usize) -> R<Sym> {
    Ok(match r.u8()? {
        0 => Sym::C(r.ext()?),
        1 => {
            let i = r.u32()?;
            // a node reads only earlier nodes
            if i >= below {
                return Err(PcsError::Malformed);
            }
            Sym::N(i as u32)
        }
        _ => return Err(PcsError::Malformed),
    })
}

fn cells(w: &mut Writer, v: &[(u32, u32, Coef)]) {
    w.u32(v.len());
    for &(i, x, c) in v {
        w.u32(i as usize);
        w.u32(x as usize);
        coef(w, c);
    }
}

fn read_cell_list(r: &mut Reader<'_>) -> R<Vec<(u32, u32, Coef)>> {
    let n = r.count(9)?;
    (0..n).map(|_| Ok((r.u32()? as u32, r.u32()? as u32, read_coef(r)?))).collect()
}

fn u32s(w: &mut Writer, v: &[u32]) {
    w.u32(v.len());
    for &x in v {
        w.u32(x as usize);
    }
}

fn read_u32s(r: &mut Reader<'_>) -> R<Vec<u32>> {
    let n = r.count(4)?;
    (0..n).map(|_| Ok(r.u32()? as u32)).collect()
}

impl WrapKey {
    /// The verifying key's canonical bytes (module docs).
    pub fn vk_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        for &b in MAGIC {
            w.u8(b);
        }
        whir_params(&mut w, &self.params.whir);
        w.u32(self.params.n);
        w.u8(match self.params.mode {
            Mode::Inner => 0,
            Mode::Final => 1,
        });
        whir_params(&mut w, &self.ivc.0);
        w.u32(self.ivc.1);
        for v in [self.fresh, self.out_row, self.constraints, self.pn, self.rows, self.census[0], self.census[1], self.census[2]] {
            w.u32(v);
        }
        w.u8(self.key_ext as u8);
        match &self.key_root {
            None => w.u8(0),
            Some(d) => {
                w.u8(1);
                digest(&mut w, d);
            }
        }
        u32s(&mut w, &self.next_cols.iter().map(|&c| c as u32).collect::<Vec<_>>());
        w.u32(self.sparse.len());
        for col in &self.sparse {
            w.u32(col.len());
            for &(x, v) in col {
                w.u32(x as usize);
                w.ext(v);
            }
        }
        match &self.wiring {
            None => w.u8(0),
            Some(wi) => {
                w.u8(1);
                w.u32(wi.reads);
                cells(&mut w, &wi.read_cells);
                u32s(&mut w, &wi.write_reads);
                u32s(&mut w, &wi.write_at);
                cells(&mut w, &wi.write_cells);
            }
        }
        w.u32(self.g.inputs);
        w.u32(self.g.nodes.len());
        for n in &self.g.nodes {
            match *n {
                Node::Input(i) => {
                    w.u8(0);
                    w.u32(i as usize);
                }
                Node::Add(a, b) | Node::Sub(a, b) | Node::Mul(a, b) => {
                    w.u8(match n {
                        Node::Add(..) => 1,
                        Node::Sub(..) => 2,
                        _ => 3,
                    });
                    sym(&mut w, a);
                    sym(&mut w, b);
                }
                Node::Neg(a) => {
                    w.u8(4);
                    sym(&mut w, a);
                }
            }
        }
        w.u32(self.g.outputs.len());
        for &s in &self.g.outputs {
            sym(&mut w, s);
        }
        w.buf
    }

    /// hemera over [`Self::vk_bytes`] (a key's pin).
    pub fn vk_digest(&self) -> [u8; 32] {
        *hemera::hash(&self.vk_bytes()).as_bytes()
    }

    /// A verifying key from its bytes (module docs): it verifies, it does
    /// not prove.
    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, String> {
        Self::read_vk(bytes).map_err(|e| format!("wrap verifying key: {e}"))
    }

    fn read_vk(bytes: &[u8]) -> R<Self> {
        let mut r = Reader::new(bytes);
        for &b in MAGIC {
            if r.u8()? != b {
                return Err(PcsError::Malformed);
            }
        }
        let whir = read_whir_params(&mut r)?;
        let n = r.u32()?;
        let mode = match r.u8()? {
            0 => Mode::Inner,
            1 => Mode::Final,
            _ => return Err(PcsError::Malformed),
        };
        let params = WrapParams { whir, n, mode };
        let ivc = (read_whir_params(&mut r)?, r.u32()?);
        let mut v = [0usize; 8];
        for x in &mut v {
            *x = r.u32()?;
        }
        let [fresh, out_row, constraints, pn, rows, c0, c1, c2] = v;
        let key_ext = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(PcsError::Malformed),
        };
        let key_root = match r.u8()? {
            0 => None,
            1 => Some(read_digest(&mut r)?),
            _ => return Err(PcsError::Malformed),
        };
        let next_cols: Vec<usize> = read_u32s(&mut r)?.into_iter().map(|c| c as usize).collect();
        let ncols = r.count(4)?;
        let mut sparse = Vec::with_capacity(ncols);
        for _ in 0..ncols {
            let m = r.count(28)?;
            sparse.push((0..m).map(|_| Ok((r.u32()? as u32, r.ext()?))).collect::<R<Vec<_>>>()?);
        }
        let wiring = match r.u8()? {
            0 => None,
            1 => {
                let reads = r.u32()?;
                let read_cells = read_cell_list(&mut r)?;
                let write_reads = read_u32s(&mut r)?;
                let write_at = read_u32s(&mut r)?;
                let write_cells = read_cell_list(&mut r)?;
                Some(Wiring { reads, read_cells, write_reads, write_at, write_cells })
            }
            _ => return Err(PcsError::Malformed),
        };
        let inputs = r.u32()?;
        let nn = r.count(2)?;
        let mut nodes = Vec::with_capacity(nn);
        for i in 0..nn {
            nodes.push(match r.u8()? {
                0 => Node::Input(r.u32()? as u32),
                t @ 1..=3 => {
                    let (a, b) = (read_sym(&mut r, i)?, read_sym(&mut r, i)?);
                    match t {
                        1 => Node::Add(a, b),
                        2 => Node::Sub(a, b),
                        _ => Node::Mul(a, b),
                    }
                }
                4 => Node::Neg(read_sym(&mut r, i)?),
                _ => return Err(PcsError::Malformed),
            });
        }
        let no = r.count(2)?;
        let outputs = (0..no).map(|_| read_sym(&mut r, nn)).collect::<R<Vec<_>>>()?;
        r.finish()?;
        let cfg = super::program::level_config(&params, n + super::CBITS, fresh).map_err(|_| PcsError::Malformed)?;
        let key = WrapKey {
            params,
            pre: Pre { cols: Vec::new() },
            sparse,
            key_root,
            wiring,
            key_ext,
            cfg,
            fresh,
            out_row,
            g: Graph { nodes, inputs, outputs },
            constraints,
            next_cols,
            pn,
            ivc,
            rows,
            census: [c0, c1, c2],
        };
        key.check_vk().then_some(key).ok_or(PcsError::Malformed)
    }

    /// Indices in range (a loaded key never panics its verifier).
    fn check_vk(&self) -> bool {
        let n = self.params.n;
        let rows = 1usize << n;
        let cells = super::WORD << n;
        let w = self.cols();
        let ok_graph = self.g.inputs == super::g_inputs(w)
            && self.g.nodes.iter().all(|x| !matches!(x, Node::Input(i) if *i as usize >= self.g.inputs))
            && self.g.outputs.len() == 1;
        let ok_sparse = self.sparse.len() == crate::recursion::circuit::layout::pre::COUNT
            && self.sparse.iter().all(|c| c.iter().all(|&(x, _)| (x as usize) < rows));
        let ok_wiring = match &self.wiring {
            None => self.params.mode == Mode::Inner,
            Some(wi) => {
                let writes = wi.write_at.len().saturating_sub(1);
                !wi.write_at.is_empty()
                    && wi.write_at.windows(2).all(|p| p[0] <= p[1])
                    && *wi.write_at.last().unwrap_or(&0) as usize == wi.write_reads.len()
                    && wi.write_reads.iter().all(|&i| (i as usize) < wi.reads)
                    && wi.read_cells.iter().all(|&(i, x, _)| (i as usize) < wi.reads && (x as usize) < cells)
                    && wi.write_cells.iter().all(|&(j, x, _)| (j as usize) < writes && (x as usize) < cells)
            }
        };
        let ok_mode = (self.params.mode == Mode::Inner) == self.key_root.is_some();
        ok_graph
            && ok_sparse
            && ok_wiring
            && ok_mode
            && self.out_row < rows
            && self.next_cols.iter().all(|&c| c < w)
            && (4..=24).contains(&n)
    }
}
