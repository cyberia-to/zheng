// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Trace bindings for pattern-15 hash blocks.
//!
//! Pattern 15 carries NO polynomial opening — the trace registers hold
//! Poseidon2 sponge state, round index and digest (nox specs/trace.md), and
//! the sponge is verified in-circuit via `particle::partial_round_ccs`. What
//! the circuit alone does not pin is the correspondence between the
//! prover-supplied [`HashAux`] rate and the recorded trace rows: full-round
//! transitions use `trivial_hash_ccs` (no constraints) and the capacity/y
//! witness columns are injected from a replay of the claimed rate.
//!
//! These eq steps (VZ_LEN=3, degree 1) bind every row of a hash block to
//! the unique Poseidon2 state sequence generated from that rate:
//!
//! - round row k (0..23): r4-r7 = state_k[0..4], r10-r13 = state_k[4..8],
//!   r14 = k
//! - squeeze row: r4-r7 = output digest (final state[0..4]),
//!   r10-r13 = final state[4..8], r14 = 24
//!
//! They fold into the shared linear eq-step accumulator group, inheriting
//! the option-A linkage digest and the degree-1 zero-error rule from
//! `verify()`. A strictness gate rejects at commit time.
//!
//! Open on the input side: the link between the rate and the structural
//! digest of the hashed particle (r15 holds the particle id, the digest
//! itself is not in the trace) — same class of residual as the axis
//! commitment registers, closed only by recursion or a nox trace change.

use nebu::Goldilocks;
use nox::TraceRow;

use hemera::field::Goldilocks as HGold;

use super::particle::HashAux;
use super::selector;
use super::verifier_steps::eq_step;
use crate::types::{CCSInstance, CCSWitness, CommitError};

/// Rows per hash block: 24 round rows + 1 squeeze row.
const BLOCK_ROWS: usize = 25;

fn reg(row: &TraceRow, i: usize) -> Goldilocks {
    Goldilocks::new(row.r()[i]).canonicalize()
}

/// Build eq binding steps for every hash block in the trace.
///
/// Block detection and `aux` pairing mirror
/// [`particle::build_hash_steps_from_trace`] exactly: consecutive tag=15
/// runs of at least 2 rows consume one [`HashAux`] each, in trace order.
///
/// Returns `Err(CommitError::TraceOverflow)` if `aux` has fewer entries than
/// hash blocks, `Err(CommitError::HashBinding)` if a block is not 25 rows or
/// any binding is unsatisfied — commit refuses to emit a proof whose hash
/// rows diverge from the replay of the claimed rate.
pub fn build_hash_binding_steps_from_trace(
    trace: &[TraceRow],
    aux: &[HashAux],
) -> Result<Vec<(CCSInstance, CCSWitness)>, CommitError> {
    let mut steps = Vec::new();
    let mut aux_idx = 0;
    let mut i = 0;

    while i < trace.len() {
        if trace[i].r()[0] != 15 {
            i += 1;
            continue;
        }
        let block_start = i;
        while i < trace.len() && trace[i].r()[0] == 15 {
            i += 1;
        }
        let block = &trace[block_start..i];
        if block.len() < 2 {
            continue;
        }

        let ha = aux.get(aux_idx).ok_or(CommitError::TraceOverflow)?;
        aux_idx += 1;

        if block.len() != BLOCK_ROWS {
            return Err(CommitError::HashBinding);
        }

        // Replay the permutation from the claimed rate — the same call
        // build_hash_steps_from_trace uses to recover capacity columns.
        let mut rate_h = [HGold::ZERO; 8];
        for (j, r) in ha.rate.iter().enumerate() {
            rate_h[j] = HGold::new(r.canonicalize().as_u64());
        }
        let states: Vec<[Goldilocks; 16]> = hemera::StepSponge::absorb(&rate_h)
            .map(|s| core::array::from_fn(|j| Goldilocks::new(s[j].as_canonical_u64())))
            .collect();

        let block_steps_start = steps.len();

        // Round rows: post-round state k lands in r4-r7 / r10-r13, r14 = k.
        for (k, row) in block[..BLOCK_ROWS - 1].iter().enumerate() {
            let st = &states[k];
            for j in 0..4 {
                steps.push(eq_step(st[j], reg(row, 4 + j)));
            }
            for j in 0..4 {
                steps.push(eq_step(st[4 + j], reg(row, 10 + j)));
            }
            steps.push(eq_step(Goldilocks::new(k as u64), reg(row, 14)));
        }

        // Squeeze row: output digest = final state[0..4], r14 = 24 sentinel,
        // budget decrement of the whole block.
        let sq = &block[BLOCK_ROWS - 1];
        let last = &states[BLOCK_ROWS - 2];
        for j in 0..4 {
            steps.push(eq_step(last[j], reg(sq, 4 + j)));
        }
        for j in 0..4 {
            steps.push(eq_step(last[4 + j], reg(sq, 10 + j)));
        }
        steps.push(eq_step(Goldilocks::new((BLOCK_ROWS - 1) as u64), reg(sq, 14)));
        // No budget binding: specs/trace.md claims r9 = r8 - 25 on the
        // squeeze row, but nox records r8 before evaluating the hash body
        // sub-formula, whose cost varies (observed r8=100, r9=74 for
        // [15 [1 s]] — 25 hash + 1 quote). Spec-code drift, tracked in the
        // plan; a binding here would reject every honest trace.

        // Strictness gate: every binding for this block must hold now.
        if steps[block_steps_start..]
            .iter()
            .any(|(inst, wit)| !selector::is_satisfied(inst, wit))
        {
            return Err(CommitError::HashBinding);
        }
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trace_yields_no_binding_steps() {
        let steps = build_hash_binding_steps_from_trace(&[], &[]).unwrap();
        assert!(steps.is_empty());
    }
}
