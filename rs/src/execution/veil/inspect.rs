//! Public reading of a zk proof's revealed values, for downstream
//! zero-knowledge tests (zheng's own is `zk_tests`): parse a proof against
//! the shape the verifier derives and return every value it reveals, by
//! category — the matrix evaluations, the masked round polynomials, the
//! mask sums, the opening's two polynomials and the opened columns (data
//! rows, then masking rows). Nothing here is secret: it is what any
//! verifier reads. A test compares the distributions for two witnesses of
//! one statement (two positions of one P1 tree, `x` and `−x`).

use nebu::{Fp3, Goldilocks};

use super::protocol::Setup;
use super::wire::Parsed;
use super::{VeilProof, hiding, with_constant};
use crate::execution::private::PrivateStatement;
use crate::types::CCSInstance;

/// Revealed values by category, each value one canonical `u64` limb.
pub type Revealed = Vec<(&'static str, Vec<u64>)>;

/// The values `proof` reveals for `statement` (its relation derived from
/// the statement's program, as the verifier does).
pub fn revealed(statement: &PrivateStatement, proof: &VeilProof) -> Result<Revealed, String> {
    let prepared = statement.prepare()?;
    let public: Vec<(usize, Goldilocks)> = prepared
        .public_coordinates
        .iter()
        .map(|&(i, v)| (i, Goldilocks::new(v)))
        .collect();
    revealed_relation(&prepared.relation.instance, &public, proof)
}

/// [`revealed`] against a relation and public coordinates the caller
/// derived (`(0, 1)` is added).
pub fn revealed_relation(
    instance: &CCSInstance,
    public: &[(usize, Goldilocks)],
    proof: &VeilProof,
) -> Result<Revealed, String> {
    let setup = Setup::new(instance, &with_constant(public))?;
    Ok(categories(&Parsed::from_bytes(
        proof.as_bytes(),
        setup.shape(),
    )?))
}

fn limbs(xs: &[Fp3]) -> Vec<u64> {
    xs.iter()
        .flat_map(|x| [x.c0.as_u64(), x.c1.as_u64(), x.c2.as_u64()])
        .collect()
}

pub(crate) fn categories(p: &Parsed) -> Revealed {
    let o = &p.opening;
    let rows = o.columns.len() / (o.salts.len() / hiding::SALT).max(1);
    let data_rows = rows - hiding::MASK_ROWS;
    let data: Vec<u64> = o
        .columns
        .chunks_exact(rows)
        .flat_map(|c| c[..data_rows].iter().map(|v| v.as_u64()))
        .collect();
    let masks: Vec<u64> = o
        .columns
        .chunks_exact(rows)
        .flat_map(|c| c[data_rows..].iter().map(|v| v.as_u64()))
        .collect();
    vec![
        ("matrix evaluations", limbs(&p.evals)),
        ("outer rounds", limbs(&p.outer.rounds.concat())),
        ("inner rounds", limbs(&p.inner.rounds.concat())),
        ("mask sums", limbs(&[p.g1, p.g2])),
        ("proximity polynomial", limbs(&o.row_test)),
        ("linear polynomial", limbs(&o.linear)),
        ("opened data columns", data),
        ("opened masking columns", masks),
    ]
}

/// Seeded proving, for reproducible downstream zk tests only (feature
/// `test-hooks`): a fixed seed fixes every mask, so a proof made this way
/// hides nothing from whoever knows the seed. Never on a production path.
#[cfg(feature = "test-hooks")]
pub mod testing {
    use super::super::key::{ProvingKey, prove_keyed};
    use super::super::{VeilProof, coins::Coins};
    use crate::execution::ExecutionNoun;
    use crate::execution::private::PrivateStatement;

    /// `veil::prove_with_key` with the coins of `seed`.
    pub fn prove_with_key_seeded(
        key: &ProvingKey,
        program: &ExecutionNoun,
        input: &[u64],
        secret: &[u64],
        budget: u64,
        seed: [u8; 32],
    ) -> Result<(PrivateStatement, VeilProof), String> {
        prove_keyed(
            key,
            program,
            input,
            secret,
            budget,
            &PrivateStatement::transcript_bytes,
            &Coins::seeded(seed),
        )
    }
}
