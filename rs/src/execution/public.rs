//! Canonical full-table opening shape for public execution proofs.
use lens::Opening;
/// Reject noncanonical byte encodings before Lens' permissive field decoder.
pub(super) fn canonical(opening: &Opening, variables: usize) -> bool {
    let Opening::TensorMerkle {
        row_combination,
        columns,
    } = opening
    else {
        return false;
    };
    let rows = 1usize << variables.div_ceil(2);
    let cols = 1usize << (variables / 2);
    fn fields(bytes: &[u8], count: usize) -> bool {
        bytes.len() == count * 8
            && bytes.chunks_exact(8).all(|chunk| {
                let mut array = [0u8; 8];
                array.copy_from_slice(chunk);
                u64::from_le_bytes(array) < nebu::field::P
            })
    }
    fields(row_combination, cols)
        && columns.len() == cols
        && columns.iter().enumerate().all(|(index, query)| {
            fields(&query.column, rows)
                && query.index == index
                && query.path.len() == cols.trailing_zeros() as usize
        })
}
