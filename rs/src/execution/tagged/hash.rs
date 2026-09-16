//! Native Hemera identity, fully constrained, including optional noun topology.
//! Keep framing aligned with nox/rs/data/hash.rs and execution/hash.rs.
use super::{build::Builder, *};
use hemera::field::Goldilocks as H;
use std::sync::OnceLock;
type State = [Wire; 16];
fn external_matrix() -> &'static [[F; 16]; 16] {
    static MATRIX: OnceLock<[[F; 16]; 16]> = OnceLock::new();
    MATRIX.get_or_init(|| {
        let mut matrix = [[F::ZERO; 16]; 16];
        for col in 0..16 {
            let mut basis = [H::ZERO; 16];
            basis[col] = H::new(1);
            hemera::field::mds_light_permutation(&mut basis);
            for row in 0..16 {
                matrix[row][col] = F::new(basis[row].as_canonical_u64());
            }
        }
        matrix
    })
}
impl Builder {
    /// Complete inverse-or-zero gadget. Its selector is one exactly when x != 0.
    pub fn inverse_or_zero(&mut self, x: Wire) -> Result<(Wire, Wire), Error> {
        let inv = self.inv(x)?;
        let nonzero = self.mul(x, inv)?;
        let zero = self.lin(vec![(ONE, F::ONE), (nonzero, -F::ONE)])?;
        self.zero_product(nonzero, vec![(zero, F::ONE)])?;
        self.zero_product(x, vec![(zero, F::ONE)])?;
        self.zero_product(inv, vec![(zero, F::ONE)])?;
        Ok((inv, nonzero))
    }
    fn linear_layer(&mut self, state: State, internal: bool) -> Result<State, Error> {
        let mut out = [ZERO; 16];
        for row in 0..16 {
            let mut terms = Vec::with_capacity(16);
            for col in 0..16 {
                let coefficient = if internal {
                    F::ONE
                        + if row == col {
                            F::new(hemera::field::MATRIX_DIAG_16[row].as_canonical_u64())
                        } else {
                            F::ZERO
                        }
                } else {
                    external_matrix()[row][col]
                };
                terms.push((state[col], coefficient));
            }
            out[row] = self.lin(terms)?;
        }
        Ok(out)
    }
    pub fn permute(&mut self, input: State) -> Result<State, Error> {
        let mut state = self.linear_layer(input, false)?;
        for round in 0..24 {
            let partial = (4..20).contains(&round);
            if partial {
                let rc = hemera::constants::ROUND_CONSTANTS_U64[128 + round - 4];
                let x = self.lin(vec![(state[0], F::ONE), (ONE, F::new(rc))])?;
                state[0] = self.inverse_or_zero(x)?.0;
            } else {
                let offset = if round < 4 {
                    round * 16
                } else {
                    (round - 16) * 16
                };
                for (lane, value) in state.iter_mut().enumerate() {
                    let rc = hemera::constants::ROUND_CONSTANTS_U64[offset + lane];
                    let x = self.lin(vec![(*value, F::ONE), (ONE, F::new(rc))])?;
                    let square = self.mul(x, x)?;
                    let cube = self.mul(square, x)?;
                    let fourth = self.mul(square, square)?;
                    *value = self.mul(cube, fourth)?;
                }
            }
            state = self.linear_layer(state, partial)?;
        }
        Ok(state)
    }
    pub fn canonical_bits(&mut self, value: Wire) -> Result<[Wire; 64], Error> {
        let mut bits = [ZERO; 64];
        let mut sum = vec![];
        for (k, b) in bits.iter_mut().enumerate() {
            *b = self.alloc(Op::Bit(value, k))?;
            self.zero_product(*b, vec![(ONE, F::ONE), (*b, -F::ONE)])?;
            sum.push((*b, F::new(1u64 << k)));
        }
        sum.push((value, -F::ONE));
        self.zero_product(ONE, sum)?;
        // p=0xffffffff00000001. A u64 below p either has high32<MAX,
        // or high32=MAX with low32=0. This excludes aliases x+p.
        let mut all_high = ONE;
        for bit in &bits[32..] {
            all_high = self.mul(all_high, *bit)?;
        }
        let low = self.pack_bits(&bits[..32])?;
        self.zero_product(all_high, vec![(low, F::ONE)])?;
        Ok(bits)
    }
    fn pack_bits(&mut self, bits: &[Wire]) -> Result<Wire, Error> {
        self.lin(
            bits.iter()
                .enumerate()
                .map(|(k, &b)| (b, F::new(1u64 << k)))
                .collect(),
        )
    }
    fn atom_digest(&mut self, value: Wire) -> Result<[Wire; 4], Error> {
        if let Some(d) = self.atom_digests.get(&value) {
            return Ok(*d);
        }
        let bits = self.canonical_bits(value)?;
        let mut state = [ZERO; 16];
        state[0] = self.pack_bits(&bits[..56])?;
        let high = self.pack_bits(&bits[56..])?;
        state[1] = self.lin(vec![(high, F::ONE), (ONE, F::new(256))])?;
        state[10] = self.constant(8)?; // byte length8, DOMAIN_HASH0
        let base = self.permute(state)?;
        state = [ZERO; 16];
        state[..4].copy_from_slice(&base[..4]);
        state[9] = self.constant(4)?; // FLAG_CHUNK, counter0, is_root=false
        let out = self.permute(state)?;
        let digest = std::array::from_fn(|i| out[i]);
        self.atom_digests.insert(value, digest);
        Ok(digest)
    }
    fn pair_digest(&mut self, left: [Wire; 4], right: [Wire; 4]) -> Result<[Wire; 4], Error> {
        if let Some(d) = self.pair_digests.get(&(left, right)) {
            return Ok(*d);
        }
        let mut state = [ZERO; 16];
        state[..4].copy_from_slice(&left);
        state[4..8].copy_from_slice(&right);
        state[9] = self.constant(2)?; // FLAG_PARENT, is_root=false
        let out = self.permute(state)?;
        let digest = std::array::from_fn(|i| out[i]);
        self.pair_digests.insert((left, right), digest);
        Ok(digest)
    }
    pub fn structural_digest(&mut self, node: &Rc<Node>) -> Result<[Wire; 4], Error> {
        if let Some(d) = self.digests.get(&node.id) {
            return Ok(*d);
        }
        // These are verifier-known constant wire identities, never witness tags.
        let digest = if node.tag == ZERO {
            self.atom_digest(node.value)?
        } else if let Some((a, b)) = &node.children {
            let a = self.structural_digest(a)?;
            let b = self.structural_digest(b)?;
            let pair = self.pair_digest(a, b)?;
            if node.tag == ONE {
                pair
            } else {
                let atom = self.atom_digest(node.value)?;
                let mut out = [ZERO; 4];
                for i in 0..4 {
                    out[i] = self.select(node.tag, atom[i], pair[i])?;
                }
                out
            }
        } else {
            // node() already constrains a leaf-schema tag to zero.
            self.atom_digest(node.value)?
        };
        self.digests.insert(node.id, digest);
        Ok(digest)
    }
    pub fn digest_noun(&mut self, digest: [Wire; 4], active: Wire) -> Result<Rc<Node>, Error> {
        let mut leaves = Vec::with_capacity(4);
        for v in digest {
            let v = self.mul(active, v)?;
            leaves.push(self.node(ZERO, v, None)?);
        }
        let left = self.node(active, ZERO, Some((leaves[0].clone(), leaves[1].clone())))?;
        let right = self.node(active, ZERO, Some((leaves[2].clone(), leaves[3].clone())))?;
        self.node(active, ZERO, Some((left, right)))
    }
    pub fn digest_unequal(&mut self, a: [Wire; 4], b: [Wire; 4]) -> Result<Wire, Error> {
        let mut unequal = ZERO;
        for i in 0..4 {
            let delta = self.lin(vec![(a[i], F::ONE), (b[i], -F::ONE)])?;
            let bit = self.inverse_or_zero(delta)?.1;
            let both = self.mul(unequal, bit)?;
            unequal = self.lin(vec![(unequal, F::ONE), (bit, F::ONE), (both, -F::ONE)])?;
        }
        Ok(unequal)
    }
}
