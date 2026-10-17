---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: block aggregation spec, one proof per block, AGG
---
# aggregation

One proof per block (soft3 `proposals/privacy-frozen.md` §1.8, gate G2):
the block proof verifies every transaction's zero-knowledge proof inside
the recursion circuit, so a node verifies one constant-size proof per
block and transaction proofs travel only in the mempool.
`rs/src/execution/veil/rec/` (the transaction proof) and
`rs/src/recursion/agg/` (the block proof). Measured figures:
`audit/block-aggregate-2026-10.md`.

## the transaction proof: veil-r

veil's protocol (`zk-profile` in `soundness.md`: masked relation, Libra
masks on both sumchecks, one hiding Reed–Solomon tensor commitment with a
zero-knowledge linear test, coins from the counter-mode PRF) on the
recursion profile's hashing, so that the recursion circuit can run its
verifier:

- **transcript**: the duplex sponge of `recursion.md` (tag `VEIL` = 12),
  challenges as output limbs, indices as the low bits of a limb
  `v ≠ p − 1`, grinding as a nonce absorbed as one lane;
- **statement**: the verifying key's digest (32 bytes as four limbs, each
  8-byte word mod p), the hiding parameters, `ℓ`, the row count, the
  outer degree, the width `k`, then the pinned public values in
  coordinate order (the constant `(0, 1)` excluded) — all field elements;
- **commitment**: leaf `j` is the leaf sponge (tag `LEAF`) over column
  `j`'s `T` symbols then its four salt limbs; the tree is 4-ary
  (`word::Arity::Four`);
- **openings**: the `q` sampled indices are not deduplicated; each opens
  its column with its own path (a repeated index opens a column twice; at
  most `q ≤ k − 1` distinct columns are ever revealed — the zero-knowledge
  condition of `hiding`);
- **width**: `k` minimises the circuit cost of the opening,
  `q·(5k + 2T + 16·(⌈(T + 4)/9⌉ + ⌈log N/2⌉))` gates, under `k ≥ q + 1`
  (`hiding::Config::derive_rec`).

```text
transcript  tag VEIL: header, pins, root; τ (log m); Σg1, ρ1 (≠ 0);
            outer rounds (c0, c2..cd), r each; v_i (t); γ; Σg2, ρ2;
            inner rounds (c0, c2), r each; λ; μ; α, ρ_L; p_P (K), q (K+k−1);
            grinding; q indices
checks      as veil: g1(ρ_x) = (C1 − eq(τ, ρ_x)·G(v))/ρ1;
            inner from Σγ^i v_i − P + ρ2·Σg2, P the pinned half;
            q[k−1] = λ·g1(ρ_x) + C2 + ρ_L·μ; per query the leaf and path,
            p_P(ω^j) = Σ α^i col_i, q(ω^j) = Σ Λ'_i(ω^j)·col_i + ρ_L·(m_a + X^K m_b)
wire        "ZHVEILR1", root, g1, outer, v, g2, inner, μ, p_P, q, nonce,
            q × (T + 4 symbols, path) — every count fixed by the key
```

The verifier (`rec::verify::verify`) is written once over `Ops`: the
native interpreter is the transaction verifier, the circuit builder the
aggregation leaf. Its sparse sums — `P` and `A(0, r) = Σ γ^i M̃'_i(ρ_x, (0, r))`
— read the relation's matrices from the key: one gate per two entries,
one per row and matrix, the column `eq` table (`2^{ℓ+1}` gates) and the
row `eq` as two tensor halves.

## the block proof

A key set `AggKeys` for one relation (one verifying key per rule set) and
a depth `D` (blocks of `1..=2^D` transactions):

```text
level 0      leaf a transaction: X = H_TX(vk ‖ pins), veil-r verified
             in the circuit against those pins
level 1..D   node a pair: X = H_NODE(X_l ‖ X_r ‖ h), h a bit,
             (1 − h)·(X_r − X_l) = 0; both children verified under X_l, X_r
             (a lone child is verified twice, h = 0)
top          X = H_BLOCK(X_root ‖ N ‖ fields); the root verified
final        X = H_PASS(X_block); the top verified — the block proof
```

Tags `AGG_TX` 13, `AGG_NODE` 14, `AGG_BLOCK` 15, `AGG_PASS` 16; every
digest is four output limbs of its chain's last block, the public-input
row of the level's circuit. The tree is the canonical left-complete one:
level `j` node `i` has children `2i`, `2i + 1` of level `j − 1`, the
second absent when the level has an odd count. Levels 0..D are inner wrap
levels at rate 1/16 with 16 grinding bits, the top an inner level at
1/128 with 22, the final level a final-mode level at 1/512 with 26 —
profile 6's chain after the tree (`wrap::SHIPPED`). A level's circuit
embeds the key root of the level below, so every level has its own key;
`AggKeys::derive` refuses a set whose final proofs can exceed 64 KiB
(`wrap::wire::max_bytes`) or any of whose ledger rows is below 128 bits.

**Verifier** (`agg::verify`): from the block statement — every
transaction's pins in order and the block's fields (four limbs) —
recompute the digests natively, then verify the final wrap proof under
`X`. It reads no transaction proof and calls no prover backend.

**Prover** (`agg::prove`): every transaction proof is verified natively
first (an invalid one is refused before any proving); then the leaves,
the levels, the top and the final level, each a wrap proof of its
program (`wrap::prove_with`).

## soundness

The block proof is sound without being zero knowledge.

*Soundness.* A verifying block proof for statement `(pins_1..N, fields)`
yields, level by level, accepting runs of each level's circuit (the wrap
rows of `soundness.md`, every level ≥ 128 bits; the composition row is
conjectured as for every recursive proof system). The top's run binds
`X_root`, `N` and the fields; a node's binds its children's digests and
verifies their proofs under them, and `h = 0` forces `X_r = X_l`; a
leaf's binds `vk` and the pins it verified the transaction proof
against. The verifier recomputes the same digests from the statement, so
any other tree — a missing, extra, reordered or altered transaction —
needs a hemera collision on the digest chain. Each leaf run holds an
accepting veil-r proof for its pins, and veil-r is knowledge-sound (its
ledger rows), so a witness of every transaction exists. The aggregator
needs no witness: it holds the transaction proofs only.

*Zero knowledge.* The block proof is a deterministic public function of
the statement and the transaction proofs (the wrap provers draw no coins).
Whatever it reveals, anyone holding the transaction proofs can compute.
The transaction proofs are zero knowledge (veil-r is veil's
honest-verifier statistical zero-knowledge protocol under the BCS
transform with salted leaves; the hashing it changes is the random oracle
of that argument), so a simulator given the pins outputs transaction
proofs at statistical distance `≤ Σ_i ε_zk`, and the aggregation of
simulated proofs is a simulated block proof. Hence the aggregator, the
nodes and the mempool learn nothing about a witness beyond its pins: the
aggregator sees proofs, never witnesses, and the proofs are zero
knowledge to it as to everyone.

Ledger rows: `soundness.md` § block aggregation.

## not built

- the matrix claims deferred: today every leaf evaluates
  `A(0, r)` and `P` in the circuit (≈ half its gates at 2^14 rows,
  197k nonzeros); carried as claims up the tree and folded along lines,
  the final verifier would evaluate them once per block;
- a multi-opening wire for veil-r (shared upper path nodes);
- an envelope profile for block proofs.
