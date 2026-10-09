# Compact public execution relation — 2026-10-09

Status: implemented and measured on the `zheng-nox-public-execution-v2`
(`JOYEXEC2`) path. The protocol, the artifact format and the soundness
argument of [public execution](public-execution.md) are unchanged: the
verifier still derives the whole relation from the program and checks every
row against the authenticated full witness. What changed is the size of
that witness.

## What was found

For `joy/rs/tests/fixtures/hash.tri` (`hash(a,0,0,0,0,0,0,0)`, 61
reductions) the certificate was 294,861 bytes, of which about 262 KB was the
witness vector `z` itself and about 30 KB its Merkle paths. `z` was almost
entirely hemera permutation wires: 1,120 wires per permutation, of which 400
were pure linear copies (the MDS layers) and 16 per full round were the round
constant additions; and the seven constant zero atoms were hashed in-circuit
with a full 64-bit decomposition and two permutations each, although their
digests are fixed by the program.

## What changed

- `Value::Linear` — a public linear form over existing wires. Additions,
  MDS layers (external and internal) and bit packing are forms; they allocate
  no wire and no row. Only products, inverses, bits, secrets, lookups and the
  public outputs allocate wires. Forms are normalised (sorted, merged, zero
  coefficients dropped), so a lane after sixteen partial rounds carries at
  most one term per distinct wire it depends on.
- Constant subtrees are hashed natively at compile time: a value that is a
  constant noun returns `nox::data::hash` digests as constants, and a
  permutation whose sixteen lanes are constants runs `hemera::permutation::permute`.
  The verifier derives the same constants from the same program; the circuit
  this replaces had no witness freedom.

Per permutation with a wired input: 512 S-box product wires over eight full
rounds (x², x³, x⁴, x⁷ — four is the minimum addition chain for 7 under
degree-2 rows), 48 inverse/selector wires over sixteen partial rounds, zero
MDS wires. Rows keep the same shape `a · b = c`; a row's linear forms may now
carry up to thirty-two terms.

## Measured (joy 0.5.0 `main` 10844a8 built against this zheng, Apple M4 Max,
release build, three runs each)

| program | before | after |
|---|---|---|
| hash.tri prove | 460 ms | 81 ms |
| hash.tri verify | 460 ms | 80 ms |
| hash.tri certificate | 294,861 B | 47,612 B |
| add.tri certificate | 2,290 B | 2,207 B |

The hash certificate moved from n = 2^15 to n = 2^12 columns. The "before"
numbers are the shipped joy 0.5.0 binary and the same source built against
zheng 0.4.0 (`chore/coordinated-release-20260916`), measured 2026-10-08 on the
same machine.

## Tests

`cargo test -p zheng`: 259 lib tests and all integration tests pass. The
relation tests compare every circuit digest against the native nox/hemera
value and forge individual wires; `partial_inverse_zero_is_constrained` was
updated because the one-minus-selector value is now a form, not a wire.

## What this does not change

The certificate still discloses the full witness and verifies linearly; it
is not succinct and not zero-knowledge. The next size levers, in order:

1. degree-7 S-box rows (CCS multisets of degree 7) — one wire per lane per
   full round instead of four; the hash certificate would fall to about
   n = 2^10 (~15 KB);
2. a public/private witness split so the verifier evaluates the public
   prefix itself, and a verifying-key digest instead of absorbing every
   matrix entry;
3. a sound sublinear PCS (Reed–Solomon/Ligero with multiproofs, or
   Basefold/WHIR) replacing `PublicTensor`, with extension-field challenges —
   the first step that actually makes the proof succinct.
