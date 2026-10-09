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

- The full-round S-box is one degree-7 CCS row: `x^7 = w` with `x` a linear
  form. The relation carries two matrix kinds — three matrices for the
  degree-2 rows `a · b = c`, two for the degree-7 rows — with multisets
  `[0,1] − [2] + [3,3,3,3,3,3,3] − [4]`; a row of one kind is all-zero in the
  other kind's matrices. Programs without a hash keep the three-matrix
  instance. Witness generation gained `Op::Pow7`.

Per permutation with a wired input: 128 S-box wires over eight full rounds
(one per lane), 48 inverse/selector wires over sixteen partial rounds, zero
MDS wires — 176 instead of 1,120. A row's linear forms may carry up to
thirty-two terms. The Spartan sumcheck degree rises from 2 to 7 on hash
programs (`MAX_DEGREE` is 16); the Triton zk backend evaluates CCS
multisets generically and is unaffected.

## Measured (joy 0.5.0 `main` 10844a8 built against this zheng, Apple M4 Max,
release build, three runs each)

| program | before | linear forms + constants | + degree-7 S-box |
|---|---|---|---|
| hash.tri prove | 460 ms | 81 ms | 36 ms |
| hash.tri verify | 460 ms | 80 ms | 30 ms |
| hash.tri certificate | 294,861 B | 47,612 B | 15,608 B |
| add.tri certificate | 2,290 B | 2,207 B | 2,207 B |
| add.tri `--zk` (Triton) | 816 KB · 2.1 s | — | 768 KB · 0.9 s |

The hash certificate moved from n = 2^15 to n = 2^10 columns. The "before"
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

1. the Merkle paths of the `PublicTensor` opening (~5 KB of the 15.6 KB) —
   the verifier rebuilds the whole tree and only compares them; dropping
   them is a wire-format change (a new protocol string);
2. a public/private witness split so the verifier evaluates the public
   prefix itself, and a verifying-key digest instead of absorbing every
   matrix entry;
3. a sound sublinear PCS (Reed–Solomon/Ligero with multiproofs, or
   Basefold/WHIR) replacing `PublicTensor`, with extension-field challenges —
   the first step that actually makes the proof succinct.
