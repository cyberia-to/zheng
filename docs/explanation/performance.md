# performance characteristics

[[zheng]] produces proofs that are larger than pairing-based schemes and
smaller than FRI-based [[STARKs]], with verification speed that matches
or beats both. the concrete numbers matter for system design, so this
page presents them without hedging.

## proof sizes

proof size depends on the security level and the size of the execution
trace.

| security level | proof size | verification time |
|---|---|---|
| 100-bit | ~60 KiB | ~290 μs |
| 128-bit | ~157 KiB | ~1.0 ms |

the 128-bit level is the default for production use. 100-bit is suitable
for applications where speed matters more than long-term security — fast
interactive proofs, ephemeral attestations, or inner layers of recursive
composition where the outer proof provides the full security guarantee.

## verification time

sub-millisecond verification at 100-bit security. approximately one
millisecond at 128-bit security. the verifier performs a fixed sequence
of hemera hashes and [[Goldilocks]] field operations — its cost is
determined by the security parameter, independent of the original
computation size.

this is the property that enables cheap [[recursive composition]]. the
verifier runs inside [[nox]] as a program of roughly 70,000 constraints
(with jets). at one microsecond per constraint, verification proving
takes about 70 ms. this is the cost of one recursion level.

## prover time

the prover runs in time linear in the trace size, dominated by two
components.

the [[SuperSpartan]] IOP processes the execution trace with O(N) field
operations. the [[sumcheck protocol]] streams through the trace
variable by variable, performing additions and multiplications with no
NTT and no FFT. the absence of NTT is a structural advantage of
multilinear polynomials over univariate ones — the prover avoids the
O(N log N) bottleneck that FRI-based systems face in polynomial
evaluation.

the [[WHIR]] commitment constructs a Merkle tree over the polynomial
evaluations, costing O(N log N) hemera hashes. this dominates the total
prover time for large traces. each hemera call processes [[Goldilocks]]
field elements natively, so the constant factor is small.

total prover cost: O(N log N), dominated by WHIR's Merkle construction,
with the linear-time SuperSpartan IOP as the smaller term.

## constraint costs for common operations

these numbers reflect nox constraint counts and estimated proving times
at one microsecond per constraint.

| operation | constraints | proving time |
|---|---|---|
| identity proof (hemera preimage) | ~300 | ~0.3 ms |
| anonymous [[cyberlink]] | ~13,000 | ~13 ms |
| delivery proof per hop | ~60,000 | ~60 ms |
| recursive verification (with jets) | ~70,000 | ~70 ms |
| recursive verification (no jets) | ~600,000 | ~600 ms |

the identity proof is the lightest operation: prove knowledge of a
hemera preimage without revealing it. 300 constraints, proved in a
third of a millisecond. this is the primitive that enables anonymous
identity in [[cyber]].

the anonymous cyberlink is the core operation of the knowledge graph:
prove that a valid agent created a link between two content identifiers
without revealing which agent. 13,000 constraints encode the signature
verification, the merkle membership check, and the nullifier derivation.

the delivery proof attests that a message was correctly forwarded at one
hop of its path through the network. 60,000 constraints cover the
hemera-based routing verification and the hop metadata commitment.

recursive verification is the operation that makes all other operations
composable. with jets — hardware-accelerated hemera and field arithmetic
built into nox — the verifier compiles to 70,000 constraints. without
jets, the hemera sponge must be decomposed into individual field
operations, inflating the circuit to 600,000 constraints. jets provide
an 8.5x reduction.

## comparison at 128-bit security

| system | proof size | verify time | setup | post-quantum |
|---|---|---|---|---|
| [[Groth16]] | 128 bytes | ~1.5 ms | trusted (per-circuit) | no |
| [[PLONK]] | ~400 bytes | ~5 ms | universal ceremony | no |
| univariate [[STARK]] (FRI) | ~200 KiB | 10-50 ms | transparent | yes |
| zheng ([[Whirlaway]]) | ~157 KiB | ~1.0 ms | transparent | yes |

Groth16 wins on proof size by three orders of magnitude. PLONK wins on
proof size by two. both lose on trust assumptions and quantum resistance.
FRI-based STARKs share zheng's transparency and quantum resistance but
verify 10-50x slower. zheng occupies the unique position of hash-based
security with pairing-competitive verification speed.

## the Goldilocks advantage

the [[Goldilocks field]] p = 2^64 - 2^32 + 1 was chosen because its
arithmetic maps directly to 64-bit CPU instructions. addition is a
64-bit add with a conditional subtraction. multiplication uses the
CPU's native 64-bit multiply followed by a cheap reduction — the
special structure of the prime (a sparse polynomial in powers of two)
makes modular reduction a few shifts and adds rather than a full
division.

this eliminates the need for big-integer libraries. there is no
[[Montgomery multiplication]] overhead, no multi-limb carries, no
word-by-word schoolbook multiplication. every field operation is a
handful of native CPU instructions. this is why [[aurum]] exists as a
standalone library — the field implementation is performance-critical
and benefits from assembly-level optimization.

the constant factor matters because zheng's prover performs billions of
field operations on large traces. a 2x improvement in field arithmetic
translates directly to a 2x improvement in proving time. Goldilocks
provides roughly 3-5x faster field operations compared to the 256-bit
fields used by pairing-based systems.

## future: the Goldilocks field processor

the current performance numbers assume commodity x86-64 hardware. the
[[cyber]] roadmap includes a custom Goldilocks field processor — silicon
optimized specifically for Goldilocks arithmetic and hemera hashing.
the target is 10x acceleration over general-purpose CPUs.

at 10x, the anonymous cyberlink drops from 13 ms to 1.3 ms proving
time. recursive verification drops from 70 ms to 7 ms. an entire block
of 1000 transactions, tree-aggregated with O(log 1000) ≈ 10 recursion
levels, proves in under 100 ms on dedicated hardware. the proof size
remains ~157 KiB. the verification time remains ~1.0 ms.

the architecture is designed so that every performance gain in the field
processor multiplies through the entire stack — prover, recursive
composition, block production, epoch aggregation. the numbers on this
page are the floor. the ceiling depends on silicon.
