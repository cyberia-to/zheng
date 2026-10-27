# Native private CCS proofs

Protocol `zheng-ccs-mith-goldilocks-v1` proves knowledge of a Goldilocks witness
for a verifier-derived CCS. It is the arithmetic three-party linear decomposition
of ZKBoo (Giacomelli, Madsen, Orlandi, USENIX Security 2016, sections 4.1.1–4.2
and Appendix A), instantiated with Hemera commitments and Fiat–Shamir. The
construction belongs to Zheng and uses no external execution or proof engine.

## Relation and public values

The caller supplies the CCS, statement bytes and strictly increasing public
coordinate/value pairs, excluding coordinate zero. The circuit outputs every
nontrivial CCS row residual, `z[0]-1`, and every supplied public-coordinate
residual. Its required output is the all-zero vector. Literal constants use
party zero's share. Every matrix, coefficient, dimension, statement byte and
public coordinate is included in the relation digest. Identically zero terms
and rows may be omitted using only public matrix data. No randomized constraint
aggregation or small-field sumcheck establishes acceptance.

The execution caller reconstructs the CCS from the public program. Public input,
output, selected reduction count, budget and authenticated state context remain
bound by that caller. Secret witness preparation and native execution
comparison stay in their existing owners; public BBG tables of a private-state
statement are authenticated by zheng (`PrivateStateStatement::verify_mith`).

## Three-party decomposition

For each of exactly 219 repetitions, fresh OS entropy supplies three 32-byte
seeds. Domain-separated Hemera XOF streams generate additive input shares zero
and one; share two is the witness minus those shares. Independent streams supply
one field mask per party per multiplication. A multiplication computes

`c_i = a_i*b_i + a_(i+1)*b_i + a_i*b_(i+1) + R_i - R_(i+1)`.

Indices wrap modulo three. Linear gates are local. Each view commitment hashes
the protocol/relation, repetition and party indices, seed, input share and all
multiplication shares with explicit lengths. The secret seed randomizes a
commitment even for a relation containing only linear gates.

The first message consists of all three commitments and all three output-share
vectors for every repetition. Their sum must equal zero component by component.
The global Fiat–Shamir transcript binds the entire first message and relation.
Challenges are sampled uniformly from three possibilities by rejection from
canonical Goldilocks XOF elements. A challenge opens parties `e` and `e+1`.
The verifier reconstructs party `e` using party `e+1`'s supplied multiplication
shares, verifies both output functions and authenticates both opened views.

## Wire and validation

`PrivateProof` serializes as a bounded byte sequence. The native fixed-width
payload begins with `ZHMITH01` and three little-endian u32 circuit dimensions.
Each repetition stores its challenge index, the hidden commitment and output
vector, two opened seeds, share two if opened, and the neighbor's multiplication
shares. All field elements are canonical little-endian u64. No vector lengths
come from proof data: the verified relation fixes them. Truncation, trailing
bytes, noncanonical fields and wrong dimensions fail.

This losslessly compresses the first message: opened outputs and commitments
are reconstructed from the opened views. The verifier reconstructs the complete
first message before recomputing every challenge and comparing the stored
indices. Hidden outputs are supplied and transcript-bound; they are never freely
chosen after an independently accepted challenge.

The payload is capped at 256 MiB, including during serde deserialization.
Relations have at most 65,536 rows and columns, 64 matrices and product terms,
degree 16, and 1,048,576 total sparse entries or matrix/row slots. The derived
circuit has at most 65,536 multiplication gates. Its worst-case proof size is
checked before proving or verification allocation. Work and proof size are
linear in the admitted circuit, multiplied by the fixed repetition count.

## Security and disclosure

Three accepting responses for the same first message determine mutually
consistent views and a satisfying witness. The interactive error is bounded
by `(2/3)^219 < 2^-128`. Noninteractive security additionally assumes the
Fiat–Shamir random-oracle model and Hemera binding, hiding and pseudorandom
expansion. The two-view simulator samples the exposed input shares and the
neighbor's multiplication shares and derives the hidden output from the public
zero result. Real and simulated views agree under the stream assumptions.

The protocol makes no succinctness, independently audited production security,
Spartan proof, or 128-bit post-quantum claim. Proof size is linear. The underlying
relation remains separately responsible for correct nox semantics. Public output,
program, dimensions and reduction count remain visible, including any information
their values reveal about branch choices. Private-state queries use complete
authenticated public tables; database contents are not hidden by this protocol.

### Local proving process

Zero knowledge describes the proof transcript under the assumptions above.
Local timing, cache, process-memory and dump observations require a separate
threat model. Witness activity branches, native execution and hidden table
indexing depend on private values. Field and runtime operations have no
whole-engine constant-time guarantee. Symbolic inverse witnesses always evaluate
the field inversion routine, including its defined zero-to-zero case; this
removes one avoidable secret-dependent shortcut.

Memory erasure is best effort. The backend wipes owned seed and view buffers.
Private preparation still uses ordinary secret and witness vectors, the caller
owns additional copies, and Hemera PRG state has no wiping destruction contract.
Complete erasure requires secret-owned preparation buffers, explicit stream
erasure in Hemera, and review of caller/runtime copies and temporary values.
Full local side-channel hardening additionally requires oblivious private-state
access and field/runtime analysis. These remain open implementation work.

Reference: https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_giacomelli.pdf
