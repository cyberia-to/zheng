# Public execution certificates

Implemented protocols:

- public profile v3, `zheng-nox-public-execution-v3`
  (`certify_execution` / `verify_certificate`) — the default;
- authenticated-state profile v3 (`state::certify_state_execution` /
  `StateStatement::verify_certificate`);
- the succinct profile, `zheng-nox-succinct-execution-v1`
  (`succinct::prove` / `succinct::verify`, `succinct::prove_state` /
  `succinct::verify_state`) — the same statements with the witness
  committed instead of disclosed;
- all carried by the `ZHENGPF1` envelope (`zheng::envelope`, profiles 0
  and 3 for the certificates, 1 for the succinct profile; profile 2 carries
  native private proofs).

Retired and read for one release: public v2 `zheng-nox-public-execution-v2`
(`prove_execution` / `verify_execution`, a `DirectProof`) and state v1
(`prove_state_execution` / `StateStatement::verify`). The owner authorized
execution/output binding on 2026-09-11. Soundness of every profile is
recorded in the [soundness ledger](soundness.md).

## Statement and relation

`ExecutionStatement` contains a flat canonical nox program, public input
atoms, output atoms, reduction count and budget. The verifier derives the
subject shape from input length in Joy reverse-cons order with trailing zero,
and derives a global CCS from the public program. Constants reference wire 0.
Operands, intermediate values and output coordinates share global indices.
Matrices depend on the program and subject shape, never witness values.

Profile v3: the prover supplies the witness values at every non-pinned
position in index order, with the trailing zeros of the power-of-two padding
removed (`Certificate`). The verifier places `z[0] = 1`, the inputs, the
outputs and the cost wire itself, fills the remaining positions from the
certificate, pads with zeros and checks **every CCS row exactly**. It rejects a
certificate with a trailing zero, a value at or above p, or more values than
the relation has free positions below its last referenced column. There is no
commitment, sumcheck or challenge: soundness rests on the relation compiler
alone. Every free position the certificate can change without rejection is a
"don't care" wire whose every product term has a factor that is zero in the
honest witness (`certificate::malleability`).

Retired v2: a direct Spartan proof with a `PublicTensor` commitment and a
complete authenticated evaluation table; the verifier authenticates all columns
and checks the same rows. Its transcript binds the canonical statement,
dimensions, full relation and public coordinate mapping and uses the 0.4.0
challenge rule (`Transcript::new_v1`) so that existing artifacts still verify.
Program terms use tagged flat prefix encoding. Public vector limits apply during
deserialization.

The verifier does not invoke native nox, generate a witness, or accept a
trace from another computation. Prover-side native execution independently
checks output and cost agreement but is not the verifier's security boundary.
A newly generated certificate for another input or result cannot satisfy
verification against the original statement.

## Supported nox surface

| Tags | Semantics |
|---|---|
| 0 | static axis traversal; axis0 structural digest |
| 1–3 | quote, compose with static continuation, cons |
| 4 | constrained conditional selector and fixed-shape output |
| 5–8 | field add/sub/mul/inverse |
| 9–10 | structural digest equality and canonical 64-bit less-than, nox zero=true |
| 11–14 | canonical 32-bit XOR/AND/NOT/variable left shift |
| 15 | full structural Hemera hashing and final permutation |

The native private backend supports atom call witnesses (16), with checked continuation.
State backends authenticate lookups (17), including private query selection over
complete public tables. Direct public stateless proving accepts no secret stream
or unauthenticated lookup. See [backend contract](ccs-execution-backends.md).

Dynamic continuation formulas and differently shaped branch outputs remain
unsupported. Activity gates inverse validity, word ranges and call success;
inactive errors do not reject a successful selected path. The public budget must cover
the authenticated cost of the selected path, not an unselected expensive branch.
The relation bounds every possible cost below the field modulus, so its cost
wire cannot wrap; canonical public cycles are bound to that wire and must not
exceed the canonical budget. Native nox falls back to sequential budget threading
when static child reservations do not fit. Public cycles can reveal branch-cost
information even when the execution witness is private.

Limits: 64 public inputs, 4096 program/symbolic noun nodes, 128 depth, 4096 symbolic
calls, 32768 gates/rows (checked before constructing sparse matrices), 4096 output
atoms. Hash round construction checks limits at permutation boundaries. The
generic direct wrapper also caps matrix dimensions and total sparse entries.
The native private backend separately caps circuit work and fixed-width proof
size before allocation; see [its contract](native-private-ccs.md).

## Disclosure, complexity and assurance

This is a full public algebraic witness certificate. It reveals every witness
element and has linear verification/storage cost; it is not a succinct or
zero-knowledge proof. The stateless public API accepts public input; authenticated
state execution and private proving have separate protocols. There is no silent
fallback to the legacy trace-statement format.

Profile v3 draws no challenge. In the retired v2, `PublicTensor` checks all raw
columns under a domain-separated Merkle root and exact CCS checking removes
small-field sumcheck error as a basis for acceptance; its Goldilocks Spartan
transcript is a consistency check and must not be advertised as 128-bit
soundness. See `lens/specs/public-tensor.md` for that commitment contract.

## Authenticated-state profile v3

`StateStatement` adds the state root (four field limbs), a 32-byte caller
context, whether the root sits at the head of the subject, and one
`PublicLookup` per lookup site of the compiled relation (active flag,
namespace, key, value; inactive reads carry zeros). The verifier recompiles
the relation for that subject shape, asks the caller's lookup — which MUST
come from a state certificate already verified under `state_root` — for every
active read, pins the active flag of every read and the root limbs, namespace,
key and value of every active read, together with the constant, inputs (and
the root when it sits in the subject), outputs and cost, and checks the
certificate exactly as profile v3. At most `MAX_READS = 4096` reads. A root
limb the program never computes on is bound through the reads' authentication;
a limb it reads from the subject is also bound by the relation. The context is
caller metadata that zheng carries and does not interpret.

## Succinct profile (envelope profile 1)

Same statements as public v3 and state v3; the verifier derives the relation
and every pinned coordinate exactly as they do. The witness is committed with
a multilinear PCS over Goldilocks (`lens::MultilinearPcs`, a type parameter:
WHIR id 1, TensorRs id 2) and never sent.

Layout. Let `P` be the pinned columns (`z[0] = 1`, inputs, outputs, cost,
and for state statements every read coordinate) and `W` the other columns
some row reads, both in index order. With `ℓ = ⌈log2 max(|W|, |P|, 2)⌉` the
verifier relabels the CCS columns into `z' = (w ‖ p)`, `|w| = |p| = 2^ℓ`:
`w` = the values of `W` then zeros, `p` = the values of `P` then zeros.
Columns no row reads are dropped. `z̃'(r_0, r') = (1 − r_0)·w̃(r') +
r_0·p̃(r')` with `r_0` the top index bit; the verifier computes
`p̃(r') = Σ_j p_j·eq(r', j)` from the statement. Only `w` is committed, so a
pinned value cannot be changed by the prover — this is the statement binding
once the witness leaves the wire.

Protocol, on the zheng transcript (`Transcript::new`, wide challenges):

1. absorb `"zheng-succinct-v1"`, the statement's `transcript_bytes` (length
   prefixed), the PCS id, its parameter header, `ℓ` and the row count `m`;
2. `root = PCS.commit(w)`, absorbed with `absorb_commitment`;
3. Spartan over Fp3 (`spartan::iop::prove::<Fp3>` on the relabelled CCS):
   `τ`, the outer sumcheck (`log m` rounds, degree `d + 1`), the matrix
   evaluations `M̃_i(ρ_x)`, `γ`, the inner sumcheck (`ℓ + 1` rounds, degree
   2). Round polynomials travel without their linear coefficient; the
   verifier restores `c_1 = claim − 2c_0 − Σ_{i≥2} c_i`
   (`spartan::reduce`), so it absorbs and checks the same polynomials;
4. a lens transcript `Transcript::new("zheng-succinct-pcs-v1")` absorbs one
   32-byte squeeze of the zheng transcript; the PCS opens `w̃` at `r'`
   (reversed: lens points are LSB-first) and returns `v = w̃(r')`;
5. the verifier checks `claim = weight·((1 − r_0)·v + r_0·p̃(r'))`, where
   `weight = Σ_i γ^i M̃_i(ρ_x, r)` is computed from the relation it compiled,
   then the opening at `(root, ℓ, r', v)`.

Policy (`succinct::admit`): the parameters must be in range (WHIR rate 1/2 …
1/64, folding factor 1 … 6, grinding ≤ 32, final variables ≤ 16; TensorRs
rate 1/2 … 1/64, grinding ≤ 32), ask for a target of at least 128 bits, and
lens's proven `security_bits(params, ℓ)` must be ≥ 128. The prover refuses
the same parameters. The composed bound is in the [soundness ledger](soundness.md).
The shipped choice (`succinct::prove_default` / `params_for`, used by `joy
prove --succinct`) is WHIR at rate 1/64, folding factor 4, 24 grinding bits,
Johnson decoding, final polynomial ≤ 2^8, for both size classes — the
smallest ≥ 128-bit proof in the bake-off
(`audit/succinct-profile-2026-10.md`). A verifier admits any in-range
parameters that meet the policy, not only the shipped ones.

Body (profile 1): PCS id (u8), its parameter header (WHIR 8 bytes, TensorRs
6), statement kind (0 execution, 1 state), the statement in the profile-0 or
profile-3 encoding, the root (32 bytes, canonical limbs), `t` matrix
evaluations, the outer rounds (count, width, values), the inner rounds
(count, width 2 implied), `v`, then the PCS proof bytes after its parameter
header (lens's canonical encoding; the header is restored before parsing).
Fp3 values are three fixed 8-byte canonical limbs. Shapes — `t`, round
counts and widths, the proof's internal lengths — are checked by the
verifier against the relation it compiled and the configuration lens derives.

## Envelope

`zheng::envelope::Envelope` is the one wire form: magic `ZHENGPF1`, version
u16 little-endian (1), profile byte (0 public, 1 succinct, 2 zk,
3 state-public), then a canonical body — shortest-form LEB128 integers, field
values below p, flags 0 or 1, every length bounded statically and by the
remaining bytes before allocation, no trailing bytes. A wrong magic, an
unknown version, an unknown profile, truncation and every
noncanonical encoding fail at decoding; `Envelope::verify` runs the profile's
verifier. The zk body binds a 32-byte context through `zk_statement_bytes`.

## Legacy

The 0.3.x folded trace API (`commit`, `open`, `verify_eval`, `verify`, `fold`,
`decide`, the universal CCS, HyperNova folding, phi) compiles only with the
cargo feature `legacy`, off by default. It is unsound — the fold is unchecked
and the statement unbound ([decider](decider.md) §soundness) — and must not be
used on a production path.

This establishes the stated bounded relation. The symbolic compiler and Hemera
permutation still require independent security review.

Private execution uses Zheng's native `zheng-ccs-mith-goldilocks-v1` protocol:
219 repetitions of arithmetic MPC-in-the-head prove every row and every public
coordinate while hiding the witness. The protocol has linear proof size and
verification cost. Its stated interactive soundness bound and noninteractive
random-oracle assumptions are specified in [native private CCS](native-private-ccs.md).
This is a separate construction from the public Spartan consistency transcript.
Trisha retains its own Triton/Neptune execution stack; Joy has no dependency on it.

## Joy integration

Default stateless public `joy prove` and `Prover` use this format. Secret input
or explicit `--zk` selects native private proving; explicit state files select
authenticated public execution or private queries according to that choice.
Proof-mode `--claim` and
`--input-values` compare verified values. `--proof` also binds the supplied
program; self-contained verification uses the canonical embedded program.
`--budget` is an upper limit on the certificate's declared budget.

Joy's public `ExecutionArtifact` is the profile-0 envelope itself, capped at
32 MiB. Joy's state artifact `JOYST002` carries the BBG state certificate and
a profile-3 envelope. Joy reads `JOYEXEC2` (public v2) and `JOYST001`
(state v1) for one release. Legacy trace artifacts require
`--legacy-trace-statement` and refuse IO/state/secret constraints.

Native private artifacts use `joy-nox-zheng-private-execution-v1` and `JOYZH001`,
with a 256 MiB outer artifact cap. Their embedded native proof has a distinct
`ZHMITH01` header and fixed-width canonical fields. Old foreign-backend private
artifacts require regeneration; they cannot be relabeled as native proofs.

Tests compare native nox with symbolic witnesses, include real compiled
Trident imports/loops/branches, mutate intermediate/hash/bit witnesses and
public claims, construct malicious proofs bypassing the honest prover, and
verify through fresh CLI processes. See audit/public-execution.md
for historical measurements. Current state acceptance tests exercise the new
protocol; obsolete recursive-opening requests remain rejected.
