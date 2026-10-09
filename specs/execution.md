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
- the zk profile, `zheng-nox-veil-execution-v1` (`veil::prove` /
  `veil::verify`) — succinct proofs of statements with secret inputs, the
  witness hidden;
- verifying keys (`VerifyingKey`), which let a verifier compile each
  program once;
- all carried by the `ZHENGPF1` envelope (`zheng::envelope`, profiles 0
  and 3 for the certificates, 1 for the succinct profile, 2 for zero
  knowledge — veil, or MPC-in-the-head as the fallback).

Retired and read for one release: public v2 `zheng-nox-public-execution-v2`
(`prove_execution` / `verify_execution`, a `DirectProof`) and state v1
(`prove_state_execution` / `StateStatement::verify_v1`). The owner authorized
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

`StateStatement` adds the state root (four field limbs), whether the root
sits at the head of the subject, and one `PublicLookup` per lookup site of
the compiled relation (active flag, namespace, key, value; inactive reads
carry zeros). At most `MAX_READS = 4096` reads.

Every verifier of a state statement (`verify_certificate`, `verify_v1`,
`succinct::verify_state`, `Envelope::verify`) takes the reads' evidence,
`state_evidence::StateEvidence`, and authenticates it itself: the 14 root
leaves fold to the statement's `state_root` (`compress4`, the first four
elements of the hemera permutation over `[acc ‖ leaf ‖ 0⁸]`, from the IV
`["bbg-root", 0, 0, 0]`), and every table the evidence carries matches its
leaf (the lens Brakedown commitment of its fields zero-padded to a power of
two; header `[2, len, entries]`, so a table with appended zeros has another
header). Then the verifier recompiles the relation for the subject shape,
answers every active read from the authenticated tables (field `key` of
table `namespace`), pins the active flag of every read and the root limbs,
namespace, key and value of every active read, together with the constant,
inputs (and the root when it sits in the subject), outputs and cost, and
checks the certificate exactly as profile v3. No caller authenticates
anything on zheng's behalf: evidence for another root, without the table a
read names, or with a value its leaf does not commit is rejected. The layout
is BBG's (`bbg/rs/src/root.rs`, `certificate.rs`); `StateCertificate::evidence`
converts, and both repositories pin the frozen root vectors. The prover takes
the same evidence and states the root it authenticates. The private-state path
takes the same evidence (`specs/ccs-execution-backends.md`).

The statement carries no caller context. Under the public profiles the
witness is disclosed, so whoever holds a certificate can re-certify the same
execution under any label: no relation can bind one, and labels such as a
program name or source hash stay the artifact's own metadata. The retired v1
transcript absorbed a 32-byte context; `verify_v1(context, …)` and
`transcript_bytes_v1(context)` reproduce it so that v1 proofs keep verifying.

## Verifying keys

`program_key(statement)` hashes what the relation depends on — the program
tokens, the input count and the statement kind (execution, or state with the
root in the subject or not); it costs a hash of the program. A
`VerifyingKey` is derived only by the verifier (`for_execution`,
`for_state`; no constructor from parts, no deserialisation) and holds the
program key, the compiled relation and `digest` = the hemera Merkle root
(1024-byte leaves, batched) of `"zheng-vk-relation-v1" ‖ program_key ‖` the
canonical relation encoding: dimensions, every matrix row by row, the
multisets and coefficients, the input/output/cost wiring, the cost bound and
every lookup's coordinates — LEB128 integers, each coefficient as the zigzag
of its centred representative. `verify_with`, `verify_state_with`,
`verify_certificate_with` and `veil::verify_with` accept an optional key;
a key whose program key differs from the statement's is rejected, and with a
matching key the relation is not recompiled. Succinct and zk transcripts
absorb `"zheng-vk" ‖ digest` before the statement, so a proof is bound to the
relation it was made for; a key carrying another relation under the same
program key changes the digest and the proof fails.

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

1. absorb `"zheng-succinct-v1"`, then `"zheng-vk" ‖ digest ‖` the
   statement's `transcript_bytes` (length prefixed; the digest of the
   statement's verifying key), the PCS id, its parameter header, `ℓ` and the
   row count `m`;
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

## Zk profile (envelope profile 2, scheme veil)

Statements are `PrivateStatement`s: the program, the public inputs, the
outputs, the cycles and the budget. Secret inputs (`[16 [tag check]]` call
sites) and every intermediate value are witness columns and stay with the
prover. `veil::prove(program, public, secret, budget)`; `veil::verify` /
`verify_with`; the relation-level `prove_relation` / `verify_relation`
mirror `zk::prove` / `zk::verify` (MITH) for callers that derive their own
relation (joy's private state queries).

Masked relation (`veil::pad`). The verifier appends masking rows to the
compiled CCS: for the gate `y0·y1 − y2` the types T0 (`y0 = s`), T1
(`y1 = s`), TB (`y0 = s, y1 = z[0], y2 = s`); for `y0·y1 − y2 + y3^7 − y4`
also TA (`y2 = s, y4 = −s`) and TE (`y3 = s, y4 = s^7`); three rows per type
on fresh columns, placed in trailing empty rows or after doubling the row
count. Every masking row is satisfied by any value of its fresh columns, so
the masked relation is equisatisfiable with the statement's; the prover
fills them uniformly. Other gates are refused (MITH is the fallback).

Layout as the succinct profile on the masked relation: `z' = (w ‖ p)`, `p`
pinned and computed by the verifier. Committed: one hiding commitment
(`veil::hiding`) to `w ‖ g1 ‖ g2`, where `g1` (outer, `log m` rounds, degree
`d + 1`) and `g2` (inner, `ℓ` rounds, degree 2) are Libra masks
`g(x) = Σ_i g_i(x_i)` with uniform Fp3 coefficients, three base entries per
coefficient.

Protocol (`veil::protocol`), zheng transcript, Fp3 challenges:

1. absorb `"zheng-veil-v1"`, `"zheng-vk" ‖ digest ‖` the statement bytes
   (length prefixed), the commitment parameters, `ℓ`, `m`, the outer degree,
   then the root;
2. `τ`; send `Σ g1`; `ρ1`; sumcheck of `eq(τ,·)·G(Mz) + ρ1·g1` from claim
   `ρ1·Σ g1`, `log m` rounds (without `c_1`); send `v_i = M̃_i z(ρ_x)`;
3. `γ`; the verifier computes `P = Σ_i γ^i Σ_rows eq(ρ_x, row) Σ_{pinned c}
   M_i[row][c]·p(c)`; send `Σ g2`; `ρ2`; sumcheck of `A(0,·)·w̃ + ρ2·g2` from
   `Σ γ^i v_i − P + ρ2·Σ g2` over `ℓ` rounds, where `A = Σ_i γ^i M̃'_i(ρ_x,
   ·)`;
4. `λ`; the verifier sets `g1(ρ_x) := (C1 − eq(τ,ρ_x)·G(v))/ρ1` (rejecting
   `ρ1 = 0`) and checks one opening of the functional `λ·g1(ρ_x) +
   A(0,r')·w̃(r') + ρ2·g2(r')` at `λ·g1(ρ_x) + C2`, on a lens transcript
   seeded by a squeeze of the zheng transcript.

Hiding commitment (`veil::hiding`): rows of width `k` (a power of two),
row polynomial `p_i = Σ_{c<k} u_{i,c}X^c + X^k ν_i` with `ν_i` uniform of
degree `< k`, RS-encoded on `N = 2k·2^r` points; masking rows `m_a`, `m_b`
(degree `< k − 1`), `m_P`; leaf = column ‖ four uniform salt limbs. The
opening sends `μ = [X^{k−1}]m_a`, then (after `α`, `ρ_L`) the proximity
polynomial `Σ α^i p_i` (all rows, `m_P` last) and the linear polynomial
`q = Σ_i Λ'_i p_i + ρ_L(m_a + X^{2k} m_b)` with `Λ'_i = Σ_c Λ_{i,c}X^{k−1−c}`;
the verifier checks `[X^{k−1}]q = V + ρ_L μ`, then grinding, `t` sampled
columns, the Merkle multi-opening and both polynomials on every opened
column. The tensor block (`w`) costs `O(log k)` per column through
`Σ_c eq(r_lo, c) x^{k−1−c} = x^{k−1} Π_t((1 − r_t) + r_t x^{−2^{lo−1−t}})`.
Shape: `k` is the power of two minimising the estimated size subject to
`k > t` (the padding and `m_b` cover every opened column).

Policy (`veil::protocol::admit`): parameters in range (rate `2^-3 … 2^-8`,
grinding ≤ 30, target 128 … 256) and the proven bound
`hiding::Config::security_bits ≥ 128`. Default: rate 1/32, 16 grinding bits.

Body (`ZHVEIL01`): root, `Σ g1`, the outer rounds (`log m × (d + 1)` Fp3,
without `c_1`), the `t` evaluations, `Σ g2`, the inner rounds (`ℓ × 2`), the
opening (parameter header, `μ`, `2k` + `3k − 1` Fp3 coefficients, the nonce,
the opened count, the columns with their salts, the Merkle siblings). Every
count but the opened columns and the siblings comes from the verifier's
shape; the proof must be consumed exactly.

Zero knowledge, as proven in the [soundness ledger](soundness.md) § zk:
honest-verifier statistical zero knowledge in the random-oracle model, and
zero knowledge in the ROM after Fiat–Shamir.

## Envelope

`zheng::envelope::Envelope` is the one wire form: magic `ZHENGPF1`, version
u16 little-endian (1), profile byte (0 public, 1 succinct, 2 zk,
3 state-public), then a canonical body — shortest-form LEB128 integers, field
values below p, flags 0 or 1, every length bounded statically and by the
remaining bytes before allocation, no trailing bytes. A wrong magic, an
unknown version, an unknown profile, truncation and every
noncanonical encoding fail at decoding; `Envelope::verify(state)` runs the
profile's verifier, with the state evidence for profiles 3 and 1-with-state.
The zk body starts with a scheme byte (1 = MPC-in-the-head `ZHMITH01`, 2 =
veil `ZHVEIL01`) and binds a 32-byte context through `zk_statement_bytes`
(veil keys it with the verifying key's digest); `envelope::prove_zk` builds
a veil envelope. The state-public body is the execution statement, the root
limbs, the root-in-subject flag and the reads.

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
