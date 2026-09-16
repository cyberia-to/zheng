# Private execution and state: full release requirements

Status: implementation assessment, 2026-09-11. Stateless private execution now
has a functional Triton-backed proof path through Trisha and Joy. The backend is now pinned Triton7, incorporating the AIR soundness fixes
missing from the former Triton2 backend. Joy's full60-test release suite passes
with real private execution/state proofs (`/tmp/joy-triton7-full-release.log`).
Earlier Triton2 timings below are historical and do not certify the new release.
[Upstream changelog](https://github.com/TritonVM/triton-vm/blob/v7.0.0/CHANGELOG.md).
Private queries over authenticated public BBG tables are implemented in JOYZK003;
the private query coordinates are constrained inside that same proved CCS. Full supported
execution and authenticated private state remain release requirements. This
document records implementation evidence and remaining security arguments;
it does not declare the full release complete.
The current implementation is described in [public execution](public-execution.md)
and specified in [execution](../specs/execution.md).

## What the existing proof establishes

`rs/src/execution/proof.rs` authenticates the complete witness through Lens
`PublicTensor`, checks every verifier-derived CCS row exactly, and pins the
constant, public inputs and output. Full disclosure and linear verification are
essential to this path's current soundness argument. Removing disclosure also
removes the exact check on which that argument depends.

The local Spartan implementation sends witness-dependent sumcheck polynomials
and polynomial evaluations. Its transcript and witness commitments provide no
complete zero-knowledge construction. Replacing its PCS with a hiding PCS
alone leaves these other messages exposed. Zheng's current direct dependencies
provide no reviewed private execution backend or complete blinding protocol.

The bounded compiler in `rs/src/execution/relation.rs` now supports atom call
witnesses and checks their continuation under the selected branch. Dynamic
continuations and incompatible branch shapes remain outside this relation;
private queries over authenticated public tables now have explicit selector constraints.
Private database commitments require a separate hiding authentication protocol. Register traces
alone do not authenticate the noun arena, its pointers or callable formulas.
A private proof for all supported nox programs therefore requires both a
complete execution relation and a complete zero-knowledge protocol.

## Cryptographic requirements

Goldilocks has modulus `p = 2^64 - 2^32 + 1`. Ordinary degree-d sumcheck over
this field has error terms proportional to `d * rounds / p`; a 128-bit hash
does not make those terms 128-bit. A native succinct implementation needs a
reviewed extension-field or repetition construction and a security calculation
covering every sumcheck, lookup, PCS query and Fiat–Shamir reduction together.
A cubic extension can provide a larger challenge space, but introducing it
requires compatible polynomial evaluation and opening protocols throughout.

`rs/src/transcript.rs::squeeze_challenge` reduces one hash-derived u64 modulo
p. Its comment that approximately 2^-32 sampling bias is negligible at
128-bit security is unjustified. Use a protocol-defined unbiased sampler,
version the transcript, and review the full soundness analysis. Changing this
sampler alone does not solve the small-field or privacy problems.

All witness-dependent protocol messages need the selected upstream protocol's
hiding construction, including sumcheck rounds and openings. Randomness must
come from a cryptographic random source, with fresh prover randomness and
no deterministic production seed. A security review must cover transcript
ordering, domain separation, canonical encodings, malformed proofs, query
sampling, opening consistency and the exact code revision shipped.

## Available implementation routes

| Route | Available dependency | Required local work | Principal limitation |
|---|---|---|---|
| Execute the real nox interpreter inside a Rust zkVM guest | New `risc0-zkvm`, `risc0-build` and guest toolchain | Guest-compatible arena/providers; verify state and call witnesses inside guest; bind public journal and image ID | Additional backend; security parameters and resources require qualification |
| Implement nox semantics inside Triton VM | Existing Trisha `triton-vm` 7.0.0 | Complete interpreter in TASM, arena/memory semantics, Hemera and state authentication | Substantial new interpreter with differential verification |
| Native nox AIR with a reviewed hiding STARK stack | New Plonky3 stack or another qualified backend | Universal relation, lookup/memory arguments, hiding integration and security review | A toolkit supplies primitives, not a complete reviewed nox prover |
| Convert the complete relation to upstream Spartan/Nova | New `libspartan` / `nova-snark` and curve dependencies | Goldilocks arithmetic gadgets, R1CS lowering, universal execution relation | Different field and assumptions; upstream review status must be qualified |

RISC Zero supports Rust guests and binds the journal to a verified image ID.
Its current README reports perfect zero knowledge and **98 bits of conjectured
security with default parameters**. Production verification must disable dev
mode. A Groth16 receipt introduces different assumptions from a STARK receipt;
receipt kind and parameters must be explicit. These defaults do not establish
a 128-bit transparent Zheng release. [Upstream implementation and security](https://github.com/risc0/risc0),
[upstream audit collection](https://github.com/risc0/rz-security).

Triton uses Goldilocks with cubic-extension challenges and a randomized ZK
prover. Its program attestation binds program digest, public input and output.
Reusing this backend requires proving the nox interpreter itself, including
providers; compiling an unrelated source program to Triton does not establish
nox semantics. [Triton specification](https://triton-vm.org/spec/),
[program attestation](https://triton-vm.org/spec/program-attestation.html).

The original local Trisha lock contains Triton VM2.0.0, fixing the earlier FRI
randomness vulnerability. That fix is insufficient: later AIR fixes require a
Triton7 upgrade and new proof-version acceptance. Historical audit coverage of
0.42.1 does not certify this integration. Rebuild and reprove after migration.
[RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0004.html),
[Triton audit report](https://neptune.cash/file-uploads/Triton_VM_Code_Final_Publishable_Audit_Hridam_Basu.pdf).

Plonky3 has a `HidingFriPcs` implementation. The earlier Least Authority review
covered a non-hiding configuration and recommended review of added hiding and
recursion. A new composition cannot inherit a zero-knowledge audit merely from
using these crates. [Hiding PCS source](https://raw.githubusercontent.com/Plonky3/Plonky3/main/fri/src/hiding_pcs.rs),
[auditor report](https://leastauthority.com/blog/audit-of-plonky3/).

Microsoft's Spartan uses curve-based commitments and explicitly identifies
its implementation as unaudited. Nova supplies an upstream folding/compression
construction with its own field cycles and zero-knowledge mechanism. Local
Goldilocks CCS cannot be copied directly into a different scalar field:
modular multiplication needs constrained quotient and canonical range gadgets,
for example `a*b = c + k*p`, with bounds preventing wraparound in that field.
[Spartan implementation](https://github.com/microsoft/Spartan),
[Nova implementation](https://github.com/microsoft/Nova).

## Concrete reuse: prove a deterministic CCS checker in Triton

The Trisha checker implementation now proves supplied Zheng CCS relations directly.
`trisha/rs/ccs.rs` contains the generator, bounded envelope codec and genuine
Triton proving/verification. Four tests pass, including a real randomized STARK
round trip and forged claim/relation rejection. One debug smoke measured
594,224 proof bytes and 1.083 seconds proving a 75-line square checker; these
are single-run observations, not application benchmarks. Joy stateless and public-table private-query integration is implemented; full dynamic
execution and private-database coverage remain release gates.

The integration route can reuse the complete Zheng relation directly.
Zheng derives a canonical CCS and public-coordinate mapping; a Trisha-owned
adapter deterministically generates a Triton program that checks that CCS.
Joy orchestrates the two through `rs/zk_execution.rs`. Its current `JOYZK003`
artifact contains the public statement and opaque STARK envelope. It
requires the `zheng-ccs-triton7-zk-v2` backend and rejects older envelopes. `--secret`
automatically selects this backend; `--zk` also selects it without secret
inputs. Prover/Verifier traits use the same dispatch. A compiled source with
two divine inputs, multiplication and public addition proved successfully:
a single debug run produced an 807,535-byte artifact in 40.408 seconds, and
independent decoding/verification rejected altered IO, program, cost, budget
and compilation identity. These are smoke measurements, not release benchmarks.
Zheng needs no Triton dependency. This is an explicit
Triton-backed private proof format whose semantic relation is owned by Zheng.

The verifier independently derives the relation from the requested statement
and generates the expected checker program digest. It verifies a Triton claim
with that digest and the exact expected public inputs/outputs. Neither a CCS
nor its claimed digest supplied by the prover is authoritative. Generator
version, target/ABI identity and public-coordinate ordering must be bound.
The current direct relation uses constant coordinate zero; the generic
`CCSWitness` comment describes a different layout, so use the relation's
explicit mapping rather than inferring coordinates from that comment.

The checker reads each private witness column exactly once with `divine`,
stores it in initialized RAM, pins the constant and public coordinates, and
checks every row of `sum_j coeff[j] * product_i(M[i] * z)[row] == 0`.
It must use one consistent stored value for all occurrences of a column.
Duplicated matrix entries accumulate, repeated multiset members multiply
repeatedly, and an empty product equals one. Reject malformed dimensions,
indices, encodings and excessive allocations before program generation.
Initialize every matrix accumulator explicitly; nondeterministic initial RAM
must never supply unconstrained computed values. Successful execution asserts
all rows and halts. The checker must not output private columns or matrix sums.

Goldilocks arithmetic is native to both systems, so this approach avoids
nonnative arithmetic and Zheng's small-field sumcheck entirely: every relation
row is computed inside the upstream ZK VM. Its privacy and succinct soundness
come from Triton's randomized proof system, with its actual pinned parameters.
Prover-only CCS validation remains a useful diagnostic but provides no security
unless the generated program performs the same complete checks.

With n columns, K matrices, E sparse entries, m rows and total term degree D,
a checker caching each matrix dot product once per row takes
O(n + E + m*(K + D)) VM operations up to instruction expansion, and O(n + K)
RAM. An unrolled program has comparable size. Regeneration and program hashing
are linear work for the verifier; cache only under a fully bound relation and
generator identity. A generic checker could reduce code size but would need
authenticated coefficient input, so deterministic unrolling is the simpler
first implementation. VM proof cost includes memory, instruction and hashing
trace overhead; actual proof bytes/time/memory require measurement.

This route proves exactly the derived CCS. It does not fill missing call,
state, dynamic continuation or private branch constraints automatically.
State openings must be checked inside that relation or inside the checker
using sound state commitments. An external public check cannot authenticate
a secret lookup whose value is never linked to the proved computation.
Test malicious private columns, public-coordinate substitutions, omitted rows,
changed coefficients and proof-supplied checker digests with independent proof
construction. Keep witness files and VM debug traces out of public artifacts.

## State authentication without recursive Tensor constraints

A public certificate can verify authenticated state directly alongside its
exact execution checks. It need not recursively prove its own opening verifier.
The statement must name the complete trusted state root and the verifier must:

1. Bind each namespace's dimension commitment to that root, using canonical
   root leaves, dimensions, lengths and empty-dimension rules.
2. Derive the Boolean evaluation point from the executed key and dimension
   shape. Verify the opening for precisely that point and returned value.
3. Pin that value to the actual executed lookup result. Check the consumed
   lookup sequence, active branches and exact count; reject unused or missing
   witnesses. A prover-supplied list of unrelated valid openings is insufficient.
4. Authenticate call formulas and their requested identities similarly.
5. For state transitions, verify the update rules and resulting root as well
   as the read relation. A read proof does not establish a state transition.

`bbg/rs/src/query.rs::verify_opening` checks a polynomial opening but does not
itself bind the namespace to the root. Its provider's `_commitment` argument
is ignored. These checks must live in the accepting verifier, and in the
proved guest/circuit for private execution. A root supplied solely by the
prover proves consistency relative to that root; an application must compare
it with its authenticated checkpoint or consensus state.

The earlier commitment and key-encoding findings are corrected in the current
working tree. Lens commitment version2 includes the systematic raw input prefix;
BBG dimension version2 uses eight u32 limbs for arbitrary32-byte keys and two
u32 limbs for arbitraryu64 values, with version/length/count headers. Public
state certificates authenticate full dimension tables against the14-leaf root.
Old roots must be recomputed; old opening payloads cannot be reinterpreted as v2.
Standalone public query version3 carries bounded authenticated context and pins
the exact entity key and primary cell. Private contextless queries do not acquire
additional table disclosure or claim authenticated public root/key semantics.

Joy requires all10 public namespaces and at most2048 total fields for hidden
queries. Zheng constrains the selected namespace/index/value and all four actual
root limbs inside the checker. The public tables and root are independently
authenticated before verifier relation derivation. A public context check alone
would not suffice; the hidden selection constraints provide the missing link.
Actual CLI proof generation and fresh verification pass without a private key
on the verifier side. This proves queries over public data, not private BBG data.

## Implementation sequence and release evidence

First specify the complete public statement: protocol/version, backend and
verifier identity, program and target-package identity, public IO, authenticated
initial/final state roots, call policy, and declared bounds. Specify which
lengths, costs and access patterns are public. Private subject values and
witnesses belong only to the prover input, never proof headers or logs.

Next implement a bounded universal nox evaluator relation. It must cover noun
allocation and structural equality, canonical atoms, program fetch, dynamic
continuations, frame/call-stack transitions, all reduction semantics, cost
reservation and halting, authenticated calls and state reads/updates. Inactive
branches must not impose live inverse or provider constraints. A zkVM guest
can reuse the interpreter; a native AIR needs explicit memory and transition
arguments. Keep an independent evaluator for differential tests.

Implement the deterministic CCS-to-Triton checker route first, extending the
verifier-derived CCS to the complete supported nox semantics. Measure checker
size and proof costs before optimizing its encoding. A Rust zkVM guest remains
an alternative if relation construction becomes the limiting engineering cost;
its security parameters and dependencies require separate qualification.

Then integrate the selected upstream private proof protocol without local
cryptographic shortcuts. Keep public and private proof formats distinct,
reject cross-format downgrade, bind every statement field and provider result,
and verify independently in a fresh process with only the public statement.
Any optional recursion must preserve the same statement and verified relation.

Release requires adversarial tests for changed program/IO/budget, wrong roots,
namespace/key/value swaps, missing/extra/reordered openings, forged calls,
noncanonical limbs, malformed arenas, branch-dependent calls and state,
secret-dependent division and every supported dynamic opcode. Include hostile
proof constructors outside the honest prover. Test rejected private inputs on
public-only APIs until the private backend is actually integrated.

Measure native runtime, proved steps, peak prover memory, proof bytes,
proving/verification time and installation footprint on representative compiled
programs, with increasing execution and state sizes. Full-witness public
verification costs at least linear work in the authenticated witness and state
material; zkVM cost follows guest instruction count, and a native relation's
cost follows its trace and constraint sizes. Only the recorded small private smoke cases have been measured; no application
throughput or completion estimate is claimed. Publish exact revisions, parameters and fresh-process measurements.

Finally obtain independent review of the complete relation, commitment format
and selected protocol integration; resolve findings and rerun release gates.
Passing public-certificate tests, installing a ZK library, or proving a small
arithmetic example does not complete the requested private/state release.
