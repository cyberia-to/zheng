# polynomial commitment schemes

a [[polynomial commitment scheme]] is the trust anchor of any proof system. it lets a prover commit to a polynomial — lock it in, irrevocably — and later prove facts about that polynomial without revealing the whole thing. in [[zheng]]'s succinct profile, the committed polynomial is the witness of the relation compiled from a [[nox]] program. the proof reduces to a single opening of that commitment.

## what a commitment does

think of a commitment as a sealed envelope. the prover puts a polynomial inside, seals it, and hands the envelope to the verifier. later, the prover can open the envelope at a specific point: "the polynomial evaluates to y at point r." the verifier checks this claim against the sealed envelope. if it passes, the verifier knows the prover is telling the truth about that evaluation — without ever seeing the polynomial itself.

three operations define the scheme:

```
commit(f) → C           seal the polynomial, produce a short commitment
open(f, r) → (y, π)     evaluate at r, produce the value y and a proof π
verify(C, r, y, π) → bool   check the opening against the commitment
```

the commitment C is small — typically a single hash or group element. the polynomial f can be enormous, encoding millions of trace rows. the compression from f to C is what makes proof systems compact.

## why polynomials

why commit to polynomials specifically, rather than arbitrary data? because polynomials have a remarkable structural property that makes random spot-checks overwhelmingly powerful.

the [[Schwartz-Zippel lemma]] says: two distinct polynomials of degree d can agree on at most d points. if f and g are different polynomials of degree at most d, and you pick a random point r from a field of size p, the probability that f(r) = g(r) is at most d/p. over the [[Goldilocks field]] (p = 2^64 - 2^32 + 1) alone that is only about 2^-64 per check, too large for a 128-bit claim — so zheng draws every challenge from the cubic extension Fp3, where p³ ≈ 2^192.

this is the mathematical lever. checking one random evaluation gives overwhelming confidence about the entire polynomial. if the prover committed to a polynomial that disagrees with the claimed one at even a single point out of 2^k, a random evaluation catches the lie with probability close to 1.

this is why the [[sumcheck protocol]] reduces everything to one evaluation at one random point. one check suffices because polynomials are rigid — they cannot agree "mostly" without agreeing everywhere.

## the landscape

several families of polynomial commitment schemes exist, each with different tradeoffs.

```
scheme     setup       assumption        post-quantum    verifier
─────────────────────────────────────────────────────────────────
KZG        trusted     pairings          no              O(1) — one pairing check
IPA        none        discrete log      no              O(d) — linear in degree
FRI-based  none        hash collision    yes             O(log²d) — polylogarithmic
```

[[KZG]] is elegant: commitments are single group elements, openings are single group elements, verification is one pairing check. the cost is a trusted setup ceremony — someone generates structured reference strings, and if that someone is dishonest, soundness collapses. KZG also relies on elliptic curve pairings, which a quantum computer would break.

[[IPA]] (inner product argument) eliminates the trusted setup but pays with a slow verifier — linear in the polynomial degree. fine for small polynomials, impractical for large execution traces.

FRI-family schemes ([[FRI]], [[STIR]], [[WHIR]]) and other hash-based codes (Ligero, Brakedown) need only a collision-resistant hash. no trusted setup, no pairings, no quantum vulnerability. the tradeoff is proof size: every query carries a Merkle path, so hash-only openings are tens of kilobytes where KZG's is one group element.

## the commitment in zheng

[[zheng]] commits with Reed–Solomon codes over Goldilocks and [[hemera]] Merkle trees, and opens a multilinear polynomial at one point of the cubic extension Fp3. the succinct profile ships [[WHIR]] (rate 1/64, folding factor 4, 24 grinding bits), the winner of the phase-2 bake-off of the [[soft3/proposals/proof-system-repair|proof-system repair]]; the RS tensor code with Ligero geometry (TensorRs) lost and stays readable until phase 5. the zk profile uses a hiding Ligero-style RS tensor commitment instead (masking rows, salted leaves). the earlier expander-code (Brakedown) commitment without Merkle trees had no real opening and is retired — see [[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]].

the pipeline of the succinct profile:

```
nox program + statement
    ↓
the verifier and the prover compile the same CCS; only the witness w is committed
    ↓
lens.commit(w̃) → hemera Merkle root C
    ↓
Spartan: outer and inner sumcheck over Fp3 reduce every constraint
    to one evaluation claim: w̃(r) = v
    ↓
WHIR.open(w̃, r) → (v, π)        Merkle paths for every query
    ↓
verifier checks: WHIR.verify(C, r, v, π)
```

one commitment. one opening. the [[sumcheck protocol]] inside [[SuperSpartan|Spartan]] does the structural work of reducing every constraint check to a single evaluation; the opening handles that one evaluation with proven soundness, no trusted setup and post-quantum security. the opening dominates the proof: for the hash of one hemera call it is most of a 15,921 B proof (measured, `audit/succinct-profile-2026-10.md`).

## the lens as unified primitive

WHIR unifies proximity testing (is the committed function close to a Reed–Solomon codeword?) and evaluation proving (does the polynomial evaluate to v at point r?) into a single protocol. [[zheng]] needs exactly one cryptographic primitive for commitments.

the proximity test ensures the prover actually committed to a low-degree polynomial (not arbitrary noise). the evaluation proof ensures the opened value matches the commitment. both guarantees come from the same protocol, and both are paid for with Merkle paths: a hash commitment can be opened at one position only by authenticating that position.

## the commitment as interface

from the perspective of the rest of the [[zheng]] stack, a polynomial commitment scheme (PCS) — called a lens in zheng — is an interface with three methods: commit, open, verify. [[SuperSpartan]] calls commit once at the start and open once at the end. the [[sumcheck protocol]] runs in between, oblivious to which lens sits underneath.

this abstraction is deliberate. the phase-2 bake-off swapped TensorRs and WHIR under the same Spartan transcript and fixtures; the IOP layer, the constraint system and the statement did not change. only the implementation behind commit/open/verify changed, and with it proof size and verification time.

the commitment scheme is the trust anchor because it is the only component that touches the real world — the only place where computational hardness assumptions enter. everything else in the proof system is information-theoretic, secured by the mathematics of polynomials and probability. the lens is where cryptography meets algebra.

## what the verifier trusts

when a verifier accepts a [[zheng]] proof, the chain of trust is:

```
"the nox trace is valid"
    ← SuperSpartan reduced all constraints to one evaluation
    ← sumcheck proved the reduction honestly (Schwartz-Zippel)
    ← WHIR proved the evaluation matches the commitment (Reed–Solomon proximity + collision resistance of Hemera)
```

the only cryptographic assumption is that [[Hemera]] ([[Poseidon2]] over [[Goldilocks]]) behaves as a random oracle (collision resistance for the Merkle trees, Fiat–Shamir for the challenges); the bits each component contributes are in [[zheng/specs/soundness|the soundness ledger]]. everything else — the sumcheck soundness, the constraint reduction, the Schwartz-Zippel bound — is pure mathematics. the polynomial commitment scheme concentrates the trust into one clean assumption. that assumption is post-quantum, requires no ceremony, and rests on hash function analysis — for hemera's own parameters still young, which is why the ledger lists the hash row as conjectured.
