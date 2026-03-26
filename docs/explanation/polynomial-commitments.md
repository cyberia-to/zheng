# polynomial commitment schemes

a [[polynomial commitment scheme]] is the trust anchor of any proof system. it lets a prover commit to a polynomial — lock it in, irrevocably — and later prove facts about that polynomial without revealing the whole thing. in [[zheng]], the committed polynomial encodes the entire [[nox]] execution trace. the proof reduces to a single opening of that commitment.

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

the [[Schwartz-Zippel lemma]] says: two distinct polynomials of degree d can agree on at most d points. if f and g are different polynomials of degree at most d, and you pick a random point r from a field of size p, the probability that f(r) = g(r) is at most d/p. over the [[Goldilocks field]] where p = 2^64 - 2^32 + 1, this probability is negligible for any practical degree.

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

FRI-based schemes ([[FRI]], [[STIR]], [[WHIR (legacy)]]) and Brakedown need only collision-resistant hash functions. no trusted setup, no pairings, no quantum vulnerability. the verifier is polylogarithmic — fast enough for recursive composition. the tradeoff is larger proof sizes compared to KZG, though recent advances have narrowed the gap dramatically.

## Brakedown in zheng

[[zheng]] uses recursive Brakedown as its polynomial commitment scheme. Brakedown is Merkle-free, eliminating the Merkle tree overhead that dominated earlier FRI-family schemes.

the pipeline:

```
nox execution trace
    ↓
encode as multilinear polynomial f over Goldilocks
    ↓
Brakedown.commit(f) → commitment C
    ↓
SuperSpartan sumcheck reduces all constraints
    to one evaluation query: f(r₁, ..., rₖ) = ?
    ↓
Brakedown.open(f, r) → (y, π)
    ↓
verifier checks: Brakedown.verify(C, r, y, π)
```

one commitment. one opening. one proof. the [[sumcheck protocol]] inside [[SuperSpartan]] does the structural work of reducing a million constraint checks to a single evaluation. Brakedown handles just that one evaluation — but handles it with full soundness, no trusted setup, and post-quantum security.

## the lens as unified primitive

Brakedown unifies proximity testing (is the committed function close to a low-degree polynomial?) and evaluation proving (does the polynomial evaluate to y at point r?) into a single protocol. [[zheng]] needs exactly one cryptographic primitive for commitments.

the proximity test ensures the prover actually committed to a low-degree polynomial (not arbitrary noise). the evaluation proof ensures the opened value matches the commitment. both guarantees come from the same protocol.

## the commitment as interface

from the perspective of the rest of the [[zheng]] stack, a polynomial commitment scheme (PCS) — called a lens in zheng — is an interface with three methods: commit, open, verify. [[SuperSpartan]] calls commit once at the start and open once at the end. the [[sumcheck protocol]] runs in between, oblivious to which lens sits underneath.

this abstraction is deliberate. when the lens improves — from [[FRI]] to [[STIR]] to [[WHIR (legacy)]] to recursive Brakedown — everything above stays the same. the IOP layer, the constraint system, the VM trace format, the recursive verifier: none of them change. only the implementation behind commit/open/verify changes, and proof sizes shrink, and verification gets faster.

the commitment scheme is the trust anchor because it is the only component that touches the real world — the only place where computational hardness assumptions enter. everything else in the proof system is information-theoretic, secured by the mathematics of polynomials and probability. the lens is where cryptography meets algebra, and Brakedown sits at that junction.

## what the verifier trusts

when a verifier accepts a [[zheng]] proof, the chain of trust is:

```
"the nox trace is valid"
    ← SuperSpartan reduced all constraints to one evaluation
    ← sumcheck proved the reduction honestly (Schwartz-Zippel)
    ← Brakedown proved the evaluation matches the commitment (collision resistance of Hemera)
```

the only cryptographic assumption is that [[Hemera]] ([[Poseidon2]] over [[Goldilocks]]) is collision-resistant. everything else — the sumcheck soundness, the constraint reduction, the Schwartz-Zippel bound — is pure mathematics. the polynomial commitment scheme concentrates the trust into one clean assumption. that assumption is post-quantum, requires no ceremony, and rests on decades of hash function analysis.
