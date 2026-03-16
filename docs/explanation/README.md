# zheng explanations

conceptual documentation — why zheng works the way it does, how proof systems compose, and what makes [[Whirlaway]] the right architecture for [[cyber]].

these pages illuminate the design. for formal definitions, see reference/. for the hash primitive, see [[hemera]]. for the VM whose traces we prove, see [[nox]].

## reading path

```
why-zheng ─── the-name
    │
stark ─── CCS ─── landscape
    │
    ├── sumcheck ──────────────┐
    ├── polynomial-commitments │
    └── fri-to-whir ───────────┤
                               │
    superspartan ──────────────┤
                               │
    whirlaway ─────────────────┘
        │
    trace-to-proof
        │
    ├── recursion
    ├── security
    ├── performance
    └── bbg-integration
```

start with vision, then foundations and landscape orient the design space. core protocols provide the cryptographic primitives. architecture shows how the pieces compose. powers describe what the composed system achieves.

## pages

### vision

| page | topic |
|------|-------|
| why-zheng.md | why a custom proof system — what [[Whirlaway]] enables and why existing systems fall short |
| the-name.md | 証 etymology — proof as evidence, verification as witnessing |

### foundations

| page | topic |
|------|-------|
| stark.md | [[STARKs]] — arithmetization (AIR, R1CS, [[CCS]]), univariate vs multilinear, heritage |
| CCS.md | [[CCS|Customizable Constraint Systems]] — why unified constraints matter for zheng and folding |
| landscape.md | proof system taxonomy — trusted setup vs transparent, pre-quantum vs post-quantum, [[SNARKs]] vs [[STARKs]] vs [[multilinear STARKs]] |

### core protocols

| page | topic |
|------|-------|
| sumcheck.md | the heart of the system — reducing exponential verification to logarithmic via the [[sumcheck protocol]] |
| polynomial-commitments.md | the trust anchor — commit to data, prove evaluations, bind the prover to a single polynomial |
| fri-to-whir.md | the PCS evolution — [[FRI]] to [[STIR]] to [[WHIR]], each generation's insight and what it unlocks |

### architecture

| page | topic |
|------|-------|
| superspartan.md | [[CCS]] as universal constraint system — why [[AIR]] matters for [[nox]] and how [[SuperSpartan]] unifies them |
| whirlaway.md | how the pieces compose — [[sumcheck protocol]], [[WHIR]], and [[SuperSpartan]] into one proof system |
| trace-to-proof.md | from [[nox]] execution trace to zheng proof — the concrete pipeline |

### powers

| page | topic |
|------|-------|
| recursion.md | recursive composition — [[IVC]], [[folding]], O(1) verification regardless of computation depth |
| security.md | hash-based assumptions — post-quantum guarantees, concrete security levels, no trusted setup |
| performance.md | prover costs, verifier costs, proof sizes — comparisons with [[Plonky3]], [[Binius]], [[Stwo]] |
| bbg-integration.md | shared WHIR primitives between proofs and [[BBG]] state — EdgeSets, LogUp, batch verification |

## see also

- [[nebu]] — the [[Goldilocks field]] underlying all arithmetic
- [[hemera]] — the hash primitive used in every Merkle tree and commitment
- [[nox]] — the VM whose execution traces zheng proves
- [[BBG]] — the state database whose integrity proofs zheng generates
