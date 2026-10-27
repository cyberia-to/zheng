# zheng explanations

zheng is a polynomial proof system. these documents explain the concepts, design decisions, and historical context.

for formal definitions, see specs/ (soundness per component: [[zheng/specs/soundness|specs/soundness.md]]). for the hash primitive, see [[hemera]]. for the VM whose traces we prove, see [[nox]].

## reading path

```
                              ╭──────── vision ────────╮
                              │                        │
                     [[zheng/docs/explanation/why-zheng|why-zheng]]                [[zheng/docs/explanation/the-name|the-name]]
                              │
                              │
                    ╭──────── foundations ────────╮
                    │            │               │
                 [[zheng/docs/explanation/stark|stark]]          [[zheng/docs/explanation/CCS|CCS]]         [[zheng/docs/explanation/landscape|landscape]]
                    │            │               │
                    ╰────────────┼───────────────╯
                                 │
                   ╭──────── protocols ────────╮
                   │             │             │
              [[zheng/docs/explanation/sumcheck|sumcheck]]    [[zheng/docs/explanation/polynomial-commitments|poly-commits]]    [[zheng/docs/explanation/fri-to-whir|fri-to-whir]]
                   │             │             │
                   ╰─────────────┼─────────────╯
                                 │
                                 │
                        [[zheng/docs/explanation/superspartan|superspartan]]
                                 │
                                 │
                           [[zheng/docs/explanation/whirlaway|whirlaway]]
                                 │
                                 │
                        [[zheng/docs/explanation/trace-to-proof|trace-to-proof]]
                                 │
                                 │
                    ╭──────── powers ──────────╮
                    │       │        │         │
              [[zheng/docs/explanation/recursion|recursion]]  [[zheng/docs/explanation/security|security]]  [[zheng/docs/explanation/performance|performance]]  [[zheng/docs/explanation/bbg-integration|bbg-integration]]
```

## pages

### vision

| page | topic |
|------|-------|
| [[zheng/docs/explanation/why-zheng|why-zheng]] | why a custom proof system — what zheng enables and why existing systems fall short |
| [[zheng/docs/explanation/the-name|the-name]] | 証 etymology — proof as evidence, verification as witnessing |

### foundations

| page | topic |
|------|-------|
| [[zheng/docs/explanation/stark|stark]] | STARK systems — arithmetization (AIR, R1CS, [[CCS]]), univariate vs multilinear, heritage; zheng proofs are not STARKs |
| [[zheng/docs/explanation/CCS|CCS]] | [[CCS|Customizable Constraint Systems]] — why unified constraints matter for zheng and accumulation |
| [[zheng/docs/explanation/landscape|landscape]] | proof system taxonomy — trusted setup vs transparent, pre-quantum vs post-quantum, SNARKs vs [[STARKs]] vs [[multilinear STARKs]] |

### core protocols

| page | topic |
|------|-------|
| [[zheng/docs/explanation/sumcheck|sumcheck]] | the heart of the system — reducing exponential verification to logarithmic via the [[sumcheck protocol]] |
| [[zheng/docs/explanation/polynomial-commitments|polynomial-commitments]] | the trust anchor — commit to data, prove evaluations, bind the prover to a single polynomial |
| [[zheng/docs/explanation/fri-to-whir|fri-to-whir]] | the PCS evolution — FRI to STIR to [[WHIR]], each generation's insight and what it unlocks |
| [[zheng/docs/explanation/whir|whir]] | the shipped commitment of the succinct profile — protocol, parameters, measured figures |
| [[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]] | a retired design: what it was and why it was unsound |

### architecture

| page | topic |
|------|-------|
| [[zheng/docs/explanation/superspartan|superspartan]] | [[CCS]] as universal constraint system — why [[AIR]] matters for [[nox]] and how [[SuperSpartan]] unifies them |
| [[zheng/docs/explanation/whirlaway|whirlaway]] | the architecture of the succinct profile — how [[sumcheck protocol]], [[WHIR]] and [[SuperSpartan]] compose |
| [[zheng/docs/explanation/trace-to-proof|trace-to-proof]] | from a [[nox]] program to a zheng proof: the compiled relation, the machine trace, and the retired register trace |
| [[zheng/docs/explanation/zheng-vs-starks|zheng-vs-starks]] | zheng proofs and STARK systems — shared trust model, different IOP and commitment, measured figures |

### powers

| page | topic |
|------|-------|
| [[zheng/docs/explanation/recursion|recursion]] | accumulation, IVC and wrap — how a nox run of any length becomes one proof of constant size |
| [[zheng/docs/explanation/security|security]] | hash-based assumptions — post-quantum guarantees, the soundness ledger explained, no trusted setup |
| [[zheng/docs/explanation/performance|performance]] | measured proof sizes and verification times per profile, against the goal |
| [[zheng/docs/explanation/bbg-integration|bbg-integration]] | how a proof reads [[BBG]] state — state roots, evidence, the QueryProof migration |

### tooling

| page | topic |
|------|-------|
| [[zheng/docs/explanation/zippel|zippel]] | eniac/zippel as a checker for zheng's IOPs — derived transcripts, completeness and special-soundness analyses; what it cannot cover and the first experiment |

## see also

- [[nebu]] — the [[Goldilocks field]] underlying all arithmetic
- [[hemera]] — the hash primitive used in every Merkle tree and commitment
- [[nox]] — the VM whose execution traces zheng proves
- [[BBG]] — the state database whose integrity proofs zheng generates
