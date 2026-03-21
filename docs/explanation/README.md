# zheng explanations

conceptual documentation — why zheng works the way it does, how proof systems compose, and what makes [[Whirlaway]] the right architecture for [[cyber]].

these pages illuminate the design. for formal definitions, see reference/. for the hash primitive, see [[hemera]]. for the VM whose traces we prove, see [[nox]].

## reading path

```
                  ╭──── vision ────╮
                  │                │
     [[zheng/docs/explanation/why-zheng|why-zheng]]        [[zheng/docs/explanation/the-name|the-name]]
                  │
           ╭──── foundations ────╮
           │         │           │
     [[zheng/docs/explanation/stark|stark]]       [[zheng/docs/explanation/CCS|CCS]]     [[zheng/docs/explanation/landscape|landscape]]
           │
    ╭──── core protocols ────╮
    │           │             │
 [[zheng/docs/explanation/sumcheck|sumcheck]]  [[zheng/docs/explanation/polynomial-commitments|poly-commits]]  [[zheng/docs/explanation/fri-to-whir|fri-to-whir]]
    ╰───────────┬─────────────╯
                │
       [[zheng/docs/explanation/superspartan|superspartan]]
                │
          [[zheng/docs/explanation/whirlaway|whirlaway]]
                │
       [[zheng/docs/explanation/trace-to-proof|trace-to-proof]]
                │
         ╭──── powers ────╮
         │    │     │      │
  [[zheng/docs/explanation/recursion|recursion]] │ [[zheng/docs/explanation/performance|performance]]
       [[zheng/docs/explanation/security|security]]     │
            [[zheng/docs/explanation/bbg-integration|bbg-integration]]
```

### vision

[[zheng/docs/explanation/why-zheng|why-zheng]] → [[zheng/docs/explanation/the-name|the-name]]

### foundations

[[zheng/docs/explanation/stark|stark]] → [[zheng/docs/explanation/CCS|CCS]] → [[zheng/docs/explanation/landscape|landscape]]

### core protocols

[[zheng/docs/explanation/sumcheck|sumcheck]] · [[zheng/docs/explanation/polynomial-commitments|polynomial-commitments]] · [[zheng/docs/explanation/fri-to-whir|fri-to-whir]]

### architecture

[[zheng/docs/explanation/superspartan|superspartan]] → [[zheng/docs/explanation/whirlaway|whirlaway]] → [[zheng/docs/explanation/trace-to-proof|trace-to-proof]]

### powers

[[zheng/docs/explanation/recursion|recursion]] · [[zheng/docs/explanation/security|security]] · [[zheng/docs/explanation/performance|performance]] · [[zheng/docs/explanation/bbg-integration|bbg-integration]]

## pages

### vision

| page | topic |
|------|-------|
| [[zheng/docs/explanation/why-zheng|why-zheng]] | why a custom proof system — what [[Whirlaway]] enables and why existing systems fall short |
| [[zheng/docs/explanation/the-name|the-name]] | 証 etymology — proof as evidence, verification as witnessing |

### foundations

| page | topic |
|------|-------|
| [[zheng/docs/explanation/stark|stark]] | [[STARKs]] — arithmetization (AIR, R1CS, [[CCS]]), univariate vs multilinear, heritage |
| [[zheng/docs/explanation/CCS|CCS]] | [[CCS|Customizable Constraint Systems]] — why unified constraints matter for zheng and folding |
| [[zheng/docs/explanation/landscape|landscape]] | proof system taxonomy — trusted setup vs transparent, pre-quantum vs post-quantum, [[SNARKs]] vs [[STARKs]] vs [[multilinear STARKs]] |

### core protocols

| page | topic |
|------|-------|
| [[zheng/docs/explanation/sumcheck|sumcheck]] | the heart of the system — reducing exponential verification to logarithmic via the [[sumcheck protocol]] |
| [[zheng/docs/explanation/polynomial-commitments|polynomial-commitments]] | the trust anchor — commit to data, prove evaluations, bind the prover to a single polynomial |
| [[zheng/docs/explanation/fri-to-whir|fri-to-whir]] | the PCS evolution — [[FRI]] to [[STIR]] to [[WHIR]], each generation's insight and what it unlocks |

### architecture

| page | topic |
|------|-------|
| [[zheng/docs/explanation/superspartan|superspartan]] | [[CCS]] as universal constraint system — why [[AIR]] matters for [[nox]] and how [[SuperSpartan]] unifies them |
| [[zheng/docs/explanation/whirlaway|whirlaway]] | how the pieces compose — [[sumcheck protocol]], [[WHIR]], and [[SuperSpartan]] into one proof system |
| [[zheng/docs/explanation/trace-to-proof|trace-to-proof]] | from [[nox]] execution trace to zheng proof — the concrete pipeline |

### powers

| page | topic |
|------|-------|
| [[zheng/docs/explanation/recursion|recursion]] | recursive composition — [[IVC]], [[folding]], O(1) verification regardless of computation depth |
| [[zheng/docs/explanation/security|security]] | hash-based assumptions — post-quantum guarantees, concrete security levels, no trusted setup |
| [[zheng/docs/explanation/performance|performance]] | prover costs, verifier costs, proof sizes — comparisons with [[Plonky3]], [[Binius]], [[Stwo]] |
| [[zheng/docs/explanation/bbg-integration|bbg-integration]] | shared WHIR primitives between proofs and [[BBG]] state — EdgeSets, LogUp, batch verification |

## see also

- [[nebu]] — the [[Goldilocks field]] underlying all arithmetic
- [[hemera]] — the hash primitive used in every Merkle tree and commitment
- [[nox]] — the VM whose execution traces zheng proves
- [[BBG]] — the state database whose integrity proofs zheng generates
