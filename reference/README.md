# zheng reference

formal specifications for the zheng proof system. each page defines one protocol component with enough precision for independent implementation.

zheng is pre-implementation. specifications will be written alongside the code — each page moves from planned to draft to stable as the corresponding module solidifies. for design rationale behind these choices, see docs/explanation/.

## reading order

read [[iop]] and [[sumcheck]] first — they define the core interactive oracle proof. then [[pcs]] and [[transcript]] provide the commitment and non-interactivity layers. [[constraints]] bridges [[nox]] traces into the proof system. [[verifier]] and [[recursion]] define what a completed proof looks like and how proofs compose. [[api]] is the surface that [[nox]] and [[BBG]] call.

## specification pages

| page | scope | status |
|------|-------|--------|
| iop.md | [[SuperSpartan]] interactive oracle proof specification — CCS instance format, round structure, verifier checks | planned |
| pcs.md | [[WHIR]] polynomial commitment specification — commit, open, verify, Reed-Solomon proximity parameters | planned |
| sumcheck.md | [[sumcheck protocol]] specification — round messages, verifier algorithm, degree bounds, batching | planned |
| transcript.md | Fiat-Shamir transcript construction — absorb semantics, squeeze semantics, [[hemera]] sponge binding | planned |
| constraints.md | [[AIR]] constraint definitions for [[nox]] patterns — transition constraints, boundary constraints, degree analysis | planned |
| verifier.md | standalone verifier specification — inputs, outputs, acceptance criteria, error probabilities | planned |
| recursion.md | recursive composition protocol — accumulation scheme, [[IVC]] chain structure, base case | planned |
| api.md | public API surface — prove, verify, recursive_verify, constraint registration | planned |

## see also

- [[aurum]] reference — [[Goldilocks field]] arithmetic specification
- [[hemera]] reference — hash primitive specification (the sponge zheng calls)
- [[nox]] reference — VM instruction set (the traces zheng proves)
