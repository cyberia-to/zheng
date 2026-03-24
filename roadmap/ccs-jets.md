---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: draft
date: 2026-03-24
---
# CCS jets — constraint-level optimization for state transitions

## the problem

[[nox]] jets optimize EXECUTION — the program runs fewer steps. but every state transition still produces a full nox trace that [[SuperSpartan]] proves row by row. a user-defined table transition that runs a 500-step nox program generates 500 trace rows × ~8 constraints per row = ~4,000 constraints. this is correct but wasteful when the transition follows a common pattern (insert, update, transfer) that can be expressed in 3-10 constraints directly.

the gap: there is no mechanism to optimize PROVING the way nox jets optimize COMPUTING.

## the idea

CCS jets recognize STATE TRANSITION PATTERNS and replace the generic nox execution proof with a direct CCS encoding. the prover bypasses the nox trace entirely for recognized patterns — the constraint system expresses the invariant directly.

```
generic path:
  nox program → N trace rows → SuperSpartan sumcheck over N rows
  cost: ~4K-50K constraints (depends on program)

CCS jet path:
  transition pattern recognized → direct CCS encoding
  cost: ~3-10 constraints (the algebraic invariant itself)
```

the semantic contract is identical to nox jets: the CCS jet produces the same result as running the nox program. if the jet is removed, the system falls back to generic nox proof. CCS jets are OPTIMIZATION — correctness is unchanged.

## two-level jet system

| level | what it optimizes | mechanism | example |
|---|---|---|---|
| nox jet | execution speed | formula hash → fast implementation | hemera hash: 2,800 → 300 patterns |
| CCS jet | proof size | transition pattern → direct CCS encoding | token transfer: 4,000 → 3 constraints |

nox jets and CCS jets are independent:
- nox jet without CCS jet: fast execution, normal-size proof
- CCS jet without nox jet: normal execution, small proof
- both: fast execution AND small proof
- neither: generic everything (correct but slow)

## the genesis insight

the 12 [[BBG]] dimensions (particles, axons, neurons, etc.) are HAND-WRITTEN CCS jets. the ~3,200 constraint encoding for a [[cyberlinks|cyberlink]] IS a CCS jet for the pattern "update 4-5 polynomial dimensions with conservation and authorization."

the difference between a "genesis table" and a "user table" is not architectural — it is whether a CCS jet exists for the transition pattern:

```
genesis table (particles, axons):    CCS jet exists    ~3.2K constraints
user table (no jet):                 generic nox proof  ~10-50K constraints
user table (jet added later):        CCS jet exists    ~3-10K constraints
```

the 12 genesis dimensions are the first batch of CCS jets. new jets can be added without changing the architecture.

## jet recognition hierarchy

three levels, from most to least specific:

### level 1: exact formula match

```
recognition: H(transition_formula) → specific CCS encoding
mechanism:   identical to nox jets — formula hash lookup

example:
  H(cyberlink_transition_formula) → cyberlink_ccs_jet
  the cyberlink CCS jet encodes:
    BBG_poly(particles, p, t) += energy_delta
    BBG_poly(axons_out, p, t) ← updated
    BBG_poly(axons_in, q, t) ← updated
    BBG_poly(neurons, ν, t) -= focus_cost
    conservation: Σ energy_in = Σ energy_out
  total: ~3,200 constraints (hand-optimized)

properties:
  maximum optimization
  zero generality (one formula, one jet)
  requires manual CCS encoding per formula
```

### level 2: pattern match

```
recognition: transition follows a known template
mechanism:   analyze nox formula structure → match template → parameterize jet

templates:

  TRANSFER(source, target, amount, conservation_invariant):
    source' = source - amount
    target' = target + amount
    amount > 0
    Σ unchanged
    3 constraints regardless of table schema

  INSERT(table, key, value, uniqueness_check):
    key ∉ table (PCS opening shows no existing value)
    value matches schema
    commitment extended at new point
    ~5 constraints

  UPDATE(table, key, old_value, new_value, authorization):
    key ∈ table (PCS opening shows existing value)
    old_value matches committed
    new_value replaces old
    authorization valid (signature or nox program)
    ~5 constraints

  DELETE(table, key, authorization):
    key ∈ table
    nullifier added
    authorization valid
    ~4 constraints

  AGGREGATE(table, key, delta, accumulator):
    accumulator' = accumulator + delta
    delta authorized
    ~2 constraints

properties:
  moderate optimization (~3-10 constraints for any matching pattern)
  moderate generality (5 templates cover ~90% of database operations)
  automatic recognition from formula analysis
```

### level 3: type-based

```
recognition: transition operates on a typed table with known schema
mechanism:   schema-aware generic CCS encoding

  given schema S = { key: CID, fields: [(name, type)] }:
    read:   O(|fields|) constraints (one PCS opening per field)
    write:  O(|fields|) constraints (one evaluation update per field)
    verify: O(|authorization|) constraints

properties:
  minimal optimization (proportional to schema size)
  maximum generality (any table, any schema)
  automatic from schema declaration
```

### fallback: generic nox proof

```
no pattern matched → full nox execution trace → SuperSpartan proof
cost: program-dependent (~4K-50K constraints)
always correct, always available
```

## cost comparison

```
transition type          generic nox    level 3    level 2    level 1
                         (fallback)     (typed)    (pattern)  (exact)
──────────────────────   ───────────    ───────    ─────────  ────────
token transfer           ~8K            ~20        3          3 (hand)
insert record            ~6K            ~15        5          — (use L2)
update field             ~4K            ~10        5          — (use L2)
aggregate increment      ~4K            ~8         2          — (use L2)
cyberlink (genesis)      ~50K           ~30        ~15        3.2K → 3.2K
complex custom logic     ~50K           ~30        —          — (no pattern)
```

for level 2 patterns: user tables achieve ~3-10 constraints per operation. this is GENESIS-TABLE EFFICIENCY for standard database operations — without any hand-optimization.

## the jet registry

```
ccs_jet_registry: {
  level_1: HashMap<H(formula), CCSEncoding>,      // exact formula → encoding
  level_2: Vec<(Template, ParamExtractor, CCSGenerator)>,  // pattern → parameterized encoding
  level_3: SchemaAnalyzer,                          // schema → typed encoding
}
```

the registry is a protocol constant for level 1 (like nox jets — adding a new exact jet is a protocol upgrade). levels 2 and 3 are ALGORITHMIC — they derive CCS encodings from formula structure or schema, so they extend automatically when new patterns or types are introduced.

this means: level 2 and 3 CCS jets need NO protocol upgrade. a user deploys a nox program, the system analyzes it, recognizes TRANSFER or INSERT template, and uses the optimized encoding automatically.

## interaction with [[proof-carrying computation|proof-carrying]]

proof-carrying folds each nox reduce() step into the [[HyperNova]] accumulator (~30 field ops per step). CCS jets change this:

```
proof-carrying WITHOUT CCS jet:
  each nox step → fold trace row → ~30 field ops per step
  500-step transition → 500 folds = 15,000 field ops + decider

proof-carrying WITH CCS jet (level 2):
  recognize pattern → emit ~5 CCS constraints directly
  fold: 1 fold of the 5-constraint instance = ~30 field ops
  total: ~30 field ops + decider

speedup: 500× per transition (500 folds → 1 fold)
```

CCS jets make proof-carrying dramatically more efficient for recognized patterns. the fold cost is per-INSTANCE, not per-ROW. a CCS jet collapses the entire transition into one instance.

## interaction with [[BBG]] extensible tables

CCS jets are what make user-defined tables practical:

```
without CCS jets:
  user table transition = generic nox proof = 10-50K constraints
  genesis tables = hand-optimized = 3.2K constraints
  15× penalty for user tables → nobody uses them

with CCS jets:
  user table using TRANSFER pattern = 3 constraints (level 2 jet)
  user table using INSERT pattern = 5 constraints (level 2 jet)
  genesis tables = 3.2K constraints (level 1 jet)
  user tables can be CHEAPER than genesis tables for simple operations
```

the database extensibility question is answered: any nox program defines a table, CCS jets make standard operations on that table as cheap as genesis tables. complex custom logic falls back to generic proof. the user pays for COMPLEXITY, not for being "non-genesis."

## open questions

1. **pattern analysis**: how does the system analyze a nox formula to determine which level-2 template it matches? this is a form of program analysis — extracting the transition pattern from the formula AST. false negatives (missing a pattern) are safe (fallback to generic). false positives (matching wrong pattern) would be unsound. the analysis must be conservative.

2. **jet soundness**: each CCS jet must be EQUIVALENT to the nox program it replaces. for level 1 (exact match), this is verified manually (like nox jets). for level 2 (pattern match), the template must be proven correct for all parameter instantiations. for level 3 (type-based), the schema-aware encoding must handle all valid schemas.

3. **jet composition**: can CCS jets compose? if a transition matches TRANSFER + INSERT (transfer value and create a receipt), can both jets fire? or must the composition be a separate jet? nox jets don't compose — each formula matches one jet. CCS jets may benefit from composition since database operations naturally combine.

4. **dynamic jet registry**: level 1 jets are protocol constants. could they be governed on-chain? a polynomial commitment over the jet registry, updatable by governance. this would allow the community to add CCS jets for popular user tables without hard forks.

5. **jet verification cost**: verifying that a CCS jet was correctly applied (not just that the CCS is satisfied) requires checking the pattern match. this is a meta-proof: "this transition matches template T, and template T is sound." the cost of pattern verification must be less than the savings from using the jet.

see [[jets]] for the nox jet mechanism, [[SuperSpartan]] for CCS satisfaction, [[proof-carrying]] for fold integration, [[BBG]] architecture for genesis table CCS encodings
