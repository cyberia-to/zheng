# state operations

version: 0.1
status: canonical

## overview

state operations are the primitive instructions for modifying [[BBG]] polynomial state within a [[zheng]] proof. every state transition — cyberlink, transfer, user-defined table update — decomposes into these operations. [[CCS jets|ccs-jets]] optimize common compositions.

five operations. three groups. irreducible.

## derivation

a CCS satisfaction equation is:

$$\sum_j c_j \cdot \bigodot_{i \in S_j} M_i \cdot z = 0$$

where z is the witness vector (state values), M are constraint matrices, and the equation asserts a relationship holds.

decomposing this:
- z contains state values → accessed by **READ** and modified by **WRITE**
- $M_i \cdot z$ computes linear combinations → **ADD**
- $\bigodot$ computes Hadamard (element-wise) products → **MUL**
- $= 0$ asserts equality → **ASSERT_EQ**

these five operations ARE CCS in human-readable form. they are not an abstraction on top of CCS — they are what CCS does.

## the five operations

### group 1: state access

**READ(dimension, key) → value**

open BBG_poly at an evaluation point. returns the current value at (dimension, key, t_current).

```
semantics:    value = BBG_poly(dimension, key, t)
CCS encoding: z[i] = committed_evaluation
constraints:  1 (binding between z and polynomial)
cost:         O(1) field operations (PCS evaluation)
```

every state transition begins with reads. a cyberlink reads 5 dimensions. a transfer reads 2 balances. a query reads 1 point.

**WRITE(dimension, key, value)**

update BBG_poly at an evaluation point. sets (dimension, key, t_new) to the new value.

```
semantics:    BBG_poly(dimension, key, t+1) = value
CCS encoding: z[j] = new_value (committed in updated polynomial)
constraints:  1 (binding between z and updated polynomial)
cost:         O(1) field operations (polynomial update)
```

writes are collected per block and batch-committed via Brakedown recommit.

### group 2: verification

**ASSERT_EQ(a, b)**

assert two values are equal. THE fundamental constraint — CCS is a system of equality assertions.

```
semantics:    a = b (or equivalently: a - b = 0)
CCS encoding: M_a · z - M_b · z = 0
constraints:  1
cost:         O(1) field operations
```

every invariant check reduces to ASSERT_EQ. conservation (sum_in = sum_out). authorization (caller_id = owner_id). correctness (computed_result = claimed_result).

### group 3: arithmetic

**ADD(a, b) → c**

field addition on state values.

```
semantics:    c = a + b mod p
CCS encoding: M_a · z + M_b · z = M_c · z
constraints:  1
cost:         O(1)
```

computes new state from old. new_balance = old_balance + credit. new_energy = old_energy + delta.

**MUL(a, b) → c**

field multiplication on state values.

```
semantics:    c = a × b mod p
CCS encoding: (M_a · z) ⊙ (M_b · z) = M_c · z  (Hadamard product)
constraints:  1
cost:         O(1)
```

enables non-linear constraints. range checks (bit decomposition: b × (1-b) = 0). weighted updates (weight × delta). inverse verification (a × a⁻¹ = 1 for non-membership).

## irreducibility

remove any one operation and the system loses a capability the remaining four cannot provide:

| removed | what breaks | why irreplaceable |
|---|---|---|
| READ | can't access state | no other operation retrieves polynomial evaluations |
| WRITE | can't modify state | no other operation updates polynomial evaluations |
| ASSERT_EQ | can't verify anything | CCS without equality = no constraints |
| ADD | can't compute sums | multiplication alone can't express a + b (char ≠ 2) |
| MUL | can't compute products | addition alone can't express a × b |

five operations. none removable. none derivable from the other four.

## derived operations

every other state operation is a COMPOSITION of the five primitives. these compositions are the natural targets for [[CCS jets|ccs-jets]]:

### EXTEND(dimension, key, value)

add a new entry (key didn't exist before):

```
decomposition:
  old = READ(dimension, key)        // read current value
  ASSERT_EQ(old, 0)                 // verify key is unused (evaluates to 0)
  WRITE(dimension, key, value)      // write new value

constraints: 3
jet cost:    3 (already minimal, but the pattern is recognizable)
```

used by: new particle creation, new record commitment, new table entry.

### AUTHORIZE(caller_id, owner_id)

verify the caller has permission to modify the state:

```
decomposition:
  owner = READ(state_dimension, owner_key)   // read authorized owner
  ASSERT_EQ(caller_id, owner)                // verify caller matches

constraints: 2
```

caller_id comes from the zheng proof layer (proven via nox execution). the state transition just checks it matches the on-chain authorized owner.

### ASSERT_NEQ(a, 0)

verify a value is non-zero (non-membership check for nullifier polynomials):

```
decomposition:
  // witness b = a⁻¹ provided by zheng proof layer
  c = MUL(a, b)                    // compute a × b
  ASSERT_EQ(c, 1)                  // verify a × b = 1 → a ≠ 0

constraints: 2
```

used by: double-spend prevention (N(nullifier) ≠ 0 → not yet spent).

### RANGE(value, 0, 2^k)

verify value is within bounds:

```
decomposition:
  // bit decomposition b₀...b_{k-1} provided by zheng proof layer
  for i in 0..k:
    sq = MUL(b[i], b[i])           // b²
    ASSERT_EQ(sq, b[i])            // b² = b → b ∈ {0, 1}
  sum = ADD(b[0], ADD(MUL(b[1], 2), ADD(MUL(b[2], 4), ...)))
  ASSERT_EQ(sum, value)            // Σ bᵢ × 2ⁱ = value

constraints: 2k + 1
```

used by: balance sufficiency (amount ≤ balance), focus metering (cost ≤ remaining).

### CONSERVE(inputs, outputs)

verify economic conservation law:

```
decomposition:
  sum_in = ADD(inputs[0], ADD(inputs[1], ...))
  sum_out = ADD(outputs[0], ADD(outputs[1], ...))
  ASSERT_EQ(sum_in, sum_out)

constraints: |inputs| + |outputs| - 1
```

used by: every economic operation (transfer, cyberlink focus deduction, mint/burn).

### HASH

not a state operation. hemera hash is computed in the [[nox]] layer (pattern 15). the result enters the state transition as a proven value from the zheng proof. the state transition uses the hash as a READ/WRITE key, never computes it.

```
nox layer:    H(content) = CID        (proven by zheng)
state layer:  WRITE(particles, CID, energy_value)   (uses CID as key)
```

this separation is clean: nox handles computation (including hashing). state operations handle state modification. the zheng proof bridges them — proven computation outputs become state transition inputs.

## the parallel to nox

| | nox (computation) | state operations (transitions) |
|---|---|---|
| irreducible core | 5 structural patterns | 5 state operations |
| domain-specific | 11 patterns (field, bitwise, hash, hint) | derived operations (EXTEND, AUTHORIZE, RANGE, CONSERVE, ASSERT_NEQ) |
| total | 16 patterns | 5 core + compositions |
| jets | formula hash → fast execution | pattern match → direct CCS encoding |
| sufficiency | Turing-complete | all state transitions expressible |
| encoding | 4-bit tag | CCS matrix structure |

nox's 5 structural patterns (axis, quote, compose, cons, branch) make computation Turing-complete. the 5 state operations make state transitions universally expressible. domain-specific operations (nox patterns 5-16, state EXTEND/AUTHORIZE/etc.) are compositions optimized by jets.

## CCS jet hierarchy (revisited)

the [[CCS jets|ccs-jets]] hierarchy maps directly to composition depth:

```
level 1 (exact match):   hand-optimized CCS for specific formulas
                         genesis tables: specific composition of 20-30 state operations
                         encoded as a fixed CCS matrix (~3,200 constraints)

level 2 (pattern match): recognized templates over the 5 primitives
                         TRANSFER = READ + READ + RANGE + ADD + ADD + WRITE + WRITE + ASSERT_EQ
                         encoded as parameterized CCS (~3-10 constraints)

level 3 (type-based):    schema-aware composition
                         N reads + M writes + authorization
                         encoded proportionally (~2N + 2M constraints)

fallback:                generic nox execution trace
                         each nox step = one trace row = ~8 constraints
                         full program traced and proven
```

every level is a composition of the 5 primitives. the jet optimizes how the composition is ENCODED in CCS, not what it COMPUTES.

## constraint cost table

| operation | CCS constraints | notes |
|---|---|---|
| READ | 1 | PCS evaluation binding |
| WRITE | 1 | updated polynomial binding |
| ASSERT_EQ | 1 | the fundamental constraint |
| ADD | 1 | linear combination in CCS matrix |
| MUL | 1 | Hadamard product in CCS |
| EXTEND | 3 | READ + ASSERT_EQ(=0) + WRITE |
| AUTHORIZE | 2 | READ(owner) + ASSERT_EQ(caller) |
| ASSERT_NEQ | 2 | MUL(a, witness) + ASSERT_EQ(=1) |
| RANGE(k bits) | 2k+1 | k bit checks + reconstruction |
| CONSERVE(n) | n | n-1 ADDs + 1 ASSERT_EQ |

a cyberlink touches ~30 state operations → ~3,200 constraints (level 1 jet).
a simple transfer touches ~8 state operations → 3 constraints (level 2 jet).

see [[ccs-jets]] for jet recognition and optimization, [[superspartan]] for CCS format, [[BBG]] architecture for polynomial state, [[nox]] patterns for the computation layer parallel
