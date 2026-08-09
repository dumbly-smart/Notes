---
tags: [binary-analysis, symbolic-execution, z3, bitvectors, chapter-notes]
chapter: 12
---

# Chapter 12 — Principles of Symbolic Execution

## Chapter overview

Symbolic execution represents selected inputs as expressions rather than single concrete values. Each conditional adds a path constraint; a solver finds inputs satisfying a desired path. The chapter contrasts concrete/symbolic/concolic execution, explains path explosion, and uses Z3 for reachability and bitvector reasoning.

```text
symbolic input X
 → execute semantics, build expressions
 → branch: PC ∧ condition | PC ∧ ¬condition
 → solver model
 → concrete input replay
```

## 12.1 Concrete versus symbolic

```c
int f(int x) {
    int y = x + 3;
    if (y == 10) return 1;
    return 0;
}
```

Concrete `x=2` follows only `y=5`. Symbolic `X` obtains `Y=X+3`; success constraint is `X+3=10`, whose model is `X=7`.

### Path state

A symbolic state contains registers/memory expressions, path constraint, program counter, and environment model. Branching can fork states.

### Variants

| Method | Behavior |
|---|---|
| pure symbolic | explores symbolic states from model |
| concolic | executes one concrete path while collecting symbolic alternatives |
| selective | symbolizes only chosen data/regions |
| backward | reasons from goal toward required predecessors |

### Limitations

- exponential paths;
- loops/recursion;
- symbolic pointers and memory aliasing;
- syscalls/libraries/environment;
- threads/scheduling;
- unsupported instructions, floating point, self-modification;
- solver-hard nonlinear/cryptographic constraints;
- concretization losing alternatives.

### Scalability tools

Bound input/loops, merge compatible states, summarize functions, concretize irrelevant state, use search heuristics, cache solver results, slice expressions, and prioritize new coverage.

## 12.2 Z3 reasoning

### Reachability

An instruction/path is reachable in the model if its accumulated constraint is satisfiable (`sat`). `unsat` means no model exists under the encoded assumptions. `unknown` is not `unsat`.

### Validity

Formula `F` is valid if `¬F` is unsatisfiable. This transforms a universal claim into a solver query.

### Bitvectors

Machine integers wrap at fixed width. For 8-bit `x`:

```text
x = 255; x + 1 = 0  (mod 256)
```

Signed and unsigned comparisons interpret the same bitvector differently. Z3 provides distinct operations/relations.

### Worked opaque predicate

Consider 8-bit `x` and `(x * (x + 1)) & 1 == 0`. Consecutive integers always include an even number, so the product is even. To prove validity, ask whether the negation—low bit equals 1—is satisfiable. It is unsatisfiable for all 8-bit values.

**Why this works:** parity survives modular arithmetic; the least significant bit of an even product is zero.

### Added Z3 example

```python
from z3 import BitVec, Solver, UGT
x = BitVec('x', 8)
s = Solver()
s.add(UGT(x, 200))
s.add(x + 100 == 50)  # modulo 256
print(s.check(), s.model())
```

The arithmetic equality means `x + 100 ≡ 50 (mod 256)`, so `x ≡ 206`, which also satisfies unsigned `x > 200`.

Using mathematical integers would incorrectly treat the equation as `x=-50`.

## Path explosion example

Ten independent symbolic `if` statements can create up to `2^10 = 1024` paths; 30 create over a billion. Correlated branches or unsatisfiable constraints reduce realized paths, while loops can make them unbounded.

## Common mistakes

- Modeling machine arithmetic with unbounded integers.
- Mixing signed and unsigned predicates.
- Treating solver `unknown` as proof of impossibility.
- Forgetting environmental assumptions.
- Generating a model and not replaying it.
- Symbolizing far more state than the goal needs.

## Practice questions

1. Derive path constraints for `if (x<5) if (x%2==0) target`.
2. Why does concolic execution reduce but not eliminate path explosion?
3. Prove validity using a satisfiability query.
4. Solve 8-bit `x + 250 = 10`.
5. Compare signed `x < 0` with unsigned `x < 0` for a bitvector.
6. Give three ways a concrete replay can disagree with a solver model.

## Solutions

1. Target constraint is `x<5 ∧ x mod 2=0`, with precise signedness/width specified. Other paths negate one predicate at the point taken.
2. It explores one real path at a time and uses constraints to mutate inputs, but the number of feasible alternatives can still be exponential.
3. To prove `F`, ask solver for `¬F`; `unsat` under the assumptions establishes validity.
4. Modulo 256, `x = 16` because `16+250=266 ≡ 10`.
5. Signed negative values have top bit set; unsigned `x<0` is impossible because zero is the minimum unsigned value.
6. Wrong syscall/library model, different ASLR/environment, unsupported instruction semantics, concretization, race/schedule, input encoding, or incorrect target version.

## Mastery checklist

- [ ] Maintain symbolic expressions and path constraints on paper.
- [ ] Distinguish sat/unsat/unknown and reachability/validity.
- [ ] Use fixed-width bitvectors and correct signedness.
- [ ] Bound a path-search problem and replay every model.
