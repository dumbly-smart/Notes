---
tags: [binary-analysis, triton, symbolic-execution, ast, chapter-notes]
chapter: 13
---

# Chapter 13 — Practical Symbolic Execution with Triton

## Chapter overview

The final chapter uses Triton to maintain symbolic machine state, compute backward slices, generate inputs for new coverage, and automate an exploitation task in the book’s controlled environment. The transferable lesson is building a feedback loop between concrete execution, symbolic constraints, and concrete validation.

> [!warning] Authorized lab use
> Apply exploit generation only to intentionally vulnerable local programs or explicitly authorized targets. Use a benign success function in practice rather than privileged shells.

## 13.1 Triton

Triton provides instruction semantics, symbolic expressions/ASTs, taint support, and solver integration. A client supplies instruction bytes and concrete machine/environment effects around the core semantics.

## 13.2 Symbolic state and ASTs

An abstract syntax tree represents expression construction:

```text
        ==
       /  \
      +    0x42
     / \
    X   3
```

This models `X + 3 == 0x42`. AST nodes retain widths and operations. Simplification reduces noise, but incorrect algebra across bit widths changes meaning.

Registers and memory can have both concrete values (to execute the current path) and symbolic expressions (to reason about alternatives). Synchronization between them is essential.

## 13.3 Backward slicing

A backward slice starts at a target expression and recursively retains only symbolic dependencies that influence it.

```text
input A ─→ transform ─┐
                     ├→ branch condition
input B ─→ irrelevant┘
```

If `B` has no dependency path to the branch, it is excluded. This reduces expressions and identifies relevant input bytes.

Implementation steps:

1. configure architecture and modes;
2. load concrete register/memory state;
3. symbolize chosen input bytes;
4. emulate each instruction on the concrete trace/path;
5. capture symbolic expressions/branch constraints;
6. request the slice of the selected expression;
7. map symbolic variables back to original input offsets.

## 13.4 Increasing code coverage

Concolic path exploration:

1. execute seed input;
2. collect ordered path constraints;
3. choose a branch not previously taken;
4. preserve earlier decisions and negate that branch condition;
5. solve for symbolic input bytes;
6. materialize a new test case;
7. run it concretely;
8. retain it if it reaches new coverage;
9. repeat with worklist limits.

For path decisions `C1, C2, C3`, to flip the third while retaining the prefix:

```text
C1 ∧ C2 ∧ ¬C3
```

Do not include later constraints because they occurred after the branch being changed.

### Search strategy

Breadth-first favors shallow alternatives; depth-first dives quickly; coverage-guided prioritizes unseen edges; distance-to-target uses CFG estimates. Timeouts and solver complexity need explicit budgets.

## 13.5 Automated vulnerability exploitation

The book demonstrates a controlled vulnerable program and automatically constructs input that redirects execution. General safe-lab pipeline:

```text
find vulnerable call site
 → symbolize attacker input
 → execute until control data is overwritten/used
 → constrain target to benign `win()` address
 → solve input bytes under format constraints
 → replay against exact lab binary
```

### Root cause versus solve target

The root cause might be an unbounded copy. The symbolic goal might constrain a saved return address. Solving the latter does not explain why the overwrite was possible; a proper analysis reports both.

### Environmental constraints

Account for:

- PIE/ASLR and address knowledge;
- stack canary and where overwrite occurs;
- NX and target choice;
- input transformations/terminators;
- bad bytes/length limits;
- calling convention/stack alignment;
- library versions and clean-run reproducibility.

For training, compile an authorized toy with a `win()` function that prints a marker, then first analyze a hardened build. Disabling protections is a learning comparison, not a production-impact claim.

## Added miniature constraint example

A four-byte input is transformed:

```text
y0 = x0 XOR 0x13
y1 = x1 + 3
success iff y0=0x58 and y1=0x48 and x2=x0-2 and x3='!'
```

Backward slicing from success retains all four inputs. Solver/algebra yields `x0='K'`, `x1='E'`, `x2='I'`, `x3='!'`. Replay `KEI!`; also test one-byte changes to verify the model.

## Common mistakes

- Failing to synchronize concrete memory changed by syscalls.
- Negating a branch while retaining later incompatible constraints.
- Losing input-offset provenance for symbolic variables.
- Solving a target address unavailable under ASLR.
- Claiming exploitability from a model without replay/reliability.
- Generating privileged payloads when a benign marker proves control.

## Practice questions

1. What information must an AST preserve for machine semantics?
2. Explain how backward slicing improves scalability.
3. Given constraints `C1,C2,C3`, formulate a query to flip the second branch.
4. Why must syscall results update concrete and perhaps symbolic state?
5. Distinguish vulnerability root cause, symbolic sink, and demonstrated primitive.
6. Design a stopping policy for coverage generation.

## Solutions

1. Operation, operand order, exact bit widths, signed/unsigned operators, extracts/extensions, and variable provenance.
2. It removes expressions/input bytes unrelated to the target, reducing AST and solver search while retaining dependencies under the model.
3. Preserve the prefix `C1` and assert `¬C2`; omit `C3` because it belongs to the old later path.
4. The emulator cannot infer external writes/returns; stale concrete state makes subsequent decoding/constraints diverge. Model taint/symbolic relationships according to policy.
5. Root cause is violated invariant, sink is constrained security-relevant use, primitive is experimentally proven capability such as target control.
6. Bound time, generated cases, solver time per query, loop iterations, memory, and no-progress attempts; prioritize new edges and record unresolved branches.

## Mastery checklist

- [ ] Build and inspect width-correct ASTs.
- [ ] Compute a backward slice with input provenance.
- [ ] Generate and replay a new-branch test case.
- [ ] Explain exploit generation without confusing model and deployed reality.
