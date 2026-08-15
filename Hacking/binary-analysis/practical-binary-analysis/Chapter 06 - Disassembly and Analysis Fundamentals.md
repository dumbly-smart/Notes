---
tags: [binary-analysis, disassembly, cfg, data-flow, chapter-notes]
chapter: 6
---

# Chapter 6 — Disassembly and Binary Analysis Fundamentals

## Chapter overview

Decoding a known instruction is easy compared with deciding which bytes are instructions and organizing them into functions, control flow, data, and meaning. This chapter contrasts static and dynamic disassembly, then introduces program properties, CFGs, and data-flow analysis.

```text
bytes → instruction boundaries → basic blocks → functions/CFG
                                      ↓
                              data-flow facts
                                      ↓
                               security property
```

## 6.1 Static disassembly

### Linear sweep

Start at a region beginning, decode one instruction, advance by decoded length, repeat.

```text
pc = start
while pc < end:
    insn = decode(bytes[pc])
    emit(insn)
    pc += insn.length
```

**Advantages:** fast, simple, high coverage.

**Failure:** inline data, padding, or one wrong boundary poisons later decoding.

### Recursive traversal

Start from known entry points and follow direct control-flow successors.

```text
worklist = {entry}
while worklist:
    address = pop
    decode block until branch/return
    add known successors not visited
```

**Advantages:** avoids much unreachable inline data and naturally builds CFG edges.

**Failure:** indirect calls/jumps, missing entry points, callbacks, exceptions, jump tables, shared tails, and obfuscation create under-coverage.

| Question | Linear | Recursive |
|---|---|---|
| Does it decode unreachable bytes? | often | less often |
| Does it find disconnected code? | possibly | only with seeded entry |
| Handles inline data | poorly | better if unreachable |
| Handles indirect target | not semantically | needs target recovery |

Practical tools combine algorithms and metadata rather than treating either as infallible.

## 6.2 Dynamic disassembly

Dynamic tracing records instructions actually executed in a run. This guarantees those bytes were executed under that run’s state, handles generated/self-modified code, and exposes targets of indirect branches.

It does **not** show unexecuted paths.

### Coverage strategies

- construct input classes manually;
- fuzz inputs and retain coverage-increasing cases;
- use concolic/symbolic path exploration;
- force or snapshot environment states;
- merge traces across runs;
- use static reachability to target uncovered branches.

**Coverage is relative to a model:** instruction, basic-block, edge, path, function, or state coverage. “90% coverage” is meaningless without the denominator and measurement definition.

## 6.3 Structuring code and data

### Basic blocks

A basic block has one entry and straight-line execution to one terminating transfer. Leaders include known entries, branch targets, and fall-through after conditional transfers.

### Functions

Evidence for starts includes call targets, symbols, unwind data, exported entries, constructors, pointer tables, and compiler patterns. Prologues are clues, not requirements. Optimization permits tail calls, inlining, shared epilogues, and omitted frame pointers.

### Data structures

Repeated address patterns reveal arrays/structures:

```asm
mov eax, [rdi+8]
mov rdx, [rdi+16]
cmp byte ptr [rdi+24], 0
```

This supports a hypothesis of fields at offsets 8, 16, and 24. Determine type using access widths, consumers, pointer validity, and multiple call sites.

### Decompilation

Decompilation translates lower-level semantics into a high-level representation. It invents variable names/types and structures control flow heuristically. Treat it as a readable hypothesis over instructions.

### Intermediate representations

An IR normalizes ISA-specific instructions into fewer semantic operations, making analysis reusable.

```text
x86 `add eax, ebx`
 → t0 = read_reg(EAX)
 → t1 = read_reg(EBX)
 → t2 = t0 + t1
 → write_reg(EAX,t2)
 → update_flags(t0,t1,t2)
```

The quality of analysis depends on faithful flag, width, memory, and undefined-behavior semantics.

## 6.4 Analysis properties

### Soundness and completeness

Terminology depends on the property, but useful intuition is:

- **sound over-approximation:** includes every real possibility, perhaps false positives;
- **complete/precise in another sense:** excludes impossibilities, difficult for undecidable general problems;
- **under-approximation:** reports only observed/proven behaviors, but may miss others.

Dynamic execution is an under-approximation of all possible paths. Conservative static analysis often over-approximates indirect targets.

### Decidability and Rice-like limits

Nontrivial semantic properties of arbitrary programs cannot generally be decided perfectly. Real tools choose tradeoffs: bound analysis, approximate, time out, model only supported instructions, or require human input.

### Control-flow analysis

A CFG is `G = (V,E)`, where vertices are blocks and edges are possible transfers. Conditional branches add taken/fall-through edges; calls may add call and return relationships; indirect transfers require target analysis.

**Worked CFG:**

```asm
cmp edi, 0
jle fail
call process
test eax, eax
je fail
mov eax, 1
ret
fail: xor eax,eax
ret
```

There are entry/test, process-call/test, success, and failure blocks. `fail` has two predecessors. `process` return affects the second branch.

### Data-flow analysis

Data-flow equations compute facts to a fixed point.

For reaching definitions:

```text
IN[B]  = union OUT[P] for predecessors P
OUT[B] = GEN[B] ∪ (IN[B] - KILL[B])
```

`GEN` contains definitions produced by the block; `KILL` contains older definitions overwritten. Iterate until sets stop changing.

Use-def chains then answer which definitions may reach a use. Liveness runs backward to identify values that may be used before redefinition.

## 6.5 Compiler settings

Optimization, PIE, stack protection, CFI, sanitizers, LTO, and frame-pointer settings alter layout and patterns. Debug symbols may preserve source relationships but do not undo optimization.

## Difficult example — signedness

```asm
cmp eax, 10
jle small     ; signed
```

versus:

```asm
cmp eax, 10
jbe small     ; unsigned
```

The same bit pattern `0xffffffff` is `-1` signed and a very large unsigned integer. Signedness is encoded by how flags are consumed, not by the register itself.

## Common mistakes

- Assuming every executable-section byte is code.
- Treating one dynamic trace as complete behavior.
- Declaring function boundaries from prologues alone.
- Believing decompiler names/types are recovered facts.
- Ignoring instruction widths, flag semantics, and aliasing in data flow.
- Comparing coverage percentages with different denominators.

## Practice questions

1. Construct a byte-layout situation where linear sweep fails but recursive traversal succeeds.
2. Give three code paths recursive traversal can miss.
3. Why is an indirect-branch target set often an over-approximation?
4. Compute reaching definitions for a diamond CFG with `x=1` on one arm and `x=2` on the other.
5. Explain why dynamic coverage is strong evidence yet incomplete.
6. What evidence would raise confidence that an address begins a function?
7. Why is an IR useful, and what semantic omissions make it dangerous?

## Solutions

1. Place a jump over embedded table bytes. Linear sweep decodes the table; recursive traversal follows the jump and skips unreachable data.
2. Callback address never seeded, indirect jump target unresolved, exception/TLS entry, disconnected exported entry, or path behind unsupported semantics.
3. Static values may be imprecise because aliases, arithmetic, and input widen possibilities; including all potential targets preserves soundness at the cost of false edges.
4. At the merge, both definitions reach `x` unless a subsequent definition kills them; the use-def set is `{arm1.x=1, arm2.x=2}`.
5. Executed instructions are real for that state, including generated code, but other inputs/environment/schedules can reach different paths.
6. Direct calls, symbol/unwind entry, pointer references, coherent CFG, ABI-consistent use, separate callers, and dynamic entry observations.
7. It normalizes ISAs and supports reusable analyses. Wrong widths, flags, memory aliasing, exceptions, or undefined results lead to wrong facts.

## Mastery checklist

- [ ] Implement linear and recursive algorithms on paper.
- [ ] Build a CFG and identify blocks/edges.
- [ ] Explain over- versus under-approximation.
- [ ] Solve a small reaching-definitions problem.
- [ ] Critique decompiler output using instructions and runtime evidence.

## Extended chapter synthesis

**Key ideas:** decoding, boundary discovery, CFG recovery, function recovery, and data-flow reasoning are separate approximating layers. Static analysis seeks coverage; dynamic analysis supplies concrete truth for exercised states.

**Key formulas:** `G=(V,E)` for CFG; `IN[B]=⋃OUT[pred]`; `OUT[B]=GEN[B]∪(IN[B]-KILL[B])` for reaching definitions.

**You should be able to solve:** ambiguous boundaries, block splitting, indirect-edge uncertainty, reaching definitions/liveness, signedness, compiler-optimization distortions, and decompiler verification.

Full 48-question set with worked solutions: [[Workbooks/Chapter 06 - Practice and Complete Solutions]].
