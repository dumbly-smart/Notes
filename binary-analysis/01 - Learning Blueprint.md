# Learning Blueprint

This note defines the overall learning method and dependency structure; it is not the chapter-by-chapter curriculum.

## What the book is really teaching

The book is not simply a reverse-engineering manual. Its central progression is:

```text
How source becomes a binary
          ↓
How ELF/PE files represent programs
          ↓
How to inspect and disassemble binaries
          ↓
How to modify and instrument them
          ↓
How to track information through execution
          ↓
How to reason automatically about program paths
```

Its 13 chapters form four conceptual layers:

| Layer | Chapters | Core outcome |
|---|---:|---|
| Binary foundations | 1–4 | Understand executable construction, ELF/PE, and binary loading |
| Analysis fundamentals | 5–7 | Inspect, disassemble, reason about, and modify binaries |
| Analysis infrastructure | 8–9 | Build custom disassembly and instrumentation tools |
| Automated reasoning | 10–13 | Apply taint analysis and symbolic execution |

Appendix A is effectively a hidden prerequisite: x86/x86-64 assembly. Appendices B–D are supporting references rather than a normal final unit.

## Important dependencies

- Chapter 1 is foundational for nearly everything.
- Chapter 2's ELF concepts are essential for Chapters 4, 5, 7, 8, and parts of 9.
- Chapter 3's PE material is comparatively brief and can be treated as a comparison unit unless Windows analysis is a priority.
- Chapter 4 creates a reusable binary loader that later custom tools build upon.
- Chapter 5 teaches the standard Linux analysis toolchain: `file`, `ldd`, `xxd`, `readelf`, `nm`, `strings`, `strace`, `ltrace`, `objdump`, and `gdb`.
- Chapter 6 is a major conceptual bottleneck: static versus dynamic disassembly, code discovery, control-flow structures, and analysis patterns.
- Chapter 7 depends heavily on ELF layout, linking, loading, addressing, and control flow.
- Chapter 8 combines the loader from Chapter 4 with Capstone to build custom disassembly passes and a ROP-gadget scanner.
- Chapter 9 introduces static and dynamic instrumentation, Pin, profiling, and unpacking.
- Chapters 10 and 11 form a theory–practice pair: dynamic taint analysis followed by libdft implementation.
- Chapters 12 and 13 form another theory–practice pair: symbolic execution and constraint solving followed by Triton-based tools.
- Chapter 13 reconnects symbolic execution with taint analysis, culminating in automated exploitation.

Weak assembly, C/C++, ELF, or debugger knowledge would compound in later chapters. We therefore diagnose those foundations before fixing the final route.

## Proposed approach

### Phase 0: Readiness diagnosis

Before Chapter 1, use short practical diagnostics covering:

- C pointers, structs, arrays, compilation, and linking;
- basic C++ classes and containers;
- processes and virtual memory;
- Linux shell usage;
- hexadecimal, endianness, and bit operations;
- x86-64 registers, stack frames, calls, branches, and memory operands.

This determines whether Appendix A should be studied first, used as a targeted refresher, or kept as a reference.

### Phase 1: Build the binary mental model

Establish a coherent model connecting:

```text
C source → preprocessing → assembly → object files
→ linking → ELF file → loader → process memory → execution
```

Every later subject attaches to this model. The target is to explain not only what a field or tool displays, but why it exists and how it affects execution.

### Phase 2: Learn through controlled experiments

Pair each concept with a tiny program that we compile and transform ourselves:

- compile the same program at different stages;
- strip symbols and compare the results;
- inspect sections and segments;
- change optimization and observe disassembly;
- trace calls and system calls;
- patch a harmless binary and predict the result.

This prevents commands such as `readelf` and `objdump` from becoming memorized incantations.

### Phase 3: Move from tool user to tool builder

1. Inspect binaries with standard utilities.
2. Manually interpret their results.
3. Write a binary loader.
4. Build custom disassembly logic.
5. Add instrumentation.
6. Build data-flow and symbolic-reasoning tools.

At every transition, explain what the abstraction automates and what information it can lose.

### Phase 4: Master advanced techniques as reasoning systems

Taint analysis and symbolic execution begin with hand-worked examples:

- manually propagate taint through registers and memory;
- identify sources, sinks, policies, colors, and implicit flows;
- construct symbolic expressions and path constraints;
- solve simple constraints manually;
- draw execution trees and identify path explosion;
- only then implement the reasoning with libdft, Z3, and Triton.

### Phase 5: Integration and independent analysis

The final proof of understanding will be an unfamiliar, legal practice binary analyzed from scratch:

- identify its format and security properties;
- map important code and data;
- form behavioral hypotheses;
- validate them dynamically;
- write a small custom analysis or instrumentation component;
- explain limitations and possible false conclusions.

## Interactive lesson cycle

Each lesson follows short cycles:

1. **Explanation** — teach one bounded concept.
2. **Mental model** — connect it to the larger system.
3. **Prediction** — predict what should happen before running anything.
4. **Experiment** — inspect or modify a real sample.
5. **Interpretation** — explain the result in your own words.
6. **Challenge** — apply the idea in a changed situation.
7. **Correction** — address the misconception revealed.
8. **Mastery check** — verify explanation, recognition, and application.
9. **Retention hook** — revisit it through cumulative recall later.

The pacing and difficulty adapt to the learner's answers.

## Practical compatibility issue

The book's original lab uses Ubuntu 16.04 and older releases of Pin, libdft, Triton, and related libraries. Some advanced examples may not run unchanged on a modern system. We should use a reproducible isolated environment or carefully adapted equivalents while preserving the concepts.
