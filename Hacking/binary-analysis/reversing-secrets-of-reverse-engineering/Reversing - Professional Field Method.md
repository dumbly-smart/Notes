---
tags: [reverse-engineering, methodology, field-guide]
---
x
# Reversing — Professional Field Method

## The real “secret”

Expert reversing is not memorizing instructions. It is repeatedly reducing uncertainty while moving between representations:

```text
external behavior ⇄ OS events ⇄ functions/CFG ⇄ instructions
       ⇅                  ⇅             ⇅             ⇅
 files/protocols     objects/handles   structures    bytes/flags
```

## Rule 1 — Begin with a question

Bad objective: “understand the whole binary.”

Useful questions:

- Which input selects this error?
- Where is this file field validated?
- What object owns this pointer?
- Which bytes become the network command?
- Why does this function return failure?

A precise question tells you where to slice and what evidence would settle it.

## Rule 2 — Rename only at earned confidence

Use progressive names:

```text
sub_401230
 → parses_16_byte_header?
 → parse_archive_header
 → parse_archive_header_v2
```

Store the reason: xrefs, arguments, side effects, data layout, and runtime test. Names are compressed hypotheses; careless names contaminate later reasoning.

## Rule 3 — Track types as constraints

Type inference is accumulated evidence:

- access width suggests scalar width;
- sign/zero extension suggests interpretation;
- scaled index suggests element size;
- stable field offsets suggest structure;
- consumer APIs constrain pointer/string/object meaning;
- constructor/destructor/copy behavior constrains lifetime.

Do not force an exact source type when only “32-bit unsigned-like count” is known.

## Rule 4 — Recover invariants, not syntax

The best explanation of a loop is often its invariant:

```text
before every iteration:
0 ≤ cursor ≤ payload_size
sum equals bytes[0..cursor)
```

This survives compiler reordering better than a guessed `for` loop.

## Rule 5 — Use two independent evidence layers

Examples:

- static xref plus debugger argument;
- file-field arithmetic plus successful independent parser;
- inferred callback table plus observed indirect calls;
- decompiler structure plus instruction flag semantics;
- unpacking write trace plus execution of written bytes.

Agreement increases confidence; disagreement identifies the next question.

## Rule 6 — Make experiments discriminating

Change one factor while keeping others stable. To test whether byte 4 is a version:

1. save baseline input/output/trace;
2. alter only byte 4;
3. compare branch and error path;
4. test values below, at, and above accepted range;
5. restore byte 4 and alter a different byte as control.

## Rule 7 — Maintain an uncertainty register

| Claim | Evidence | Confidence | Competing explanation | Next test |
|---|---|---:|---|---|
| field +8 is count | loop bound, allocation multiplier | medium | byte length | compare element strides |

This prevents polished pseudocode from hiding unanswered questions.

## Rule 8 — Learn compiler families, not magic signatures

Compile tiny programs with several compilers, optimization levels, architectures, and flags. For every pattern ask which semantics must remain and which surface form can change. A prologue signature is brittle; ABI and data-flow reasoning transfer.

## Rule 9 — Separate historical source from equivalent model

You can often recover behavior precisely without knowing original variable names, class layout declarations, macro boundaries, or source control structure. State “equivalent model” when exact historical recovery is impossible.

## Rule 10 — Stop with a reproducible answer

A completed reversing result contains:

- exact target hash/version/environment;
- the question and answer;
- facts versus inference;
- annotated addresses/module offsets;
- reconstructed types/algorithm/interface;
- reproduction commands/input;
- negative/edge tests;
- remaining unknowns and confidence.

## Daily drills

1. **Ten-minute function:** identify inputs, outputs, blocks, calls, side effects.
2. **Type drill:** reconstruct a structure from five offset accesses.
3. **Branch drill:** explain signed/unsigned flag use.
4. **Cross-view drill:** correlate one syscall with its call site and data producer.
5. **Compiler drill:** reverse the same source at `-O0/-O2` without reading source.
6. **Naming drill:** justify every renamed function in one sentence.
7. **Unknown drill:** list three facts you still cannot infer.

## Plateau breakers

- If assembly feels like noise, draw blocks and track only one value.
- If the graph is huge, start from a string/import/error/output and slice backward.
- If dynamic tracing is noisy, break at semantic boundaries and use conditional breakpoints.
- If the decompiler looks convincing, verify every security-relevant comparison in instructions.
- If indirect control blocks progress, use runtime targets, relocations, pointer tables, and value-set constraints.
- If the sample is packed, stop analyzing stub junk as application logic; find write-to-execute transition.
- If you are guessing types, compare multiple call sites and access widths.

## Professional report skeleton

```markdown
# Target and scope
## Executive behavior
## Environment and sample identity
## Questions answered
## External behavior timeline
## Component and function map
## Data structures / file or protocol specification
## Key algorithms and invariants
## Security-relevant findings
## Anti-analysis or packing
## Experiments and reproduction
## Confidence, competing hypotheses, and unknowns
```


> [!integration]
> Perform these exercises with [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] and the paired mentor-code volumes. A lab is complete only when static predictions agree with dynamic evidence.
