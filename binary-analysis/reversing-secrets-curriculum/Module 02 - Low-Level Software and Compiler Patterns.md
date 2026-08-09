---
tags: [reverse-engineering, ia32, compilers, curriculum]
source_chapter: 2
---

# Module 2 — Low-Level Software and Compiler Patterns

## Module overview

This chapter connects high-level modules, data structures, control flow, and languages to registers, stacks, heaps, data sections, IA-32 instructions, compiler architecture, virtual machines, and processor execution. It is the central fluency module.

## High-level to low-level map

```text
variables → registers / stack slots / globals / heap fields
function → entry convention + blocks + calls + return
if/loop/switch → comparisons + flags + branch/jump table
object → pointer + field offsets + vtable/callbacks
list → node allocations + next/prev pointer traversal
```

## Registers, flags, and instructions

Track instruction state transitions. On IA-32, general registers include `EAX,EBX,ECX,EDX,ESI,EDI,EBP,ESP`; `EIP` selects execution; flags encode arithmetic/branch conditions.

```asm
cmp eax, ebx       ; flag effects of eax-ebx
jl signed_less
jb unsigned_below
```

The bits have no inherent signed type. The consuming instruction reveals interpretation.

## Stack and calls

Historical 32-bit calling conventions pass many arguments on stack and differ in cleanup/name decoration/register use. Recover convention from repeated call sites and stack deltas, not one prologue.

```text
caller pushes arguments → call pushes return address
callee optionally builds frame → locals/temporaries
callee returns → caller/callee restores arguments depending convention
```

## Heap and structures

Heap allocations establish lifetimes; offset accesses reveal fields. Repeated `base+4`, `base+8`, `base+0xc` accesses suggest structure but types come from widths, consumers, and invariants.

## Compiler architecture

```text
front end → IR → optimizer → back end → machine code
```

The front end parses language/type semantics; IR enables general transforms; optimizer changes representation while preserving observable behavior; backend selects/schedules instructions. Reversers reason backward through transformations but cannot uniquely recover lost source.

## Virtual machines and processors

Bytecode may be interpreted or JIT-compiled. Decide whether to analyze metadata/IL, interpreter behavior, or generated native code. Hardware pipelines, micro-ops, and prediction explain performance/timing but architectural semantics remain the primary correctness model.

## Pattern lab set

Compile and reverse these at debug/optimized settings:

1. signed and unsigned comparisons;
2. `for`, `while`, and `do` loops;
3. dense and sparse switches;
4. structure/array/list traversal;
5. recursion and tail calls;
6. C++ virtual dispatch;
7. integer division by constant;
8. short-circuit boolean expressions.

For each: draw CFG, identify induction variables/invariant, recover types with confidence, and explain compiler changes.

## Mastery gate

- [ ] Read 25 unseen compiler-generated functions with ≥80% semantic accuracy.
- [ ] Distinguish signed/unsigned branches and extension.
- [ ] Recover stack arguments, locals, loops, switches, and structures.
- [ ] Explain where optimizer transformations prevent exact source recovery.
